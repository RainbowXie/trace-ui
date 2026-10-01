//! Formal logical bundle projection and checked, pre-materialization accounting.
use crate::api_types::*;
use crate::error::{Result, TraceError};
use serde::Serialize;
use std::io::{self, Write};

pub const FACT_BUNDLE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FactSourceReference<'a> {
    pub artifact: &'a str,
    pub pointer: &'a str,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct FactActivationSelector<'a> {
    pub trace: FactSourceReference<'a>,
    pub function: &'a str,
    pub call_seq: u32,
    pub entry_seq: u32,
}
/// Actual, caller-verified source identity, not an arbitrary byte allowance.
#[derive(Clone, Copy, Debug)]
pub struct FunctionFactContext<'a> {
    pub trace: FactSourceReference<'a>,
    pub activation: FactActivationSelector<'a>,
}

#[derive(Serialize)]
struct Projection<'a, 'b> {
    trace: FactSourceReference<'a>,
    activation: FactActivationSelector<'a>,
    anchors: &'b FunctionTraceAnchorsDto,
    abi: &'b FunctionAbiDto,
    executed_block_sequence: &'b [ExecutedBlockEntryDto],
    memory_reads: &'b [FunctionMemoryReadDto],
    global_reads: &'b [FunctionGlobalReadDto],
    memory_writes: &'b [FunctionMemoryWriteDto],
    global_writes: &'b [FunctionGlobalWriteDto],
    external_call_events: &'b [FunctionExternalCallEventDto],
    unresolved: &'b [FunctionFactUnresolvedDto],
}
impl<'a, 'b> Projection<'a, 'b> {
    fn new(context: FunctionFactContext<'a>, dto: &'b FunctionFactBundleDto) -> Self {
        Self {
            trace: context.trace,
            activation: context.activation,
            anchors: &dto.trace_anchors,
            abi: &dto.abi,
            executed_block_sequence: &dto.executed_block_sequence,
            memory_reads: &dto.memory_reads,
            global_reads: &dto.global_reads,
            memory_writes: &dto.memory_writes,
            global_writes: &dto.global_writes,
            external_call_events: &dto.external_call_events,
            unresolved: &dto.unresolved,
        }
    }
}
struct Counter {
    bytes: u64,
    newlines: u64,
    limit: u64,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::other("function facts logical bundle size limit exceeded"))?;
        self.bytes = next;
        self.newlines = self
            .newlines
            .checked_add(bytes.iter().filter(|b| **b == b'\n').count() as u64)
            .ok_or_else(|| io::Error::other("function facts count overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn measure(value: &impl Serialize, limit: u64) -> Result<(u64, u64)> {
    let mut counter = Counter {
        bytes: 0,
        newlines: 0,
        limit,
    };
    serde_json::to_writer_pretty(&mut counter, value)
        .map_err(|e| TraceError::Internal(e.to_string()))?;
    Ok((counter.bytes, counter.newlines))
}

/// Serialize the formal temporary bundle (no top-level function; anchors, not
/// trace_anchors). The entire output, including its sole trailing LF, is bounded.
pub fn write_function_fact_projection(
    context: FunctionFactContext<'_>,
    dto: &FunctionFactBundleDto,
    output: &mut impl Write,
) -> Result<u64> {
    struct Bounded<'a, W> {
        output: &'a mut W,
        bytes: u64,
    }
    impl<W: Write> Write for Bounded<'_, W> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let next = self
                .bytes
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= FACT_BUNDLE_LIMIT)
                .ok_or_else(|| {
                    io::Error::other("function facts logical bundle size limit exceeded")
                })?;
            self.output.write_all(bytes)?;
            self.bytes = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.output.flush()
        }
    }
    let mut writer = Bounded { output, bytes: 0 };
    serde_json::to_writer_pretty(&mut writer, &Projection::new(context, dto))
        .map_err(|e| TraceError::Internal(e.to_string()))?;
    writer.write_all(b"\n")?;
    Ok(writer.bytes)
}

pub(super) struct Budget {
    used: u64,
    limit: u64,
}
impl Budget {
    #[cfg(test)]
    pub(super) fn used_for_test(&self) -> u64 {
        self.used
    }
    #[cfg(test)]
    pub(super) fn limit_for_test(&mut self, limit: u64) {
        self.limit = limit;
    }
    #[cfg(test)]
    pub(super) fn new(
        context: FunctionFactContext<'_>,
        dto: &FunctionFactBundleDto,
    ) -> Result<Self> {
        Self::with_limit(context, dto, FACT_BUNDLE_LIMIT)
    }
    pub(super) fn with_limit(
        context: FunctionFactContext<'_>,
        dto: &FunctionFactBundleDto,
        limit: u64,
    ) -> Result<Self> {
        let used = measure(&Projection::new(context, dto), limit)?
            .0
            .checked_add(1)
            .ok_or_else(overflow)?;
        let mut budget = Self { used: 0, limit };
        budget.add(used)?;
        Ok(budget)
    }
    pub(super) fn add(&mut self, bytes: u64) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| {
                TraceError::Internal("function facts logical bundle size limit exceeded".into())
            })?;
        Ok(())
    }
    /// Cost of a standalone item shifted to its actual pretty-array depth.
    /// For first item replace [] with [LF item LF closing-indent]; later add comma/LF.
    pub(super) fn item_cost(&self, item: &impl Serialize, depth: u64, first: bool) -> Result<u64> {
        if depth == 0 {
            return Err(overflow());
        }
        let (bytes, lines) = measure(
            item,
            self.limit.checked_sub(self.used).ok_or_else(overflow)?,
        )?;
        let indentation = depth.checked_mul(2).ok_or_else(overflow)?;
        bytes
            .checked_add(
                lines
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(indentation))
                    .ok_or_else(overflow)?,
            )
            .and_then(|n| n.checked_add(if first { indentation } else { 2 }))
            .ok_or_else(overflow)
    }
    pub(super) fn item(&mut self, item: &impl Serialize, depth: u64, first: bool) -> Result<()> {
        self.add(self.item_cost(item, depth, first)?)
    }
    pub(super) fn verify(
        &self,
        context: FunctionFactContext<'_>,
        dto: &FunctionFactBundleDto,
    ) -> Result<()> {
        let actual = measure(&Projection::new(context, dto), self.limit)?
            .0
            .checked_add(1)
            .ok_or_else(overflow)?;
        if actual != self.used {
            return Err(TraceError::Internal(format!(
                "function facts budget mismatch: reserved {} actual {actual}",
                self.used
            )));
        }
        Ok(())
    }
}
fn overflow() -> TraceError {
    TraceError::Internal("function facts checked count overflow".into())
}

pub(super) struct Seqs<I>(pub I);
impl<I: Clone + Iterator<Item = u32>> Serialize for Seqs<I> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;
        for value in self.0.clone() {
            seq.serialize_element(&value)?;
        }
        seq.end()
    }
}
