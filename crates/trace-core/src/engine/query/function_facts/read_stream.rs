//! Rescan final read groups before reserving their fields: conflicting dynamic
//! values become null without first budgeting/retaining all observations.
use super::{
    block_stream::scan_owned,
    budget::Budget,
    collector,
    fact_work::{Dependency, Fixed},
    lines,
};
use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;
use std::sync::atomic::AtomicBool;

struct Reads<'a> {
    state: &'a SessionState,
    tree: &'a ActivationTree,
    root: &'a ConfirmedActivation,
    cancel: &'a AtomicBool,
    relevant: &'a Option<Fixed<Dependency>>,
    stack: &'a [FunctionStackArgumentDto],
    sp: u64,
}
impl Reads<'_> {
    fn scan(&self, mut visit: impl FnMut(u64, u32, Option<&str>, u32) -> Result<()>) -> Result<()> {
        scan_owned(self.state, self.tree, self.root, self.cancel, |insn| {
            let Some((m, op)) = trace_parser::strict_memory::instruction_parts(insn.line) else {
                return Ok(true);
            };
            let Some(address) = lines::line_mem_annotation(insn.line, "mem_r") else {
                return Ok(true);
            };
            let Some(size) = lines::access_width(m, op) else {
                return Ok(true);
            };
            if trace_parser::strict_memory::memory_op(insn.line).is_none()
                || address.checked_add(size as u64 - 1).is_none()
            {
                return Ok(true);
            }
            let mut relevant = self
                .relevant
                .as_ref()
                .is_none_or(|r| r.values.binary_search_by_key(&insn.seq, |d| d.seq).is_ok());
            if !relevant && super::dataflow::literal_load_address(m, op) == Some(address) {
                let register = op.split(',').next().unwrap_or("").trim();
                scan_owned(self.state, self.tree, self.root, self.cancel, |consumer| {
                    if consumer.seq > insn.seq {
                        if let Some((_, operands)) =
                            trace_parser::strict_memory::instruction_parts(consumer.line)
                        {
                            if operands.split(',').skip(1).any(|p| p.trim() == register) {
                                relevant = true;
                                return Ok(false);
                            }
                        }
                    }
                    Ok(true)
                })?;
            }
            if !relevant
                || (self.sp != u64::MAX
                    && self.stack.iter().any(|s| {
                        self.sp.checked_add(s.offset as u64) == Some(address) && s.size == size
                    }))
            {
                return Ok(true);
            }
            let external = super::memory_stream::external_mask(
                self.state,
                self.tree,
                self.root,
                self.cancel,
                address,
                size,
                insn.seq,
            )?;
            let bytes = super::byte_effect::memory_bytes(insn.line, size);
            let mut offset = 0;
            while offset < size as usize {
                if !external[offset] {
                    offset += 1;
                    continue;
                }
                let start = offset;
                while offset < size as usize && external[offset] {
                    offset += 1;
                }
                let range = &bytes[start..offset];
                // Fixed ISA-width scratch, never a growing output string.
                let mut hex = [0u8; 128];
                let known = range.iter().all(Option::is_some);
                if known {
                    const DIGITS: &[u8] = b"0123456789abcdef";
                    for (pos, byte) in range.iter().enumerate() {
                        let byte = byte.expect("known");
                        hex[pos * 2] = DIGITS[(byte >> 4) as usize];
                        hex[pos * 2 + 1] = DIGITS[(byte & 15) as usize];
                    }
                }
                visit(
                    address + start as u64,
                    range.len() as u32,
                    known.then(|| std::str::from_utf8(&hex[..range.len() * 2]).expect("hex")),
                    insn.seq,
                )?;
            }
            Ok(true)
        })
    }
}
struct GroupSeqs<'a, 'b> {
    reads: &'a Reads<'b>,
    key: (u64, u32),
}
impl serde::Serialize for GroupSeqs<'_, '_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut out = serializer.serialize_seq(None)?;
        let mut last = None;
        self.reads
            .scan(|address, size, _, seq| {
                if (address, size) == self.key && last != Some(seq) {
                    out.serialize_element(&seq)
                        .map_err(|e| TraceError::Internal(e.to_string()))?;
                    last = Some(seq);
                }
                Ok(())
            })
            .map_err(S::Error::custom)?;
        out.end()
    }
}
#[derive(serde::Serialize)]
struct Plain<'a, 'b, 'c> {
    address: &'a str,
    size: u32,
    bytes: Option<&'a str>,
    read_seqs: GroupSeqs<'b, 'c>,
}
#[derive(serde::Serialize)]
struct Global<'a, 'b, 'c> {
    global: &'a str,
    size: u32,
    bytes: Option<&'a str>,
    read_seqs: GroupSeqs<'b, 'c>,
}

pub(super) fn collect(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
    relevant: &Option<Fixed<Dependency>>,
    sp: u64,
    modules: &[String],
    dto: &mut FunctionFactBundleDto,
    budget: &mut Budget,
) -> Result<()> {
    let reads = Reads {
        state,
        tree,
        root,
        cancel,
        relevant,
        stack: &dto.abi.stack_arguments,
        sp,
    };
    let mut previous = None;
    loop {
        let mut next = None;
        reads.scan(|address, size, _, _| {
            let key = (address, size);
            if previous.is_none_or(|p| key > p) && next.is_none_or(|n| key < n) {
                next = Some(key);
            }
            Ok(())
        })?;
        let Some(key @ (address, size)) = next else {
            break;
        };
        let mut bytes = [0u8; 128];
        let mut known = true;
        let mut first = true;
        let mut global = None;
        let mut all_global = !modules.is_empty();
        reads.scan(|addr, width, hex, seq| {
            if (addr, width) != key {
                return Ok(());
            }
            match hex {
                Some(hex) if first => bytes[..hex.len()].copy_from_slice(hex.as_bytes()),
                Some(hex) if &bytes[..hex.len()] != hex.as_bytes() => known = false,
                None => known = false,
                _ => {}
            }
            first = false;
            if all_global {
                match super::global_stream::identity(
                    state, tree, root, cancel, modules, seq, address, size,
                )? {
                    Some(identity) if global.as_ref().is_none_or(|old| old == &identity) => {
                        global = Some(identity)
                    }
                    _ => all_global = false,
                }
            }
            Ok(())
        })?;
        let bytes = known.then(|| std::str::from_utf8(&bytes[..size as usize * 2]).expect("hex"));
        let address = format!("0x{address:x}");
        let global = if all_global { global } else { None };
        if let Some(global) = &global {
            budget.item(
                &Global {
                    global,
                    size,
                    bytes,
                    read_seqs: GroupSeqs { reads: &reads, key },
                },
                2,
                dto.global_reads.is_empty(),
            )?;
        } else {
            budget.item(
                &Plain {
                    address: &address,
                    size,
                    bytes,
                    read_seqs: GroupSeqs { reads: &reads, key },
                },
                2,
                dto.memory_reads.is_empty(),
            )?;
        }
        let mut seqs = Vec::new();
        reads.scan(|addr, width, _, seq| {
            if (addr, width) == key && seqs.last() != Some(&seq) {
                collector::reserve_vec(&mut seqs)?;
                seqs.push(seq);
            }
            Ok(())
        })?;
        if bytes.is_none() {
            collector::unresolved(
                &mut dto.unresolved,
                budget,
                "missing_memory_definition",
                seqs.iter().copied(),
                Some(&address),
                &format!("内存读取 {address} 字节值未完全确定"),
            )?;
        }
        if let Some(global) = global {
            collector::reserve_vec(&mut dto.global_reads)?;
            dto.global_reads.push(FunctionGlobalReadDto {
                global,
                size,
                bytes: bytes.map(str::to_owned),
                read_seqs: seqs,
            });
        } else {
            collector::reserve_vec(&mut dto.memory_reads)?;
            dto.memory_reads.push(FunctionMemoryReadDto {
                address,
                size,
                bytes: bytes.map(str::to_owned),
                read_seqs: seqs,
            });
        }
        previous = Some(key);
    }
    Ok(())
}
