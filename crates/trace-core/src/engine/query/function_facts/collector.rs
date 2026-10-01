//! Final fields are retained only after formal pretty-encoding reservations.
use super::budget::{Budget, Seqs};
use crate::api_types::*;
use crate::error::{Result, TraceError};
use serde::Serialize;

pub(super) fn reserve_vec<T>(values: &mut Vec<T>) -> Result<()> {
    values
        .try_reserve_exact(1)
        .map_err(|e| TraceError::Internal(format!("function facts allocation: {e}")))
}
#[derive(Serialize)]
#[serde(bound(serialize = "I: Clone + Iterator<Item = u32>"))]
struct Unresolved<'a, I, D: std::fmt::Display + ?Sized> {
    kind: &'a str,
    seqs: Seqs<I>,
    location: Option<&'a str>,
    detail: DisplayText<'a, D>,
}
struct DisplayText<'a, D: ?Sized>(&'a D);
impl<D: std::fmt::Display + ?Sized> Serialize for DisplayText<'_, D> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}
fn display_eq(value: &(impl std::fmt::Display + ?Sized), text: &str) -> bool {
    struct Compare<'a> {
        remaining: &'a str,
        equal: bool,
    }
    impl std::fmt::Write for Compare<'_> {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            if let Some(rest) = self.remaining.strip_prefix(value) {
                self.remaining = rest;
            } else {
                self.equal = false;
            }
            Ok(())
        }
    }
    let mut compare = Compare {
        remaining: text,
        equal: true,
    };
    let _ = std::fmt::write(&mut compare, format_args!("{value}"));
    compare.equal && compare.remaining.is_empty()
}
pub(super) fn unresolved<I: Clone + Iterator<Item = u32>>(
    out: &mut Vec<FunctionFactUnresolvedDto>,
    budget: &mut Budget,
    kind: &str,
    seqs: I,
    location: Option<&str>,
    detail: &(impl std::fmt::Display + ?Sized),
) -> Result<()> {
    // Dedupe before charging; no temporary sequence vector.
    if out.iter().any(|u| {
        u.kind == kind && display_eq(detail, &u.detail) && u.seqs.iter().copied().eq(seqs.clone())
    }) {
        return Ok(());
    }
    let item = Unresolved {
        kind,
        seqs: Seqs(seqs.clone()),
        location,
        detail: DisplayText(detail),
    };
    budget.item(&item, 2, out.is_empty())?;
    reserve_vec(out)?;
    let mut materialized = Vec::new();
    for seq in seqs {
        reserve_vec(&mut materialized)?;
        materialized.push(seq);
    }
    out.push(FunctionFactUnresolvedDto {
        kind: kind.into(),
        seqs: materialized,
        location: location.map(str::to_owned),
        detail: detail.to_string(),
    });
    Ok(())
}

/// Serialize lowercase hex directly from byte cells for reservation, without
/// constructing a potentially over-budget String first.
pub(super) struct Hex<'a>(
    pub &'a [super::fact_work::Cell],
    pub &'a std::sync::atomic::AtomicBool,
);
impl Serialize for Hex<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        struct DisplayHex<'a>(&'a [super::fact_work::Cell]);
        impl std::fmt::Display for DisplayHex<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for c in self.0 {
                    write!(f, "{:02x}", c.value.expect("known range"))?;
                }
                Ok(())
            }
        }
        if self.1.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(serde::ser::Error::custom("operation cancelled"));
        }
        serializer.collect_str(&DisplayHex(self.0))
    }
}
#[derive(Serialize)]
#[serde(bound(serialize = "I: Clone + Iterator<Item = u32>"))]
struct WritePreview<'a, I> {
    address: &'a str,
    size: u32,
    bytes: Option<Hex<'a>>,
    write_seqs: Seqs<I>,
}
pub(super) fn writes(
    state: &crate::session::SessionState,
    tree: &crate::query::activation::ActivationTree,
    root: &crate::query::activation::ConfirmedActivation,
    cancel: &std::sync::atomic::AtomicBool,
    modules: &[String],
    dto: &mut FunctionFactBundleDto,
    budget: &mut Budget,
    cells: &[super::fact_work::Cell],
) -> Result<()> {
    let check = || {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            Err(TraceError::Cancelled)
        } else {
            Ok(())
        }
    };
    let mut start = 0;
    while start < cells.len() {
        check()?;
        let mut end = start + 1;
        while end < cells.len()
            && cells[end - 1].address.checked_add(1) == Some(cells[end].address)
            && cells[start].value.is_some() == cells[end].value.is_some()
            && (cells[start].value.is_some() || cells[end].seq == cells[start].seq)
        {
            check()?;
            end += 1;
        }
        let range = &cells[start..end];
        // Contributions preserve the existing first-address encounter ordering.
        let seqs = range.iter().enumerate().filter_map(|(pos, c)| {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return None;
            }
            (!range[..pos].iter().any(|prior| {
                cancel.load(std::sync::atomic::Ordering::Relaxed) || prior.seq == c.seq
            }))
            .then_some(c.seq)
        });
        let address = format!("0x{:x}", range[0].address);
        let size = u32::try_from(range.len())
            .map_err(|_| TraceError::Internal("write size overflow".into()))?;
        let known = range[0].value.is_some();
        let mut global = None;
        let mut all_global = !modules.is_empty();
        for seq in seqs.clone() {
            if !all_global {
                break;
            }
            match super::global_stream::identity(
                state,
                tree,
                root,
                cancel,
                modules,
                seq,
                range[0].address,
                size,
            )? {
                Some(next) if global.as_ref().is_none_or(|old| old == &next) => global = Some(next),
                _ => all_global = false,
            }
        }
        let global = if all_global { global } else { None };
        #[derive(Serialize)]
        #[serde(bound(serialize = "I: Clone + Iterator<Item = u32>"))]
        struct GlobalPreview<'a, I> {
            global: &'a str,
            size: u32,
            bytes: Option<Hex<'a>>,
            write_seqs: Seqs<I>,
        }
        if let Some(global) = &global {
            budget.item(
                &GlobalPreview {
                    global,
                    size,
                    bytes: known.then_some(Hex(range, cancel)),
                    write_seqs: Seqs(seqs.clone()),
                },
                2,
                dto.global_writes.is_empty(),
            )?;
        } else {
            budget.item(
                &WritePreview {
                    address: &address,
                    size,
                    bytes: known.then_some(Hex(range, cancel)),
                    write_seqs: Seqs(seqs.clone()),
                },
                2,
                dto.memory_writes.is_empty(),
            )?;
        }
        check()?;
        let mut bytes = known.then(String::new);
        if let Some(bytes) = &mut bytes {
            bytes
                .try_reserve_exact(
                    range
                        .len()
                        .checked_mul(2)
                        .ok_or_else(|| TraceError::Internal("hex length overflow".into()))?,
                )
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            use std::fmt::Write;
            for c in range {
                check()?;
                write!(bytes, "{:02x}", c.value.expect("known range")).expect("String write");
            }
        }
        let mut write_seqs = Vec::new();
        for seq in seqs {
            check()?;
            reserve_vec(&mut write_seqs)?;
            write_seqs.push(seq);
        }
        if !known {
            unresolved(
                &mut dto.unresolved,
                budget,
                "missing_memory_definition",
                write_seqs.iter().copied(),
                Some(&address),
                &format!("内存写入 {address} 字节值未完全确定"),
            )?;
        }
        if let Some(global) = global {
            reserve_vec(&mut dto.global_writes)?;
            dto.global_writes.push(FunctionGlobalWriteDto {
                global,
                size,
                bytes,
                write_seqs,
            });
        } else {
            reserve_vec(&mut dto.memory_writes)?;
            dto.memory_writes.push(FunctionMemoryWriteDto {
                address,
                size,
                bytes,
                write_seqs,
            });
        }
        start = end;
    }
    Ok(())
}
