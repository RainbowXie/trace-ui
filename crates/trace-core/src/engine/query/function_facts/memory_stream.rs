//! Bounded final-byte state and dependency closure, without write history.
use super::{
    block_stream::scan_owned,
    fact_work::{Cell, Dependency, Fixed},
    lines,
};
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) enum Effect {
    None,
    Applied {
        address: u64,
        size: u32,
        bytes: Vec<Option<u8>>,
    },
    Block {
        address: u64,
        size: u32,
    },
}
/// Decode only ISA-width memory items (at most 64 bytes); unknown never becomes zero.
pub(super) fn effect(line: &str) -> Option<Effect> {
    let address = lines::line_mem_annotation(line, "mem_w")?;
    let (mnemonic, operand) = trace_parser::strict_memory::instruction_parts(line)?;
    Some(
        match lines::exclusive_store_outcome(line, mnemonic, operand) {
            Some(lines::ExclusiveStoreOutcome::Failed) => Effect::None,
            Some(lines::ExclusiveStoreOutcome::Succeeded { width }) => Effect::Applied {
                address,
                size: width,
                bytes: super::byte_effect::memory_bytes(line, width),
            },
            Some(lines::ExclusiveStoreOutcome::Unknown) => Effect::Block { address, size: 64 },
            None => match lines::access_width(mnemonic, operand) {
                Some(size) if trace_parser::strict_memory::memory_op(line).is_some() => {
                    Effect::Applied {
                        address,
                        size,
                        bytes: super::byte_effect::memory_bytes(line, size),
                    }
                }
                width => Effect::Block {
                    address,
                    size: width.unwrap_or(64),
                },
            },
        },
    )
}

pub(super) fn final_bytes(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
) -> Result<Fixed<Cell>> {
    let mut cells = Fixed::<Cell>::new()?;
    scan_owned(state, tree, root, cancel, |insn| {
        if let Some(Effect::Applied {
            address,
            size,
            bytes,
        }) = effect(insn.line)
        {
            if address.checked_add(u64::from(size) - 1).is_some() {
                for (offset, value) in bytes.into_iter().enumerate() {
                    if cancel.load(Ordering::Relaxed) {
                        return Err(TraceError::Cancelled);
                    }
                    cells.apply(address + offset as u64, value, insn.seq)?;
                }
            }
        }
        Ok(true)
    })?;
    Ok(cells)
}

pub(super) fn relevant(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
) -> Result<Option<Fixed<Dependency>>> {
    let Some(deps) = state.deps_view() else {
        return Ok(None);
    };
    let pair_split = state.pair_split_view();
    let mut relevant = Fixed::<Dependency>::new()?;
    let mut lower = None;
    let mut upper = None;
    let mut return_producer = None;
    scan_owned(state, tree, root, cancel, |insn| {
        lower.get_or_insert(insn.seq);
        upper = Some(insn.seq);
        if lines::arrow_register_value(insn.line, "x0").is_some() {
            return_producer = Some(insn.seq);
        }
        // Preserve existing write_winners seed semantics: every applied write,
        // not just final winners, seeds target relevance.
        if let Some(Effect::Applied { address, size, .. }) = effect(insn.line) {
            if address.checked_add(u64::from(size) - 1).is_some() {
                relevant.seed(insn.seq)?;
            }
        }
        Ok(true)
    })?;
    if let Some(seq) = return_producer {
        relevant.seed(seq)?;
    }
    let (Some(lower), Some(upper)) = (lower, upper) else {
        return Ok(Some(relevant));
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        let Some(pos) = relevant.values.iter().position(|d| !d.expanded) else {
            break;
        };
        let seq = relevant.values[pos].seq;
        relevant.values[pos].expanded = true;
        let mut seed = |producer: u32| -> Result<()> {
            if cancel.load(Ordering::Relaxed) {
                return Err(TraceError::Cancelled);
            }
            let producer = producer & crate::scanner::LINE_MASK;
            if producer >= lower && producer <= upper {
                relevant.seed(producer)?;
            }
            Ok(())
        };
        for producer in deps
            .row(seq as usize)
            .iter()
            .chain(deps.patch_row(seq as usize).iter())
        {
            seed(*producer)?;
        }
        if let Some(split) = pair_split.as_ref().and_then(|view| view.get(&seq)) {
            for producer in split
                .shared
                .iter()
                .chain(split.half1_deps.iter())
                .chain(split.half2_deps.iter())
            {
                seed(*producer)?;
            }
        }
    }
    Ok(Some(relevant))
}

/// Determine which bytes were externally supplied, rescanning prior raw writes
/// instead of retaining a blocked-write history. Size is an ISA access width.
pub(super) fn external_mask(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
    address: u64,
    size: u32,
    seq: u32,
) -> Result<Vec<bool>> {
    let mut external = vec![true; size as usize];
    scan_owned(state, tree, root, cancel, |insn| {
        if insn.seq >= seq {
            return Ok(false);
        }
        let blocked = match effect(insn.line) {
            Some(Effect::Applied { address, size, .. }) | Some(Effect::Block { address, size }) => {
                Some((address, size))
            }
            _ => None,
        };
        if let Some((start, width)) = blocked {
            for (offset, external) in external.iter_mut().enumerate() {
                if let Some(byte) = address.checked_add(offset as u64) {
                    if byte >= start && byte - start < u64::from(width) {
                        *external = false;
                    }
                }
            }
        }
        Ok(true)
    })?;
    Ok(external)
}
