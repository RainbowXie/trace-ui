//! Allocation-independent owned instruction and executed-block scans.
//!
//! This is only the block component, not a bounded FunctionFactBundle builder.
//! The sink must reserve the actual formal envelope before retaining each item.
//! Retroactive block starts use repeated scans: worst-case quadratic in owned
//! instructions, with an additional activation-tree scan per raw instruction.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;

use super::super::activation::stable_site;
use super::blocks::is_control_transfer;

/// All text borrows the retained mmap under the session read lock. A canonical
/// site is generated for one instruction only; no raw-line copies are retained.
pub(super) struct BorrowedOwnedInsn<'a> {
    pub(super) seq: u32,
    pub(super) site: String,
    pub(super) line: &'a str,
}

impl BorrowedOwnedInsn<'_> {
    fn transfer(&self) -> bool {
        trace_parser::strict_memory::instruction_parts(self.line)
            .is_some_and(|(mnemonic, _)| is_control_transfer(mnemonic))
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(TraceError::Cancelled)
    } else {
        Ok(())
    }
}

pub(super) fn scan_owned(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    mut visit: impl FnMut(BorrowedOwnedInsn<'_>) -> Result<bool>,
) -> Result<()> {
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    for seq in activation.entry_seq..=activation.exit_seq {
        check_cancel(cancel)?;
        // Same strict-contained interval rule as owned_instructions, including
        // unresolved nested activations. Do not allocate a nested interval list.
        let mut nested = false;
        for other in &tree.activations {
            check_cancel(cancel)?;
            if other.id != activation.id
                && other.entry_seq > activation.entry_seq
                && other.exit_seq < activation.exit_seq
                && other.exit_seq >= other.entry_seq
                && seq >= other.entry_seq
                && seq <= other.exit_seq
            {
                nested = true;
                break;
            }
        }
        if nested {
            continue;
        }
        let raw = index
            .get_line(&state.mmap, seq)
            .ok_or_else(|| TraceError::InvalidArgument(format!("seq {seq} 不在 trace 内")))?;
        let line =
            std::str::from_utf8(raw).map_err(|error| TraceError::Internal(error.to_string()))?;
        let Some(site) = stable_site(line) else {
            if trace_parser::gumtrace::parse_special_line(line).is_some() {
                continue;
            }
            return Err(TraceError::InvalidArgument(format!(
                "seq {seq} 缺少稳定 module+offset"
            )));
        };
        if !visit(BorrowedOwnedInsn { seq, site, line })? {
            break;
        }
    }
    Ok(())
}

fn is_observed_target(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    site: &str,
) -> Result<bool> {
    let mut previous_transfer = false;
    let mut found = false;
    scan_owned(state, tree, activation, cancel, |insn| {
        if previous_transfer && insn.site == site {
            found = true;
            return Ok(false);
        }
        previous_transfer = insn.transfer();
        Ok(true)
    })?;
    Ok(found)
}

fn stream_executed_blocks(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    mut sink: impl FnMut(&str, u32) -> Result<()>,
) -> Result<()> {
    let mut first = true;
    let mut previous_transfer = false;
    scan_owned(state, tree, activation, cancel, |insn| {
        let starts = first
            || previous_transfer
            || is_observed_target(state, tree, activation, cancel, &insn.site)?;
        if starts {
            check_cancel(cancel)?;
            sink(&insn.site, insn.seq)?;
            check_cancel(cancel)?;
        }
        first = false;
        previous_transfer = insn.transfer();
        Ok(true)
    })
}

impl crate::engine::TraceEngine {
    /// Visit the exact executed block sequence without retaining owned raw lines
    /// or the set of observed branch targets. The callback's site is valid only
    /// during the call. An error stops immediately; already accepted items are
    /// not a complete result. This API neither builds nor budgets the full facts
    /// bundle. It holds the retained session read lock throughout all passes.
    /// As with existing retained-mmap queries, callers must keep the underlying
    /// trace immutable: a session lock does not prevent external file writes.
    /// The caller is responsible for FD identity verification before/after use.
    pub fn visit_function_executed_blocks(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        cancel: &AtomicBool,
        sink: impl FnMut(&str, u32) -> Result<()>,
    ) -> Result<()> {
        check_cancel(cancel)?;
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let activation = tree
            .activations
            .iter()
            .find(|item| item.call_seq == call_seq && item.entry_seq == entry_seq)
            .ok_or_else(|| TraceError::InvalidArgument("Activation selector not found".into()))?;
        if activation.id == 0
            || activation.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= activation.exit_seq
                && activation.exit_seq < activation.resume_seq
                && activation.resume_seq < state.total_lines)
        {
            return Err(TraceError::InvalidArgument(
                "block stream requires a closed Confirmed Activation".into(),
            ));
        }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        for seq in [
            call_seq,
            entry_seq,
            activation.exit_seq,
            activation.resume_seq,
        ] {
            check_cancel(cancel)?;
            let line = index
                .get_line(&state.mmap, seq)
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .ok_or_else(|| TraceError::InvalidArgument("block boundary missing".into()))?;
            let site = stable_site(line).ok_or_else(|| {
                TraceError::InvalidArgument("block boundary lacks stable instruction site".into())
            })?;
            if trace_parser::strict_memory::instruction_parts(line).is_none()
                || (seq == entry_seq && site != function)
            {
                return Err(TraceError::InvalidArgument(
                    "block selector boundary mismatch".into(),
                ));
            }
        }
        stream_executed_blocks(&state, tree, activation, cancel, sink)
    }
}
