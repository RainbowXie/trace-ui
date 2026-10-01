//! Event construction preflights borrowed symbols before any expansion.
use super::super::activation::stable_site;
use super::{block_stream::scan_owned, budget::Budget, collector::reserve_vec, known_register};
use crate::api_types::*;
use crate::error::Result;
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

fn site(state: &SessionState, seq: u32) -> Result<String> {
    let raw = state
        .line_index_view()
        .ok_or(crate::error::TraceError::IndexNotReady)?
        .get_line(&state.mmap, seq)
        .ok_or_else(|| {
            crate::error::TraceError::InvalidArgument(format!("seq {seq} 不在trace内"))
        })?;
    super::block_stream::check_raw(raw)?;
    std::str::from_utf8(raw)
        .ok()
        .and_then(stable_site)
        .ok_or_else(|| {
            crate::error::TraceError::InvalidArgument(format!("seq {seq} 缺少稳定 module+offset"))
        })
}
fn event(
    state: &SessionState,
    call: u32,
    resume: u32,
    out: &mut Vec<FunctionExternalCallEventDto>,
    budget: &mut Budget,
    cancel: &AtomicBool,
) -> Result<()> {
    let call_regs = super::replay::registers_at(state, call, cancel)?;
    let return_regs = super::replay::registers_at(state, resume, cancel)?;
    let arguments: BTreeMap<_, _> = (0..8)
        .map(|r| (format!("X{r}"), known_register(&call_regs, r)))
        .collect();
    let returns = BTreeMap::from([("X0".to_owned(), known_register(&return_regs, 0))]);
    let symbol = state
        .call_annotations
        .get(&call)
        .map(|a| a.func_name.as_str());
    let callsite = FunctionAnchorDto {
        seq: call,
        offset: site(state, call)?,
    };
    let resume = Some(FunctionAnchorDto {
        seq: resume,
        offset: site(state, resume)?,
    });
    let call_sp = known_register(&call_regs, 31);
    let unresolved = if symbol.is_none() {
        vec![FunctionEventUnresolvedDto {
            kind: "indirect_target_unresolved".into(),
            detail: "未记录函数体的调用没有任何目标身份证据（无注解符号）".into(),
        }]
    } else {
        Vec::new()
    };
    #[derive(Serialize)]
    struct Target<'a> {
        module: Option<&'a str>,
        entry: Option<&'a str>,
        symbol: Option<&'a str>,
    }
    #[derive(Serialize)]
    struct Preview<'a> {
        callsite: &'a FunctionAnchorDto,
        resume: &'a Option<FunctionAnchorDto>,
        target: Target<'a>,
        call_sp: &'a Option<String>,
        arguments: &'a BTreeMap<String, Option<String>>,
        stack_arguments: &'a [FunctionExternalStackArgumentDto],
        returns: &'a BTreeMap<String, Option<String>>,
        memory_reads: &'a [FunctionEventMemoryRecordDto],
        global_reads: &'a [FunctionEventGlobalRecordDto],
        memory_writes: &'a [FunctionEventMemoryRecordDto],
        global_writes: &'a [FunctionEventGlobalRecordDto],
        unresolved: &'a [FunctionEventUnresolvedDto],
    }
    budget.item(
        &Preview {
            callsite: &callsite,
            resume: &resume,
            target: Target {
                module: None,
                entry: None,
                symbol,
            },
            call_sp: &call_sp,
            arguments: &arguments,
            stack_arguments: &[],
            returns: &returns,
            memory_reads: &[],
            global_reads: &[],
            memory_writes: &[],
            global_writes: &[],
            unresolved: &unresolved,
        },
        2,
        out.is_empty(),
    )?;
    reserve_vec(out)?;
    out.push(FunctionExternalCallEventDto {
        callsite,
        resume,
        target: FunctionExternalTargetDto {
            module: None,
            entry: None,
            symbol: symbol.map(str::to_owned),
        },
        call_sp,
        arguments,
        stack_arguments: Vec::new(),
        returns,
        memory_reads: Vec::new(),
        global_reads: Vec::new(),
        memory_writes: Vec::new(),
        global_writes: Vec::new(),
        unresolved,
    });
    Ok(())
}
pub(super) fn collect(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
    out: &mut Vec<FunctionExternalCallEventDto>,
    budget: &mut Budget,
) -> Result<()> {
    // Selection sort over borrowed records, not a bypassed/recorded HashSet.
    let mut previous = None;
    loop {
        let mut next = None;
        for call in &tree.bypassed_calls {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(crate::error::TraceError::Cancelled);
            }
            if call.parent_id == Some(root.id)
                && previous.is_none_or(|p| call.call_seq > p)
                && next.is_none_or(|c: &crate::query::activation::BypassedCall| {
                    call.call_seq < c.call_seq
                })
            {
                next = Some(call);
            }
        }
        let Some(call) = next else {
            break;
        };
        event(state, call.call_seq, call.resume_seq, out, budget, cancel)?;
        previous = Some(call.call_seq);
    }
    scan_owned(state, tree, root, cancel, |insn| {
        if tree.bypassed_calls.iter().any(|c| c.call_seq == insn.seq)
            || tree
                .activations
                .iter()
                .any(|a| a.id != 0 && a.call_seq == insn.seq)
        {
            return Ok(true);
        }
        let Some((m, _)) = trace_parser::strict_memory::instruction_parts(insn.line) else {
            return Ok(true);
        };
        if !matches!(
            trace_parser::insn_class::classify(m, None),
            trace_parser::insn_class::InsnClass::Branch
                | trace_parser::insn_class::InsnClass::BranchReg
        ) || !state.call_annotations.contains_key(&insn.seq)
        {
            return Ok(true);
        }
        let mut resume = root.resume_seq;
        scan_owned(state, tree, root, cancel, |next| {
            if next.seq > insn.seq {
                resume = next.seq;
                return Ok(false);
            }
            Ok(true)
        })?;
        event(state, insn.seq, resume, out, budget, cancel)?;
        Ok(true)
    })
}
