//! CallTree 事件重放、GumTrace 注解重放与寄存器检查点修复。

use std::collections::HashMap;

use crate::parallel_types::{CallTreeEvent, GumtraceAnnotEvent, SpecialLineData};
use crate::query::call_tree::{CallTree, CallTreeBuilder};
use crate::query::registers::RegCheckpoints;
use trace_parser::gumtrace::CallAnnotation;
use trace_parser::types::RegId;

/// Replay CallTree events sequentially through a single CallTreeBuilder.
/// This handles blr_pending_pc logic correctly across chunk boundaries.
pub fn replay_call_tree_events(events: &[CallTreeEvent], total_lines: u32) -> CallTree {
    let mut builder = CallTreeBuilder::new();
    let mut blr_pending_pc: Option<u64> = None;
    let mut root_addr_set = false;

    for event in events {
        match event {
            CallTreeEvent::SetRootAddr { addr } => {
                if !root_addr_set {
                    builder.set_root_addr(*addr);
                    root_addr_set = true;
                }
            }
            CallTreeEvent::LineAddr { seq, addr } => {
                // Handle BLR pending check (same logic as scan_unified/phase2)
                if let Some(blr_pc) = blr_pending_pc.take() {
                    if *addr != 0 {
                        builder.update_current_func_addr(*addr);
                        if *addr == blr_pc + 4 {
                            // unidbg intercepted call — no function body
                            builder.on_ret(seq.saturating_sub(1));
                        }
                    } else {
                        // Can't extract address, keep pending
                        blr_pending_pc = Some(blr_pc);
                    }
                }
            }
            CallTreeEvent::Call { seq, target } => {
                builder.on_call(*seq, *target);
            }
            CallTreeEvent::Ret { seq } => {
                builder.on_ret(*seq);
            }
            CallTreeEvent::BlrPending { seq: _, pc } => {
                blr_pending_pc = Some(*pc);
            }
            CallTreeEvent::SetFuncName { entry_seq, name } => {
                builder.set_func_name_by_entry_seq(*entry_seq, name);
            }
        }
    }

    builder.finish(total_lines)
}

/// Replay Gumtrace annotation events sequentially.
/// Produces exact call_annotations and extra consumed_seqs.
pub fn replay_gumtrace_annotations(
    events: &[GumtraceAnnotEvent],
) -> (HashMap<u32, CallAnnotation>, Vec<u32>) {
    let mut call_annotations = HashMap::new();
    let mut extra_consumed = Vec::new();
    let mut pending_call_seq: Option<u32> = None;
    let mut current_annotation: Option<(u32, CallAnnotation)> = None;

    for event in events {
        match event {
            GumtraceAnnotEvent::BranchInstr { seq } => {
                pending_call_seq = Some(*seq);
            }
            GumtraceAnnotEvent::SpecialLine { seq: _, special } => {
                match special {
                    SpecialLineData::CallFunc { name, is_jni, raw } => {
                        // Flush previous unfinished annotation
                        if let Some((bl_seq, ann)) = current_annotation.take() {
                            call_annotations.insert(bl_seq, ann);
                        }
                        if let Some(bl_seq) = pending_call_seq.take() {
                            current_annotation = Some((
                                bl_seq,
                                CallAnnotation {
                                    func_name: name.clone(),
                                    is_jni: *is_jni,
                                    args: Vec::new(),
                                    ret_value: None,
                                    raw_lines: vec![raw.clone()],
                                },
                            ));
                        }
                    }
                    SpecialLineData::Arg { index, value, raw } => {
                        if let Some((_, ref mut ann)) = current_annotation {
                            ann.args.push((index.clone(), value.clone()));
                            ann.raw_lines.push(raw.clone());
                        }
                    }
                    SpecialLineData::Ret { value, raw } => {
                        if let Some((bl_seq, mut ann)) = current_annotation.take() {
                            ann.ret_value = Some(value.clone());
                            ann.raw_lines.push(raw.clone());
                            call_annotations.insert(bl_seq, ann);
                        }
                    }
                    SpecialLineData::HexDump { raw } => {
                        if let Some((_, ref mut ann)) = current_annotation {
                            ann.raw_lines.push(raw.clone());
                        }
                    }
                }
            }
            GumtraceAnnotEvent::OrphanLine { seq } => {
                if current_annotation.is_some() {
                    extra_consumed.push(*seq);
                }
            }
        }
    }

    // Flush remaining
    if let Some((bl_seq, ann)) = current_annotation.take() {
        call_annotations.insert(bl_seq, ann);
    }

    (call_annotations, extra_consumed)
}

/// Fix RegCheckpoints by propagating previous chunk's final register values.
/// For each snapshot, if a register value is u64::MAX (unknown), replace with prev chunk's value.
pub fn fix_reg_checkpoints(
    ckpts: &mut RegCheckpoints,
    prev_final_reg_values: &[u64; RegId::COUNT],
) {
    for snapshot in &mut ckpts.snapshots {
        for (r, &prev_val) in prev_final_reg_values.iter().enumerate() {
            if snapshot.0[r] == u64::MAX && prev_val != u64::MAX {
                snapshot.0[r] = prev_val;
            }
        }
    }
}
