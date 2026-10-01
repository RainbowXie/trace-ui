//! 单次 Confirmed Activation 的 FunctionCallRecord 机械事实查询。
//!
//! 子模块按机械事实类别拆分：`lines`（raw 行片段解析）、`blocks`（owned
//! 指令集合与两阶段块切分）、`abi`（栈参数三门）、`dataflow`（producer→
//! consumer 读写）、`events`（External Call Event）。

mod abi;
mod address_provenance;
pub(crate) mod blocks;
mod byte_effect;
pub(crate) mod dataflow;
pub(crate) mod events;
pub(crate) mod global_map;
pub(crate) mod globals;
pub(crate) mod lines;

use std::collections::BTreeMap;

use crate::api_types::*;
use crate::error::{Result, TraceError};

use super::activation::stable_site;
use abi::collect_stack_arguments;
use blocks::{owned_instructions, split_executed_blocks};
use dataflow::collect_memory_facts;
use events::collect_external_call_events;
use lines::arrow_register_value;

impl crate::engine::TraceEngine {
    pub fn get_function_facts(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
    ) -> Result<FunctionFactBundleDto> {
        self.get_function_facts_for_modules(session_id, call_seq, entry_seq, &[])
    }

    pub fn get_function_facts_for_modules(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        target_modules: &[String],
    ) -> Result<FunctionFactBundleDto> {
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
            .ok_or_else(|| {
                TraceError::InvalidArgument(format!(
                    "未找到 call_seq={} entry_seq={} 的 Activation",
                    call_seq, entry_seq
                ))
            })?;
        if activation.id == 0 || activation.unresolved_reason.is_some() {
            return Err(TraceError::InvalidArgument(
                "Function facts 只接受边界已闭合的 Confirmed Activation".to_string(),
            ));
        }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let site = |seq| {
            index
                .get_line(&state.mmap, seq)
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .and_then(stable_site)
                .ok_or_else(|| {
                    TraceError::InvalidArgument(format!("seq {} 缺少稳定 module+offset", seq))
                })
        };
        let function = site(activation.entry_seq)?;
        let mut entry_registers = registers_at(&state, activation.entry_seq)?;
        let resume_registers = registers_at(&state, activation.resume_seq)?;
        if entry_registers[31] == u64::MAX {
            // 若检查点未观察到 SP 的前序修改（如函数处于 trace 起始前缀），
            // 从入口指令本身的 pre-state（分号与箭头之间）提取 entry_sp。
            if let Some(raw) = index.get_line(&state.mmap, activation.entry_seq) {
                if let Ok(line) = std::str::from_utf8(raw) {
                    if let Some(sp) = lines::prestate_register_value(line, "sp") {
                        entry_registers[31] = sp;
                    }
                }
            }
        }
        let arguments = (0..=7)
            .map(|index| {
                let name = format!("X{}", index);
                let value = known_register(&entry_registers, index);
                (name, value)
            })
            .collect::<BTreeMap<_, _>>();
        let mut returns = BTreeMap::new();
        returns.insert("X0".to_string(), known_register(&resume_registers, 0));
        let owned = owned_instructions(&state, tree, activation)?;
        let executed_block_sequence = split_executed_blocks(&owned);
        // 栈参数槽的 (address,size) 集合：memory facts 侧用它去重——
        // abi.stack_arguments 是这些读取的正式位置。
        let stack_argument_slots: std::collections::HashSet<(u64, u32)> =
            if entry_registers[31] == u64::MAX {
                Default::default()
            } else {
                collect_stack_arguments(&owned, entry_registers[31])
                    .into_iter()
                    .map(|slot| (entry_registers[31] + slot.offset as u64, slot.size))
                    .collect()
            };
        // 返回值生产者：owned 内最后一条定义 X0 的指令（箭头后 x0= 或
        // ret: 注解行）——影响目标闭包的种子之一。
        let return_producer = owned
            .iter()
            .rfind(|insn| arrow_register_value(&insn.line, "x0").is_some())
            .map(|insn| insn.seq);
        let (memory_reads, memory_writes, mut access_unresolved) =
            collect_memory_facts(&state, &owned, &stack_argument_slots, return_producer);
        for insn in &owned {
            if insn.mnemonic.as_deref().is_some_and(|mnemonic| {
                matches!(mnemonic, "mov" | "movz" | "movn")
                    && insn
                        .first_operand
                        .as_deref()
                        .is_some_and(pure_immediate_source)
            }) {
                access_unresolved.push(crate::api_types::FunctionFactUnresolvedDto {
                    kind: "unsupported_instruction".to_owned(),
                    seqs: vec![insn.seq],
                    location: None,
                    detail: "pure immediate source has no frozen SourceReference".to_owned(),
                });
            }
        }
        access_unresolved.sort_by(|left, right| {
            left.seqs
                .cmp(&right.seqs)
                .then(left.kind.cmp(&right.kind))
                .then(left.detail.cmp(&right.detail))
        });
        access_unresolved.dedup_by(|left, right| {
            left.seqs == right.seqs && left.kind == right.kind && left.detail == right.detail
        });
        let global_map = global_map::StableGlobalMap::collect(&state, target_modules)?;
        let (memory_reads, global_reads, memory_writes, global_writes) =
            globals::partition_memory_facts(&owned, &global_map, memory_reads, memory_writes);
        let external_call_events = collect_external_call_events(&state, tree, activation, &owned)?;

        Ok(FunctionFactBundleDto {
            function: function.clone(),
            trace_anchors: FunctionTraceAnchorsDto {
                call: FunctionAnchorDto {
                    seq: activation.call_seq,
                    offset: site(activation.call_seq)?,
                },
                entry: FunctionAnchorDto {
                    seq: activation.entry_seq,
                    offset: function.clone(),
                },
                exit: FunctionAnchorDto {
                    seq: activation.exit_seq,
                    offset: site(activation.exit_seq)?,
                },
                resume: FunctionAnchorDto {
                    seq: activation.resume_seq,
                    offset: site(activation.resume_seq)?,
                },
            },
            abi: FunctionAbiDto {
                entry_sp: known_register(&entry_registers, 31),
                arguments,
                stack_arguments: if entry_registers[31] == u64::MAX {
                    Vec::new()
                } else {
                    collect_stack_arguments(&owned, entry_registers[31])
                },
                returns,
            },
            executed_block_sequence,
            memory_reads,
            global_reads,
            memory_writes,
            global_writes,
            external_call_events,
            unresolved: access_unresolved,
        })
    }
}

fn pure_immediate_source(operands: &str) -> bool {
    let parts = operands.split(',').map(str::trim).collect::<Vec<_>>();
    parts.len() >= 2
        && parts[1].starts_with('#')
        && !operands.contains('[')
        && !matches!(parts[0], "sp" | "wsp")
}

/// 从最近的寄存器检查点重放到 `seq` 之前（不含 `seq`）：边界值必须取
/// 边界指令执行前的状态，不能把边界指令自身的效果算进去。
pub(super) fn registers_at(
    state: &crate::session::SessionState,
    seq: u32,
) -> Result<[u64; trace_parser::types::RegId::COUNT]> {
    let checkpoints = state
        .reg_checkpoints_view()
        .ok_or(TraceError::IndexNotReady)?;
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let (checkpoint_seq, snapshot) = checkpoints
        .nearest_before(seq)
        .ok_or_else(|| TraceError::Internal("无可用检查点".to_string()))?;
    let mut values = *snapshot;
    for replay_seq in checkpoint_seq..seq {
        if let Some(raw) = index.get_line(&state.mmap, replay_seq) {
            if let Ok(line) = std::str::from_utf8(raw) {
                crate::phase2::update_reg_values(&mut values, line);
            }
        }
    }
    Ok(values)
}

/// 未跟踪寄存器（u64::MAX 哨兵）保持 None，不以零值补齐。
pub(super) fn known_register(
    registers: &[u64; trace_parser::types::RegId::COUNT],
    index: usize,
) -> Option<String> {
    let value = registers[index];
    (value != u64::MAX).then(|| format!("0x{:016x}", value))
}
