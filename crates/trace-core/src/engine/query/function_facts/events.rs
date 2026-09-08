//! 未记录函数体的调用 → caller 的 External Call Event。

use std::collections::BTreeMap;

use crate::api_types::{
    FunctionAnchorDto, FunctionEventUnresolvedDto, FunctionExternalCallEventDto,
    FunctionExternalStackArgumentDto, FunctionExternalTargetDto,
};
use crate::error::{Result, TraceError};

use super::super::activation::stable_site;
use super::blocks::OwnedInsn;
use super::lines::{access_width, base_register, line_mem_annotation, prestate_register_value};
use super::{known_register, registers_at};

/// 未记录函数体的调用 → caller 的 External Call Event。
///
/// target 身份只接受注解符号（模块映射对数据地址不可用，entry 无来源）；
/// 三字段全空时以 indirect_target_unresolved 记录缺口，不伪造身份。
/// Event 访存数组只收明确捕获证据——trace-ui V1 没有 hook 捕获通道，
/// 恒为空。截断（resume 未观察）的调用在 Activation 模型里必然伴随
/// 包含它的 Activation 未闭合，confirmed-only 查询不可达；该形状由
/// 状态机侧（build/merge 校验）负责。
pub(super) fn collect_external_call_events(
    state: &crate::session::SessionState,
    tree: &crate::query::activation::ActivationTree,
    activation: &crate::query::activation::ConfirmedActivation,
    owned: &[OwnedInsn],
) -> Result<Vec<FunctionExternalCallEventDto>> {
    let mut bypassed: Vec<&crate::query::activation::BypassedCall> = tree
        .bypassed_calls
        .iter()
        .filter(|call| call.parent_id == Some(activation.id))
        .collect();
    bypassed.sort_by_key(|call| call.call_seq);

    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let site = |seq| -> Result<String> {
        index
            .get_line(&state.mmap, seq)
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .and_then(stable_site)
            .ok_or_else(|| {
                TraceError::InvalidArgument(format!("seq {} 缺少稳定 module+offset", seq))
            })
    };
    let mut events = Vec::new();
    for call in bypassed {
        let callsite_registers = registers_at(state, call.call_seq)?;
        let resume_registers = registers_at(state, call.resume_seq)?;
        let arguments = (0..=7)
            .map(|register| {
                (
                    format!("X{register}"),
                    known_register(&callsite_registers, register),
                )
            })
            .collect();
        let mut returns = BTreeMap::new();
        returns.insert("X0".to_string(), known_register(&resume_registers, 0));
        let target_symbol = state
            .call_annotations
            .get(&call.call_seq)
            .map(|annotation| annotation.func_name.clone());
        let mut unresolved = Vec::new();
        if target_symbol.is_none() {
            unresolved.push(FunctionEventUnresolvedDto {
                kind: "indirect_target_unresolved".to_string(),
                detail: "未记录函数体的调用没有任何目标身份证据（无注解符号）".to_string(),
            });
        }
        // 调用方准备的栈参数：call 之前 SP/FP 基址写入且地址 ≥ call_sp。
        let call_sp = callsite_registers[31];
        let mut stack_slots: BTreeMap<(u64, u32), FunctionExternalStackArgumentDto> =
            BTreeMap::new();
        if call_sp != u64::MAX {
            for insn in owned.iter().take_while(|insn| insn.seq < call.call_seq) {
                let Some((mnemonic, operand)) =
                    insn.mnemonic.as_deref().zip(insn.first_operand.as_deref())
                else {
                    continue;
                };
                let Some(address) = line_mem_annotation(&insn.line, "mem_w") else {
                    continue;
                };
                if address < call_sp {
                    continue;
                }
                let stack_based =
                    base_register(operand).is_some_and(|base| base == "sp" || base == "fp");
                let Some(size) = (stack_based)
                    .then(|| access_width(mnemonic, operand))
                    .flatten()
                else {
                    continue;
                };
                let value = operand
                    .split(',')
                    .next()
                    .and_then(|register| prestate_register_value(&insn.line, register.trim()));
                let slot = stack_slots.entry((address - call_sp, size)).or_insert(
                    FunctionExternalStackArgumentDto {
                        offset: (address - call_sp) as i64,
                        size,
                        value: value.map(|value| format!("0x{value:016x}")),
                        evidence_seqs: Vec::new(),
                    },
                );
                if slot.value.is_none() {
                    slot.value = value.map(|value| format!("0x{value:016x}"));
                }
                slot.evidence_seqs.push(insn.seq);
            }
        }
        events.push(FunctionExternalCallEventDto {
            callsite: FunctionAnchorDto {
                seq: call.call_seq,
                offset: site(call.call_seq)?,
            },
            resume: Some(FunctionAnchorDto {
                seq: call.resume_seq,
                offset: site(call.resume_seq)?,
            }),
            target: FunctionExternalTargetDto {
                module: None,
                entry: None,
                symbol: target_symbol,
            },
            call_sp: (call_sp != u64::MAX).then(|| format!("0x{call_sp:016x}")),
            arguments,
            stack_arguments: stack_slots.into_values().collect(),
            returns,
            memory_reads: Vec::new(),
            global_reads: Vec::new(),
            memory_writes: Vec::new(),
            global_writes: Vec::new(),
            unresolved,
        });
    }
    Ok(events)
}
