//! 未记录函数体的调用 → caller 的 External Call Event。

use std::collections::BTreeMap;

use crate::api_types::{
    FunctionAnchorDto, FunctionEventUnresolvedDto, FunctionExternalCallEventDto,
    FunctionExternalTargetDto,
};
use crate::error::{Result, TraceError};

use super::super::activation::stable_site;
use super::blocks::OwnedInsn;
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
        // Event 栈参数：机械上无法把「出参区准备」与「callee-saved spill /
        // 局部溢出」按地址区分（两者都落在 [call_sp, +N) 且编译器复用同一
        // 栈帧），任何按地址/基址的收集都会伪造栈参数（合同 §7.2 要求
        // 「调用方能够证明已为外部调用准备」）。V1 恒为空；需要 args 注解
        // 或 capture 证据后才能恢复收集。
        let call_sp = callsite_registers[31];
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
            stack_arguments: Vec::new(),
            returns,
            memory_reads: Vec::new(),
            global_reads: Vec::new(),
            memory_writes: Vec::new(),
            global_writes: Vec::new(),
            unresolved,
        });
    }
    // br/PLT-stub 形态的外部调用：stub activation（adrp/ldr/add/br）没有
    // BL/BLR，bypassed_calls 不覆盖；hook 注解（call func:）键在 br 的
    // seq 上。resume 即本 Activation 的 resume（外部函数返回后回到
    // caller），返回值经含 ret: 效应的检查点重放取得。
    let bypassed_seqs: std::collections::HashSet<u32> = tree
        .bypassed_calls
        .iter()
        .map(|call| call.call_seq)
        .collect();
    // 只有间接分支（b/br/PAC 变体）是「未记录函数体」的外部调用载体：
    // BL/BLR 是调用边界——有 ConfirmedActivation 的 callee 即使带
    // call func: 注解也必须由自己的 Activation 记录，不能在这里伪造成
    // Event（否则 Event 的 resume 还会被错设为本 Activation 的终点）。
    let recorded_call_seqs: std::collections::HashSet<u32> = tree
        .activations
        .iter()
        .filter(|other| other.id != 0)
        .map(|other| other.call_seq)
        .collect();
    for (position, insn) in owned.iter().enumerate().filter(|(_, insn)| insn.transfer) {
        if bypassed_seqs.contains(&insn.seq) || recorded_call_seqs.contains(&insn.seq) {
            continue;
        }
        if !is_indirect_branch(insn.mnemonic.as_deref().unwrap_or("")) {
            continue;
        }
        let Some(annotation) = state.call_annotations.get(&insn.seq) else {
            continue;
        };
        // resume = 外部函数返回后 caller 的续行：优先窗口内下一条 owned
        // 指令（函数中段的外部调用）；尾跳转（PLT stub）后窗口内无指令，
        // 用本 Activation 的 resume。
        let resume_seq = owned[position + 1..]
            .first()
            .map_or(activation.resume_seq, |next| next.seq);
        let callsite_registers = registers_at(state, insn.seq)?;
        let resume_registers = registers_at(state, resume_seq)?;
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
        events.push(FunctionExternalCallEventDto {
            callsite: FunctionAnchorDto {
                seq: insn.seq,
                offset: insn.site.clone(),
            },
            resume: Some(FunctionAnchorDto {
                seq: resume_seq,
                offset: site(resume_seq)?,
            }),
            target: FunctionExternalTargetDto {
                module: None,
                entry: None,
                symbol: Some(annotation.func_name.clone()),
            },
            call_sp: (callsite_registers[31] != u64::MAX)
                .then(|| format!("0x{:016x}", callsite_registers[31])),
            arguments,
            stack_arguments: Vec::new(),
            returns,
            memory_reads: Vec::new(),
            global_reads: Vec::new(),
            memory_writes: Vec::new(),
            global_writes: Vec::new(),
            unresolved: Vec::new(),
        });
    }
    Ok(events)
}

/// 只有间接分支可以是注解外部调用的载体：BL/BLR 属于调用边界（由
/// Activation/bypassed 覆盖），RET 是返回。
fn is_indirect_branch(mnemonic: &str) -> bool {
    matches!(
        trace_parser::insn_class::classify(mnemonic, None),
        trace_parser::insn_class::InsnClass::Branch
            | trace_parser::insn_class::InsnClass::BranchReg
    )
}
