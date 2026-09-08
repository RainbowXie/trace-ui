//! owned 指令集合与 Basic Block 两阶段切分（冻结规则见
//! docs/trace-ui/cfg-generation.md）。

use std::collections::HashSet;

use crate::api_types::ExecutedBlockEntryDto;
use crate::error::{Result, TraceError};
use trace_parser::insn_class::InsnClass;

use super::super::activation::stable_site;
use super::lines::{first_operand, line_mnemonic};

/// 本 Activation 窗口内属于它自己的一条指令：稳定身份 + 是否控制转移 +
/// 栈参数机械查询需要的行内片段（V1 保存行文本；有界 serializer 任务
/// 到来时改为流式两遍扫描）。
pub(super) struct OwnedInsn {
    pub(super) seq: u32,
    pub(super) site: String,
    pub(super) transfer: bool,
    pub(super) line: String,
    pub(super) mnemonic: Option<String>,
    pub(super) first_operand: Option<String>,
}

/// 冻结切分规则的块终止指令：条件/无条件/间接跳转、调用边界与返回。
/// classify 已把 PAC 认证变体（braa/blraa/retaa 家族）归入对应分支类。
fn is_control_transfer(mnemonic: &str) -> bool {
    matches!(
        trace_parser::insn_class::classify(mnemonic, None),
        InsnClass::CondBranchNzcv
            | InsnClass::CondBranchReg
            | InsnClass::Branch
            | InsnClass::BranchLink
            | InsnClass::BranchReg
            | InsnClass::BranchLinkReg
            | InsnClass::Return
    )
}

/// 窗口内属于本 Activation 的指令序列：嵌套 Activation（含未闭合者，
/// 只要窗口严格包含）的指令不属于 caller，按区间排除；BL 与 resume 指令
/// 仍属 caller。
pub(super) fn owned_instructions(
    state: &crate::session::SessionState,
    tree: &crate::query::activation::ActivationTree,
    activation: &crate::query::activation::ConfirmedActivation,
) -> Result<Vec<OwnedInsn>> {
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let mut nested: Vec<(u32, u32)> = tree
        .activations
        .iter()
        .filter(|other| {
            other.id != activation.id
                && other.entry_seq > activation.entry_seq
                && other.exit_seq < activation.exit_seq
                && other.exit_seq >= other.entry_seq
        })
        .map(|other| (other.entry_seq, other.exit_seq))
        .collect();
    nested.sort_unstable();
    let mut cursor = 0usize;
    let mut owned = Vec::new();
    for seq in activation.entry_seq..=activation.exit_seq {
        // 跳过当前嵌套区间。
        while cursor < nested.len() && seq > nested[cursor].1 {
            cursor += 1;
        }
        if cursor < nested.len() && seq >= nested[cursor].0 {
            continue;
        }
        let raw = index
            .get_line(&state.mmap, seq)
            .ok_or_else(|| TraceError::InvalidArgument(format!("seq {} 不在 trace 内", seq)))?;
        let line =
            std::str::from_utf8(raw).map_err(|error| TraceError::Internal(error.to_string()))?;
        let Some(site) = stable_site(line) else {
            // 注解等特殊行不是指令：不参与块切分/访存/ABI，跳过。
            if trace_parser::gumtrace::parse_special_line(line).is_some() {
                continue;
            }
            return Err(TraceError::InvalidArgument(format!(
                "seq {} 缺少稳定 module+offset",
                seq
            )));
        };
        let mnemonic = line_mnemonic(line).map(str::to_owned);
        let transfer = mnemonic.as_deref().is_some_and(is_control_transfer);
        let first_operand = first_operand(line);
        owned.push(OwnedInsn {
            seq,
            site,
            transfer,
            line: line.to_owned(),
            mnemonic,
            first_operand,
        });
    }
    Ok(owned)
}

/// 两阶段切分：先收集本次执行观察到的全部控制转移落点，再用最终起点集
/// 合切分——后期观察到的目标会回溯拆开第一次的线性执行。
pub(super) fn split_executed_blocks(owned: &[OwnedInsn]) -> Vec<ExecutedBlockEntryDto> {
    let mut targets: HashSet<&str> = HashSet::new();
    for pair in owned.windows(2) {
        if pair[0].transfer {
            targets.insert(pair[1].site.as_str());
        }
    }
    let mut blocks = Vec::new();
    for (position, insn) in owned.iter().enumerate() {
        let starts =
            position == 0 || owned[position - 1].transfer || targets.contains(insn.site.as_str());
        if starts {
            blocks.push(ExecutedBlockEntryDto {
                block: insn.site.clone(),
                entry_seq: insn.seq,
            });
        }
    }
    blocks
}
