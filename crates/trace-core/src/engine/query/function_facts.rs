//! 单次 Confirmed Activation 的 FunctionCallRecord 机械事实查询。

use std::collections::{BTreeMap, HashSet};

use crate::api_types::*;
use crate::error::{Result, TraceError};
use trace_parser::insn_class::InsnClass;

use super::activation::stable_site;

/// 本 Activation 窗口内属于它自己的一条指令：稳定身份 + 是否控制转移。
struct OwnedInsn {
    seq: u32,
    site: String,
    transfer: bool,
}

/// 冻结切分规则（docs/trace-ui/cfg-generation.md）的块终止指令：
/// 条件/无条件/间接跳转、调用边界与返回。PAC 变体在 classify 的分支
/// 表之外，按同一合同显式列入。
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
    ) || matches!(
        mnemonic,
        "braa"
            | "braaz"
            | "brab"
            | "brabz"
            | "blraa"
            | "blraaz"
            | "blrab"
            | "blrabz"
            | "retaa"
            | "retab"
    )
}

/// 从 raw 行提取助记符：`[module] 0xPC!0xOFF <mnemonic> ...`。
fn line_mnemonic(line: &str) -> Option<&str> {
    let bang = line.find("!0x")?;
    let rest = &line[bang + 3..];
    let hex_end = rest.find(|c: char| !c.is_ascii_hexdigit())?;
    let rest = rest[hex_end..].trim_start();
    let end = rest.find(|c: char| c.is_whitespace() || c == ';')?;
    Some(&rest[..end])
}

impl crate::engine::TraceEngine {
    pub fn get_function_facts(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
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
        let entry_registers = registers_at(&state, activation.entry_seq)?;
        let resume_registers = registers_at(&state, activation.resume_seq)?;
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
                stack_arguments: Vec::new(),
                returns,
            },
            executed_block_sequence,
            memory_reads: Vec::new(),
            global_reads: Vec::new(),
            memory_writes: Vec::new(),
            global_writes: Vec::new(),
            external_call_events: Vec::new(),
            unresolved: Vec::new(),
        })
    }
}

/// 窗口内属于本 Activation 的指令序列：嵌套 Activation（含未闭合者，
/// 只要窗口严格包含）的指令不属于 caller，按区间排除；BL 与 resume 指令
/// 仍属 caller。
fn owned_instructions(
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
        let site = stable_site(line).ok_or_else(|| {
            TraceError::InvalidArgument(format!("seq {} 缺少稳定 module+offset", seq))
        })?;
        let transfer = line_mnemonic(line).is_some_and(is_control_transfer);
        owned.push(OwnedInsn {
            seq,
            site,
            transfer,
        });
    }
    Ok(owned)
}

/// 两阶段切分：先收集本次执行观察到的全部控制转移落点，再用最终起点集
/// 合切分——后期观察到的目标会回溯拆开第一次的线性执行。
fn split_executed_blocks(owned: &[OwnedInsn]) -> Vec<ExecutedBlockEntryDto> {
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

fn registers_at(
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

fn known_register(
    registers: &[u64; trace_parser::types::RegId::COUNT],
    index: usize,
) -> Option<String> {
    let value = registers[index];
    (value != u64::MAX).then(|| format!("0x{:016x}", value))
}
