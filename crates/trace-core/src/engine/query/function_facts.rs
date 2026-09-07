//! 单次 Confirmed Activation 的 FunctionCallRecord 机械事实查询。

use std::collections::BTreeMap;

use crate::api_types::*;
use crate::error::{Result, TraceError};

use super::activation::stable_site;

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
            executed_block_sequence: vec![ExecutedBlockEntryDto {
                block: function,
                entry_seq: activation.entry_seq,
            }],
            memory_reads: Vec::new(),
            global_reads: Vec::new(),
            memory_writes: Vec::new(),
            global_writes: Vec::new(),
            external_call_events: Vec::new(),
            unresolved: Vec::new(),
        })
    }
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
