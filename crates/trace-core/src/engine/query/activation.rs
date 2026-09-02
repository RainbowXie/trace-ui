//! Confirmed Activation 查询方法：
//! get_activation_tree / get_activation_for_seq / get_instruction_owner。

use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation, UnresolvedReason};

fn reason_str(r: &UnresolvedReason) -> &'static str {
    match r {
        UnresolvedReason::TraceEndStillActive => "trace_end_still_active",
        UnresolvedReason::NextInsnNeitherEntryNorResume => "next_insn_neither_entry_nor_resume",
        UnresolvedReason::DisplacedByAnotherCall => "displaced_by_another_call",
        UnresolvedReason::NoNextInsn => "no_next_insn",
    }
}

fn activation_to_dto(a: &ConfirmedActivation) -> ConfirmedActivationDto {
    ConfirmedActivationDto {
        id: a.id,
        func_addr: format!("0x{:x}", a.func_addr),
        func_name: a.func_name.clone(),
        call_seq: a.call_seq,
        call_pc: format!("0x{:x}", a.call_pc),
        entry_seq: a.entry_seq,
        entry_pc: format!("0x{:x}", a.entry_pc),
        exit_seq: a.exit_seq,
        exit_pc: format!("0x{:x}", a.exit_pc),
        expected_resume: format!("0x{:x}", a.expected_resume),
        resume_seq: a.resume_seq,
        parent_id: a.parent_id,
        children_ids: a.children_ids.clone(),
        unresolved_reason: a
            .unresolved_reason
            .as_ref()
            .map(|r| reason_str(r).to_string()),
    }
}

fn tree_to_dto(tree: &ActivationTree) -> ActivationTreeDto {
    ActivationTreeDto {
        activations: tree.activations.iter().map(activation_to_dto).collect(),
        bypassed_calls: tree
            .bypassed_calls
            .iter()
            .map(|c| BypassedCallDto {
                call_seq: c.call_seq,
                call_pc: format!("0x{:x}", c.call_pc),
                expected_resume: format!("0x{:x}", c.expected_resume),
                resume_seq: c.resume_seq,
                parent_id: c.parent_id,
            })
            .collect(),
    }
}

impl crate::engine::TraceEngine {
    /// 整棵 Confirmed Activation 树 + bypassed 调用集合。
    pub fn get_activation_tree(&self, session_id: &str) -> Result<ActivationTreeDto> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        Ok(tree_to_dto(tree))
    }

    /// 按 seq 查询唯一归属的非 root Activation（嵌套时取最内层）。
    pub fn get_activation_for_seq(
        &self,
        session_id: &str,
        seq: u32,
    ) -> Result<Option<ConfirmedActivationDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        if seq >= state.total_lines {
            return Err(TraceError::InvalidArgument(format!(
                "seq {} 超出 trace 总行数 {}",
                seq, state.total_lines
            )));
        }

        Ok(tree.activation_for_seq(seq).map(activation_to_dto))
    }

    /// 指令归属（agent-api.md §2）：seq → Activation + 边界位置。
    ///
    /// 边界位置：call/entry/exit/resume 四个边界点精确标注，其余为 body。
    /// call 行的 owner 是 caller 侧 activation（BL 属于 caller 的块），
    /// 此时另给 callee_id 指向被创建的 child activation。
    pub fn get_instruction_owner(&self, session_id: &str, seq: u32) -> Result<InstructionOwnerDto> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        if seq >= state.total_lines {
            return Err(TraceError::InvalidArgument(format!(
                "seq {} 超出 trace 总行数 {}",
                seq, state.total_lines
            )));
        }

        let owner = tree.activation_for_seq(seq);

        // call 行：owner 是 caller，但位置语义是调用点，另指 callee id
        let callee_for_call = if owner.is_none_or(|a| a.call_seq != seq) {
            tree.activations
                .iter()
                .find(|a| a.call_seq == seq && seq != 0)
                .map(|a| a.id)
        } else {
            None
        };

        let position = |a: Option<&ConfirmedActivation>| -> String {
            if callee_for_call.is_some() {
                return "call".to_string();
            }
            let Some(a) = a else {
                return "root".to_string();
            };
            if seq == a.entry_seq {
                "entry".to_string()
            } else if seq == a.exit_seq {
                "exit".to_string()
            } else if seq == a.resume_seq {
                "resume".to_string()
            } else {
                "body".to_string()
            }
        };

        Ok(InstructionOwnerDto {
            seq,
            activation: owner.map(activation_to_dto),
            position: position(owner),
            callee_id: callee_for_call,
        })
    }
}
