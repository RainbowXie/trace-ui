use super::query::activation::{stable_runtime_site, stable_site};
use crate::control_flow::{types::*, ControlFlowIndex};
use crate::error::{Result, TraceError};
use std::sync::atomic::Ordering;
fn pc(line: &str) -> Option<u64> {
    stable_runtime_site(line).map(|(_, pc, _)| pc)
}
fn fresh(state: &crate::session::SessionState) -> Result<()> {
    if crate::memory_search::compute_trace_content_hash(&state.mmap) != state.trace_hash {
        return Err(TraceError::InvalidArgument(
            "opened trace content changed since session creation".into(),
        ));
    }
    Ok(())
}
impl super::TraceEngine {
    /// 构建独立control-only索引。取消/失败不发布；消费原会话mmap，不重新打开label路径。
    pub fn build_control_flow_index(&self, session_id: &str) -> Result<()> {
        let handle = self.get_handle(session_id)?;
        if handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(TraceError::OperationInProgress("index build".into()));
        }
        struct Reset<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _reset = Reset(&handle.building);
        handle.build_cancel.store(false, Ordering::SeqCst);
        let mut state = handle
            .state
            .write()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        if state.mmap.len() > crate::control_flow::MAX_TRACE_BYTES {
            return Err(TraceError::InvalidArgument(
                "control-flow memory byte capacity exceeded".into(),
            ));
        }
        fresh(&state)?;
        let index = ControlFlowIndex::build(&state.mmap, &handle.build_cancel, stable_site, pc)?;
        fresh(&state)?;
        if handle.build_cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        state.control_flow = Some(index);
        Ok(())
    }
    pub fn get_activation_cfg(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        blocks: CfgPage,
        occurrences: CfgPage,
    ) -> Result<CfgView> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        fresh(&state)?;
        state
            .control_flow
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?
            .activation_cfg(
                &state.mmap,
                call_seq,
                entry_seq,
                function,
                &blocks,
                &occurrences,
            )
    }
    pub fn get_function_cfg(
        &self,
        session_id: &str,
        function: &str,
        blocks: CfgPage,
        occurrences: CfgPage,
    ) -> Result<CfgView> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        fresh(&state)?;
        state
            .control_flow
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?
            .function_cfg(&state.mmap, function, &blocks, &occurrences)
    }
    pub fn get_cfg_occurrence_for_seq(
        &self,
        session_id: &str,
        seq: u32,
    ) -> Result<Option<CfgOccurrence>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        fresh(&state)?;
        state
            .control_flow
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?
            .occurrence_for_seq(&state.mmap, seq)
    }
}
