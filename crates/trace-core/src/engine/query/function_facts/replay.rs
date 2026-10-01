use crate::error::{Result, TraceError};
use crate::session::SessionState;
use std::sync::atomic::{AtomicBool, Ordering};
/// Existing pre-instruction register replay, with a cancellation point per row.
pub(super) fn registers_at(
    state: &SessionState,
    seq: u32,
    cancel: &AtomicBool,
) -> Result<[u64; trace_parser::types::RegId::COUNT]> {
    let checkpoints = state
        .reg_checkpoints_view()
        .ok_or(TraceError::IndexNotReady)?;
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let (checkpoint_seq, snapshot) = checkpoints
        .nearest_before(seq)
        .ok_or_else(|| TraceError::Internal("无可用检查点".into()))?;
    let mut values = *snapshot;
    for replay in checkpoint_seq..seq {
        if cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        if let Some(raw) = index.get_line(&state.mmap, replay) {
            super::block_stream::check_raw(raw)?;
            if let Ok(line) = std::str::from_utf8(raw) {
                crate::phase2::update_reg_values(&mut values, line);
            }
        }
    }
    Ok(values)
}
