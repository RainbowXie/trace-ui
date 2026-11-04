mod browse;
mod control_flow;
mod disk_control_flow;
mod build;
mod memory;
mod query;
pub use query::saved_events::{SavedEventObservation,SavedEventMemory,SavedEventAnchor,SavedEventTarget};
pub(crate) use query::activation::{stable_site, stable_runtime_site};
pub use query::function_facts::{FactSourceReference, FactActivationSelector, FunctionFactContext, write_function_fact_projection};
mod search;
mod slice;

#[cfg(test)]
mod cache_identity_tests;

use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::session::{SessionHandle, SessionState};
use trace_parser::types::TraceFormat;

/// fd helper 的会话显示标签前缀。标签只进入诊断输出，不进入持久化缓存键。
pub const INHERITED_FD_SESSION_PREFIX: &str = "inherited-fd:";

/// fd 号每次 helper 调用都不同，若它直接拼进缓存文件名，同一 trace 永远 miss
/// 并全量重扫。fd 会话改用内容指纹作缓存身份；内容变化时缓存 header 里的
/// trace_hash 仍会判定失效，不会返回过期索引。路径会话保持原键，行为不变。
fn session_cache_identity(display_path: &str, trace_hash: &[u8; 32]) -> String {
    if !display_path.starts_with(INHERITED_FD_SESSION_PREFIX) {
        return display_path.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(trace_hash);
    format!("fd-content:{:x}", hasher.finalize())
}

#[derive(Default)]
pub struct TraceEngine {
    sessions: RwLock<HashMap<String, Arc<SessionHandle>>>,
    disk_cfg_sessions: RwLock<HashMap<String, Arc<disk_control_flow::DiskCfgSession>>>,
}

impl TraceEngine {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            disk_cfg_sessions: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn get_handle(&self, session_id: &str) -> Result<Arc<SessionHandle>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| TraceError::SessionNotFound(session_id.to_string()))
    }

    // ━━ 会话管理 ━━

    pub fn create_session(&self, path: &str) -> Result<SessionInfo> {
        let file = std::fs::File::open(path).map_err(TraceError::Io)?;
        self.create_session_from_file(file, path)
    }

    pub fn create_session_from_file(&self, file: std::fs::File, path: &str) -> Result<SessionInfo> {
        let metadata = file.metadata().map_err(TraceError::Io)?;
        let file_size = metadata.len();
        let mmap = unsafe { Mmap::map(&file) }.map_err(TraceError::Io)?;
        let trace_hash = crate::memory_search::compute_trace_content_hash(&mmap);

        #[cfg(unix)]
        let _ = mmap.advise(memmap2::Advice::WillNeed);

        let total_lines_estimate = (file_size / 110).max(1) as u32;
        let session_id = uuid::Uuid::new_v4().to_string();

        let session_state = SessionState {
            mmap: Arc::new(mmap),
            file_path: path.to_string(),
            cache_identity: session_cache_identity(path, &trace_hash),
            total_lines: total_lines_estimate,
            file_size,
            trace_hash,
            trace_metadata: metadata.clone(),
            trace_format: TraceFormat::Unidbg,
            call_tree: None,
            activation_tree: None,
            control_flow: None,
            phase2_store: None,
            string_index: None,
            scan_store: None,
            reg_last_def: None,
            lidx_store: None,
            slice_result: None,
            slice_origin: None,
            scan_strings_cancelled: Arc::new(AtomicBool::new(false)),
            call_annotations: HashMap::new(),
            consumed_seqs: Vec::new(),
            call_search_texts: HashMap::new(),
            crypto_cache: None,
        };

        let handle = Arc::new(SessionHandle {
            file_path: path.to_string(),
            file_size,
            building: AtomicBool::new(false),
            build_cancel: AtomicBool::new(false),
            scanning_strings: AtomicBool::new(false),
            scan_strings_cancel: AtomicBool::new(false),
            search_cache: std::sync::Mutex::new((0, Vec::new())),
            state: RwLock::new(session_state),
        });

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.insert(session_id.clone(), handle);
        }

        Ok(SessionInfo {
            session_id,
            file_path: path.to_string(),
            file_size,
            total_lines: total_lines_estimate,
            index_ready: false,
            building: false,
            has_slice_result: false,
            trace_format: Some(TraceFormat::Unidbg),
        })
    }

    pub fn close_session(&self, session_id: &str) -> Result<()> {
        if session_id.starts_with("disk-cfg:") {
            let removed = self.disk_cfg_sessions.write().map_err(|e| TraceError::Internal(e.to_string()))?.remove(session_id);
            if let Some(handle) = removed {
                handle.closed.store(true, Ordering::SeqCst);
                handle.cancel.store(true, Ordering::SeqCst);
                drop(handle);
            }
            return Ok(());
        }
        let removed = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.remove(session_id)
        };
        if let Some(handle) = removed {
            std::thread::spawn(move || drop(handle));
        }
        Ok(())
    }

    pub fn get_session_info(&self, session_id: &str) -> Result<SessionInfo> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        Ok(SessionInfo {
            session_id: session_id.to_string(),
            file_path: handle.file_path.clone(),
            file_size: handle.file_size,
            total_lines: state.total_lines,
            index_ready: state.scan_store.is_some(),
            building: handle.building.load(Ordering::Relaxed),
            has_slice_result: state.slice_result.is_some(),
            trace_format: Some(state.trace_format),
        })
    }

    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = match self.sessions.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        sessions
            .iter()
            .filter_map(|(id, handle)| {
                let state = handle.state.read().ok()?;
                Some(SessionInfo {
                    session_id: id.clone(),
                    file_path: handle.file_path.clone(),
                    file_size: handle.file_size,
                    total_lines: state.total_lines,
                    index_ready: state.scan_store.is_some(),
                    building: handle.building.load(Ordering::Relaxed),
                    has_slice_result: state.slice_result.is_some(),
                    trace_format: Some(state.trace_format),
                })
            })
            .collect()
    }

    // ━━ 缓存管理 ━━

    pub fn get_cache_dir(&self) -> CacheInfo {
        let (path, size) = crate::cache::get_cache_info();
        CacheInfo { path, size }
    }

    pub fn set_cache_dir(&self, path: Option<String>) -> Result<()> {
        let path_buf = path.map(std::path::PathBuf::from);
        if let Some(ref p) = path_buf {
            std::fs::create_dir_all(p).map_err(TraceError::Io)?;
        }
        crate::cache::set_cache_dir_override(path_buf);
        Ok(())
    }

    pub fn clear_all_cache(&self) -> ClearResult {
        let (files_deleted, bytes_freed) = crate::cache::clear_all_cache();
        ClearResult {
            files_deleted,
            bytes_freed,
        }
    }

    pub fn delete_file_cache(&self, path: &str) {
        crate::cache::delete_cache(path);
    }
}
