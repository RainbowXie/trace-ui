use crate::error::{Result, TraceError};
use crate::memory_search::{MemorySearchOptions, MemorySearchResult};
use std::time::SystemTime;

use super::TraceEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraceMetadataSignature {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

fn trace_metadata_signature(metadata: &std::fs::Metadata) -> TraceMetadataSignature {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        TraceMetadataSignature {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
    #[cfg(not(unix))]
    {
        TraceMetadataSignature {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

impl TraceEngine {
    /// Search the temporal memory state of an opened trace session.
    pub fn search_memory(
        &self,
        session_id: &str,
        options: MemorySearchOptions,
    ) -> Result<MemorySearchResult> {
        let handle = self.get_handle(session_id)?;
        let (file_path, mmap, trace_format, trace_hash, expected_signature) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (
                state.file_path.clone(),
                state.mmap.clone(),
                state.trace_format,
                state.trace_hash,
                trace_metadata_signature(&state.trace_metadata),
            )
        };
        let before = std::fs::metadata(&file_path).map_err(TraceError::Io)?;
        if trace_metadata_signature(&before) != expected_signature {
            return Err(TraceError::CacheError(
                "trace changed after the session opened; reopen the trace".to_string(),
            ));
        }
        let result = crate::memory_search::search_memory_cached_with_trace_hash(
            &mmap,
            trace_format,
            options,
            trace_hash,
        );
        let after = std::fs::metadata(&file_path).map_err(TraceError::Io)?;
        if trace_metadata_signature(&after) != expected_signature {
            return Err(TraceError::CacheError(
                "trace changed while memory search was running; retry after reopening".to_string(),
            ));
        }
        result
    }
}
