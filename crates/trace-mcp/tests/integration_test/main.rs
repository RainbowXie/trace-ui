//! Integration tests for all MCP tools.
//!
//! These tests instantiate TraceToolHandler directly and call each tool method,
//! verifying that they return valid JSON responses without errors.

use std::sync::Arc;
use trace_core::TraceEngine;

// We can't directly call the tool methods because they're behind the #[tool_router] macro.
// Instead, we test by calling TraceEngine methods the same way tools.rs does,
// verifying the actual logic paths that MCP tools exercise.

mod analysis;
mod export;
mod misc;
mod search;
mod session;
mod strings;

fn get_trace_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../example-trace-gumtrace.txt", manifest_dir)
}

fn get_unidbg_trace_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../example-trace-unidbg.txt", manifest_dir)
}

/// Helper: create session + build index, return (engine, session_id)
fn setup_session(path: &str) -> (Arc<TraceEngine>, String) {
    let engine = Arc::new(TraceEngine::new());
    let info = engine.create_session(path).expect("create_session failed");
    let sid = info.session_id.clone();
    let build = engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("build_index failed");
    assert!(build.total_lines > 0, "trace should have lines");
    (engine, sid)
}
