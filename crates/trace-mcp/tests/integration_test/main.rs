//! Integration tests for all MCP tools.
//!
//! These tests instantiate TraceToolHandler directly and call each tool method,
//! verifying that they return valid JSON responses without errors.

use std::sync::Arc;
use trace_core::TraceEngine;

// We can't directly call the tool methods because they're behind the #[tool_router] macro.
// Instead, we test by calling TraceEngine methods the same way tools.rs does,
// verifying the actual logic paths that MCP tools exercise.

mod activation;
mod analysis;
mod cache_corruption;
mod cache_semantic_corruption;
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

/// 多阶段测试（build→改缓存→reopen）用：全程持锁目自建目录。
/// 返回 (engine, session_id, guard)；guard 存活期间全局 override 不变。
fn setup_session_locked(
    path: &str,
) -> (Arc<TraceEngine>, String, std::sync::MutexGuard<'static, ()>) {
    let guard = trace_core::cache::cache_dir_override_test_lock();
    let dir = std::env::temp_dir().join(format!("trace-ui-itest-locked-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create isolated cache dir");
    trace_core::cache::set_cache_dir_override(Some(dir));

    let engine = Arc::new(TraceEngine::new());
    let info = engine.create_session(path).expect("create_session failed");
    let sid = info.session_id.clone();
    engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("build_index failed");
    (engine, sid, guard)
}

/// Helper: create session + build index, return (engine, session_id)
///
/// 每次 setup 隔离 cache 目录：集成测试并行运行时共享真实缓存目录会在
/// mmap 上互相覆盖写（重写缓存文件的测试会让其他测试的 mmap 读到 SIGBUS）。
/// 目录按进程内递增编号分配；build 完成后 session 已持有 mmap/索引，
/// 切换目录不影响已建立的 session。多阶段缓存测试用 setup_session_locked。
fn setup_session(path: &str) -> (Arc<TraceEngine>, String) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let _guard = trace_core::cache::cache_dir_override_test_lock();
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("trace-ui-itest-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create isolated cache dir");
    trace_core::cache::set_cache_dir_override(Some(dir));

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
    drop(_guard);
    (engine, sid)
}
