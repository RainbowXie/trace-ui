//! 写路径回归：rename 成功后父目录 fsync 失败不得把第一次搜索写成 Err。

use std::sync::atomic::Ordering;
use trace_parser::types::TraceFormat;

use super::{
    memory_cache_path, search_memory_cached, sha256, MemorySearchOptions, SEARCH_SCAN_COUNT,
};
use crate::cache::cache_dir_override_test_lock as cache_test_guard;
use crate::staging::ForceParentFsyncFailGuard;

#[test]
fn stream_cache_parent_fsync_failure_after_rename_is_not_fatal() {
    // 注入点在 sync_parent_dir，调用点是 complete_cached_page → stream_cache。
    // 若 rename 成功后改回 `sync_parent_dir(parent)?`，第一次搜索会变 Err。
    let _guard = cache_test_guard();
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-ms-parent-fsync-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);

    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let first = {
        let _fail = ForceParentFsyncFailGuard::arm();
        search_memory_cached(
            "/tmp/parent-fsync-memory-search.trace",
            trace.as_bytes(),
            TraceFormat::Unidbg,
            options.clone(),
        )
    };
    let first = first.expect("第一次搜索在父目录 fsync 失败后仍必须 Ok");
    assert_eq!(first.total, 1);
    assert_eq!(first.matches.len(), 1);
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);

    let trace_hash = sha256(trace.as_bytes());
    let pattern_hash = sha256(&options.pattern);
    let cache_path =
        memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options).unwrap();
    assert!(
        cache_path.is_file(),
        "rename 已发布：最终缓存必须可读，不得被失败路径删掉"
    );

    let second = search_memory_cached(
        "/tmp/parent-fsync-memory-search.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options,
    )
    .expect("已发布文件必须能被后续命中");
    assert_eq!(second.total, 1);
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);

    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}
