//! 缓存与 fingerprint 的单元测试：篡改拒绝、staging 回收、页边界与签名顺序。

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use trace_parser::types::TraceFormat;

use super::cache::sync_parent_dir;
#[cfg(unix)]
use super::fingerprint::{
    fd_signature, fingerprint_path, search_memory_fd_verified,
    search_memory_fd_verified_with_signature, FingerprintSource,
};
use super::{
    cache_header_total_len, memory_cache_path, search_memory_cached,
    search_memory_cached_with_trace_hash, sha256, trace_content_hash, MemorySearchOptions,
    CACHE_HEADER_LEN, CACHE_RECORD_LEN, CACHE_RECORD_READ_COUNT, CACHE_TAG_LEN, SEARCH_SCAN_COUNT,
    TRACE_HASH_COUNT,
};
use crate::cache::cache_dir_override_test_lock as cache_test_guard;
#[cfg(unix)]
use crate::error::TraceError;

#[test]
fn cache_contains_all_occurrences_and_default_ranges_hit_without_rescanning() {
    let _guard = cache_test_guard();
    let mut trace = String::new();
    for index in 0..201u32 {
        trace.push_str(&format!(
            "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
            seq = index * 2,
        ));
        if index != 200 {
            trace.push_str(&format!(
                "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n",
                seq = index * 2 + 1,
            ));
        }
    }
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);

    let first = search_memory_cached(
        "/tmp/target-discovery.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        },
    )
    .expect("first cached search");
    assert_eq!(first.total, 201);
    CACHE_RECORD_READ_COUNT.store(0, Ordering::SeqCst);

    let second = search_memory_cached(
        "/tmp/renamed-target-discovery.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 200,
            limit: 1,
        },
    )
    .expect("cached second page");
    assert_eq!(second.total, 201);
    assert_eq!(second.matches.len(), 1);
    assert_eq!(second.matches[0].seq, 400);
    assert_eq!(CACHE_RECORD_READ_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);

    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn cache_identity_uses_trace_content_not_pathname() {
    let _guard = cache_test_guard();
    let data = b"trace";
    let trace_hash = sha256(data);
    let pattern_hash = sha256(&[1, 2, 3]);
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    assert_eq!(
        memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options),
        memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options),
    );
}

#[test]
fn cache_with_nonzero_reserved_record_bytes_is_rejected_and_rebuilt() {
    let _guard = cache_test_guard();
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-corrupt-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let path = "/tmp/corrupt-memory-search.trace";
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    let trace_hash = sha256(trace.as_bytes());
    let pattern_hash = sha256(&options.pattern);
    let cache_path = memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options)
        .expect("cache path");
    let mut bytes = std::fs::read(&cache_path).expect("read cache");
    bytes[cache_header_total_len() as usize + 5] = 1;
    std::fs::write(&cache_path, bytes).expect("corrupt cache");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("rebuild cache");
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn cache_with_duplicate_occurrence_key_is_rejected_and_rebuilt() {
    let _guard = cache_test_guard();
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-duplicate-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 10,
    };
    let path = "/tmp/duplicate-memory-search.trace";
    let first = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    assert_eq!(first.total, 2);
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let mut bytes = std::fs::read(&cache_path).expect("read cache");
    let first_record = bytes
        [cache_header_total_len() as usize..cache_header_total_len() as usize + CACHE_RECORD_LEN]
        .to_vec();
    let second_record = cache_header_total_len() as usize + CACHE_RECORD_LEN;
    bytes[second_record..second_record + CACHE_RECORD_LEN].copy_from_slice(&first_record);
    std::fs::write(&cache_path, bytes).expect("corrupt cache");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    let rebuilt = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("rebuild cache");
    assert_eq!(rebuilt.total, 2);
    assert_eq!(rebuilt.matches.len(), 2);
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn session_fingerprint_reuses_trace_hash_across_pages() {
    let _guard = cache_test_guard();
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-hash-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let path = "/tmp/hash-count-memory-search.trace";
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    let trace_hash = trace_content_hash(trace.as_bytes());
    TRACE_HASH_COUNT.store(0, Ordering::SeqCst);
    search_memory_cached_with_trace_hash(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options.clone(),
        trace_hash,
    )
    .expect("first page");
    search_memory_cached_with_trace_hash(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            offset: 1,
            ..options
        },
        trace_hash,
    )
    .expect("second page");
    assert_eq!(TRACE_HASH_COUNT.load(Ordering::SeqCst), 0);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn stale_memory_cache_staging_is_removed_before_a_new_build() {
    let _guard = cache_test_guard();
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-staging-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let stale_path = cache_path.parent().expect("cache parent").join(format!(
        ".{}.tmp.4294967295.stale",
        cache_path
            .file_name()
            .expect("cache filename")
            .to_string_lossy()
    ));
    std::fs::write(&stale_path, vec![0u8; CACHE_HEADER_LEN]).expect("stale staging");
    search_memory_cached(
        "/tmp/staging-memory-search.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options,
    )
    .expect("build cache");
    assert!(!stale_path.exists());
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn malformed_memory_event_fails_scan_and_does_not_publish_cache() {
    let _guard = cache_test_guard();
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=not-an-address w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-malformed-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let result = search_memory_cached(
        "/tmp/malformed-memory-search.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options.clone(),
    );
    assert!(result.is_err());
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    assert!(!cache_path.exists());
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn cache_scan_failure_does_not_publish_partial_cache() {
    let _guard = cache_test_guard();
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-failure-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    let trace = b"\xff\n";
    let options = MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let result = search_memory_cached(
        "/tmp/invalid-memory-search.trace",
        trace,
        TraceFormat::Unidbg,
        options.clone(),
    );
    assert!(result.is_err());
    let cache_path = memory_cache_path(
        &sha256(trace),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    assert!(!cache_path.exists());
    let temporary_files = std::fs::read_dir(&cache_dir)
        .expect("cache directory")
        .filter_map(|entry| entry.ok())
        .count();
    assert_eq!(temporary_files, 0);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

/// 三条 occurrence 的 trace，供 cache 篡改测试复用。
fn three_occurrence_trace() -> &'static str {
    "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 003][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 004][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n"
}

fn tamper_cache_dir(label: &str) -> PathBuf {
    let cache_dir = std::env::temp_dir().join(format!(
        "trace-ui-memory-cache-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
    cache_dir
}

fn default_options() -> MemorySearchOptions {
    MemorySearchOptions {
        pattern: vec![1, 2, 3, 4],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 10,
    }
}

#[test]
fn cache_valid_looking_record_tamper_is_detected_and_rebuilt() {
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("tamper");
    let options = default_options();
    let path = "/tmp/tamper-memory-search.trace";
    let fresh = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    assert_eq!(fresh.total, 3);
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let mut bytes = std::fs::read(&cache_path).expect("read cache");
    // 把第一条 record 的 seq 从 0 改成 1：格式完全合法、顺序仍然递增，
    // 但内容是假的（seq 1 的写入值其实是 0x08070605）。
    // 文件布局是 [字段区|摘要|records|tags]，记录区从总头长之后开始。
    let rec0 = cache_header_total_len() as usize;
    bytes[rec0..rec0 + 4].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(&cache_path, bytes).expect("tamper cache");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    let served = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("rebuilt search");
    assert_eq!(
        served, fresh,
        "valid-looking tampered record must never be served"
    );
    assert_eq!(
        SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
        1,
        "tampered cache must trigger a rebuild"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn cache_cross_page_duplicate_is_detected_via_boundary_record() {
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("cross-page");
    let options = default_options();
    let path = "/tmp/cross-page-memory-search.trace";
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let mut bytes = std::fs::read(&cache_path).expect("read cache");
    // 第二页只有 record[1]；把它改成 record[0] 的副本。只读当前页时
    // 页内顺序校验发现不了跨页重复，必须回读边界 record 或校验完整性。
    let rec_base = cache_header_total_len() as usize;
    let first_record = bytes[rec_base..rec_base + CACHE_RECORD_LEN].to_vec();
    bytes[rec_base + CACHE_RECORD_LEN..rec_base + 2 * CACHE_RECORD_LEN]
        .copy_from_slice(&first_record);
    std::fs::write(&cache_path, bytes).expect("tamper cache");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    let second_page = search_memory_cached(
        path,
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            offset: 1,
            limit: 1,
            ..default_options()
        },
    )
    .expect("rebuilt second page");
    assert_eq!(second_page.matches.len(), 1);
    assert_eq!(second_page.matches[0].seq, 2);
    assert_eq!(
        SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
        1,
        "cross-page duplicate must trigger a rebuild"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn cache_tamper_on_a_later_page_is_detected_when_that_page_is_served() {
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("later-page");
    let options = default_options();
    let path = "/tmp/later-page-memory-search.trace";
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let mut bytes = std::fs::read(&cache_path).expect("read cache");
    // 篡改第三页（record[2]）的 address，先请求第 0 页再请求第 2 页。
    // 文件布局是 [字段区|摘要|records|tags]，记录区从总头长之后开始。
    let rec2 = cache_header_total_len() as usize + 2 * CACHE_RECORD_LEN;
    bytes[rec2 + 8..rec2 + 16].copy_from_slice(&0x9999u64.to_le_bytes());
    std::fs::write(&cache_path, bytes).expect("tamper cache");
    let page0 = search_memory_cached(
        path,
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            offset: 0,
            limit: 1,
            ..default_options()
        },
    )
    .expect("page 0");
    assert_eq!(page0.matches[0].seq, 0);
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    let page2 = search_memory_cached(
        path,
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            offset: 2,
            limit: 1,
            ..default_options()
        },
    )
    .expect("page 2");
    assert_eq!(
        page2.matches[0].seq, 4,
        "tampered page must be rebuilt, not served"
    );
    assert_eq!(page2.matches[0].address, 0x2000);
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn stale_staging_is_also_removed_on_a_cache_hit() {
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("hit-cleanup");
    let options = default_options();
    let path = "/tmp/hit-cleanup-memory-search.trace";
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("write cache");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let stale_path = cache_path.parent().expect("cache parent").join(format!(
        ".{}.tmp.4294967295.stale",
        cache_path
            .file_name()
            .expect("cache filename")
            .to_string_lossy()
    ));
    std::fs::write(&stale_path, vec![0u8; CACHE_HEADER_LEN]).expect("stale staging");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options).expect("cache hit");
    assert_eq!(
        SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
        0,
        "must be a cache hit"
    );
    assert!(
        !stale_path.exists(),
        "hit path must also reclaim stale staging"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn stale_staging_with_a_recycled_live_pid_is_removed_by_age() {
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("pid-reuse");
    let options = default_options();
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    // 当前进程 PID 一定活着：模拟 PID 被复用后遗留的 staging。
    let stale_path = cache_path.parent().expect("cache parent").join(format!(
        ".{}.tmp.{}.stale",
        cache_path
            .file_name()
            .expect("cache filename")
            .to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&stale_path, vec![0u8; CACHE_HEADER_LEN]).expect("stale staging");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
    std::fs::File::options()
        .write(true)
        .open(&stale_path)
        .expect("open stale")
        .set_modified(old)
        .expect("age stale staging");
    search_memory_cached(
        "/tmp/pid-reuse-memory-search.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options,
    )
    .expect("build cache");
    assert!(
        !stale_path.exists(),
        "aged staging must be reclaimed even when its PID is alive"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn cache_page_beyond_the_result_end_returns_empty() {
    // offset 越过缓存结果末尾：不得下溢 panic，返回空页。
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("page-beyond-end");
    let path = "/tmp/page-beyond-end-memory-search.trace";
    search_memory_cached(
        path,
        trace.as_bytes(),
        TraceFormat::Unidbg,
        default_options(),
    )
    .expect("initial search");
    let paged = search_memory_cached(
        path,
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            offset: 2,
            limit: 1,
            ..default_options()
        },
    )
    .expect("page beyond the result end must be empty, not a panic");
    assert_eq!(paged.matches.len(), 1);
    let past = search_memory_cached(
        path,
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            offset: 5,
            limit: 1,
            ..default_options()
        },
    )
    .expect("offset past the end must be an empty page");
    assert!(past.matches.is_empty());
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn corrupt_huge_record_count_is_rejected_and_rebuilt() {
    // 篡改 header 的 count 为巨大值：长度校验必须安全拒绝并重建，不能溢出。
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("huge-record-count");
    let path = "/tmp/huge-record-count-memory-search.trace";
    let options = default_options();
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("initial search");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let mut bytes = std::fs::read(&cache_path).expect("cache file");
    bytes[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
    std::fs::write(&cache_path, &bytes).expect("corrupt cache");
    let result = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("huge count must be rejected and the cache rebuilt");
    assert_eq!(result.total, 3);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn consistent_count_truncation_without_digest_is_rejected_and_rebuilt() {
    // GPT 审查 #5 的完整攻击面：把 3 条结果的缓存改成 count=2 并同步截掉
    // 一条 record + tag，使长度校验完全自洽。没有摘要保护时这会被静默
    // 当成合法空页；现在字段区摘要必然不一致 → 重建。
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("count-trunc");
    let path = "/tmp/count-trunc-memory-search.trace";
    let options = default_options();
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("initial search");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let bytes = std::fs::read(&cache_path).expect("cache file");
    let header_len = cache_header_total_len() as usize;
    assert_eq!(
        bytes.len(),
        header_len + 3 * CACHE_RECORD_LEN + 3 * CACHE_TAG_LEN
    );
    // count=2：保留 record[0..2] 与 tag[0..2]，丢弃最后一组。
    let mut crafted = bytes[..header_len].to_vec();
    crafted[112..120].copy_from_slice(&2u64.to_le_bytes());
    crafted.extend_from_slice(&bytes[header_len..header_len + 2 * CACHE_RECORD_LEN]);
    crafted.extend_from_slice(
        &bytes[header_len + 3 * CACHE_RECORD_LEN
            ..header_len + 3 * CACHE_RECORD_LEN + 2 * CACHE_TAG_LEN],
    );
    std::fs::write(&cache_path, crafted).expect("write crafted cache");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    let served = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("rebuilt search serves full result");
    assert_eq!(served.total, 3, "consistent truncation must be detected");
    assert_eq!(
        SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
        1,
        "digest mismatch must trigger a rebuild"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[test]
fn truncated_header_is_rejected_and_rebuilt() {
    // 截短到旧版 120 字节头部以下任何合法形态都必须整体重建。
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("truncated-header");
    let path = "/tmp/truncated-header-memory-search.trace";
    let options = default_options();
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("initial search");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    std::fs::write(
        &cache_path,
        &std::fs::read(&cache_path).unwrap()[..CACHE_HEADER_LEN],
    )
    .expect("truncate cache");
    SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
    let served = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("truncated cache must rebuild, not error or serve stale");
    assert_eq!(served.total, 3);
    assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[cfg(unix)]
#[test]
fn stale_baseline_signature_is_rejected_immediately() {
    // helper 的顺序保证：mmap 前取的签名与搜索开始时的 fd 不一致时必须
    // 直接报错，而不是把 mmap 内容的 hash 绑定到新身份上。
    use std::io::Write;
    let _guard = cache_test_guard();
    let cache_dir = tamper_cache_dir("stale-baseline");
    let trace_dir = std::env::temp_dir().join(format!(
        "trace-ui-stale-sig-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&trace_dir).expect("trace dir");
    let trace_path = trace_dir.join("trace.log");
    std::fs::write(&trace_path, three_occurrence_trace()).expect("trace");
    let file = std::fs::File::open(&trace_path).expect("open trace");
    let data = std::fs::read(&trace_path).expect("read trace");
    let baseline = fd_signature(&file).expect("baseline signature");
    // 模拟"取签名之后、mmap/搜索之前文件增长"。
    let mut append = std::fs::OpenOptions::new()
        .append(true)
        .open(&trace_path)
        .expect("append");
    append.write_all(b"[extra line]\n").expect("grow file");
    drop(append);
    let result = search_memory_fd_verified_with_signature(
        &file,
        &data[..data.len() - b"[extra line]\n".len()],
        TraceFormat::Unidbg,
        default_options(),
        &baseline,
        None,
    );
    assert!(
        matches!(&result, Err(TraceError::CacheError(message)) if message.contains("changed between mmap")),
        "stale baseline must be rejected with a cache error, got {result:?}"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[cfg(target_os = "linux")]
#[test]
fn fingerprint_fifo_is_rejected_not_blocked() {
    use std::sync::mpsc;
    use std::time::Duration;
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("fingerprint-fifo");
    let trace_dir = std::env::temp_dir().join(format!(
        "trace-ui-fifo-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&trace_dir).expect("trace dir");
    let trace_path = trace_dir.join("trace.log");
    std::fs::write(&trace_path, trace).expect("trace");
    let file = std::fs::File::open(&trace_path).expect("open trace");
    let data = std::fs::read(&trace_path).expect("read trace");
    let options = default_options();
    let mut decisions = Vec::new();
    search_memory_fd_verified(
        &file,
        &data,
        TraceFormat::Unidbg,
        options.clone(),
        Some(&mut |source| decisions.push(source)),
    )
    .expect("first pass computes the fingerprint");
    let signature = fd_signature(&file).expect("signature");
    let fingerprint = fingerprint_path(&signature).expect("fingerprint path");

    // 用同名 FIFO 替换 fingerprint 文件。
    std::fs::remove_file(&fingerprint).expect("remove real fingerprint");
    let status = std::process::Command::new("mkfifo")
        .arg(&fingerprint)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo failed in test environment");

    // 若 open() 阻塞，recv_timeout 会先超时并 panic，而不是挂死测试进程。
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let outcome = search_memory_fd_verified(
            &file,
            &data,
            TraceFormat::Unidbg,
            options,
            Some(&mut |source| seen.push(source)),
        )
        .map(|page| page.total);
        tx.send((outcome, seen)).ok();
    });
    let (outcome, seen) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("fingerprint open blocked on FIFO: O_NONBLOCK missing");
    assert_eq!(
        seen,
        vec![FingerprintSource::Computed],
        "FIFO must be rejected so the hash is recomputed"
    );
    assert!(
        matches!(outcome, Ok(3)),
        "search still succeeds: {outcome:?}"
    );
    handle.join().expect("probe thread");
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
    let _ = std::fs::remove_dir_all(trace_dir);
}

#[test]
fn aged_staging_still_open_by_a_live_pid_is_kept() {
    // PID 被复用时靠 mtime 年龄兜底回收；但文件仍被活着的进程实际持有
    // 时（真实长扫描的 writer），年龄规则不得误删。
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("staging-held");
    let path = "/tmp/staging-held-memory-search.trace";
    let options = default_options();
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("initial search");
    let cache_path = memory_cache_path(
        &sha256(trace.as_bytes()),
        &sha256(&options.pattern),
        TraceFormat::Unidbg,
        &options,
    )
    .expect("cache path");
    let cache_name = cache_path
        .file_name()
        .expect("cache name")
        .to_string_lossy()
        .into_owned();
    let stale_path = cache_dir.join(format!(".{cache_name}.tmp.{}.stale", std::process::id()));
    let held = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&stale_path)
        .expect("held staging");
    held.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600))
        .expect("age the staging file");
    // 文件仍被本进程（活 PID）实际持有：不得被年龄规则回收。
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
        .expect("cached search keeps the held staging");
    assert!(
        stale_path.exists(),
        "staging still open by a live pid must not be reclaimed by age alone"
    );
    // 释放后：年龄规则正常回收。
    drop(held);
    search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
        .expect("cached search reclaims the released staging");
    assert!(
        !stale_path.exists(),
        "released aged staging must be reclaimed"
    );
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
}

#[cfg(unix)]
#[test]
fn oversized_or_symlinked_fingerprint_is_rejected_and_recomputed() {
    // fingerprint 只是加速：读取必须 bounded、no-follow、精确长度预检；
    // 超大文件或符号链接一律拒绝并重新完整 hash，不能阻塞或失控分配。
    let _guard = cache_test_guard();
    let trace = three_occurrence_trace();
    let cache_dir = tamper_cache_dir("fingerprint-bounded");
    let trace_dir = std::env::temp_dir().join(format!(
        "trace-ui-fp-trace-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&trace_dir).expect("trace dir");
    let trace_path = trace_dir.join("trace.log");
    std::fs::write(&trace_path, trace).expect("trace");
    let file = std::fs::File::open(&trace_path).expect("open trace");
    let data = std::fs::read(&trace_path).expect("read trace");
    let options = default_options();
    let mut decisions = Vec::new();
    let run = |decisions: &mut Vec<FingerprintSource>| {
        search_memory_fd_verified(
            &file,
            &data,
            TraceFormat::Unidbg,
            options.clone(),
            Some(&mut |source| decisions.push(source)),
        )
        .expect("fd verified search")
    };
    run(&mut decisions);
    assert_eq!(decisions, [FingerprintSource::Computed]);
    decisions.clear();
    run(&mut decisions);
    assert_eq!(decisions, [FingerprintSource::Reused]);

    let signature = fd_signature(&file).expect("signature");
    let fingerprint = fingerprint_path(&signature).expect("fingerprint path");
    // 超大文件：必须被拒绝并重新计算。
    std::fs::write(&fingerprint, vec![0u8; 1 << 20]).expect("oversized fingerprint");
    decisions.clear();
    run(&mut decisions);
    assert_eq!(decisions, [FingerprintSource::Computed]);
    // 符号链接：必须被拒绝并重新计算。
    let _ = std::fs::remove_file(&fingerprint);
    let real = cache_dir.join("real-fingerprint-target");
    std::fs::write(&real, b"not-a-fingerprint").expect("target");
    std::os::unix::fs::symlink(&real, &fingerprint).expect("symlink");
    decisions.clear();
    run(&mut decisions);
    assert_eq!(decisions, [FingerprintSource::Computed]);
    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(cache_dir);
    let _ = std::fs::remove_dir_all(trace_dir);
}

#[test]
fn parent_directory_sync_failure_is_propagated() {
    let result = sync_parent_dir(Path::new("/proc/self/definitely-not-a-cache-dir"));
    assert!(
        result.is_err(),
        "parent directory open failure must propagate"
    );
}
