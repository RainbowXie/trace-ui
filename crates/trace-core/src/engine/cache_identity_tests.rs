//! fd 会话的持久化索引用内容指纹键控：同一内容换 fd 号必须命中，内容变化必须重建。

use std::fs::File;

use crate::api_types::BuildOptions;
use crate::cache;
use crate::TraceEngine;

/// gumtrace 格式最小 trace：带指令结构签名与内存注解，可被 build_index 接受。
const RAW: &str = "[App] 0x400000!0x0 bl #0x401000; x0=0x6000 sp=0x8000\n\
[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x6000 mem_r=0x6000 -> x9=0x1\n\
[App] 0x401008!0x1008 add x9, x9, #2; x9=0x1 -> x9=0x3\n\
[App] 0x40100c!0x100c str x9, [x3]; x9=0x3 x3=0x7000 mem_w=0x7000\n\
[App] 0x401010!0x1010 ret; x0=0x6000\n";

struct CacheDirReset;

impl Drop for CacheDirReset {
    fn drop(&mut self) {
        cache::set_cache_dir_override(None);
    }
}

fn options() -> BuildOptions {
    BuildOptions {
        force_rebuild: false,
        skip_strings: true,
    }
}

/// 每个用例用独立缓存目录，避免与并行测试共享同一批缓存文件。
fn isolated_cache_dir() -> (std::path::PathBuf, CacheDirReset) {
    let dir = std::env::temp_dir().join(format!("fd-cache-id-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("cache")).expect("create isolated cache dir");
    cache::set_cache_dir_override(Some(dir.join("cache")));
    (dir, CacheDirReset)
}

#[test]
fn inherited_fd_sessions_reuse_index_across_fd_numbers() {
    let _lock = cache::cache_dir_override_test_lock();
    let (dir, _reset) = isolated_cache_dir();
    let trace = dir.join("trace.txt");
    std::fs::write(&trace, RAW).expect("write trace");

    let engine = TraceEngine::new();
    let first = engine
        .create_session_from_file(File::open(&trace).expect("open trace"), "inherited-fd:7")
        .expect("first session");
    assert!(
        !engine
            .build_index(&first.session_id, options(), None)
            .expect("cold build")
            .from_cache,
        "首次构建必须真正扫描"
    );
    engine.close_session(&first.session_id).expect("close first");

    // 每次 helper 调用拿到的 fd 号都不同；标签随之变化，缓存键只能看内容。
    let second = engine
        .create_session_from_file(File::open(&trace).expect("open trace"), "inherited-fd:9")
        .expect("second session");
    assert!(
        engine
            .build_index(&second.session_id, options(), None)
            .expect("warm build")
            .from_cache,
        "fd 号变化不得使同一内容的索引缓存失效"
    );
    engine.close_session(&second.session_id).expect("close second");
}

#[test]
fn inherited_fd_sessions_do_not_reuse_index_across_contents() {
    let _lock = cache::cache_dir_override_test_lock();
    let (dir, _reset) = isolated_cache_dir();
    let trace = dir.join("trace.txt");
    std::fs::write(&trace, RAW).expect("write trace");
    let changed = dir.join("changed.txt");
    // 同一 fd 标签、不同内容：只有内容指纹进键才可能区分，缓存 header 的
    // trace_hash 校验负责让旧索引失效。
    std::fs::write(&changed, RAW.replace("0x401010", "0x401014")).expect("write changed trace");

    let engine = TraceEngine::new();
    let first = engine
        .create_session_from_file(File::open(&trace).expect("open trace"), "inherited-fd:7")
        .expect("first session");
    engine
        .build_index(&first.session_id, options(), None)
        .expect("cold build");
    engine.close_session(&first.session_id).expect("close first");

    let other = engine
        .create_session_from_file(File::open(&changed).expect("open changed"), "inherited-fd:7")
        .expect("other session");
    assert!(
        !engine
            .build_index(&other.session_id, options(), None)
            .expect("build other")
            .from_cache,
        "内容不同的 trace 不得复用同一标签下的索引"
    );
    engine.close_session(&other.session_id).expect("close other");
}

/// 不访问 deps/pair_split 的 fact 查询在缓存命中时跳过 931 MiB `.scan.cache`：
/// 即使 `.scan.cache` 不存在也必须判定缓存命中，而需要扫描索引的查询必须重扫。
#[test]
fn fact_index_hits_without_scan_cache_and_full_build_requires_it() {
    let _lock = cache::cache_dir_override_test_lock();
    let (dir, _reset) = isolated_cache_dir();
    let trace = dir.join("trace.txt");
    std::fs::write(&trace, RAW).expect("write trace");
    let label = trace.to_str().unwrap();

    let engine = TraceEngine::new();
    let cold = engine.create_session(label).expect("cold session");
    assert!(
        !engine
            .build_index(&cold.session_id, options(), None)
            .expect("cold build")
            .from_cache
    );
    engine.close_session(&cold.session_id).expect("close cold");

    let scan_cache = cache::cache_dir()
        .expect("cache dir")
        .join(format!("{}.scan.cache", cache::path_hash_for_test(label)));
    assert!(scan_cache.exists(), "首次构建必须落盘 .scan.cache");
    std::fs::remove_file(&scan_cache).expect("remove scan cache");

    let fact = engine.create_session(label).expect("fact session");
    assert!(
        engine
            .build_fact_index(&fact.session_id, None)
            .expect("fact build")
            .from_cache,
        "缺少 .scan.cache 不得让 fact 查询退回重扫"
    );
    assert!(
        !engine
            .get_session_info(&fact.session_id)
            .expect("fact session info")
            .index_ready,
        "跳过 .scan.cache 的 session 不得声称 scan 索引就绪"
    );
    engine.close_session(&fact.session_id).expect("close fact");

    let full = engine.create_session(label).expect("full session");
    assert!(
        !engine
            .build_index(&full.session_id, options(), None)
            .expect("full build")
            .from_cache,
        "需要 deps 的查询仍必须要求 .scan.cache 命中"
    );
    assert!(
        engine
            .get_session_info(&full.session_id)
            .expect("full session info")
            .index_ready
    );
    engine.close_session(&full.session_id).expect("close full");
}

/// `create_session_from_file` 复用 FD 指纹：同一未改动的文件不得重算内容哈希，
/// 内容改写后必须重算并得到新的指纹。
#[test]
fn fd_trace_hash_reuses_persisted_fingerprint_and_invalidates_on_rewrite() {
    let _lock = cache::cache_dir_override_test_lock();
    let (dir, _reset) = isolated_cache_dir();
    let trace = dir.join("trace.txt");
    std::fs::write(&trace, RAW).expect("write trace");

    let file = File::open(&trace).expect("open trace");
    let baseline = crate::memory_search::fd_signature(&file).expect("signature");
    let data = std::fs::read(&trace).expect("read trace");
    let mut sources = Vec::new();
    let computed = crate::memory_search::fd_trace_hash_verified(
        &file,
        &data,
        &baseline,
        Some(&mut |source| sources.push(source)),
    )
    .expect("first hash");
    let mut reused_sources = Vec::new();
    let reused = crate::memory_search::fd_trace_hash_verified(
        &file,
        &data,
        &baseline,
        Some(&mut |source| reused_sources.push(source)),
    )
    .expect("second hash");
    assert_eq!(reused, computed, "同一 FD 签名必须复用同一内容指纹");
    assert_eq!(
        sources,
        vec![crate::memory_search::FingerprintSource::Computed]
    );
    assert_eq!(
        reused_sources,
        vec![crate::memory_search::FingerprintSource::Reused]
    );

    // 同长度原地改写：mtime/ctime 变化使基线签名失配，必须重算。
    // 指纹绑定的是文件系统时间戳，同一时间戳刻度内的两次写入无法区分——
    // 先让时钟推进一格，避免把「同刻度改写」误当成复用证据。
    let changed = RAW.replace("0x401010", "0x401014");
    assert_eq!(changed.len(), RAW.len());
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(&trace, &changed).expect("rewrite trace");
    let file = File::open(&trace).expect("reopen trace");
    let baseline = crate::memory_search::fd_signature(&file).expect("signature");
    let mut invalidated_sources = Vec::new();
    let recomputed = crate::memory_search::fd_trace_hash_verified(
        &file,
        changed.as_bytes(),
        &baseline,
        Some(&mut |source| invalidated_sources.push(source)),
    )
    .expect("rewritten hash");
    assert_eq!(
        invalidated_sources,
        vec![crate::memory_search::FingerprintSource::Computed]
    );
    assert_ne!(recomputed, computed, "内容改写必须产生不同的内容指纹");
}

/// 会话级集成：fd 会话第二次打开同一文件时直接复用持久化指纹。
#[test]
fn fd_sessions_reuse_the_persisted_trace_hash() {
    let _lock = cache::cache_dir_override_test_lock();
    let (dir, _reset) = isolated_cache_dir();
    let trace = dir.join("trace.txt");
    std::fs::write(&trace, RAW).expect("write trace");
    let engine = TraceEngine::new();
    let first = engine
        .create_session_from_file(File::open(&trace).expect("open trace"), "inherited-fd:7")
        .expect("first session")
        .session_id;
    let first_hash = engine
        .get_handle(&first)
        .expect("first handle")
        .state
        .read()
        .expect("first state")
        .trace_hash;
    let second = engine
        .create_session_from_file(File::open(&trace).expect("open trace"), "inherited-fd:9")
        .expect("second session")
        .session_id;
    let second_hash = engine
        .get_handle(&second)
        .expect("second handle")
        .state
        .read()
        .expect("second state")
        .trace_hash;
    assert_eq!(first_hash, second_hash);
    assert!(
        cache::cache_dir()
            .expect("cache dir")
            .join("fingerprints")
            .read_dir()
            .expect("fingerprint dir")
            .next()
            .is_some(),
        "内容指纹必须持久化，后续子进程才能复用"
    );
    engine.close_session(&first).expect("close first");
    engine.close_session(&second).expect("close second");
}
