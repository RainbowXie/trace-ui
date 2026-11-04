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
