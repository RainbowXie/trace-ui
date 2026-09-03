//! 缓存损坏 / 升版 / 空数组命中回归。
//!
//! 从 activation.rs 拆出：损坏 miss 重扫与合法二次命中不是 Activation
//! 语义，混在同一文件会超 500 行软上限。

use super::*;

/// 当前隔离缓存目录（setup_session 已为每次调用分配独立目录；
/// 旧格式测试用它直接操作缓存文件）。
fn current_cache_dir() -> std::path::PathBuf {
    trace_core::cache::cache_dir().expect("setup_session 已设置隔离目录")
}

#[test]
fn test_activation_tree_survives_cache_reload() {
    // 多阶段（build→close→reopen）全程持锁：reopen 的缓存命中必须落在
    // 第一次 build 的同一目录，中途不得被其他测试的 setup_session 切走。
    let path = get_trace_path();
    let (engine, sid, _guard) = setup_session_locked(&path);
    let before = engine
        .get_activation_tree(&sid, 0, 100)
        .expect("first build");
    engine.close_session(&sid).unwrap();

    let info = engine.create_session(&path).expect("reopen");
    let sid2 = info.session_id.clone();
    let rebuild = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("rebuild (cache hit)");
    // 合法缓存二次加载必须命中（typed 预检不得把空数组/对齐误判为损坏，
    // 否则每次重扫，reload 假绿）
    assert!(
        rebuild.from_cache,
        "合法缓存二次加载必须命中，否则 typed 预检拒绝合法缓存"
    );
    let after = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("after reload");

    assert_eq!(before.total_activations, after.total_activations);
    assert_eq!(before.confirmed_count, after.confirmed_count);
    assert_eq!(before.bypassed_calls.len(), after.bypassed_calls.len());
    for (a, b) in before.activations.iter().zip(after.activations.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.entry_seq, b.entry_seq);
        assert_eq!(a.exit_seq, b.exit_seq);
        assert_eq!(a.resume_seq, b.resume_seq);
        assert_eq!(a.func_addr, b.func_addr);
        assert_eq!(a.unresolved_reason, b.unresolved_reason);
    }
    engine.close_session(&sid2).unwrap();
}

/// 旧格式 Phase2 缓存（7 sections，无 ActivationTree）不 panic，
/// ActivationTree 查询返回 IndexNotReady，重建后恢复。
#[test]
fn test_corrupted_v5_cache_triggers_rescan_not_stale_load() {
    // V5 缓存布局固定 8 sections：7-section 的 V5 缓存 = 损坏/截断，
    // 必须整体判 miss（重扫重建），不能部分加载留下永久缺失的能力。
    // 多阶段（build→改缓存→reopen）全程持锁自控目录。
    let (engine, sid, _guard) = setup_session_locked(&get_trace_path());
    let total = engine
        .get_activation_tree(&sid, 0, 100)
        .unwrap()
        .total_activations;
    engine.close_session(&sid).unwrap();
    let path = get_trace_path();
    let dir = current_cache_dir();

    // 构造损坏缓存：截掉最后一个 section 表项（不调整后续 offset——
    // 真实截断正是这种不一致形态；SectionReader 的范围校验也在此覆盖）
    let cache_file = dir.join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(&path),
        ".p2.cache"
    ));
    let bytes = std::fs::read(&cache_file).expect("cache written by first build");
    assert!(bytes.len() > 64);
    let num = u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
    assert_eq!(num, 8, "V5 p2 cache must have exactly 8 sections");
    let mut corrupted = bytes.clone();
    corrupted[64..68].copy_from_slice(&7u32.to_le_bytes());
    let table_end = 64 + 4 + 8 * 16;
    let new_table_end = 64 + 4 + 7 * 16;
    corrupted.drain(new_table_end..table_end);
    std::fs::write(&cache_file, &corrupted).unwrap();

    let info = engine
        .create_session(&path)
        .expect("reopen corrupted cache");
    let sid2 = info.session_id.clone();
    let build = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("corrupted cache must miss and rescan (not partial load)");
    assert!(build.total_lines > 0);
    assert!(!build.from_cache, "损坏缓存不得命中 cache");

    // 重扫后 ActivationTree 完整可用（不是 IndexNotReady）
    let tree = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("rescan must produce ActivationTree");
    assert_eq!(tree.total_activations, total);
    engine.close_session(&sid2).unwrap();
}

/// V6 缓存位损坏（ActivationTree bincode 损坏）必须整体 miss 重扫
///——不能带着 None 进入 CacheHit 让查询永远 IndexNotReady。
#[test]
fn test_bit_corrupted_v6_activation_section_triggers_rescan() {
    let (engine, sid, _guard) = setup_session_locked(&get_trace_path());
    let total = engine
        .get_activation_tree(&sid, 0, 100)
        .unwrap()
        .total_activations;
    engine.close_session(&sid).unwrap();
    let path = get_trace_path();
    let dir = current_cache_dir();

    // 损坏构造：只改 section 表里 ActivationTree 的 length 为 1（数据字节
    // 保留）。布局预检（range/对齐/整除）全部通过、magic/hash 头部完好
    //——真正到达 bincode 反序列化分支并失败。（翻转尾部字节会被更早的
    // 防御层拦下，覆盖不到本分支。）
    let cache_file = dir.join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(&path),
        ".p2.cache"
    ));
    let mut bytes = std::fs::read(&cache_file).expect("cache written by first build");
    let num = u32::from_le_bytes(bytes[64..68].try_into().unwrap()) as usize;
    assert_eq!(num, 8, "V6 p2 cache must have exactly 8 sections");
    let base = 64 + 4 + 7 * 16; // section 7 表项（offset + length）
    bytes[base + 8..base + 16].copy_from_slice(&1u64.to_le_bytes());
    std::fs::write(&cache_file, &bytes).unwrap();

    let info = engine
        .create_session(&path)
        .expect("reopen corrupted cache");
    let sid2 = info.session_id.clone();
    let build = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("bincode 损坏必须回退重扫，不得返回 Internal");
    assert!(!build.from_cache, "损坏缓存不得命中");

    let tree = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("rescan must produce ActivationTree");
    assert_eq!(tree.total_activations, total);
    engine.close_session(&sid2).unwrap();
}

/// V5→V6 升版回归：旧 V5 布局（ActivationTree 无 all_by_call/resolved_by_resume
/// 字段）的缓存不得被当作命中——magic 不匹配必须触发重扫，而不是误命中后
/// bincode 反序列化失败进入永久 IndexNotReady。
#[test]
fn test_v5_layout_cache_rejected_by_magic_bump() {
    let (engine, sid, _guard) = setup_session_locked(&get_trace_path());
    let total = engine
        .get_activation_tree(&sid, 0, 100)
        .unwrap()
        .total_activations;
    engine.close_session(&sid).unwrap();
    let path = get_trace_path();
    let dir = current_cache_dir();

    // 构造：合法 V6 文件但 magic 改回 TCACHE05。
    // 注意：这不是精确复现旧 V5 布局（V5 的 bincode 字段数与 V6 不同），
    // 只验证 magic 拒绝路径——旧 magic 必须 miss 重扫而不是误命中。
    let cache_file = dir.join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(&path),
        ".p2.cache"
    ));
    let mut bytes = std::fs::read(&cache_file).expect("cache written by first build");
    assert_eq!(&bytes[0..8], b"TCACHE06", "current cache must be V6");
    bytes[0..8].copy_from_slice(b"TCACHE05");
    std::fs::write(&cache_file, &bytes).unwrap();

    let info = engine.create_session(&path).expect("reopen with old magic");
    let sid2 = info.session_id.clone();
    let build = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("old-magic cache must miss and rescan");
    assert!(!build.from_cache, "旧 V5 magic 不得命中");

    let tree = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("rescan must produce ActivationTree");
    assert_eq!(tree.total_activations, total);
    engine.close_session(&sid2).unwrap();
}

/// 合法空数组 section（无 patch/依赖数据的极简 trace）二次加载必须命中
///——typed 预检不得把空数组误判为损坏（旧实现 length>0 强制导致
/// 部分合法缓存每次重扫甚至 view getter panic）。
#[test]
fn test_empty_array_sections_cache_reload_hits() {
    // 极简 trace：无内存访问、无 def-use，依赖/patch 数组为空
    let dir = std::env::temp_dir().join(format!("trace-ui-itest-emptyarr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let trace_path = dir.join("trace.log");
    std::fs::write(
        &trace_path,
        "[lib.so] 0x1000!0x100 nop\n[lib.so] 0x1004!0x104 nop\n[lib.so] 0x1008!0x108 nop\n",
    )
    .unwrap();

    let guard = trace_core::cache::cache_dir_override_test_lock();
    trace_core::cache::set_cache_dir_override(Some(dir.join("cache")));
    std::fs::create_dir_all(dir.join("cache")).unwrap();

    let engine = std::sync::Arc::new(trace_core::TraceEngine::new());
    let info = engine.create_session(trace_path.to_str().unwrap()).unwrap();
    let sid = info.session_id.clone();
    let b1 = engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    assert!(!b1.from_cache);
    engine.close_session(&sid).unwrap();

    let info2 = engine.create_session(trace_path.to_str().unwrap()).unwrap();
    let sid2 = info2.session_id.clone();
    let b2 = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    // 空数组 section 合法：必须命中缓存（不得误判损坏/panic）
    assert!(b2.from_cache, "合法空数组缓存必须命中");
    engine.close_session(&sid2).unwrap();
    drop(guard);
    let _ = std::fs::remove_dir_all(&dir);
}

fn corrupt_section_count(cache_file: &std::path::Path, expected: u32, reported: u32) {
    let bytes = std::fs::read(cache_file).expect("cache written by first build");
    assert!(bytes.len() > 64);
    let num = u32::from_le_bytes(bytes[64..68].try_into().unwrap());
    assert_eq!(num, expected);
    let mut corrupted = bytes.clone();
    corrupted[64..68].copy_from_slice(&reported.to_le_bytes());
    let table_end = 64 + 4 + (expected as usize) * 16;
    let new_table_end = 64 + 4 + (reported as usize) * 16;
    corrupted.drain(new_table_end..table_end);
    std::fs::write(cache_file, &corrupted).unwrap();
}

/// scan/lidx 损坏必须在加载预检 miss，不得进入 view getter unwrap panic。
#[test]
fn test_corrupted_scan_cache_triggers_rescan_not_panic() {
    let (engine, sid, _guard) = setup_session_locked(&get_trace_path());
    let total = engine
        .get_activation_tree(&sid, 0, 100)
        .unwrap()
        .total_activations;
    engine.close_session(&sid).unwrap();
    let path = get_trace_path();
    let dir = current_cache_dir();
    let cache_file = dir.join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(&path),
        ".scan.cache"
    ));
    corrupt_section_count(&cache_file, 20, 19);

    let info = engine.create_session(&path).expect("reopen scan cache");
    let sid2 = info.session_id.clone();
    let build = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("scan 损坏必须回退重扫，不得 panic");
    assert!(!build.from_cache, "损坏 scan 缓存不得命中");
    let tree = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("rescan must produce ActivationTree");
    assert_eq!(tree.total_activations, total);
    engine.close_session(&sid2).unwrap();
}

#[test]
fn test_corrupted_lidx_cache_triggers_rescan_not_panic() {
    let (engine, sid, _guard) = setup_session_locked(&get_trace_path());
    let total = engine
        .get_activation_tree(&sid, 0, 100)
        .unwrap()
        .total_activations;
    engine.close_session(&sid).unwrap();
    let path = get_trace_path();
    let dir = current_cache_dir();
    let cache_file = dir.join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(&path),
        ".lidx.cache"
    ));
    corrupt_section_count(&cache_file, 2, 1);

    let info = engine.create_session(&path).expect("reopen lidx cache");
    let sid2 = info.session_id.clone();
    let build = engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("lidx 损坏必须回退重扫，不得 panic");
    assert!(!build.from_cache, "损坏 lidx 缓存不得命中");
    let tree = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("rescan must produce ActivationTree");
    assert_eq!(tree.total_activations, total);
    engine.close_session(&sid2).unwrap();
}
