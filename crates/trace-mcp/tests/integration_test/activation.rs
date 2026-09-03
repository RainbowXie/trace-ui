//! Confirmed Activation 端到端测试：engine build → 查询 → instruction ownership。
//!
//! 样本 example-trace-gumtrace.txt 的关键事实（seq 从 0 计，special line 占 seq）：
//! - seq 1: BL 0x7522f46438（callsite 0x7522e85ce4）→ entry seq 2
//! - seq 10: BL 0x7522e31a90（callsite 0x7522f46458）→ PLT thunk
//! - seq 11..=14: thunk 指令（最后一条 seq 14 = br x17）
//! - seq 15..=17: call func:/args0:/ret: special lines（占 seq，不是指令）
//! - seq 18: resume 0x7522f4645c == callsite + 4
//! - seq 54: BLR x8（callsite 0x7522f328a4）→ JNI 拦截，无函数体 → bypassed
//! - seq 62: BLR x8（callsite 0x7522f32fe8）→ NewStringUTF JNI 拦截 → bypassed

use super::*;

/// 当前隔离缓存目录（setup_session 已为每次调用分配独立目录；
/// 旧格式测试用它直接操作缓存文件）。
fn current_cache_dir() -> std::path::PathBuf {
    trace_core::cache::cache_dir().expect("setup_session 已设置隔离目录")
}

#[test]
fn test_activation_tree_on_example_trace() {
    let (engine, sid) = setup_session(&get_trace_path());
    let tree = engine
        .get_activation_tree(&sid, 0, 100)
        .expect("get_activation_tree");

    // root + 4 个确认 activation + 2 个 bypassed；计数排除 root
    assert_eq!(tree.total_activations, 5);
    assert_eq!(tree.confirmed_count, 4, "confirmed 排除 root");
    assert_eq!(tree.unresolved_count, 0);
    assert_eq!(tree.total_bypassed, 2);

    // 稳定身份：module+offset（不是 ASLR 运行时地址），且符合 common-types.md
    // 语法（无法规范化的模块名 → None，不输出非法值）
    for a in &tree.activations {
        if a.unresolved_reason.is_none() && a.id != 0 {
            let ident = a
                .func_addr
                .as_deref()
                .expect("sample module is normalizable");
            assert!(
                ident.starts_with("libmetasec_ov.so+0x"),
                "func identity must be module+offset, got {}",
                ident
            );
            assert_eq!(a.func_addr, a.entry_pc, "identity = entry site");
        }
        // root 展示身份 = trace_root（不是 call@哨兵）；root 是 trace 上下文
        // 不是调用：call/entry/exit/resume 身份全 None，不读第 0 行伪造
        if a.id == 0 {
            assert_eq!(a.activation, "trace_root");
            assert_eq!(a.func_addr, None, "root 无函数身份");
            assert_eq!(a.entry_pc, None, "root 无入口身份");
            assert_eq!(a.exit_pc, None, "root 无出口身份");
            assert_eq!(a.expected_resume, None, "root 无 resume");
            assert_eq!(a.call_pc, None, "root 无调用点");
            assert_eq!(a.call_seq, 0, "root 无 call_seq");
        }
    }

    // 第一个调用：seq 1 BL → seq 2 entry
    let first = tree
        .activations
        .iter()
        .find(|a| a.call_seq == 1)
        .expect("BL at seq 1 must produce an activation");
    assert_eq!(first.entry_seq, 2);
    assert_eq!(first.entry_pc.as_deref(), Some("libmetasec_ov.so+0x143438"));
    assert_eq!(first.call_pc.as_deref(), Some("libmetasec_ov.so+0x82ce4"));
    assert_eq!(
        first.expected_resume.as_deref(),
        Some("libmetasec_ov.so+0x82ce8")
    );
    assert_eq!(first.activation, format!("{}:call@1", sid));

    // bypassed：JNI 拦截调用只保存调用事实；expected_resume = resume 行的
    // 稳定身份（不再是 ASLR 运行时地址）。无法规范化时 None（fail-closed）。
    assert_eq!(tree.bypassed_calls[0].call_seq, 54);
    assert_eq!(
        tree.bypassed_calls[0].call_pc,
        Some("libmetasec_ov.so+0x12f8a4".to_string())
    );
    assert_eq!(
        tree.bypassed_calls[0].expected_resume,
        Some("libmetasec_ov.so+0x12f8a8".to_string())
    );
    assert_eq!(tree.bypassed_calls[1].call_seq, 62);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_activation_tree_pagination() {
    let (engine, sid) = setup_session(&get_trace_path());

    // 第一页只取 2 条（root + 第一个 activation）
    let page1 = engine.get_activation_tree(&sid, 0, 2).unwrap();
    assert_eq!(page1.activations.len(), 2);
    assert_eq!(page1.total_activations, 5);
    assert!(page1.offset == 0);

    // 第二页
    let page2 = engine.get_activation_tree(&sid, 2, 2).unwrap();
    assert_eq!(page2.activations.len(), 2);
    assert_eq!(page2.activations[0].id, 2);

    // 超范围 offset 返回空页
    let page3 = engine.get_activation_tree(&sid, 100, 2).unwrap();
    assert!(page3.activations.is_empty());

    // 全量计数在每一页都一致
    assert_eq!(page1.confirmed_count, page2.confirmed_count);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_exit_is_last_real_insn_not_special_line() {
    let (engine, sid) = setup_session(&get_trace_path());

    let tree = engine.get_activation_tree(&sid, 0, 100).unwrap();
    let act = tree
        .activations
        .iter()
        .find(|a| a.call_seq == 10)
        .expect("BL at seq 10");
    assert!(act.unresolved_reason.is_none());
    assert_eq!(
        act.exit_seq, 14,
        "exit must be the last real instruction (br x17 at seq 14), \
         not a special line at seq 15..=17"
    );
    assert_eq!(act.exit_pc.as_deref(), Some("libmetasec_ov.so+0x2ea9c"));
    assert_eq!(act.resume_seq, 18);

    // seq 14（br x17）属于该 activation，位置是 exit
    let owner = engine.get_instruction_owner(&sid, 14).unwrap();
    assert_eq!(owner.position, "exit");
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(act.id),
        "seq 14 must belong to the seq-10 activation"
    );

    engine.close_session(&sid).unwrap();
}

/// special line 不参与指令归属（协议只定义"实际执行的指令"的归属）。
#[test]
fn test_special_lines_are_not_instructions() {
    let (engine, sid) = setup_session(&get_trace_path());

    // seq 16 = args0: special line
    let owner = engine.get_instruction_owner(&sid, 16).unwrap();
    assert_eq!(owner.position, "not_an_instruction");
    assert!(owner.activation.is_none());
    assert!(!owner.detail.is_empty());

    // seq 15 = call func: special line
    let owner = engine.get_instruction_owner(&sid, 15).unwrap();
    assert_eq!(owner.position, "not_an_instruction");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_instruction_owner_positions() {
    let (engine, sid) = setup_session(&get_trace_path());

    // entry
    let owner = engine.get_instruction_owner(&sid, 2).unwrap();
    assert_eq!(owner.position, "entry");
    assert_eq!(
        owner.activation.as_ref().and_then(|a| a.entry_pc.clone()),
        Some("libmetasec_ov.so+0x143438".to_string())
    );

    // body
    let owner = engine.get_instruction_owner(&sid, 4).unwrap();
    assert_eq!(owner.position, "body");

    // call（BL 行归属 caller 侧；opens 指向 child）
    let owner = engine.get_instruction_owner(&sid, 10).unwrap();
    assert_eq!(owner.position, "call");
    assert_eq!(owner.opens.as_deref(), Some("activation:2"));
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(1),
        "BL row belongs to the caller-side activation"
    );

    // root 指令（seq 0）
    let owner = engine.get_instruction_owner(&sid, 0).unwrap();
    assert_eq!(owner.position, "root");
    assert!(owner.activation.is_none());

    // bypassed 调用行：position = call，opens 指向调用事实（无 activation）
    let owner = engine.get_instruction_owner(&sid, 54).unwrap();
    assert_eq!(owner.position, "call");
    assert!(owner
        .opens
        .as_deref()
        .is_some_and(|o| o.starts_with("bypassed:")));
    assert!(owner.detail.contains("bypassed"));

    engine.close_session(&sid).unwrap();
}

/// resume 指令：归属 caller 上下文，position = resume，closes 指向被闭合 child。
#[test]
fn test_resume_position_and_ownership() {
    let (engine, sid) = setup_session(&get_trace_path());

    // seq 18 = activation 2（call_seq 10）的 resume
    let owner = engine.get_instruction_owner(&sid, 18).unwrap();
    assert_eq!(owner.position, "resume");
    assert_eq!(owner.closes.as_deref(), Some("activation:2"));
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(1),
        "resume 指令在 caller（activation 1）上下文执行"
    );

    // seq 59 = bypassed 调用（call_seq 54）的直接 resume：closes 指向 bypassed
    let owner = engine.get_instruction_owner(&sid, 59).unwrap();
    assert_eq!(owner.position, "resume");
    assert!(
        owner
            .closes
            .as_deref()
            .is_some_and(|c| c.starts_with("bypassed:")),
        "bypassed 调用的 resume 也必须报告 resume（不是 body）"
    );
    assert!(
        owner.activation.is_none(),
        "bypassed resume（call_seq 54 在 root 上下文）归属 root"
    );

    engine.close_session(&sid).unwrap();
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
