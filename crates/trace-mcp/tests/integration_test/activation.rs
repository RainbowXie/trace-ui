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

    // 稳定身份：module+offset（不是 ASLR 运行时地址）
    for a in &tree.activations {
        if a.unresolved_reason.is_none() && a.id != 0 {
            assert!(
                a.func_addr.starts_with("libmetasec_ov.so+0x"),
                "func identity must be module+offset, got {}",
                a.func_addr
            );
            assert_eq!(a.func_addr, a.entry_pc, "identity = entry site");
        }
    }

    // 第一个调用：seq 1 BL → seq 2 entry
    let first = tree
        .activations
        .iter()
        .find(|a| a.call_seq == 1)
        .expect("BL at seq 1 must produce an activation");
    assert_eq!(first.entry_seq, 2);
    assert_eq!(first.entry_pc, "libmetasec_ov.so+0x143438");
    assert_eq!(first.call_pc, "libmetasec_ov.so+0x82ce4");
    assert_eq!(first.expected_resume, "libmetasec_ov.so+0x82ce8");
    assert_eq!(first.activation, format!("{}:call@1", sid));

    // bypassed：JNI 拦截调用只保存调用事实
    assert_eq!(tree.bypassed_calls[0].call_seq, 54);
    assert_eq!(tree.bypassed_calls[0].call_pc, "libmetasec_ov.so+0x12f8a4");
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
    assert_eq!(act.exit_pc, "libmetasec_ov.so+0x2ea9c");
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
        owner.activation.as_ref().map(|a| a.entry_pc.clone()),
        Some("libmetasec_ov.so+0x143438".to_string())
    );

    // body
    let owner = engine.get_instruction_owner(&sid, 4).unwrap();
    assert_eq!(owner.position, "body");

    // call（BL 行归属 caller 侧；callee_id 指向 child）
    let owner = engine.get_instruction_owner(&sid, 10).unwrap();
    assert_eq!(owner.position, "call");
    assert_eq!(owner.callee_id, Some(2));
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(1),
        "BL row belongs to the caller-side activation"
    );

    // root 指令（seq 0）
    let owner = engine.get_instruction_owner(&sid, 0).unwrap();
    assert_eq!(owner.position, "root");
    assert!(owner.activation.is_none());

    // bypassed 调用行：position = call，指向调用事实
    let owner = engine.get_instruction_owner(&sid, 54).unwrap();
    assert_eq!(owner.position, "call");
    assert!(
        owner.callee_id.is_none(),
        "bypassed 调用没有 child activation"
    );
    assert!(owner.detail.contains("bypassed"));

    engine.close_session(&sid).unwrap();
}

/// resume 指令：归属 caller 上下文，position = resume，callee_id 指向被闭合 child。
#[test]
fn test_resume_position_and_ownership() {
    let (engine, sid) = setup_session(&get_trace_path());

    // seq 18 = activation 2（call_seq 10）的 resume
    let owner = engine.get_instruction_owner(&sid, 18).unwrap();
    assert_eq!(owner.position, "resume");
    assert_eq!(owner.callee_id, Some(2));
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(1),
        "resume 指令在 caller（activation 1）上下文执行"
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
    engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("rebuild (cache hit)");
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
fn test_old_phase2_cache_without_activation_section() {
    // 多阶段（build→改缓存→reopen）全程持锁自控目录
    let (engine, sid, _guard) = setup_session_locked(&get_trace_path());
    engine.close_session(&sid).unwrap();
    let path = get_trace_path();
    let dir = current_cache_dir();

    // 构造旧格式：写一个只有 7 sections 的 p2 cache（手工截掉 section 7）
    let cache_file = dir.join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(&path),
        ".p2.cache"
    ));
    if let Ok(bytes) = std::fs::read(&cache_file) {
        if bytes.len() > 64 {
            let section_area = &bytes[64..];
            let num = u32::from_le_bytes(section_area[0..4].try_into().unwrap()) as usize;
            if num == 8 {
                // 重写为 7 sections：改 num 字段并截掉最后一个 section 表项。
                // SectionReader 只信任表；activation_tree_bytes 走 None 分支。
                let mut old = bytes.clone();
                old[64..68].copy_from_slice(&7u32.to_le_bytes());
                // 截断表尾：去掉最后一个 entry（16 字节），数据区保留
                let table_end = 64 + 4 + 8 * 16;
                let new_table_end = 64 + 4 + 7 * 16;
                old.drain(new_table_end..table_end);
                std::fs::write(&cache_file, &old).unwrap();
            }
        }
    }

    let info = engine.create_session(&path).expect("reopen old cache");
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
        .expect("old cache must still load (CallTree etc.)");
    assert!(build.total_lines > 0);

    // ActivationTree 不在旧缓存：明确报 IndexNotReady 而非 panic / 伪数据
    let result = engine.get_activation_tree(&sid2, 0, 10);
    assert!(
        result.is_err(),
        "old cache without activation section must report IndexNotReady"
    );

    // force rebuild 恢复
    engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: true,
                skip_strings: false,
            },
            None,
        )
        .expect("force rebuild");
    let tree = engine
        .get_activation_tree(&sid2, 0, 100)
        .expect("after rebuild");
    assert_eq!(tree.total_activations, 5);
    engine.close_session(&sid2).unwrap();
}
