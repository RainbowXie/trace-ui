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
