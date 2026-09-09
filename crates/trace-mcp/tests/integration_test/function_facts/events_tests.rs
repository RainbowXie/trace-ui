use super::*;

#[test]
fn bypassed_calls_become_external_call_events() {
    // 未记录函数体的调用成为 caller 的 External Call Event：callsite/resume
    // 锚点、注解符号 target、call 前 ABI 参数与 SP、调用方准备的栈参数
    // （evidence_seqs 是写入序号）、resume 前返回值；无明确捕获证据的
    // Event 访存数组为空。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x5004!0x5004 bl #0x1000; sp=0x3030",
        "[App] 0x1000!0x1000 sub sp, sp, #0x10; sp=0x3030 -> sp=0x3020",
        "[App] 0x1004!0x1004 str x1, [sp]; sp=0x3020 x1=0x1234 mem_w=0x3020",
        "[App] 0x1008!0x1008 mov x0, #0x11; x0=0x0 -> x0=0x11",
        "[App] 0x100c!0x100c bl #0x3000; x0=0x11 sp=0x3020",
        "call func: extfoo(0x11)",
        "args0: 0x11",
        "ret: 0x99",
        "[App] 0x1010!0x1010 mov x2, #0x1; x0=0x99 -> x2=0x1",
        "[App] 0x1014!0x1014 ret; sp=0x3020",
        "[App] 0x5008!0x5008 mov x0, #0x99; x0=0x99 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");

    assert_eq!(bundle.external_call_events.len(), 1);
    let event = &bundle.external_call_events[0];
    assert_eq!(event.callsite.seq, 4);
    assert_eq!(event.callsite.offset, "App+0x100c");
    assert_eq!(
        event
            .resume
            .as_ref()
            .map(|anchor| (anchor.seq, anchor.offset.clone())),
        Some((8, "App+0x1010".to_string()))
    );
    assert_eq!(event.target.symbol, Some("extfoo".to_string()));
    assert!(event.target.module.is_none() && event.target.entry.is_none());
    assert_eq!(event.call_sp, Some("0x0000000000003020".to_string()));
    assert_eq!(
        event.arguments.get("X0"),
        Some(&Some("0x0000000000000011".to_string()))
    );
    assert_eq!(event.arguments.get("X7"), Some(&None));
    // Event 栈参数恒空：机械上无法区分出参准备与 spill（编译器复用同一
    // 栈帧区），按地址收集会伪造；需要 args 注解/capture 证据后才能恢复。
    assert!(event.stack_arguments.is_empty());
    assert_eq!(
        event.returns.get("X0"),
        Some(&Some("0x0000000000000099".to_string()))
    );
    assert!(event.memory_reads.is_empty());
    assert!(event.global_reads.is_empty());
    assert!(event.memory_writes.is_empty());
    assert!(event.global_writes.is_empty());
    assert!(event.unresolved.is_empty());

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn a_bypassed_call_without_annotation_marks_the_missing_target() {
    // 无注解的未记录调用：target 三个身份字段都为 null 时，Event 必须带
    // indirect_target_unresolved 缺口，不得伪造身份。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x5004!0x5004 bl #0x1000; sp=0x3030",
        "[App] 0x1000!0x1000 mov x0, #0x11; x0=0x0 -> x0=0x11",
        "[App] 0x1004!0x1004 bl #0x3000; x0=0x11 sp=0x3030",
        "[App] 0x1008!0x1008 mov x2, #0x1; sp=0x3030 -> x2=0x1",
        "[App] 0x100c!0x100c ret; sp=0x3030",
        "[App] 0x5008!0x5008 mov x0, #0x99; x0=0x99 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");

    assert_eq!(bundle.external_call_events.len(), 1);
    let event = &bundle.external_call_events[0];
    assert!(
        event.target.module.is_none()
            && event.target.entry.is_none()
            && event.target.symbol.is_none()
    );
    assert!(event
        .unresolved
        .iter()
        .any(|gap| gap.kind == "indirect_target_unresolved"));

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn ret_annotation_effects_survive_checkpoint_boundaries() {
    // ret: 特殊行的 X0 效应必须进入检查点快照：检查点落在 ret: 与 resume
    // 之间时，重放区间永远错过该行——修复前会把调用前值冒充为返回值。
    // 简化版：把外层函数放前面，外部调用跨越第 1000 行检查点。
    let mut lines: Vec<String> = vec![
        "[App] 0x5004!0x5004 bl #0x1000; sp=0x3030".to_string(),
        "[App] 0x1000!0x1000 mov x0, #0x11".to_string(),
    ];
    for _ in 2..997u32 {
        lines.push("[App] 0x1000!0x1000 orr x9, x9, x9".to_string());
    }
    // index 997：bl；998：call func；999：ret:；1000：resume（检查点边界）。
    lines.push("[App] 0x1004!0x1004 bl #0x3000; x0=0x11 sp=0x3020".to_string());
    lines.push("call func: extfoo(0x11)".to_string());
    lines.push("ret: 0x99".to_string());
    lines.push("[App] 0x1008!0x1008 mov x2, #0x1".to_string());
    lines.push("[App] 0x100c!0x100c ret".to_string());
    lines.push("[App] 0x5008!0x5008 mov x0, #0x1".to_string());
    let (engine, sid, path) =
        setup_inline_trace(&lines.iter().map(String::as_str).collect::<Vec<_>>());

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    let event = bundle
        .external_call_events
        .iter()
        .find(|event| event.callsite.offset == "App+0x1004")
        .expect("bypassed event across the checkpoint boundary");
    assert_eq!(
        event.returns.get("X0"),
        Some(&Some("0x0000000000000099".to_string())),
        "ret: 效应必须跨检查点存活，不得回退为调用前值"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn an_annotated_confirmed_child_is_not_an_external_call_event() {
    // 带注解的普通 BL：callee 真正执行并有 ConfirmedActivation——不能
    // 伪造成 Event（resume 也不能错设为外层终点）。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x5004!0x5004 bl #0x1000; sp=0x3030",
        "[App] 0x1000!0x1000 orr x1, x1, x1; x0=0x11",
        "[App] 0x1004!0x1004 bl #0x3000; x0=0x11 sp=0x3020",
        "call func: recorded_inner(0x11)",
        "[App] 0x3000!0x3000 orr x4, x4, x4; x0=0x11",
        "[App] 0x3004!0x3004 ret",
        "[App] 0x1008!0x1008 orr x5, x5, x5",
        "[App] 0x100c!0x100c ret",
        "[App] 0x5008!0x5008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert!(
        bundle
            .external_call_events
            .iter()
            .all(|event| event.callsite.offset != "App+0x1004"),
        "有 ConfirmedActivation 的 callee 即使带注解也不是 Event：{:?}",
        bundle.external_call_events
    );
    // 内层有自己的 Activation 事实。
    let inner = engine.get_function_facts(&sid, 2, 4).expect("inner facts");
    assert_eq!(inner.function, "App+0x3000");

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn fail_closed_rejects_unresolved_activation_and_missing_stable_sites() {
    // 任务 2.9 RED 测试：
    // 1. 未闭合（unresolved_reason != None）的 Activation 必须拒绝并 fail-closed，不产出事实；
    // 2. 存在畸形指令地址/无稳定 module+offset 的行，必须拒绝或返回错误，严禁输出运行时裸地址充当稳定身份。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 mov x0, #0x1; sp=0x3000",
        // 注意：没有 ret / resume，trace 直接结束，导致 activation 处于未闭合状态 (TraceEndStillActive)
    ]);

    let res = engine.get_function_facts(&sid, 0, 1);
    assert!(
        res.is_err(),
        "未闭合（截断/未正常返回）的 activation 必须 fail-closed 拒绝"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn fail_closed_rejects_lines_without_stable_module_offset() {
    // 任务 2.9 RED 测试：
    // 指令行缺少稳定 module+offset（如没有 [module] 前缀或缺少 !0x offset）
    // 必须 fail-closed 报错，不能把运行时虚拟地址当作稳定身份伪造。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "0x2000 mov x0, #0x1; sp=0x3000", // 缺少 [module] 和 !0x
        "[App] 0x2004!0x2004 ret; sp=0x3000",
        "[App] 0x1008!0x1008 mov x0, #0x2",
    ]);

    let res = engine.get_function_facts(&sid, 0, 1);
    assert!(
        res.is_err(),
        "缺少稳定 module+offset 的指令行必须 fail-closed 拒绝"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
