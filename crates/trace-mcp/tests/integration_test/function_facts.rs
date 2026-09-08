//! FunctionCallRecord 的 trace-ui 事实查询公共行为。
//!
//! 这组测试先固定调用方真正需要的边界：请求一份已确认 Activation 时，
//! provider 必须一次返回同一 Activation 的 anchors、ABI、完整执行块序列、
//! direct 读写、External Call Event 与 unresolved，避免状态机跨多个分页查询
//! 拼出不一致快照。

use super::*;

fn setup_inline_trace(lines: &[&str]) -> (Arc<TraceEngine>, String, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let suffix = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "trace-ui-function-facts-{}-{}.log",
        std::process::id(),
        suffix
    ));
    std::fs::write(&path, lines.join("\n") + "\n").expect("write inline trace");
    let (engine, sid) = setup_session(path.to_str().expect("utf8 path"));
    (engine, sid, path)
}

#[test]
fn confirmed_activation_returns_a_complete_function_fact_bundle() {
    let (engine, sid) = setup_session(&get_trace_path());
    let activation = engine
        .get_activation_tree(&sid, 0, 100)
        .expect("activation tree")
        .activations
        .into_iter()
        .find(|item| item.call_seq == 10)
        .expect("sample has the nested call activation");

    let bundle = engine
        .get_function_facts(&sid, activation.call_seq, activation.entry_seq)
        .expect("function facts");

    assert_eq!(bundle.function, "libmetasec_ov.so+0x2ea90");
    assert_eq!(bundle.trace_anchors.call.seq, 10);
    assert_eq!(bundle.trace_anchors.entry.seq, 11);
    assert_eq!(bundle.trace_anchors.exit.seq, 14);
    assert_eq!(bundle.trace_anchors.resume.seq, 18);
    assert!(!bundle.abi.arguments.is_empty());
    assert!(!bundle.abi.returns.is_empty());
    assert_eq!(
        bundle
            .executed_block_sequence
            .iter()
            .map(|block| block.entry_seq)
            .collect::<Vec<_>>(),
        vec![11]
    );
    // 样本 activation 内唯一访存：GOT 风格外部读取（x16 相对寻址，非栈
    // 参数），最终值为 0x79b745a4c0 的小端字节。
    assert_eq!(
        bundle
            .memory_reads
            .iter()
            .map(|read| (
                read.address.as_str(),
                read.size,
                read.bytes.clone(),
                read.seqs.clone()
            ))
            .collect::<Vec<_>>(),
        vec![(
            "0x7522fe1f80",
            8,
            Some("c0a445b779000000".to_string()),
            vec![12]
        )]
    );
    assert!(bundle.global_reads.is_empty());
    assert!(bundle.memory_writes.is_empty());
    assert!(bundle.global_writes.is_empty());
    // br/PLT-stub 形态的外部调用：注解 __strlen_aarch64 键在 br seq 14，
    // resume 即本 Activation 的 resume 18，返回值 0x13（ret: 注解）。
    assert_eq!(bundle.external_call_events.len(), 1);
    let event = &bundle.external_call_events[0];
    assert_eq!(event.callsite.seq, 14);
    assert_eq!(event.callsite.offset, "libmetasec_ov.so+0x2ea9c");
    assert_eq!(event.resume.as_ref().map(|anchor| anchor.seq), Some(18));
    assert_eq!(event.target.symbol, Some("__strlen_aarch64".to_string()));
    assert_eq!(
        event.returns.get("X0"),
        Some(&Some("0x0000000000000013".to_string()))
    );
    assert!(bundle.unresolved.is_empty());

    engine.close_session(&sid).unwrap();
}

#[test]
fn abi_values_come_from_before_the_entry_and_resume_instructions() {
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1000!0x1000 mov x0, #0x11; x0=0x0 -> x0=0x11",
        "[App] 0x1004!0x1004 bl #0x2000; x0=0x11 sp=0x3000",
        "[App] 0x2000!0x2000 add x0, x0, #1; x0=0x11 sp=0x3000 -> x0=0x12",
        "[App] 0x2004!0x2004 mov x0, #0x44; x0=0x12 sp=0x3000 -> x0=0x44",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x44 sp=0x3000 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 1, 2)
        .expect("function facts");

    assert_eq!(
        bundle.abi.arguments.get("X0"),
        Some(&Some("0x0000000000000011".to_string())),
        "entry 参数必须是入口指令执行前的 X0"
    );
    assert_eq!(
        bundle.abi.returns.get("X0"),
        Some(&Some("0x0000000000000044".to_string())),
        "返回值必须是 resume 指令执行前的 X0"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn executed_blocks_follow_execution_order_and_keep_loop_repeats() {
    // 循环体执行两轮：块序列必须按执行顺序保留 0x2000 的重复出现，
    // 条件分支/无条件分支的落点各自开始新块。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; x0=0x11 sp=0x3000",
        "[App] 0x2000!0x2000 orr x9, x9, x9; x0=0x11 sp=0x3000",
        "[App] 0x2004!0x2004 cbz x2, #0x2014; x0=0x11 sp=0x3000",
        "[App] 0x2008!0x2008 sub x2, x2, #1; x2=0x2 sp=0x3000 -> x2=0x1",
        "[App] 0x200c!0x200c b #0x2000; x0=0x11 sp=0x3000",
        "[App] 0x2000!0x2000 orr x9, x9, x9; x0=0x11 sp=0x3000",
        "[App] 0x2004!0x2004 cbz x2, #0x2014; x0=0x11 sp=0x3000 -> x2=0x0",
        "[App] 0x2014!0x2014 ret; x0=0x11 sp=0x3000",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x11 sp=0x3000 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");

    let blocks = bundle
        .executed_block_sequence
        .iter()
        .map(|block| (block.block.as_str(), block.entry_seq))
        .collect::<Vec<_>>();
    assert_eq!(
        blocks,
        vec![
            ("App+0x2000", 1),
            ("App+0x2008", 3),
            ("App+0x2000", 5),
            ("App+0x2014", 7),
        ],
        "块序列必须按执行顺序保留循环重复，分支落点各自成块"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn nested_callee_instructions_never_enter_the_caller_block_sequence() {
    // 外层函数中嵌套一次 BL：callee 的指令（0x3000/0x3004）不得出现在
    // 外层块序列里；resume 之后的 caller 指令开始新块。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; x0=0x11 sp=0x3000",
        "[App] 0x2000!0x2000 orr x1, x1, x1; x0=0x11 sp=0x3000",
        "[App] 0x2004!0x2004 bl #0x3000; x0=0x11 sp=0x3000",
        "[App] 0x3000!0x3000 orr x4, x4, x4; x0=0x11 sp=0x3000",
        "[App] 0x3004!0x3004 ret; x0=0x11 sp=0x3000",
        "[App] 0x2008!0x2008 orr x5, x5, x5; x0=0x11 sp=0x3000",
        "[App] 0x200c!0x200c ret; x0=0x11 sp=0x3000",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x11 sp=0x3000 -> x0=0x99",
    ]);

    let outer = engine
        .get_function_facts(&sid, 0, 1)
        .expect("outer function facts");
    let blocks = outer
        .executed_block_sequence
        .iter()
        .map(|block| (block.block.as_str(), block.entry_seq))
        .collect::<Vec<_>>();
    assert_eq!(
        blocks,
        vec![("App+0x2000", 1), ("App+0x2008", 5),],
        "nested callee 的指令不进入 caller；resume 开始新块"
    );

    // 内层 Activation 自己的块序列独立可查。
    let inner = engine
        .get_function_facts(&sid, 2, 3)
        .expect("inner function facts");
    assert_eq!(
        inner
            .executed_block_sequence
            .iter()
            .map(|block| (block.block.as_str(), block.entry_seq))
            .collect::<Vec<_>>(),
        vec![("App+0x3000", 3)],
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn a_later_observed_target_splits_the_earlier_linear_execution() {
    // 第一次顺序执行 0x2000→0x2004→0x2008 时没有观察到任何跳转目标；
    // 随后 b #0x2004 把 0x2004 确认为块起点，第一次执行也必须回溯切分。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; x0=0x11 sp=0x3000",
        "[App] 0x2000!0x2000 orr x1, x1, x1; x0=0x11 sp=0x3000",
        "[App] 0x2004!0x2004 add x1, x1, #1; x1=0x1 sp=0x3000 -> x1=0x2",
        "[App] 0x2008!0x2008 b #0x2004; x0=0x11 sp=0x3000",
        "[App] 0x2004!0x2004 add x1, x1, #1; x1=0x2 sp=0x3000 -> x1=0x3",
        "[App] 0x2008!0x2008 b #0x2010; x0=0x11 sp=0x3000",
        "[App] 0x2010!0x2010 ret; x0=0x11 sp=0x3000",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x11 sp=0x3000 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");

    let blocks = bundle
        .executed_block_sequence
        .iter()
        .map(|block| (block.block.as_str(), block.entry_seq))
        .collect::<Vec<_>>();
    assert_eq!(
        blocks,
        vec![
            ("App+0x2000", 1),
            ("App+0x2004", 2),
            ("App+0x2004", 4),
            ("App+0x2010", 6),
        ],
        "后期观察到的跳转目标必须回溯切分第一次线性执行"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn stack_arguments_come_from_real_reads_of_the_caller_area() {
    // 栈参数三门合同：只有本次 Activation 实际读取、且地址在 entry SP 及
    // 之上的栈槽进入 stack_arguments；未读取的槽与 callee 自己的局部读取
    // 都不进入。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1000!0x1000 sub sp, sp, #0x20; sp=0x3020 -> sp=0x3000",
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 sub sp, sp, #0x20; sp=0x3000 -> sp=0x2fe0",
        "[App] 0x2004!0x2004 ldr x0, [sp, #0x20]; sp=0x2fe0 mem_r=0x3000 -> x0=0x41",
        "[App] 0x2008!0x2008 ldr x1, [sp, #0x30]; sp=0x2fe0 mem_r=0x3010 -> x1=0x42",
        "[App] 0x200c!0x200c ldr x2, [sp, #0x8]; sp=0x2fe0 mem_r=0x2fe8 -> x2=0x99",
        "[App] 0x2010!0x2010 ret; sp=0x2fe0",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x41 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 1, 2)
        .expect("function facts");

    assert_eq!(
        bundle.abi.entry_sp,
        Some("0x0000000000003000".to_string()),
        "entry SP 必须是入口指令执行前的 SP"
    );
    let slots = bundle
        .abi
        .stack_arguments
        .iter()
        .map(|slot| {
            (
                slot.offset,
                slot.size,
                slot.value.clone(),
                slot.read_seqs.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        slots,
        vec![
            (0, 8, Some("0x0000000000000041".to_string()), vec![3]),
            (16, 8, Some("0x0000000000000042".to_string()), vec![4]),
        ],
        "只有实际读取且位于 entry SP 之上的槽进入；偏移 8 的未读槽与 entry SP 之下的局部读取都不进入"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn a_written_slot_before_its_first_read_keeps_a_null_value() {
    // callee 在首次读取前写回了同一栈槽：入口原始值无法从 trace 恢复，
    // value 必须保持 null，不得用写入后的值或读取值冒充。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1000!0x1000 sub sp, sp, #0x20; sp=0x3020 -> sp=0x3000",
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 str x3, [sp]; sp=0x3000 x3=0x77 mem_w=0x3000",
        "[App] 0x2004!0x2004 ldr x0, [sp]; sp=0x3000 mem_r=0x3000 -> x0=0x77",
        "[App] 0x2008!0x2008 ret; sp=0x3000",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x77 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 1, 2)
        .expect("function facts");

    assert_eq!(
        bundle
            .abi
            .stack_arguments
            .iter()
            .map(|slot| (slot.offset, slot.size, slot.value.is_none()))
            .collect::<Vec<_>>(),
        vec![(0, 8, true)],
        "写后读的槽保留读取证据但 value 为 null"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn external_reads_and_final_writes_follow_the_producer_rules() {
    // producer→consumer：函数先写后读的地址是内部数据流，不进 memory_reads；
    // 只进最终写入。从未在本次调用内写入的读取是外部输入，bytes 取读取值
    // （小端、按地址递增）。同一地址多次写入保留全部 write_seqs 与最终值。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1000!0x1000 sub sp, sp, #0x20; sp=0x3020 -> sp=0x3000",
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldr x0, [sp]; sp=0x3000 mem_r=0x3000 -> x0=0x1111",
        "[App] 0x2004!0x2004 str x1, [x8]; x1=0xaa x8=0x5000 mem_w=0x5000",
        "[App] 0x2008!0x2008 str x1, [x8]; x1=0xbb x8=0x5000 mem_w=0x5000",
        "[App] 0x200c!0x200c ldr x2, [x8]; x8=0x5000 mem_r=0x5000 -> x2=0xbb",
        "[App] 0x2010!0x2010 ldr x3, [x9]; x9=0x6000 mem_r=0x6000 -> x3=0x4142",
        "[App] 0x2014!0x2014 ret; sp=0x3000",
        "[App] 0x1008!0x1008 mov x0, #0x99; x0=0x1111 -> x0=0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 1, 2)
        .expect("function facts");

    // 外部读取：0x3000（caller 栈槽——已作为 stack argument 报告，不重复
    // 进入 memory_reads）、0x6000（从未写过 → 外部输入）。
    let reads = bundle
        .memory_reads
        .iter()
        .map(|read| {
            (
                read.address.as_str(),
                read.size,
                read.bytes.clone(),
                read.seqs.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reads,
        vec![(
            "0x6000",
            8,
            Some("4241000000000000".to_string()),
            vec![6]
        )],
        "写后读（0x5000）不进入 memory_reads；已确认的栈参数槽（0x3000）不重复进入；外部读取 bytes 为小端实际字节"
    );

    // 最终写入：0x5000 两次写入合并，保留全部 write_seqs 与最终值 0xbb。
    let writes = bundle
        .memory_writes
        .iter()
        .map(|write| {
            (
                write.address.as_str(),
                write.size,
                write.bytes.clone(),
                write.seqs.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        writes,
        vec![("0x5000", 8, Some("bb00000000000000".to_string()), vec![4])],
        "同一地址多次写入合并为一项，bytes 为最终值，write_seqs 只保留对最终字节有贡献的写（前写被完全覆盖）"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

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
fn pair_writes_block_forged_external_values() {
    // stp 写入后读取同槽：pair 写必须参与「写后读」判定——栈参数 value
    // 为 null，且该地址不得作为外部输入进入 memory_reads。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 sub sp, sp, #0x20; sp=0x3000 -> sp=0x2fe0",
        "[App] 0x2004!0x2004 stp x2, x3, [sp]; sp=0x2fe0 x2=0x1111 x3=0x2222 mem_w=0x2fe0",
        "[App] 0x2008!0x2008 ldr x0, [sp]; sp=0x2fe0 mem_r=0x2fe0 -> x0=0x1111",
        "[App] 0x200c!0x200c ret",
        "[App] 0x1008!0x1008 mov x0, #0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");

    // 0x2fe0 在 entry SP 之下（局部区）：不是栈参数，也不得作为外部读取。
    assert!(bundle.abi.stack_arguments.is_empty());
    assert!(
        bundle
            .memory_reads
            .iter()
            .all(|read| read.address != "0x2fe0"),
        "pair 写后的读取是内部数据流，不得伪造为外部输入"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn exclusive_store_status_register_does_not_shrink_the_block_radius() {
    // stxr 的第一个操作数是状态寄存器 Ws：不能据此把写宽声明成 4 字节
    // ——x0 的 8 字节独占写必须按未知宽度保守阻断后续读取。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x5000",
        "[App] 0x2000!0x2000 stxr w1, x0, [x9]; x0=0xfeed x9=0x6000 mem_w=0x6000",
        "[App] 0x2004!0x2004 ldr x2, [x9, #4]; x9=0x6000 mem_r=0x6004 -> x2=0xfeed",
        "[App] 0x2008!0x2008 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert!(
        bundle
            .memory_reads
            .iter()
            .all(|read| read.address != "0x6000"),
        "独占写后的读取是内部数据流，不得因 Ws 缩窄写宽而漏阻断"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn pair_reads_of_stack_arguments_keep_a_null_value() {
    // ldp 读取 ≥ entry SP 的栈槽：进入 stack_arguments（读取证据），但
    // 单箭头值只覆盖一半，value 必须为 null。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1000!0x1000 sub sp, sp, #0x20; sp=0x3020 -> sp=0x3000",
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldp x0, x1, [sp]; sp=0x3000 mem_r=0x3000 -> x0=0x1111",
        "[App] 0x2004!0x2004 ret",
        "[App] 0x1008!0x1008 mov x0, #0x99",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 1, 2)
        .expect("function facts");
    assert_eq!(
        bundle
            .abi
            .stack_arguments
            .iter()
            .map(|slot| (
                slot.offset,
                slot.size,
                slot.value.is_none(),
                slot.read_seqs.clone()
            ))
            .collect::<Vec<_>>(),
        vec![(0, 16, true, vec![2])],
        "pair 读保留读取证据但 value 为 null（单箭头值只覆盖一半）"
    );
    // 该槽也不得重复进入 memory_reads。
    assert!(bundle.memory_reads.is_empty());

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn w_pair_values_are_not_half_forged() {
    // W-pair（stp w8, w0）总宽 8 字节：宽度守卫不触发，但值横跨两个寄存器
    // ——bytes 必须为 null，不得把第二个寄存器的字节伪造为零。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 stp w8, w0, [x19]; x19=0x7000 w8=0x14 w0=0x13 mem_w=0x7000",
        "[App] 0x2004!0x2004 ldr x2, [x19]; x19=0x7000 mem_r=0x7000 -> x2=0x1314",
        "[App] 0x2008!0x2008 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);
    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    let writes = bundle
        .memory_writes
        .iter()
        .map(|write| (write.address.as_str(), write.size, write.bytes.is_none()))
        .collect::<Vec<_>>();
    assert_eq!(writes, vec![("0x7000", 8, true)], "W-pair 写 bytes 为 null");
    assert!(
        bundle
            .memory_reads
            .iter()
            .all(|read| read.address != "0x7000"),
        "pair 写后的读取是内部数据流"
    );
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
