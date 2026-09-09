//! FunctionCallRecord 的 trace-ui 事实查询公共行为。
//!
//! 这组测试先固定调用方真正需要的边界：请求一份已确认 Activation 时，
//! provider 必须一次返回同一 Activation 的 anchors、ABI、完整执行块序列、
//! direct 读写、External Call Event 与 unresolved，避免状态机跨多个分页查询
//! 拼出不一致快照。

use super::*;
mod dataflow_tests;
mod events_tests;

pub(super) fn setup_inline_trace(lines: &[&str]) -> (Arc<TraceEngine>, String, std::path::PathBuf) {
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
    // 样本 activation 是 PLT stub：唯一访存（GOT 读取 seq 12）的值只流向
    // br 的目标解析——不影响记录的任何输出（返回值/写入/事件参数），按
    // 动态依赖筛选不进入 memory_reads。
    assert!(bundle.memory_reads.is_empty());
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
        "[App] 0x2012!0x2012 mov x0, x3; x3=0x4142 -> x0=0x4142",
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
                read.read_seqs.clone(),
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
                write.write_seqs.clone(),
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
