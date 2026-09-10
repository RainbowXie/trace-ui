use super::*;

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
            .all(|read| read.address != "0x6004"),
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

#[test]
fn ldpsw_stack_argument_reads_keep_a_null_value() {
    // ldpsw 访存 8 字节但写两个寄存器（箭头值只覆盖 Xt1，高 4 字节是
    // 符号扩展）：进入 stack_arguments 但 value 必须为 null，且不重复
    // 进入 memory_reads——钉住 is_pair_access 对 ldpsw 的覆盖。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1000!0x1000 sub sp, sp, #0x20; sp=0x3020 -> sp=0x3000",
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldpsw x0, x1, [sp]; sp=0x3000 mem_r=0x3000 -> x0=0x14",
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
            .map(|slot| (slot.offset, slot.size, slot.value.is_none()))
            .collect::<Vec<_>>(),
        vec![(0, 8, true)],
        "ldpsw 栈参数保留读取证据但 value 为 null（箭头值只覆盖 Xt1）"
    );
    assert!(bundle.memory_reads.is_empty());

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn failed_exclusive_stores_have_no_memory_effect() {
    // stxr 状态寄存器非 0（失败）：无内存效果——既不写也不阻断，后续
    // 外部读取必须保留。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x5000",
        "[App] 0x2000!0x2000 stxr w1, x0, [x9]; x0=0xfeed x9=0x6000 mem_w=0x6000 -> w1=0x1",
        "[App] 0x2004!0x2004 mov x0, x2; -> x0=0x1234",
        "[App] 0x2008!0x2008 ldr x2, [x9]; x9=0x6000 mem_r=0x6000 -> x2=0x1234",
        "[App] 0x200c!0x200c mov x0, x2; x2=0x1234 -> x0=0x1234",
        "[App] 0x2010!0x2010 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert!(
        bundle
            .memory_reads
            .iter()
            .any(|read| read.address == "0x6000"),
        "失败的独占写不产生内存效果，真实外部读取不得被吞：{:?}",
        bundle.memory_reads
    );
    assert!(
        bundle
            .memory_writes
            .iter()
            .all(|write| write.address != "0x6000"),
        "失败的独占写不得进入 writes"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn successful_exclusive_stores_write_the_data_register_width() {
    // stxr 状态 0（成功）：真实写入数据寄存器宽度（x → 8 字节）。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x5000",
        "[App] 0x2000!0x2000 stxr w1, x0, [x9]; x0=0xfeed x9=0x6000 mem_w=0x6000 -> w1=0x0",
        "[App] 0x2004!0x2004 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert_eq!(
        bundle
            .memory_writes
            .iter()
            .map(|write| (
                write.address.as_str(),
                write.size,
                write.bytes.clone(),
                write.write_seqs.clone()
            ))
            .collect::<Vec<_>>(),
        vec![("0x6000", 8, Some("edfe000000000000".to_string()), vec![1])],
        "成功的独占写按数据寄存器宽度记录最终值"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn irrelevant_reads_do_not_enter_memory_facts() {
    // 同一 Activation：流入返回值的读取相关（进入）；与任何输出无关的
    // 读取（值进 x3 后死亡）不进入。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldr x0, [x8]; x8=0x8000 mem_r=0x8000 -> x0=0x77",
        "[App] 0x2004!0x2004 ldr x3, [x9]; x9=0x9000 mem_r=0x9000 -> x3=0x42",
        "[App] 0x2008!0x2008 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert_eq!(
        bundle
            .memory_reads
            .iter()
            .map(|read| (read.address.as_str(), read.bytes.clone()))
            .collect::<Vec<_>>(),
        vec![("0x8000", Some("7700000000000000".to_string()))],
        "只有影响目标（流入返回值）的读取进入 memory_reads"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn relevant_reads_with_uncovered_widths_surface_as_unresolved() {
    // 影响目标但宽度未覆盖的读取（ldapr）：不得「空 reads + 空 unresolved」
    // 静默消失——必须留下 unsupported_instruction 缺口。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldapr x0, [x9]; x9=0x9000 mem_r=0x9000 -> x0=0x42",
        "[App] 0x2004!0x2004 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert!(bundle.memory_reads.is_empty());
    assert!(
        bundle
            .unresolved
            .iter()
            .any(|gap| gap.kind == "unsupported_instruction"
                && gap.location.as_deref() == Some("0x9000")),
        "影响目标的未覆盖访存必须产生结构化 unresolved：{:?}",
        bundle.unresolved
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn partially_overwritten_writes_split_into_final_byte_ranges() {
    // 8 字节写的后半被 4 字节写覆盖：不得保留互相矛盾的两条 8 字节
    // 最终事实——按字节粒度拆成两个互不重叠的最终范围。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 str x0, [x8]; x0=0x1122334455667788 x8=0x7000 mem_w=0x7000",
        "[App] 0x2004!0x2004 str w1, [x8, #4]; w1=0xaabbccdd x8=0x7000 mem_w=0x7004",
        "[App] 0x2008!0x2008 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    assert_eq!(
        bundle
            .memory_writes
            .iter()
            .map(|write| (
                write.address.as_str(),
                write.size,
                write.bytes.clone(),
                write.write_seqs.clone()
            ))
            .collect::<Vec<_>>(),
        vec![(
            "0x7000",
            8,
            Some("88776655ddccbbaa".to_string()),
            vec![1, 2],
        )],
        "部分覆盖按字节粒度合并出正确的 8 字节最终值，两个真实贡献者都保留"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn pair_spill_chains_keep_upstream_reads_relevant() {
    // ldp 恢复 spill 后再读取恢复值并流入返回值：pair 行的 deps.row 恒空，
    // 闭包必须沿 pair_split 的 shared/half 切片继续向上——上游读取不得
    // 因 pair 标记位或空 deps.row 被静默丢弃。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldp x0, x1, [x9]; x9=0x3000 mem_r=0x3000 -> x0=0x77 x1=0x88",
        "[App] 0x2004!0x2004 ldr x2, [x1]; x1=0x88 mem_r=0x8800 -> x2=0x99",
        "[App] 0x2008!0x2008 mov x0, x2; x2=0x99 -> x0=0x99",
        "[App] 0x200c!0x200c ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    let reads = bundle
        .memory_reads
        .iter()
        .map(|read| (read.address.as_str(), read.bytes.clone()))
        .collect::<Vec<_>>();
    // ldp 读（外部 spill 输入）与 ldr 读（经 pair 恢复寄存器的二级外部
    // 输入，流入返回值）都必须进入 memory_reads。
    // ldp 读 16B：pair 值横跨两个寄存器 → bytes null（不是半值冒充）；
    // 上游 ldr 读经 pair 恢复寄存器流入返回值 → 保留。
    assert_eq!(
        reads,
        vec![
            ("0x3000", None),
            ("0x8800", Some("9900000000000000".to_string())),
        ],
        "pair 生产者链上的上游读取不得被静默丢弃：{reads:?}"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn simd_vector_writes_generate_real_records_and_missing_definitions() {
    // 验证 HIGH-003：stp q0, q1 写入 32 字节且值未完整时，
    // 必须物化为 bytes=null 的 memory_writes 并在 unresolved 中产出
    // 匹配的 missing_memory_definition，绝不静默消失。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 stp q0, q1, [x9]; x9=0xa000 mem_w=0xa000",
        "[App] 0x2004!0x2004 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");

    assert_eq!(bundle.memory_writes.len(), 1);
    let write = &bundle.memory_writes[0];
    assert_eq!(write.address, "0xa000");
    assert_eq!(write.size, 32);
    assert_eq!(write.bytes, None);
    assert_eq!(write.write_seqs, vec![1]);

    assert!(
        bundle.unresolved.iter().any(|u| {
            u.kind == "missing_memory_definition"
                && u.location.as_deref() == Some("0xa000")
                && u.seqs == vec![1]
        }),
        "stp q0, q1 未完整写入必须产出 matching missing_memory_definition: {:?}",
        bundle.unresolved
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
