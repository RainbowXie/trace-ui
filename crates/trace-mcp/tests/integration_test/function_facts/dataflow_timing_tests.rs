use super::*;

#[test]
fn read_before_write_keeps_external_input_and_final_write() {
    // ISSUE-H10：seq 1 读取进入函数前已存在并流入返回值的字节，seq 2 才原地写回。
    // 不得用未来写把这次外部输入从 memory_reads 里删掉。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldr x0, [x8]; x8=0x6000 mem_r=0x6000 -> x0=0x1111",
        "[App] 0x2004!0x2004 str x1, [x8]; x1=0x2222 x8=0x6000 mem_w=0x6000",
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
            .map(|read| {
                (
                    read.address.as_str(),
                    read.bytes.clone(),
                    read.read_seqs.clone(),
                )
            })
            .collect::<Vec<_>>(),
        vec![("0x6000", Some("1111000000000000".to_string()), vec![1])],
        "read-before-write 必须保留进入函数前的输入：{:?}",
        bundle.memory_reads
    );
    assert_eq!(
        bundle
            .memory_writes
            .iter()
            .map(|write| {
                (
                    write.address.as_str(),
                    write.bytes.clone(),
                    write.write_seqs.clone(),
                )
            })
            .collect::<Vec<_>>(),
        vec![("0x6000", Some("2222000000000000".to_string()), vec![2])],
        "最终写入仍须保留：{:?}",
        bundle.memory_writes
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn write_before_read_still_excludes_internal_read() {
    // 写后读仍是内部数据流，不得进入外部 memory_reads。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 str x1, [x8]; x1=0x2222 x8=0x6000 mem_w=0x6000",
        "[App] 0x2004!0x2004 ldr x0, [x8]; x8=0x6000 mem_r=0x6000 -> x0=0x2222",
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
        "写后读不得进入外部 memory_reads：{:?}",
        bundle.memory_reads
    );
    assert_eq!(bundle.memory_writes.len(), 1);
    assert_eq!(bundle.memory_writes[0].address, "0x6000");

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn two_relevant_reads_with_different_values_keep_unfillable_null() {
    // ISSUE-H13：冻结合同要求同范围不重复。两次相关同址读取值不同时，
    // 合成一条 bytes=null 的记录并留下 unresolved，不能用重复范围表达时点。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldr x0, [x8]; x8=0x6000 mem_r=0x6000 -> x0=0x1111",
        "[App] 0x2004!0x2004 ldr x1, [x8]; x8=0x6000 mem_r=0x6000 -> x1=0x2222",
        "[App] 0x2008!0x2008 add x0, x0, x1; x0=0x1111 x1=0x2222 -> x0=0x3333",
        "[App] 0x200c!0x200c ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    let reads = bundle
        .memory_reads
        .iter()
        .map(|read| {
            (
                read.address.as_str(),
                read.bytes.clone(),
                read.read_seqs.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reads,
        vec![("0x6000", None, vec![1, 2])],
        "不同动态值必须同范围合并为 bytes=null：{reads:?}"
    );
    assert!(
        bundle.unresolved.iter().any(|gap| {
            gap.kind == "missing_memory_definition" && gap.location.as_deref() == Some("0x6000")
        }),
        "异值同范围必须留下 unresolved：{:?}",
        bundle.unresolved
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn two_relevant_reads_with_same_value_merge_seqs() {
    // ISSUE-H13：相同 address/size/bytes 必须合并 read_seqs。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 ldr x0, [x8]; x8=0x6000 mem_r=0x6000 -> x0=0x1111",
        "[App] 0x2004!0x2004 ldr x1, [x8]; x8=0x6000 mem_r=0x6000 -> x1=0x1111",
        "[App] 0x2008!0x2008 add x0, x0, x1; x0=0x1111 x1=0x1111 -> x0=0x2222",
        "[App] 0x200c!0x200c ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
    let reads = bundle
        .memory_reads
        .iter()
        .map(|read| {
            (
                read.address.as_str(),
                read.bytes.clone(),
                read.read_seqs.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reads,
        vec![("0x6000", Some("1111000000000000".to_string()), vec![1, 2])],
        "同值同范围必须合并 read_seqs：{reads:?}"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn partial_write_before_read_keeps_only_external_bytes() {
    // ISSUE-H12：seq 1 写低 4 字节，seq 2 读 8 字节。低 4 字节是内部生产，
    // 不得作为入口 MemoryRead；只有高 4 字节可作为外部输入。
    let (engine, sid, path) = setup_inline_trace(&[
        "[App] 0x1004!0x1004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 str w1, [x8]; w1=0x2222 x8=0x6000 mem_w=0x6000",
        "[App] 0x2004!0x2004 ldr x0, [x8]; x8=0x6000 mem_r=0x6000 -> x0=0x333300002222",
        "[App] 0x2008!0x2008 ret",
        "[App] 0x1008!0x1008 mov x0, #0x1",
    ]);

    let bundle = engine
        .get_function_facts(&sid, 0, 1)
        .expect("function facts");
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
        vec![("0x6004", 4, Some("33330000".to_string()), vec![2])],
        "只有未被更早写入覆盖的高 4 字节进入外部 MemoryRead：{reads:?}"
    );
    assert_eq!(bundle.memory_writes.len(), 1);
    assert_eq!(bundle.memory_writes[0].address, "0x6000");
    assert_eq!(bundle.memory_writes[0].size, 4);

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
