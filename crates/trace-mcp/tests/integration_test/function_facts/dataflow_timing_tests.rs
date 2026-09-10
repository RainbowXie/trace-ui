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
fn two_relevant_reads_with_different_values_are_separate_records() {
    // ISSUE-H11：两次相关同址读取观察值不同时，必须拆成两条 MemoryRead，
    // 不得压成一条 read_seqs 并集让任一 capture 整体补齐。
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
        vec![
            ("0x6000", Some("1111000000000000".to_string()), vec![1]),
            ("0x6000", Some("2222000000000000".to_string()), vec![2]),
        ],
        "不同动态值必须拆成独立读取记录：{reads:?}"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
