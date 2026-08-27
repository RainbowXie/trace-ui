use trace_core::memory_search::{
    search_memory, search_memory_cached_occurrences, MemorySearchOptions, MemorySearchRw,
};
use trace_core::TraceEngine;
use trace_parser::types::TraceFormat;

fn read_line(seq: u32, value: Option<&str>) -> String {
    let suffix = value.map(|v| format!(" => w0={v}")).unwrap_or_default();
    format!(
        "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"ldr w0, [x1]\" ; mem[READ] abs=0x2000 x1=0x3000{suffix}"
    )
}

fn write_line(seq: u32, value: &str) -> String {
    format!(
        "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0={value} x1=0x3000 => w0={value}"
    )
}

fn unknown_write_line(seq: u32) -> String {
    format!(
        "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 x1=0x3000"
    )
}

fn options(pattern: &[u8]) -> MemorySearchOptions {
    MemorySearchOptions {
        pattern: pattern.to_vec(),
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 50,
    }
}

#[test]
fn cached_occurrence_pages_do_not_materialize_pattern_bytes() {
    let trace = write_line(0, "0x04030201");
    let request = MemorySearchOptions {
        pattern: vec![0; 64 * 1024 * 1024],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let result = search_memory_cached_occurrences(
        "/tmp/trace-ui-occurrence-page.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        request,
    );
    assert!(
        result.is_ok(),
        "occurrence-only page should not clone pattern bytes"
    );
}

#[test]
fn public_search_rejects_a_response_that_would_exceed_the_serialization_budget() {
    let trace = write_line(0, "0x04030201");
    let request = MemorySearchOptions {
        pattern: vec![0; 5 * 1024 * 1024],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 2,
    };
    let result = search_memory(trace.as_bytes(), TraceFormat::Unidbg, request);
    assert!(
        result.is_err(),
        "public search must not construct an unbounded response"
    );
}

#[test]
fn occurrence_content_identity_is_content_based_not_path_based() {
    let trace = write_line(0, "0x04030201");
    let request = options(&[1, 2, 3, 4]);
    let first = search_memory_cached_occurrences(
        "/tmp/first.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        request.clone(),
    )
    .expect("first occurrence page");
    let second = search_memory_cached_occurrences(
        "/tmp/renamed.trace",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        request.clone(),
    )
    .expect("renamed occurrence page");
    assert_eq!(first.content_identity, second.content_identity);

    let changed = search_memory_cached_occurrences(
        "/tmp/renamed.trace",
        &trace.replace("0x04030201", "0x08070605").into_bytes(),
        TraceFormat::Unidbg,
        request,
    )
    .expect("changed occurrence page");
    assert_ne!(first.content_identity, changed.content_identity);
}

#[test]
fn unknown_bytes_become_a_match_when_a_read_first_reveals_them() {
    let trace = format!(
        "{}\n{}\n",
        read_line(0, None),
        read_line(1, Some("0x04030201"))
    );
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("memory search");

    assert_eq!(result.total, 1);
    assert_eq!(result.matches[0].seq, 1);
    assert_eq!(result.matches[0].address, 0x2000);
    assert_eq!(result.matches[0].rw, MemorySearchRw::Read);
    assert_eq!(result.matches[0].bytes, vec![1, 2, 3, 4]);
}

#[test]
fn write_forms_a_match_and_repeated_access_does_not_repeat_it() {
    let trace = format!(
        "{}\n{}\n",
        write_line(0, "0x04030201"),
        write_line(1, "0x04030201")
    );
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("memory search");

    assert_eq!(result.total, 1);
    assert_eq!(result.matches[0].seq, 0);
    assert_eq!(result.matches[0].rw, MemorySearchRw::Write);
}

#[test]
fn covering_the_bytes_breaks_and_reforms_the_same_match() {
    let trace = format!(
        "{}\n{}\n{}\n",
        write_line(0, "0x04030201"),
        write_line(1, "0x08070605"),
        write_line(2, "0x04030201"),
    );
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("memory search");

    assert_eq!(result.total, 2);
    assert_eq!(result.matches[0].seq, 0);
    assert_eq!(result.matches[1].seq, 2);
}

#[test]
fn sequence_memory_filters_and_pagination_are_stable() {
    let trace = format!(
        "{}\n{}\n{}\n",
        write_line(0, "0x04030201"),
        write_line(1, "0x08070605"),
        write_line(2, "0x04030201"),
    );
    let mut request = options(&[1, 2, 3, 4]);
    request.seq_range = Some((2, 2));
    request.memory_range = Some((0x2000, 0x2004));
    request.offset = 0;
    request.limit = 1;
    let first = search_memory(trace.as_bytes(), TraceFormat::Unidbg, request.clone())
        .expect("memory search");
    assert_eq!(first.total, 1);
    assert_eq!(first.matches.len(), 1);
    assert!(!first.has_more);

    request.memory_range = Some((0x2004, 0x2008));
    let outside =
        search_memory(trace.as_bytes(), TraceFormat::Unidbg, request).expect("memory search");
    assert_eq!(outside.total, 0);
    assert!(outside.matches.is_empty());
}

#[test]
fn pair_values_are_replayed_as_adjacent_little_endian_bytes() {
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"stp w0, w1, [x2]\" ; mem[WRITE] abs=0x3000 w0=0x04030201 w1=0x08070605 x2=0x3000 => w0=0x04030201 w1=0x08070605\n";
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .expect("memory search");
    assert_eq!(result.total, 1);
    assert_eq!(result.matches[0].address, 0x3000);
    assert_eq!(result.matches[0].size, 8);
}

#[test]
fn exclusive_pair_store_skips_status_register_and_starts_at_first_memory_value() {
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"stxp w0, w1, w2, [x3]\" ; mem[WRITE] abs=0x5000 w0=0x00000000 w1=0x04030201 w2=0x08070605 x3=0x5000 => w0=0x00000000\n";
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .expect("memory search");
    assert_eq!(result.total, 1);
    assert_eq!(result.matches[0].address, 0x5000);
    assert_eq!(result.matches[0].size, 8);
}

#[test]
fn an_unobserved_pair_half_is_unknown_and_cannot_form_a_match() {
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"stp w0, w1, [x2]\" ; mem[WRITE] abs=0x3000 w0=0x04030201 x2=0x3000 => w0=0x04030201\n";
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .expect("memory search");
    assert_eq!(result.total, 0);
}

#[test]
fn unknown_read_does_not_erase_an_already_known_match() {
    let trace = format!(
        "{}\n{}\n{}\n",
        write_line(0, "0x04030201"),
        read_line(1, None),
        read_line(2, Some("0x04030201")),
    );
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("memory search");
    assert_eq!(result.total, 1);
    assert_eq!(result.matches[0].seq, 0);
}

#[test]
fn unknown_write_breaks_a_match_and_a_later_known_write_reforms_it() {
    let trace = format!(
        "{}\n{}\n{}\n",
        write_line(0, "0x04030201"),
        unknown_write_line(1),
        write_line(2, "0x04030201"),
    );
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("memory search");
    assert_eq!(result.total, 2);
    assert_eq!(result.matches[1].seq, 2);
}

#[test]
fn invalid_ranges_and_page_sizes_are_rejected() {
    let trace = write_line(0, "0x04030201");
    let mut request = options(&[1, 2, 3, 4]);
    request.limit = 0;
    assert!(search_memory(trace.as_bytes(), TraceFormat::Unidbg, request).is_err());

    let mut request = options(&[1, 2, 3, 4]);
    request.seq_range = Some((2, 1));
    assert!(search_memory(trace.as_bytes(), TraceFormat::Unidbg, request).is_err());

    let mut request = options(&[1, 2, 3, 4]);
    request.memory_range = Some((0x2000, 0x2000));
    assert!(search_memory(trace.as_bytes(), TraceFormat::Unidbg, request).is_err());
}

#[test]
fn a_three_register_simd_write_invalidates_the_unobserved_tail() {
    let initial = write_line(0, "0x04030201")
        .replace("abs=0x2000", "abs=0x4020")
        .replace("x1=0x3000", "x1=0x4020");
    let wide_unknown = "[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"st1 {v0.16b, v1.16b, v2.16b}, [x0]\" ; mem[WRITE] abs=0x4000 x0=0x4000\n";
    let restored = write_line(2, "0x04030201")
        .replace("abs=0x2000", "abs=0x4020")
        .replace("x1=0x3000", "x1=0x4020");
    let trace = format!("{initial}\n{wide_unknown}{restored}");
    let result = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("memory search");
    assert_eq!(result.total, 2);
    assert_eq!(result.matches[0].seq, 0);
    assert_eq!(result.matches[1].seq, 2);
}

#[test]
fn engine_search_memory_uses_the_open_session_and_reuses_a_complete_cache() {
    let trace = write_line(0, "0x04030201");
    let path = std::env::temp_dir().join(format!(
        "trace-ui-memory-search-{}-{}.txt",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, &trace).expect("write fixture");

    let engine = TraceEngine::new();
    let session = engine
        .create_session(path.to_str().expect("utf8 path"))
        .expect("create session");
    let request = options(&[1, 2, 3, 4]);
    let first = engine
        .search_memory(&session.session_id, request.clone())
        .expect("first search");
    let second = engine
        .search_memory(&session.session_id, request)
        .expect("cached search");
    assert_eq!(first, second);

    engine
        .close_session(&session.session_id)
        .expect("close session");
    let _ = std::fs::remove_file(path);
}

#[test]
fn engine_rejects_an_in_place_trace_rewrite_on_a_later_cache_page() {
    let trace = write_line(0, "0x04030201");
    let path = std::env::temp_dir().join(format!(
        "trace-ui-memory-search-rewrite-{}-{}.txt",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, &trace).expect("write fixture");
    let engine = TraceEngine::new();
    let session = engine
        .create_session(path.to_str().expect("utf8 path"))
        .expect("create session");
    let original_metadata = std::fs::metadata(&path).expect("original metadata");
    let request = options(&[1, 2, 3, 4]);
    engine
        .search_memory(&session.session_id, request.clone())
        .expect("initial search");

    // Keep the inode but change its bytes and metadata, as an external writer
    // can do while a mapped session is alive.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open for rewrite")
        .set_len(0)
        .expect("truncate trace");
    std::fs::write(
        &path,
        format!(
            "{}\n{}",
            write_line(0, "0x08070605"),
            write_line(1, "0x04030201")
        ),
    )
    .expect("rewrite trace");
    let rewritten_metadata = std::fs::metadata(&path).expect("rewritten metadata");
    assert_ne!(
        (original_metadata.len(), original_metadata.modified().ok()),
        (rewritten_metadata.len(), rewritten_metadata.modified().ok()),
        "fixture rewrite must change metadata"
    );

    let result = engine.search_memory(&session.session_id, request);
    assert!(
        result.is_err(),
        "rewritten trace must not reuse the old cache identity"
    );
    engine
        .close_session(&session.session_id)
        .expect("close session");
    let _ = std::fs::remove_file(path);
}

// ── 指令语义合同套件（Unidbg 与 GumTrace 跑同一组语义） ──

fn uni_write_insn(seq: u32, insn: &str, ann: &str, addr: u64) -> String {
    format!(
        "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"{insn}\" ; mem[WRITE] abs=0x{addr:x} {ann}"
    )
}

fn uni_read_insn(seq: u32, insn: &str, pre: &str, addr: u64, post: &str) -> String {
    format!(
        "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"{insn}\" ; mem[READ] abs=0x{addr:x} {pre} => {post}"
    )
}

fn gum_write_insn(insn: &str, ann: &str, addr: u64) -> String {
    format!("[lib.so] 0x7522f46438!0x143438 {insn}; {ann} mem_w=0x{addr:x}")
}

fn gum_write_insn_post(insn: &str, ann: &str, addr: u64, post: &str) -> String {
    format!("[lib.so] 0x7522f46438!0x143438 {insn}; {ann} mem_w=0x{addr:x} -> {post}")
}

fn gum_read_insn(insn: &str, pre: &str, addr: u64, post: &str) -> String {
    format!("[lib.so] 0x7522f46438!0x143438 {insn}; {pre} mem_r=0x{addr:x} -> {post}")
}

fn search_both(uni_trace: &str, gum_trace: &str, pattern: &[u8]) -> (u32, u32) {
    let uni = search_memory(
        format!("{uni_trace}\n").as_bytes(),
        TraceFormat::Unidbg,
        options(pattern),
    )
    .expect("unidbg memory search");
    let gum = search_memory(
        format!("{gum_trace}\n").as_bytes(),
        TraceFormat::Gumtrace,
        options(pattern),
    )
    .expect("gumtrace memory search");
    (uni.total, gum.total)
}

#[test]
fn exclusive_scalar_store_writes_data_register_not_status() {
    for insn in ["stxr w0, w1, [x2]", "stlxr w0, w1, [x2]"] {
        let (uni, gum) = search_both(
            &uni_write_insn(
                0,
                insn,
                "w0=0xffffffff w1=0x04030201 x2=0x2000 => w0=0x00000000",
                0x2000,
            ),
            &gum_write_insn_post(insn, "w1=0x04030201 x2=0x2000", 0x2000, "w0=0x0"),
            &[1, 2, 3, 4],
        );
        assert_eq!(
            (uni, gum),
            (1, 1),
            "{insn}: real source register must match"
        );
        // 状态寄存器 w0 写入的 0 不得成为内存字节。
        let (uni_zero, gum_zero) = search_both(
            &uni_write_insn(
                0,
                insn,
                "w0=0xffffffff w1=0x04030201 x2=0x2000 => w0=0x00000000",
                0x2000,
            ),
            &gum_write_insn_post(insn, "w1=0x04030201 x2=0x2000", 0x2000, "w0=0x0"),
            &[0, 0, 0, 0],
        );
        assert_eq!(
            (uni_zero, gum_zero),
            (0, 0),
            "{insn}: status register must not be stored"
        );
    }
}

#[test]
fn exclusive_byte_and_halfword_stores_use_element_width() {
    let (uni, gum) = search_both(
        &uni_write_insn(
            0,
            "stxrb w0, w1, [x2]",
            "w0=0xffffffff w1=0x5a x2=0x2000 => w0=0x00000000",
            0x2000,
        ),
        &gum_write_insn_post("stxrb w0, w1, [x2]", "w1=0x5a x2=0x2000", 0x2000, "w0=0x0"),
        &[0x5a],
    );
    assert_eq!((uni, gum), (1, 1), "stxrb stores one known byte");
    // 只写了 1 个字节，相邻字节保持 unknown，更宽的模式不得匹配。
    let (uni_wide, gum_wide) = search_both(
        &uni_write_insn(
            0,
            "stxrh w0, w1, [x2]",
            "w0=0xffffffff w1=0x5a33 x2=0x2000 => w0=0x00000000",
            0x2000,
        ),
        &gum_write_insn_post(
            "stxrh w0, w1, [x2]",
            "w1=0x5a33 x2=0x2000",
            0x2000,
            "w0=0x0",
        ),
        &[0x33, 0x5a, 0, 0],
    );
    assert_eq!(
        (uni_wide, gum_wide),
        (0, 0),
        "stxrh covers exactly two bytes"
    );
    let (uni_h, gum_h) = search_both(
        &uni_write_insn(
            0,
            "stxrh w0, w1, [x2]",
            "w0=0xffffffff w1=0x5a33 x2=0x2000 => w0=0x00000000",
            0x2000,
        ),
        &gum_write_insn_post(
            "stxrh w0, w1, [x2]",
            "w1=0x5a33 x2=0x2000",
            0x2000,
            "w0=0x0",
        ),
        &[0x33, 0x5a],
    );
    assert_eq!((uni_h, gum_h), (1, 1), "stxrh stores the halfword value");
}

#[test]
fn zero_register_store_produces_known_zero_bytes() {
    let (uni, gum) = search_both(
        &uni_write_insn(0, "str wzr, [x1]", "x1=0x2000 => wzr=0x0", 0x2000),
        &gum_write_insn("str wzr, [x1]", "x1=0x2000", 0x2000),
        &[0, 0, 0, 0],
    );
    assert_eq!((uni, gum), (1, 1), "wzr stores known zeros");

    let (uni_pair, gum_pair) = search_both(
        &uni_write_insn(
            0,
            "stp xzr, x0, [x1]",
            "x0=0x0807060504030201 x1=0x2000 => x0=0x0807060504030201",
            0x2000,
        ),
        &gum_write_insn(
            "stp xzr, x0, [x1]",
            "x0=0x0807060504030201 x1=0x2000",
            0x2000,
        ),
        &[0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
    );
    assert_eq!(
        (uni_pair, gum_pair),
        (1, 1),
        "pair with xzr stores known zeros then x0"
    );
}

// st2 {v0.8b, v1.8b}: v0.b[i] = i, v1.b[i] = 0x10 + i。
// 真实内存按 lane 交错：00 10 01 11 02 12 ... 07 17。
const ST2_Q0: &str = "0x00000000000000000706050403020100";
const ST2_Q1: &str = "0x00000000000000001716151413121110";
const ST2_INTERLEAVED: [u8; 16] = [
    0x00, 0x10, 0x01, 0x11, 0x02, 0x12, 0x03, 0x13, 0x04, 0x14, 0x05, 0x15, 0x06, 0x16, 0x07, 0x17,
];
const ST2_CONTIGUOUS: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];

#[test]
fn simd_structure_store_interleaves_lanes() {
    let insn = "st2 {v0.8b, v1.8b}, [x0]";
    let uni = uni_write_insn(
        0,
        insn,
        &format!("x0=0x6000 q0={ST2_Q0} q1={ST2_Q1} => x0=0x6000"),
        0x6000,
    );
    let gum = gum_write_insn(insn, &format!("x0=0x6000 q0={ST2_Q0} q1={ST2_Q1}"), 0x6000);
    let (uni_hit, gum_hit) = search_both(&uni, &gum, &ST2_INTERLEAVED);
    assert_eq!(
        (uni_hit, gum_hit),
        (1, 1),
        "st2 memory layout is lane-interleaved"
    );
    let (uni_bad, gum_bad) = search_both(&uni, &gum, &ST2_CONTIGUOUS);
    assert_eq!(
        (uni_bad, gum_bad),
        (0, 0),
        "st2 must not concatenate registers"
    );
}

#[test]
fn simd_structure_store_three_and_four_registers_interleave() {
    // st3 {v0.8b, v1.8b, v2.8b}: v2.b[i] = 0x20 + i，三路 lane 交错。
    let q2 = "0x00000000000000002726252423222120";
    let insn = "st3 {v0.8b, v1.8b, v2.8b}, [x0]";
    let ann = format!("x0=0x6000 q0={ST2_Q0} q1={ST2_Q1} q2={q2}");
    let uni = uni_write_insn(0, insn, &format!("{ann} => x0=0x6000"), 0x6000);
    let gum = gum_write_insn(insn, &ann, 0x6000);
    let mut interleaved = Vec::new();
    for lane in 0..8u8 {
        interleaved.extend_from_slice(&[lane, 0x10 + lane, 0x20 + lane]);
    }
    let (uni_hit, gum_hit) = search_both(&uni, &gum, &interleaved);
    assert_eq!(
        (uni_hit, gum_hit),
        (1, 1),
        "st3 interleaves three registers"
    );

    // st4 {v0.8b, ..., v3.8b}: v3.b[i] = 0x30 + i。
    let q3 = "0x00000000000000003736353433323130";
    let insn4 = "st4 {v0.8b, v1.8b, v2.8b, v3.8b}, [x0]";
    let ann4 = format!("{ann} q3={q3}");
    let uni4 = uni_write_insn(0, insn4, &format!("{ann4} => x0=0x6000"), 0x6000);
    let gum4 = gum_write_insn(insn4, &ann4, 0x6000);
    let mut interleaved4 = Vec::new();
    for lane in 0..8u8 {
        interleaved4.extend_from_slice(&[lane, 0x10 + lane, 0x20 + lane, 0x30 + lane]);
    }
    let (uni_hit4, gum_hit4) = search_both(&uni4, &gum4, &interleaved4);
    assert_eq!(
        (uni_hit4, gum_hit4),
        (1, 1),
        "st4 interleaves four registers"
    );
}

#[test]
fn simd_structure_load_reveals_interleaved_bytes() {
    let insn = "ld2 {v0.8b, v1.8b}, [x0]";
    let uni = uni_read_insn(
        0,
        insn,
        "x0=0x6000",
        0x6000,
        &format!("q0={ST2_Q0} q1={ST2_Q1}"),
    );
    let gum = gum_read_insn(
        insn,
        "x0=0x6000",
        0x6000,
        &format!("q0={ST2_Q0} q1={ST2_Q1}"),
    );
    let (uni_hit, gum_hit) = search_both(&uni, &gum, &ST2_INTERLEAVED);
    assert_eq!(
        (uni_hit, gum_hit),
        (1, 1),
        "ld2 reveals lane-interleaved memory"
    );
    let (uni_bad, gum_bad) = search_both(&uni, &gum, &ST2_CONTIGUOUS);
    assert_eq!(
        (uni_bad, gum_bad),
        (0, 0),
        "ld2 must not concatenate registers"
    );
}

#[test]
fn gumtrace_simd_operand_reads_q_annotation() {
    // GumTrace 注解里 128-bit 向量值以 qN 记录，操作数写 v0 时必须回退到 q0。
    let q0 = "0x0f0e0d0c0b0a09080706050403020100";
    let gum = gum_write_insn("st1 {v0.16b}, [x0]", &format!("x0=0x6000 q0={q0}"), 0x6000);
    let pattern: Vec<u8> = (0u8..16).collect();
    let result = search_memory(
        format!("{gum}\n").as_bytes(),
        TraceFormat::Gumtrace,
        options(&pattern),
    )
    .expect("gumtrace memory search");
    assert_eq!(result.total, 1, "v0 operand must read the q0 annotation");
}

/// ldr wzr 的目标是丢弃值：它证明不了内存是零。
/// 只有 store 侧的零寄存器才是已知零内存。
#[test]
fn zero_register_load_does_not_prove_memory_zero() {
    let uni = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"ldr wzr, [x1]\" ; mem[READ] abs=0x2000 x1=0x2000";
    let gum = gum_read_insn("ldr wzr, [x1]", "x1=0x2000", 0x2000, "x1=0x2000");
    let (uni_t, gum_t) = search_both(uni, &gum, &[0, 0, 0, 0]);
    assert_eq!(
        (uni_t, gum_t),
        (0, 0),
        "ldr wzr/xzr discards the loaded value; memory stays unknown"
    );
}

/// exclusive store 只有状态寄存器为 0 才真正写入内存。
/// 失败（状态非 0）的 stxr/stxp 对内存没有任何影响：不写字节也不失效。
#[test]
fn failed_exclusive_store_has_no_memory_effect() {
    for insn in ["stxr w0, w1, [x2]", "stlxr w0, w1, [x2]"] {
        let (uni, gum) = search_both(
            &uni_write_insn(
                0,
                insn,
                "w0=0x00000000 w1=0x04030201 x2=0x2000 => w0=0x00000001",
                0x2000,
            ),
            &gum_write_insn_post(insn, "w1=0x04030201 x2=0x2000", 0x2000, "w0=0x1"),
            &[1, 2, 3, 4],
        );
        assert_eq!(
            (uni, gum),
            (0, 0),
            "{insn}: status 1 means the store did not happen"
        );
    }
    let (uni_pair, gum_pair) = search_both(
        &uni_write_insn(
            0,
            "stxp w0, x1, x3, [x2]",
            "w0=0x00000000 x1=0x0403020108070605 x3=0x0c0b0a0908070605 x2=0x2000 => w0=0x00000001",
            0x2000,
        ),
        &gum_write_insn_post(
            "stxp w0, x1, x3, [x2]",
            "x1=0x0403020108070605 x3=0x0c0b0a0908070605 x2=0x2000",
            0x2000,
            "w0=0x1",
        ),
        &[5, 6, 7, 8, 1, 2, 3, 4],
    );
    assert_eq!((uni_pair, gum_pair), (0, 0), "failed stxp writes nothing");
}

/// 状态未知的 exclusive store 不能当没发生，也不能当成功：
/// 保守处理是使整个访问范围失效。
#[test]
fn unknown_status_exclusive_store_invalidates_the_range() {
    let trace = [
        uni_write_insn(0, "str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
        // 没有 post-arrow：状态寄存器的值不可得。
        uni_write_insn(1, "stxr w0, w1, [x2]", "w1=0x0a0b0c0d x2=0x2000", 0x2000),
        uni_write_insn(2, "str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
    ]
    .join("\n");
    let result = search_memory_cached_occurrences(
        "stxr-unknown-status",
        trace.as_bytes(),
        TraceFormat::Unidbg,
        options(&[1, 2, 3, 4]),
    )
    .expect("search");
    assert_eq!(
        result.total, 2,
        "unknown-status stxr must invalidate, so the match breaks and reforms"
    );
    let gum = [
        gum_write_insn("str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
        gum_write_insn("stxr w0, w1, [x2]", "w1=0x0a0b0c0d x2=0x2000", 0x2000),
        gum_write_insn("str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
    ]
    .join("\n");
    let gum_result = search_memory_cached_occurrences(
        "stxr-unknown-status-gum",
        gum.as_bytes(),
        TraceFormat::Gumtrace,
        options(&[1, 2, 3, 4]),
    )
    .expect("gumtrace search");
    assert_eq!(gum_result.total, 2, "gumtrace: same unknown-status rule");
}

/// st2 {v0.b, v1.b}[3] 是单 lane structure store：内存只得到每个寄存器的
/// 一个 lane 元素，即 [v0.b[3], v1.b[3]]。
#[test]
fn simd_structure_lane_form_stores_single_lane_elements() {
    let pre =
        "v0=0x00000000000000000000000003000000 v1=0x00000000000000000000000013000000 x0=0x2000";
    let (uni, gum) = search_both(
        &uni_write_insn(0, "st2 {v0.b, v1.b}[3], [x0]", pre, 0x2000),
        &gum_write_insn("st2 {v0.b, v1.b}[3], [x0]", pre, 0x2000),
        &[0x03, 0x13],
    );
    assert_eq!(
        (uni, gum),
        (1, 1),
        "lane form stores exactly one element per register"
    );
    // 不得按完整向量连续拼接：v0 的 16 字节不在内存里。
    let (uni_full, gum_full) = search_both(
        &uni_write_insn(0, "st2 {v0.b, v1.b}[3], [x0]", pre, 0x2000),
        &gum_write_insn("st2 {v0.b, v1.b}[3], [x0]", pre, 0x2000),
        &[0x00, 0x00, 0x00, 0x03, 0x00, 0x13],
    );
    assert_eq!(
        (uni_full, gum_full),
        (0, 0),
        "lane form must not materialize full vector bytes"
    );
}

/// ld2r 是 replicate load：内存只读取每个结构元素（2 个字节），
/// 注解里的完整 q0/q1 是复制后的寄存器值，不能当成连续内存。
#[test]
fn simd_replicate_load_reads_only_structure_elements() {
    let post = "v0=0x01010101010101010101010101010101 v1=0x02020202020202020202020202020202";
    let (uni, gum) = search_both(
        &uni_read_insn(0, "ld2r {v0.16b, v1.16b}, [x0]", "x0=0x2000", 0x2000, post),
        &gum_read_insn("ld2r {v0.16b, v1.16b}, [x0]", "x0=0x2000", 0x2000, post),
        &[0x01, 0x02],
    );
    assert_eq!(
        (uni, gum),
        (1, 1),
        "replicate load reads one element per structure: lane 0 is the memory byte"
    );
    // 16 个 0x01 是复制结果，不是内存内容。
    let (uni_wide, gum_wide) = search_both(
        &uni_read_insn(0, "ld2r {v0.16b, v1.16b}, [x0]", "x0=0x2000", 0x2000, post),
        &gum_read_insn("ld2r {v0.16b, v1.16b}, [x0]", "x0=0x2000", 0x2000, post),
        &[0x01u8; 16],
    );
    assert_eq!(
        (uni_wide, gum_wide),
        (0, 0),
        "replicated lanes must not be fabricated into memory bytes"
    );
}

/// 十六进制前缀之外的后缀不是地址的一部分：整个事件 fail-closed。
#[test]
fn gumtrace_malformed_address_suffix_fails_closed() {
    let trace =
        "[lib.so] 0x7522f46438!0x143438 str w0, [x1]; w0=0x04030201 x1=0x2000 mem_w=0x2000oops";
    let result = search_memory_cached_occurrences(
        "malformed-address-suffix",
        trace.as_bytes(),
        TraceFormat::Gumtrace,
        options(&[1, 2, 3, 4]),
    );
    assert!(
        result.is_err(),
        "0x2000oops is not an address; the event must fail closed"
    );
    // 一行中任一 marker 损坏都不能被其他合法 marker 掩住。
    let mixed = "[lib.so] 0x7522f46438!0x143438 str w0, [x1]; w0=0x04030201 x1=0x2000 mem_r=0xZZ mem_w=0x2000";
    let mixed_result = search_memory_cached_occurrences(
        "mixed-malformed-marker",
        mixed.as_bytes(),
        TraceFormat::Gumtrace,
        options(&[1, 2, 3, 4]),
    );
    assert!(
        mixed_result.is_err(),
        "a broken mem_r marker must not be hidden by a valid mem_w"
    );
}

#[test]
fn atomic_rmw_write_invalidates_without_guessing() {
    // cas 写入的最终字节无法从寄存器注解精确恢复：不得把 w1 当成写入值。
    for insn in ["cas w0, w1, [x2]", "swp w0, w1, [x2]", "ldadd w0, w1, [x2]"] {
        let uni = format!(
            "{}\n{}\n{}\n",
            write_line(0, "0x04030201"),
            "[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 x1=0x3000",
            uni_write_insn(2, insn, "w0=0x04030201 w1=0x04030201 x2=0x2000 => w0=0x04030201", 0x2000),
        );
        let gum = format!(
            "{}\n{}\n{}\n",
            gum_write_insn("str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
            gum_write_insn("str w0, [x1]", "x1=0x2000", 0x2000),
            gum_write_insn(insn, "w0=0x04030201 w1=0x04030201 x2=0x2000", 0x2000),
        );
        let (uni_total, gum_total) = search_both(&uni, &gum, &[1, 2, 3, 4]);
        assert_eq!(
            (uni_total, gum_total),
            (1, 1),
            "{insn}: atomic write must invalidate, not guess the annotated register"
        );
    }
}

#[test]
fn atomic_rmw_read_does_not_overwrite_known_bytes() {
    // atomic read 不得覆盖已有已知值：之后的相同写入不应产生新 occurrence。
    let uni = format!(
        "{}\n{}\n{}\n",
        write_line(0, "0x04030201"),
        uni_read_insn(
            1,
            "ldadd w0, w1, [x2]",
            "w1=0x1 x2=0x2000",
            0x2000,
            "w0=0x08070605"
        ),
        write_line(2, "0x04030201"),
    );
    let gum = format!(
        "{}\n{}\n{}\n",
        gum_write_insn("str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
        gum_read_insn(
            "ldadd w0, w1, [x2]",
            "w1=0x1 x2=0x2000",
            0x2000,
            "w0=0x08070605"
        ),
        gum_write_insn("str w0, [x1]", "w0=0x04030201 x1=0x2000", 0x2000),
    );
    let (uni_total, gum_total) = search_both(&uni, &gum, &[1, 2, 3, 4]);
    assert_eq!(
        (uni_total, gum_total),
        (1, 1),
        "atomic read must not overwrite already-known bytes"
    );
}

#[test]
fn gumtrace_malformed_memory_marker_fails_closed() {
    for broken in [
        "[lib.so] 0x7522f46438!0x143438 str w0, [x1]; w0=0x04030201 x1=0x3000 mem_w=not-an-address",
        "[lib.so] 0x7522f46438!0x143438 ldr w0, [x1]; x1=0x3000 mem_r=zz -> w0=0x04030201",
    ] {
        let result = search_memory(
            format!("{broken}\n").as_bytes(),
            TraceFormat::Gumtrace,
            options(&[1, 2, 3, 4]),
        );
        assert!(
            result.is_err(),
            "malformed gumtrace memory event must fail: {broken}"
        );
    }
    // 合法的非内存行仍然忽略。
    let ok = search_memory(
        b"[lib.so] 0x7522f46438!0x143438 add x0, x1, x2; x1=0x1 x2=0x2 -> x0=0x3\n",
        TraceFormat::Gumtrace,
        options(&[1, 2, 3, 4]),
    );
    assert!(ok.is_ok(), "non-memory gumtrace line must be ignored");
}

// =========================================================================
// 第四轮审查修复的回归测试（向量与上文既有用例不同）
// =========================================================================

#[test]
fn unidbg_malformed_abs_suffix_fails_closed() {
    let broken = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x3000oops w0=0x2211 x1=0x3000 => w0=0x2211";
    let result = search_memory(
        format!("{broken}\n").as_bytes(),
        TraceFormat::Unidbg,
        options(&[0x11, 0x22]),
    );
    assert!(
        result.is_err(),
        "garbage after the hex address must not be a prefix"
    );
}

#[test]
fn unidbg_unknown_memory_tag_fails_closed() {
    let broken = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[XRITE] abs=0x3000 w0=0x2211 x1=0x3000 => w0=0x2211";
    let result = search_memory(
        format!("{broken}\n").as_bytes(),
        TraceFormat::Unidbg,
        options(&[0x11, 0x22]),
    );
    assert!(result.is_err(), "unknown mem[...] tag must fail closed");
}

#[test]
fn unidbg_corrupted_second_memory_marker_fails_closed() {
    let broken = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"ldp w0, w1, [x2]\" ; mem[READ] abs=0x3000 mem[WRITE] abs=0x9000oops w0=0x2211 x2=0x3000 => w0=0x2211";
    let result = search_memory(
        format!("{broken}\n").as_bytes(),
        TraceFormat::Unidbg,
        options(&[0x11, 0x22]),
    );
    assert!(
        result.is_err(),
        "a corrupt later marker must poison the event"
    );
}

#[test]
fn register_value_garbage_hex_suffix_is_not_trusted() {
    // 注解存在但值损坏：不得取十六进制前缀制造虚假匹配，写入按 unknown 失效。
    let uni = uni_write_insn(0, "str w5, [x9]", "w5=0x22113344oops x9=0x7000", 0x7000);
    let (uni_total,) = (search_memory(
        format!("{uni}\n").as_bytes(),
        TraceFormat::Unidbg,
        options(&[0x44, 0x33]),
    )
    .expect("unidbg scan")
    .total,);
    assert_eq!(
        uni_total, 0,
        "corrupt register value must not produce bytes"
    );
    let gum = gum_write_insn("str w5, [x9]", "w5=0x22113344oops x9=0x7000", 0x7000);
    let gum_total = search_memory(
        format!("{gum}\n").as_bytes(),
        TraceFormat::Gumtrace,
        options(&[0x44, 0x33]),
    )
    .expect("gumtrace scan")
    .total;
    assert_eq!(
        gum_total, 0,
        "corrupt register value must not produce bytes"
    );
}

#[test]
fn single_register_lane_store_writes_only_lane_element() {
    // st1 {v0.16b}[2]：真实内存只得到 v0.b[2]=0x02 一个字节；
    // 完整 16 字节向量或从未写过的首字节都不得匹配。
    let insn = "st1 {v0.16b}[2], [x0]";
    let ann = "x0=0x6000 q0=0x0f0e0d0c0b0a09080706050403020100";
    let uni = uni_write_insn(0, insn, &format!("{ann} => x0=0x6000"), 0x6000);
    let gum = gum_write_insn(insn, ann, 0x6000);
    let full16: Vec<u8> = (0u8..16).collect();
    let (uni_bad, gum_bad) = search_both(&uni, &gum, &full16);
    assert_eq!(
        (uni_bad, gum_bad),
        (0, 0),
        "single-register lane store must not expose the full vector"
    );
    let (uni_head, gum_head) = search_both(&uni, &gum, &[0x0f]);
    assert_eq!(
        (uni_head, gum_head),
        (0, 0),
        "bytes never stored must stay unknown"
    );
    let (uni_ok, gum_ok) = search_both(&uni, &gum, &[0x02]);
    assert_eq!((uni_ok, gum_ok), (1, 1), "the lane element itself matches");
}

#[test]
fn single_register_lane_load_reveals_only_element() {
    let insn = "ld1 {v0.16b}[2], [x0]";
    let post = "q0=0x0f0e0d0c0b0a09080706050403020100";
    let uni = uni_read_insn(0, insn, "x0=0x6100", 0x6100, post);
    let full16: Vec<u8> = (0u8..16).collect();
    let (uni_full, _) = search_both(
        &uni,
        &gum_read_insn(insn, "x0=0x6100", 0x6100, post),
        &full16,
    );
    assert_eq!(
        uni_full, 0,
        "single-register lane load must not reveal the whole vector"
    );
    let (uni_one, gum_one) = search_both(
        &uni,
        &gum_read_insn(insn, "x0=0x6100", 0x6100, post),
        &[0x02],
    );
    assert_eq!((uni_one, gum_one), (1, 1), "only the element is revealed");
}

#[test]
fn out_of_range_lane_is_fail_closed_not_panic() {
    // lane 下标越出寄存器范围：内容未知、绝不 panic，也不得伪造已知字节。
    for insn in ["st2 {v0.b, v1.b}[255]", "st1 {v0.4h}[200]"] {
        let ann =
            "x0=0x6200 q0=0x0102030405060708090a0b0c0d0e0f10 q1=0x1112131415161718191a1b1c1d1e1f20";
        let uni = uni_write_insn(0, insn, &format!("{ann} => x0=0x6200"), 0x6200);
        let result = search_memory(
            format!("{uni}\n").as_bytes(),
            TraceFormat::Unidbg,
            options(&[0x01, 0x02]),
        );
        let total = result
            .expect("out-of-range lane must degrade to unknown, not panic")
            .total;
        assert_eq!(
            total, 0,
            "{insn}: out-of-range lane fabricates no known byte"
        );
    }
}

#[test]
fn gumtrace_atomic_multi_marker_is_order_independent() {
    // seq0 写入 [5,6,7,8]；seq1 原子 RMW；seq2 把尾字节覆盖成 FF。
    // 正确语义：原子写使旧值失效 → [5,6,7,FF] 不应命中。
    let prior = gum_write_insn("str x1, [x2]", "x1=0x08070605 x2=0x5000", 0x5000);
    let tail = gum_write_insn("strb w5, [x6]", "w5=0xff x6=0x5003 mem_w=0x5003", 0x5003);
    let make = |markers: &str| {
        let rmw = format!(
            "[lib.so] 0x7522f46438!0x143438 ldadd w0, w2, [x3]; w2=0x11111111 x3=0x5000 {markers}"
        );
        format!("{prior}\n{rmw}\n{tail}\n")
    };
    let r_first = search_memory(
        make("mem_r=0x5000 mem_w=0x5000").as_bytes(),
        TraceFormat::Gumtrace,
        options(&[5, 6, 7, 0xff]),
    )
    .expect("r-first atomic line");
    let w_first = search_memory(
        make("mem_w=0x5000 mem_r=0x5000").as_bytes(),
        TraceFormat::Gumtrace,
        options(&[5, 6, 7, 0xff]),
    )
    .expect("w-first atomic line");
    assert_eq!(
        r_first.total, 0,
        "read-marker-first must still invalidate via the write half"
    );
    assert_eq!(
        w_first.total, 0,
        "write-invalidation must be order independent"
    );
}
