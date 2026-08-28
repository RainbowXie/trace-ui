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
