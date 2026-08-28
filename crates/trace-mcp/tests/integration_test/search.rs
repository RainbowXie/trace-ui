//! 搜索与污点分析测试。

use super::*;

#[test]
fn test_search_instructions() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .search(
            &sid,
            "str",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: Some(50),
            },
        )
        .expect("search");
    assert!(result.total_matches > 0, "should find 'str' instructions");

    // Verify get_lines works on search results (the fix for error swallowing)
    let preview: Vec<u32> = result.match_seqs.iter().copied().take(10).collect();
    let lines = engine
        .get_lines(&sid, &preview)
        .expect("get_lines on search results should not fail");
    assert!(!lines.is_empty());

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_search_regex() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .search(
            &sid,
            "bl.*0x",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: true,
                fuzzy: false,
                max_results: Some(50),
            },
        )
        .expect("regex search");
    // bl instructions exist in the trace
    assert!(result.total_scanned > 0);

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 污点分析 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_taint_analysis_full_workflow() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Run taint analysis on a register
    let result = engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            },
        )
        .expect("run_slice");
    assert!(result.marked_count > 0, "should mark some lines as tainted");
    assert!(result.total_lines > 0);

    // Get tainted sequences
    let tainted = engine.get_tainted_seqs(&sid).expect("get_tainted_seqs");
    assert_eq!(tainted.len(), result.marked_count as usize);

    // Get tainted lines (the error propagation fix)
    let lines = engine
        .get_lines(&sid, &tainted[..tainted.len().min(10)])
        .expect("get_lines on tainted seqs should not fail");
    assert!(!lines.is_empty());

    // Clear taint
    engine.clear_slice(&sid).expect("clear_slice");
    let after_clear = engine
        .get_tainted_seqs(&sid)
        .expect("get_tainted_seqs after clear");
    assert!(
        after_clear.is_empty(),
        "tainted seqs should be empty after clear"
    );

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_taint_analysis_data_only() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .run_slice(
            &sid,
            &["reg:x0@last".to_string()], // lowercase, testing case-insensitivity
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("run_slice data_only");
    assert!(result.marked_count > 0);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_taint_analysis_with_range() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).unwrap();
    let mid = info.total_lines / 2;

    let result = engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: Some(0),
                end_seq: Some(mid),
                data_only: false,
            },
        )
        .expect("run_slice with range");
    // With end_seq restriction, marked_count should be <= total
    assert!(result.marked_count <= mid + 1);

    engine.close_session(&sid).unwrap();
}
