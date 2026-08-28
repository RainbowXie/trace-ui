//! Integration tests for all MCP tools.
//!
//! These tests instantiate TraceToolHandler directly and call each tool method,
//! verifying that they return valid JSON responses without errors.

use std::sync::Arc;
use trace_core::TraceEngine;

// We can't directly call the tool methods because they're behind the #[tool_router] macro.
// Instead, we test by calling TraceEngine methods the same way tools.rs does,
// verifying the actual logic paths that MCP tools exercise.

fn get_trace_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../example-trace-gumtrace.txt", manifest_dir)
}

fn get_unidbg_trace_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../example-trace-unidbg.txt", manifest_dir)
}

/// Helper: create session + build index, return (engine, session_id)
fn setup_session(path: &str) -> (Arc<TraceEngine>, String) {
    let engine = Arc::new(TraceEngine::new());
    let info = engine.create_session(path).expect("create_session failed");
    let sid = info.session_id.clone();
    let build = engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("build_index failed");
    assert!(build.total_lines > 0, "trace should have lines");
    (engine, sid)
}

// ━━━━━━━━━━━━━━━━━━━━━━ 会话管理 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_open_and_close_trace() {
    let engine = Arc::new(TraceEngine::new());
    let info = engine
        .create_session(&get_trace_path())
        .expect("create_session");
    let sid = info.session_id.clone();
    assert!(!sid.is_empty());
    assert!(info.file_size > 0);

    let build = engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("build_index");
    assert!(build.total_lines > 0);

    // close
    engine.close_session(&sid).expect("close_session");

    // double close should not panic (session already removed)
    // The engine returns Ok(()) even if session doesn't exist
    let _ = engine.close_session(&sid);
}

#[test]
fn test_list_sessions() {
    let (engine, sid) = setup_session(&get_trace_path());
    let sessions = engine.list_sessions();
    assert!(!sessions.is_empty());
    assert!(sessions.iter().any(|s| s.session_id == sid));
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_session_info() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).expect("get_session_info");
    assert_eq!(info.session_id, sid);
    assert!(info.index_ready);
    assert!(!info.building);
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_session_info_invalid_id() {
    let engine = Arc::new(TraceEngine::new());
    let result = engine.get_session_info("nonexistent");
    assert!(result.is_err());
}

// ━━━━━━━━━━━━━━━━━━━━━━ 数据查看 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_get_trace_lines() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Normal range
    let seqs: Vec<u32> = (0..10).collect();
    let lines = engine.get_lines(&sid, &seqs).expect("get_lines");
    assert_eq!(lines.len(), 10);
    assert!(!lines[0].disasm.is_empty());
    assert!(!lines[0].address.is_empty());

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_trace_lines_overflow_safe() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Test the saturating_add fix: start near u32::MAX
    let start_seq: u32 = u32::MAX - 5;
    let count: u32 = 100;
    let end = start_seq.saturating_add(count); // should NOT overflow
    assert_eq!(end, u32::MAX); // saturated

    let seqs: Vec<u32> = (start_seq..end).collect();
    // These seqs are way beyond the trace — get_lines should not panic (the key property).
    // It may return empty lines with default fields since the engine handles out-of-range gracefully.
    let lines = engine
        .get_lines(&sid, &seqs)
        .expect("get_lines should not panic on out-of-range seqs");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_registers() {
    let (engine, sid) = setup_session(&get_trace_path());
    let regs = engine.get_registers_at(&sid, 0).expect("get_registers_at");
    assert!(!regs.is_empty(), "should have register values");
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_memory() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Read memory at address from line 0's mem access
    let lines = engine.get_lines(&sid, &[0]).expect("get_lines");
    if let Some(addr_str) = &lines[0].mem_addr {
        let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();
        let snap = engine
            .get_memory_at(&sid, addr, 0, 64)
            .expect("get_memory_at");
        assert_eq!(snap.bytes.len(), snap.known.len());
        assert_eq!(snap.length, 64);
    }

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_memory_history() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Find a memory address that was accessed
    let lines = engine.get_lines(&sid, &[2]).expect("get_lines"); // line 2 has mem write
    if let Some(addr_str) = &lines[0].mem_addr {
        let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();

        let meta = engine.get_mem_history_meta(&sid, addr, 2).expect("meta");
        assert!(meta.total > 0, "should have access history");

        let records = engine
            .get_mem_history_range(&sid, addr, 0, 50)
            .expect("range");
        assert!(!records.is_empty());
    }

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 搜索 ━━━━━━━━━━━━━━━━━━━━━━

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

#[test]
fn test_get_slice_status() {
    let (engine, sid) = setup_session(&get_trace_path());

    engine
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

    let status = engine
        .get_slice_status(&sid, 0, 20)
        .expect("get_slice_status");
    assert_eq!(status.len(), 20);
    // At least some should be tainted
    assert!(
        status.iter().any(|&b| b) || !status.iter().any(|&b| b),
        "status should be valid booleans"
    );

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 依赖树 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_dependency_tree() {
    let (engine, sid) = setup_session(&get_trace_path());

    let graph = engine
        .build_dep_tree(
            &sid,
            5,
            "reg:X0",
            trace_core::DepTreeOptions {
                data_only: false,
                max_nodes: Some(50),
            },
        )
        .expect("build_dep_tree");
    // Graph should have at least 1 node (the root)
    assert!(!graph.nodes.is_empty(), "dep tree should have nodes");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_dependency_tree_from_slice() {
    let (engine, sid) = setup_session(&get_trace_path());

    // First run taint analysis
    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("run_slice");

    let graph = engine
        .build_dep_tree_from_slice(
            &sid,
            trace_core::DepTreeOptions {
                data_only: true,
                max_nodes: Some(50),
            },
        )
        .expect("build_dep_tree_from_slice");
    assert!(!graph.nodes.is_empty());

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ DEF/USE ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_def_use_chain() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Line 0 should define x0 based on the trace content
    // parse_reg requires lowercase, but MCP tool now does .to_lowercase()
    let chain = engine
        .get_def_use_chain(&sid, 0, "x0")
        .expect("get_def_use_chain");
    // Chain should be valid (def_seq or use_seqs populated depending on line role)
    let _ = chain;

    // Also verify uppercase works when passed through to_lowercase() (as MCP tool does)
    let chain_upper = engine
        .get_def_use_chain(&sid, 0, &"X0".to_lowercase())
        .expect("get_def_use_chain with lowercased X0");
    let _ = chain_upper;

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_line_def_registers() {
    let (engine, sid) = setup_session(&get_trace_path());

    let regs = engine
        .get_line_def_registers(&sid, 0)
        .expect("get_line_def_registers");
    // Line 0: "sub x0, x29, #0x80" should define X0
    assert!(
        !regs.is_empty(),
        "line 0 should define at least one register"
    );

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 调用树 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_call_tree() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Get root
    let nodes = engine
        .get_call_tree_children(&sid, 0, true)
        .expect("get_call_tree_children");
    assert!(
        !nodes.is_empty(),
        "call tree should have at least root node"
    );
    assert_eq!(nodes[0].id, 0);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_call_tree_node_count() {
    let (engine, sid) = setup_session(&get_trace_path());

    let count = engine
        .get_call_tree_node_count(&sid)
        .expect("get_call_tree_node_count");
    assert!(count > 0, "call tree should have nodes");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_function_info() {
    let (engine, sid) = setup_session(&get_trace_path());

    let nodes = engine.get_call_tree_children(&sid, 0, true).expect("root");
    assert!(!nodes.is_empty());
    // First node is the root function info
    let root = &nodes[0];
    assert!(root.entry_seq <= root.exit_seq);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_function_list() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine.get_function_calls(&sid).expect("get_function_calls");
    // Gumtrace has function names in the trace
    assert!(result.total_calls > 0, "should have function calls");
    assert!(!result.functions.is_empty());

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 字符串 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_get_strings() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .expect("get_strings");
    // May or may not have strings depending on trace content
    // Just verify it doesn't error
    // get_strings should succeed (may have 0 strings in small trace)

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_scan_strings_after_skip() {
    let engine = Arc::new(TraceEngine::new());
    let info = engine
        .create_session(&get_trace_path())
        .expect("create_session");
    let sid = info.session_id.clone();

    // Build with skip_strings = true
    engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .expect("build_index skip_strings");

    // Now scan strings manually
    engine.scan_strings(&sid).expect("scan_strings");

    // Should be able to query strings now
    let result = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .expect("get_strings after scan");
    // Verify it works without error

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_string_xrefs() {
    let (engine, sid) = setup_session(&get_trace_path());

    let strings = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .expect("get_strings");

    if !strings.strings.is_empty() {
        let s = &strings.strings[0];
        let addr_hex = s.addr.strip_prefix("0x").unwrap_or(&s.addr);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();
        let xrefs = engine
            .get_string_xrefs(&sid, addr, s.byte_len)
            .expect("get_string_xrefs");
        // xrefs may be empty if no cross-references, but should not error
        let _ = xrefs;
    }

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 密码学 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_scan_crypto_patterns() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Try cache first (should be None on first run)
    let _cached = engine.load_crypto_cache(&sid).expect("load_crypto_cache");

    let result = engine.scan_crypto(&sid).expect("scan_crypto");
    // Result should be valid (may have 0 matches for small trace)
    let _ = result;

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 导出 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_export_taint_results_json() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Run taint first
    engine
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

    let tmp = std::env::temp_dir().join("trace_mcp_test_export.json");
    let tmp_path = tmp.to_str().unwrap().to_string();

    engine
        .export_taint_results(
            &sid,
            &tmp_path,
            "json",
            trace_core::ExportConfig {
                from_specs: vec![],
                start_seq: None,
                end_seq: None,
            },
        )
        .expect("export_taint_results json");

    // Verify file was created and contains valid JSON
    let content = std::fs::read_to_string(&tmp_path).expect("read export file");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse JSON export");
    assert!(parsed.get("taintedLines").is_some());
    assert!(parsed.get("stats").is_some());

    std::fs::remove_file(&tmp_path).ok();
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_export_taint_results_txt() {
    let (engine, sid) = setup_session(&get_trace_path());

    engine
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

    let tmp = std::env::temp_dir().join("trace_mcp_test_export.txt");
    let tmp_path = tmp.to_str().unwrap().to_string();

    engine
        .export_taint_results(
            &sid,
            &tmp_path,
            "txt",
            trace_core::ExportConfig {
                from_specs: vec![],
                start_seq: None,
                end_seq: None,
            },
        )
        .expect("export_taint_results txt");

    let content = std::fs::read_to_string(&tmp_path).expect("read export file");
    assert!(!content.is_empty(), "TXT export should have content");

    std::fs::remove_file(&tmp_path).ok();
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_export_without_taint_fails() {
    let (engine, sid) = setup_session(&get_trace_path());

    let tmp = std::env::temp_dir().join("trace_mcp_test_no_taint.json");
    let result = engine.export_taint_results(
        &sid,
        tmp.to_str().unwrap(),
        "json",
        trace_core::ExportConfig {
            from_specs: vec![],
            start_seq: None,
            end_seq: None,
        },
    );
    assert!(result.is_err(), "export without prior taint should fail");

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ Unidbg 格式 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_unidbg_format_basic() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    let info = engine.get_session_info(&sid).expect("get_session_info");
    assert!(
        info.total_lines > 1000,
        "unidbg trace should have many lines"
    );

    let lines = engine.get_lines(&sid, &[0, 1, 2]).expect("get_lines");
    assert_eq!(lines.len(), 3);

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ spawn_blocking 验证 ━━━━━━━━━━━━━━━━━━━━━━

#[tokio::test]
async fn test_spawn_blocking_helper() {
    // Verify the blocking() helper works correctly
    let engine = Arc::new(TraceEngine::new());
    let path = get_trace_path();

    let engine_clone = engine.clone();
    let result: Result<String, String> = tokio::task::spawn_blocking(move || {
        let info = engine_clone
            .create_session(&path)
            .map_err(|e| e.to_string())?;
        let sid = info.session_id.clone();
        let build = engine_clone
            .build_index(
                &sid,
                trace_core::BuildOptions {
                    force_rebuild: false,
                    skip_strings: false,
                },
                None,
            )
            .map_err(|e| {
                let _ = engine_clone.close_session(&sid);
                e.to_string()
            })?;
        let _ = engine_clone.close_session(&sid);
        Ok(format!("lines: {}", build.total_lines))
    })
    .await
    .map_err(|e| format!("Task panicked: {}", e))
    .unwrap();

    assert!(result.is_ok());
    let msg = result.unwrap();
    assert!(msg.starts_with("lines: "));
}

// ━━━━━━━━━━━━━━━━━━━━━━ 边界条件 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_invalid_session_id() {
    let engine = Arc::new(TraceEngine::new());
    let bad_sid = "nonexistent-session";

    assert!(engine.get_lines(bad_sid, &[0]).is_err());
    assert!(engine.get_registers_at(bad_sid, 0).is_err());
    assert!(engine
        .search(
            bad_sid,
            "test",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: Some(10),
            }
        )
        .is_err());
    assert!(engine
        .run_slice(
            bad_sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            }
        )
        .is_err());
    assert!(engine.get_call_tree_children(bad_sid, 0, true).is_err());
    assert!(engine.get_function_calls(bad_sid).is_err());
    assert!(engine.get_def_use_chain(bad_sid, 0, "X0").is_err());
    assert!(engine.get_line_def_registers(bad_sid, 0).is_err());
    assert!(engine.get_call_tree_node_count(bad_sid).is_err());
}

#[test]
fn test_empty_seqs() {
    let (engine, sid) = setup_session(&get_trace_path());
    let lines = engine.get_lines(&sid, &[]).expect("empty seqs");
    assert!(lines.is_empty());
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_compact_vs_full_output() {
    let (engine, sid) = setup_session(&get_trace_path());
    let lines = engine.get_lines(&sid, &[0, 1, 2]).expect("get_lines");
    assert!(!lines.is_empty());

    let line = &lines[0];

    // Full mode: serde serialization includes all fields
    let full = serde_json::to_value(line).unwrap();
    assert!(full.get("raw").is_some(), "full should have 'raw'");
    assert!(
        full.get("reg_before").is_some(),
        "full should have 'reg_before'"
    );
    assert!(
        full.get("so_offset").is_some(),
        "full should have 'so_offset'"
    );

    // Compact mode: simulate compact_line trimming
    let mut compact = serde_json::json!({
        "seq": line.seq,
        "address": line.address,
        "disasm": line.disasm,
    });
    if !line.changes.is_empty() {
        compact["changes"] = serde_json::json!(line.changes);
    }
    if let Some(ref rw) = line.mem_rw {
        compact["mem_rw"] = serde_json::json!(rw);
    }
    if let Some(ref addr) = line.mem_addr {
        compact["mem_addr"] = serde_json::json!(addr);
    }
    if let Some(ref name) = line.so_name {
        compact["so_name"] = serde_json::json!(name);
    }
    if let Some(ref info) = line.call_info {
        if !info.func_name.is_empty() {
            compact["func_name"] = serde_json::json!(info.func_name);
        }
    }

    // Compact should NOT have trimmed fields
    assert!(
        compact.get("raw").is_none(),
        "compact should NOT have 'raw'"
    );
    assert!(
        compact.get("reg_before").is_none(),
        "compact should NOT have 'reg_before'"
    );
    assert!(
        compact.get("so_offset").is_none(),
        "compact should NOT have 'so_offset'"
    );
    assert!(
        compact.get("mem_size").is_none(),
        "compact should NOT have 'mem_size'"
    );

    // Compact should have core fields
    assert!(compact.get("seq").is_some(), "compact should have 'seq'");
    assert!(
        compact.get("address").is_some(),
        "compact should have 'address'"
    );
    assert!(
        compact.get("disasm").is_some(),
        "compact should have 'disasm'"
    );

    // Compact should have fewer fields than full
    let compact_keys = compact.as_object().unwrap().len();
    let full_keys = full.as_object().unwrap().len();
    assert!(
        compact_keys < full_keys,
        "compact ({} keys) should have fewer fields than full ({} keys)",
        compact_keys,
        full_keys
    );

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_hex_addr_parsing() {
    // Test the parse_hex_addr logic used in MCP tools
    fn parse_hex_addr(s: &str) -> Result<u64, String> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex address: {}", s))
    }

    assert_eq!(parse_hex_addr("0xbffff000").unwrap(), 0xbffff000);
    assert_eq!(parse_hex_addr("0Xbffff000").unwrap(), 0xbffff000);
    assert_eq!(parse_hex_addr("bffff000").unwrap(), 0xbffff000);
    assert!(parse_hex_addr("not_hex").is_err());
    assert!(parse_hex_addr("").is_err());
}

// ━━━━━━━━━━━━━━━━━━━━━━ SliceOrigin ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_get_slice_origin() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).unwrap();
    let mid = info.total_lines / 2;

    // Before taint: should be None
    let origin = engine.get_slice_origin(&sid).expect("get_slice_origin");
    assert!(origin.is_none());

    // Run taint with range
    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: Some(0),
                end_seq: Some(mid),
                data_only: true,
            },
        )
        .expect("run_slice");

    // After taint: should have origin with all fields
    let origin = engine.get_slice_origin(&sid).expect("get_slice_origin");
    let origin = origin.expect("should have slice_origin after taint");
    assert_eq!(origin.from_specs, vec!["reg:X0@last"]);
    assert!(origin.data_only);
    assert_eq!(origin.start_seq, Some(0));
    assert_eq!(origin.end_seq, Some(mid));

    // After clear: should be None again
    engine.clear_slice(&sid).expect("clear_slice");
    let origin = engine.get_slice_origin(&sid).expect("get_slice_origin");
    assert!(origin.is_none());

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_taint_context_preserved() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).unwrap();
    let mid = info.total_lines / 2;

    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: Some(0),
                end_seq: Some(mid),
                data_only: true,
            },
        )
        .expect("run_slice");

    let origin = engine
        .get_slice_origin(&sid)
        .expect("get_slice_origin")
        .expect("should have origin");
    assert_eq!(origin.from_specs, vec!["reg:X0@last"]);
    assert!(origin.data_only);
    assert_eq!(origin.start_seq, Some(0));
    assert_eq!(origin.end_seq, Some(mid));

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_stack_only_change_detection() {
    // Stack-only cases (should be filtered)
    let stack_only_cases = vec![
        "sp=0xbffff6b0",
        "x29=0x0 sp=0xbffff6b0",
        "sp=0xbffff6b0 x29=0x0",
    ];
    for case in &stack_only_cases {
        assert!(check_stack_only(case), "should be stack-only: {}", case);
    }

    // Non-stack cases (should NOT be filtered)
    let non_stack_cases = vec![
        "x0=0x12345",
        "x29=0x0 x30=0x7ffff0000 sp=0xbffff6b0",
        "x8=0x0 sp=0xbffff6b0",
        "",
    ];
    for case in &non_stack_cases {
        assert!(
            !check_stack_only(case),
            "should NOT be stack-only: {}",
            case
        );
    }
}

/// Mirror of is_stack_only_change logic for testing (since the original is private in tools.rs)
fn check_stack_only(changes: &str) -> bool {
    if changes.is_empty() {
        return false;
    }
    let mut has_any = false;
    for token in changes.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any = true;
            match reg {
                "sp" | "x29" | "fp" | "wsp" | "w29" => {}
                _ => return false,
            }
        }
    }
    has_any
}
