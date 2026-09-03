//! Unidbg 格式、spawn_blocking、边界条件与输出比较测试。

use super::*;

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
    // 持锁 + 独立目录：不取锁直接 build 会与其他测试的隔离目录切换竞争，
    // 在同一缓存文件上双写（File::create 截断可让已 mmap 的会话 SIGBUS）。
    // 锁在 spawn_blocking 闭包内持有（MutexGuard 不能跨 await；目录设置
    // 也必须在锁内，否则与锁内切目录的测试竞争）。
    let dir = std::env::temp_dir().join(format!("trace-ui-itest-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create isolated cache dir");

    let engine = Arc::new(TraceEngine::new());
    let path = get_trace_path();

    let engine_clone = engine.clone();
    let result: Result<String, String> = tokio::task::spawn_blocking(move || {
        let _guard = trace_core::cache::cache_dir_override_test_lock();
        trace_core::cache::set_cache_dir_override(Some(dir));
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
