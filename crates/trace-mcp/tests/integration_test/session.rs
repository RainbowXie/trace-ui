//! 会话管理与数据查看测试。

use super::*;

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
    let _lines = engine
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
