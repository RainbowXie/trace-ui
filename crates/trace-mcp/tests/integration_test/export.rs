//! 污点结果导出测试。

use super::*;

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
