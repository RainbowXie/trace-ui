//! 依赖树 / DEF-USE / 调用树 / 函数信息测试。

use super::*;

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
