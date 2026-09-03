//! Activation 工具的端到端 MCP 测试：走真实 HTTP transport + tool_router，
//! 覆盖工具层响应拼装（分页双轨 has_more、DTO 序列化），不只测 Engine。
//!
//! 填补的审查缺口：integration_test 直接调 Engine 方法，工具层的
//! clamp/has_more 合成/JSON 拼装没有经过实际 router 验证。

use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use trace_core::TraceEngine;

fn parse_mcp_json(body: &str) -> serde_json::Value {
    let json = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: ").map(str::trim))
        .find(|data| !data.is_empty())
        .unwrap_or(body.trim());
    serde_json::from_str(json).unwrap_or_else(|error| panic!("invalid MCP body {body:?}: {error}"))
}

/// 含一个完整调用链的 GumTrace fixture：BL → entry → exit → resume。
fn fixture_trace() -> String {
    let mut lines = Vec::new();
    // root 上下文 3 条指令（0x82ce0 起）
    for i in 0..3 {
        lines.push(format!(
            "[libmetasec_ov.so] 0x7522f4643{}!0x82ce{} nop\n",
            i, i
        ));
    }
    // BL 调用（callsite 0x82ceC，resume 期望 0x82ce0+0x10）
    lines.push("[libmetasec_ov.so] 0x7522f4643f!0x82cec bl 0x143438\n".to_string());
    // callee 入口 + 2 条体 + 出口（0x143438 起）
    lines
        .push("[libmetasec_ov.so] 0x7522f46440!0x143438 stp x29, x30, [sp, #-0x10]!\n".to_string());
    for i in 1..3 {
        lines.push(format!(
            "[libmetasec_ov.so] 0x7522f4644{}!0x14343{} nop\n",
            i + 1,
            i
        ));
    }
    // resume 回 caller（0x82cf0 = callsite+4）
    lines.push("[libmetasec_ov.so] 0x7522f46444!0x82cf0 nop\n".to_string());
    lines.join("")
}

#[tokio::test]
async fn test_mcp_activation_tools_end_to_end() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-mcp-activation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("fixture directory");
    let trace_path = root.join("trace.log");
    std::fs::write(&trace_path, fixture_trace()).expect("fixture trace");

    let engine = Arc::new(TraceEngine::new());
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let ct = cancel.clone();
    let handle = tokio::spawn(async move {
        trace_mcp::start_sse(engine, 0, ct, ready_tx).await.unwrap();
    });
    let port = ready_rx
        .await
        .expect("ready channel closed")
        .expect("server failed to bind");
    let url = format!("http://127.0.0.1:{port}/mcp");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("http client");

    let initialize = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "activation-e2e-test", "version": "0.1.0"}
            }
        }))
        .send()
        .await
        .expect("initialize request");
    assert!(
        initialize.status().is_success(),
        "initialize: {}",
        initialize.status()
    );
    let mcp_session_id = initialize
        .headers()
        .get("mcp-session-id")
        .expect("MCP session id")
        .to_str()
        .expect("session id header")
        .to_owned();
    client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .expect("initialized notification");

    // open + build（tools/call 走真实 router；后续调用直接内联避免闭包生命周期）
    let open = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "open_trace",
                "arguments": {
                    "file_path": trace_path.to_str().expect("fixture path"),
                    "skip_strings": true
                }
            }
        }))
        .send()
        .await
        .expect("open_trace request");
    assert!(open.status().is_success(), "open_trace: {}", open.status());
    let open_text = parse_mcp_json(&open.text().await.expect("open body"))["result"]["content"][0]
        ["text"]
        .as_str()
        .expect("open text")
        .to_string();
    let open_result: serde_json::Value = serde_json::from_str(&open_text).expect("open JSON");
    let trace_session_id = open_result["session_id"]
        .as_str()
        .expect("opened session id")
        .to_string();

    // get_activation_tree 走 router：分页双轨 has_more + root 哨兵字段
    let tree_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_activation_tree",
                "arguments": {
                    "session_id": trace_session_id,
                    "offset": 0,
                    "limit": 10
                }
            }
        }))
        .send()
        .await
        .expect("activation tree request");
    assert!(
        tree_resp.status().is_success(),
        "get_activation_tree: {}",
        tree_resp.status()
    );
    let tree_text = parse_mcp_json(&tree_resp.text().await.expect("tree body"))["result"]
        ["content"][0]["text"]
        .as_str()
        .expect("tree text")
        .to_string();
    let tree: serde_json::Value = serde_json::from_str(&tree_text).expect("tree JSON");
    // 工具层响应拼装字段（integration_test 只测 Engine，这里测 router 输出）
    assert!(tree["activations_has_more"].is_boolean(), "双轨标记");
    assert!(tree["bypassed_has_more"].is_boolean(), "双轨标记");
    assert!(tree["limit"].as_u64().unwrap() <= 1000, "clamp 生效");
    let root_dto = &tree["activations"][0];
    assert_eq!(root_dto["activation"], "trace_root");
    // root 哨兵字段经工具层序列化后必须是 null（不是空串/伪身份）
    assert!(root_dto["func_addr"].is_null(), "root func_addr");
    assert!(root_dto["entry_pc"].is_null(), "root entry_pc");
    assert!(
        root_dto["expected_resume"].is_null(),
        "root expected_resume"
    );
    assert!(root_dto["call_pc"].is_null(), "root call_pc");
    // 完整调用链：root + 1 个 confirmed activation
    let confirmed: Vec<_> = tree["activations"]
        .as_array()
        .expect("activations")
        .iter()
        .filter(|a| a["unresolved_reason"].is_null())
        .collect();
    assert_eq!(
        confirmed.len(),
        2,
        "root + 1 confirmed（root 无 unresolved）"
    );
    let act = confirmed
        .iter()
        .find(|a| a["id"].as_u64() != Some(0))
        .expect("non-root confirmed");
    assert!(
        act["func_addr"]
            .as_str()
            .unwrap()
            .starts_with("libmetasec_ov.so+0x"),
        "稳定身份: {}",
        act["func_addr"]
    );

    // get_instruction_owner 走 router：resume 行归属 caller 上下文
    let owner_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "get_instruction_owner",
                "arguments": {
                    "session_id": trace_session_id,
                    "seq": 3
                }
            }
        }))
        .send()
        .await
        .expect("owner request");
    assert!(
        owner_resp.status().is_success(),
        "get_instruction_owner: {}",
        owner_resp.status()
    );
    let owner_text = parse_mcp_json(&owner_resp.text().await.expect("owner body"))["result"]
        ["content"][0]["text"]
        .as_str()
        .expect("owner text")
        .to_string();
    let owner: serde_json::Value = serde_json::from_str(&owner_text).expect("owner JSON");
    assert_eq!(owner["seq"], 3);
    assert_eq!(owner["position"], "call", "seq 3 是 BL 调用行");
    assert!(
        owner["opens"].as_str().unwrap().starts_with("activation:"),
        "opens: {:?}",
        owner["opens"]
    );

    // 越界 seq：工具层错误路径（isError，不 panic）
    let bad_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "get_instruction_owner",
                "arguments": {
                    "session_id": trace_session_id,
                    "seq": 99999
                }
            }
        }))
        .send()
        .await
        .expect("bad owner request");
    let bad_body = parse_mcp_json(&bad_resp.text().await.expect("bad body"));
    let bad_text = bad_body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        bad_body["result"]["isError"].as_bool() == Some(true)
            || bad_text.contains("超出")
            || bad_body["error"].is_object(),
        "越界 seq 错误路径: {bad_body}"
    );

    cancel.cancel();
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(root);
}
