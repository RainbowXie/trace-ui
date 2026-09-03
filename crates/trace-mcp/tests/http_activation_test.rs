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

/// 含一个完整调用链 + 一个 bypassed 调用的 GumTrace fixture。
///
/// PC 设计（激活匹配用 runtime PC，即 `!` 左侧；module offset 仅身份）：
/// - seq 0..2: root 指令（runtime 0x7522f46430..32）
/// - seq 3: BL runtime 0x7522f46434 → expected_resume = 0x7522f46438
/// - seq 4..6: callee 体（entry 0x7522f46440 = BL target 0x143438 的 runtime 行）
/// - seq 7: runtime 0x7522f46438 == callsite+4 → resume 在此关闭 activation
/// - seq 8: BL runtime 0x7522f46439 → expected_resume = 0x7522f4643d
/// - seq 9: runtime 0x7522f4643d == callsite+4，无函数体 → bypassed
fn fixture_trace() -> String {
    let mut lines = Vec::new();
    for i in 0..3 {
        lines.push(format!(
            "[libmetasec_ov.so] 0x7522f4643{}!0x82ce{} nop\n",
            i, i
        ));
    }
    // BL 调用（runtime callsite 0x7522f46434，期望 resume 0x7522f46438）
    lines.push("[libmetasec_ov.so] 0x7522f46434!0x82cec bl 0x143438\n".to_string());
    // callee 入口（module 0x143438 == BL target）+ 2 条体
    lines
        .push("[libmetasec_ov.so] 0x7522f46440!0x143438 stp x29, x30, [sp, #-0x10]!\n".to_string());
    lines.push("[libmetasec_ov.so] 0x7522f46441!0x143439 nop\n".to_string());
    lines.push("[libmetasec_ov.so] 0x7522f46442!0x14343a nop\n".to_string());
    // resume：runtime 0x7522f46438 == callsite(0x7522f46434)+4
    lines.push("[libmetasec_ov.so] 0x7522f46438!0x82cf0 nop\n".to_string());
    // bypassed：BL 后一行即 callsite+4（目标无函数体）
    lines.push("[libmetasec_ov.so] 0x7522f46439!0x82ce4 bl 0x14344c\n".to_string());
    lines.push("[libmetasec_ov.so] 0x7522f4643d!0x82ce8 nop\n".to_string());
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

    // get_activation_tree 走 router：分页双轨 has_more + root 哨兵字段。
    // limit=5000 触发工具层 clamp——断言返回值恰为 1000 才证明 clamp 生效。
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
                    "limit": 5000
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
    assert_eq!(tree["limit"].as_u64(), Some(1000), "clamp 5000→1000");
    assert!(!tree["activations_has_more"].as_bool().unwrap_or(true));
    assert!(!tree["bypassed_has_more"].as_bool().unwrap_or(true));
    // 双轨分页不对称：offset=0 limit=1 只拿 root——activations 还有 1 个
    // confirmed（has_more=true），bypassed 仅 1 个恰好拿完（has_more=false）。
    let page_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "get_activation_tree",
                "arguments": {
                    "session_id": trace_session_id,
                    "offset": 0,
                    "limit": 1
                }
            }
        }))
        .send()
        .await
        .expect("activation page request");
    let page_text = parse_mcp_json(&page_resp.text().await.expect("page body"))["result"]
        ["content"][0]["text"]
        .as_str()
        .expect("page text")
        .to_string();
    let page: serde_json::Value = serde_json::from_str(&page_text).expect("page JSON");
    assert_eq!(
        page["activations"].as_array().map(Vec::len),
        Some(1),
        "limit=1 截 activations"
    );
    assert_eq!(
        page["bypassed_calls"].as_array().map(Vec::len),
        Some(1),
        "limit=1 截 bypassed"
    );
    assert!(
        page["activations_has_more"].as_bool() == Some(true),
        "activations 还有第二页"
    );
    assert!(
        page["bypassed_has_more"].as_bool() == Some(false),
        "bypassed 恰拿完"
    );
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
    // 完整调用链：root + 1 confirmed；counts 必须与分页内容一致
    let activations = tree["activations"].as_array().expect("activations");
    let confirmed: Vec<_> = activations
        .iter()
        .filter(|a| a["unresolved_reason"].is_null())
        .collect();
    assert_eq!(confirmed.len(), 2, "root + 1 confirmed");
    assert_eq!(tree["total_activations"].as_u64(), Some(2));
    assert_eq!(
        tree["confirmed_count"].as_u64(),
        Some(1),
        "confirmed 排除 root"
    );
    assert_eq!(tree["unresolved_count"].as_u64(), Some(0));
    // counts 生产路径验证：一页（limit=1000）已拿全部内容，DTO 计数
    // 必须等于从内容重新统计的值（而非同一公式的镜像）
    let content_confirmed = confirmed.len() - 1; // 排除 root
    let content_unresolved = activations.len() - confirmed.len();
    assert_eq!(
        tree["confirmed_count"].as_u64(),
        Some(content_confirmed as u64)
    );
    assert_eq!(
        tree["unresolved_count"].as_u64(),
        Some(content_unresolved as u64)
    );
    // bypassed：1 个，地址为稳定 module 表示
    let bypassed = tree["bypassed_calls"].as_array().expect("bypassed");
    assert_eq!(bypassed.len(), 1);
    assert!(
        bypassed[0]["call_pc"]
            .as_str()
            .is_some_and(|s| s.starts_with("libmetasec_ov.so+0x")),
        "bypassed 稳定身份: {:?}",
        bypassed[0]["call_pc"]
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
    // 边界事实：entry=seq 4，exit=seq 6（体最后一条），resume 在 seq 7
    assert_eq!(act["entry_seq"].as_u64(), Some(4));
    assert_eq!(act["exit_seq"].as_u64(), Some(6));

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

    // resume 边界：seq 7（runtime == callsite+4）必须归属 caller 且
    // 关闭该 activation——之前 fixture PC 错位在 seq 6 提前关闭。
    let resume_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {
                "name": "get_instruction_owner",
                "arguments": {
                    "session_id": trace_session_id,
                    "seq": 7
                }
            }
        }))
        .send()
        .await
        .expect("resume owner request");
    let resume_text = parse_mcp_json(&resume_resp.text().await.expect("resume body"))["result"]
        ["content"][0]["text"]
        .as_str()
        .expect("resume text")
        .to_string();
    let resume_owner: serde_json::Value = serde_json::from_str(&resume_text).expect("resume JSON");
    assert_eq!(resume_owner["position"], "resume", "seq 7 是 resume 行");
    assert!(
        resume_owner["closes"]
            .as_str()
            .unwrap()
            .starts_with("activation:"),
        "seq 7 closes: {:?}",
        resume_owner["closes"]
    );
    // seq 6（体最后一条）仍属 callee 内部，不得提前关闭
    let body_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 45,
            "method": "tools/call",
            "params": {
                "name": "get_instruction_owner",
                "arguments": {
                    "session_id": trace_session_id,
                    "seq": 6
                }
            }
        }))
        .send()
        .await
        .expect("body owner request");
    let body_text = parse_mcp_json(&body_resp.text().await.expect("body owner body"))["result"]
        ["content"][0]["text"]
        .as_str()
        .expect("body owner text")
        .to_string();
    let body_owner: serde_json::Value = serde_json::from_str(&body_text).expect("body JSON");
    assert_eq!(
        body_owner["position"], "exit",
        "seq 6 是 activation 体最后一条（exit），不得提前关闭"
    );
    assert!(
        body_owner["closes"].is_null() || body_owner["closes"].as_str().is_none_or(str::is_empty),
        "seq 6 不得关闭 activation: {:?}",
        body_owner["closes"]
    );
    // bypassed：seq 8 是调用行但无函数体，不 opens activation
    let by_resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 46,
            "method": "tools/call",
            "params": {
                "name": "get_instruction_owner",
                "arguments": {
                    "session_id": trace_session_id,
                    "seq": 8
                }
            }
        }))
        .send()
        .await
        .expect("bypassed owner request");
    let by_text = parse_mcp_json(&by_resp.text().await.expect("bypassed body"))["result"]
        ["content"][0]["text"]
        .as_str()
        .expect("bypassed text")
        .to_string();
    let by_owner: serde_json::Value = serde_json::from_str(&by_text).expect("bypassed JSON");
    // bypassed 行 opens 的是 bypassed 区间（"bypassed:N"），绝非 activation
    let opens = by_owner["opens"].as_str().unwrap_or_default();
    assert!(
        opens.starts_with("bypassed:"),
        "bypassed opens 标记: {:?}",
        by_owner["opens"]
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
