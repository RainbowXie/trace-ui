//! End-to-end HTTP test for the MCP server transport layer.

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

#[tokio::test]
async fn test_mcp_http_endpoint_reachable() {
    let engine = Arc::new(TraceEngine::new());
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let ct = cancel.clone();
    let handle = tokio::spawn(async move {
        trace_mcp::start_sse(engine, 0, ct, ready_tx).await.unwrap();
    });

    // Wait for server to be ready
    let port = ready_rx
        .await
        .expect("ready channel closed")
        .expect("server failed to bind");

    let url = format!("http://127.0.0.1:{}/mcp", port);

    // Send a POST request (MCP uses POST for Streamable HTTP)
    // no_proxy ensures we bypass any system proxy for loopback requests
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("failed to build client");
    let resp = client
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
                "clientInfo": {
                    "name": "test-client",
                    "version": "0.1.0"
                }
            }
        }))
        .send()
        .await
        .expect("request failed");

    assert!(
        resp.status().is_success(),
        "Expected 2xx, got {}",
        resp.status()
    );

    // Cleanup
    cancel.cancel();
    let _ = handle.await;
}

#[tokio::test]
async fn test_mcp_real_session_lists_and_calls_search_memory() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-mcp-search-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("fixture directory");
    let trace_path = root.join("trace.log");
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    )
    .expect("fixture trace");

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
                "clientInfo": {"name": "target-discovery-test", "version": "0.1.0"}
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
    let initialize_raw = initialize.text().await.expect("initialize body");
    let initialize_body = parse_mcp_json(&initialize_raw);
    assert_eq!(initialize_body["id"], 1);

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

    let tools_list = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await
        .expect("tools/list request");
    assert!(
        tools_list.status().is_success(),
        "tools/list: {}",
        tools_list.status()
    );
    let tools_list_raw = tools_list.text().await.expect("tools/list body");
    let tools_list_body = parse_mcp_json(&tools_list_raw);
    let names = tools_list_body["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(
        names.contains(&"search_memory"),
        "registered tools: {names:?}"
    );
    let search_tool = tools_list_body["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .find(|tool| tool["name"] == "search_memory")
        .expect("search_memory tool");
    assert!(
        search_tool["inputSchema"].is_object(),
        "search_memory schema missing"
    );

    let open = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
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
    let open_raw = open.text().await.expect("open_trace body");
    let open_body = parse_mcp_json(&open_raw);
    let open_text = open_body["result"]["content"][0]["text"]
        .as_str()
        .expect("open text");
    let open_result: serde_json::Value = serde_json::from_str(open_text).expect("open result JSON");
    let trace_session_id = open_result["session_id"]
        .as_str()
        .expect("opened session id");

    let search = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "search_memory",
                "arguments": {
                    "session_id": trace_session_id,
                    "pattern": "01020304",
                    "offset": 0,
                    "limit": 1
                }
            }
        }))
        .send()
        .await
        .expect("search_memory request");
    assert!(
        search.status().is_success(),
        "search_memory: {}",
        search.status()
    );
    let search_raw = search.text().await.expect("search body");
    let search_body = parse_mcp_json(&search_raw);
    let search_text = search_body["result"]["content"][0]["text"]
        .as_str()
        .expect("search text");
    let search_result: serde_json::Value =
        serde_json::from_str(search_text).expect("search result JSON");
    assert_eq!(search_result["total"], 2);
    assert_eq!(search_result["matches"][0]["seq"], 0);
    assert_eq!(search_result["matches"][0]["bytes"], "01020304");

    let search_page_two = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "search_memory",
                "arguments": {
                    "session_id": trace_session_id,
                    "pattern": "01020304",
                    "offset": 1,
                    "limit": 1
                }
            }
        }))
        .send()
        .await
        .expect("search page two request");
    let page_two_body =
        parse_mcp_json(&search_page_two.text().await.expect("search page two body"));
    let page_two_text = page_two_body["result"]["content"][0]["text"]
        .as_str()
        .expect("page two text");
    let page_two_result: serde_json::Value =
        serde_json::from_str(page_two_text).expect("page two JSON");
    assert_eq!(page_two_result["total"], 2);
    assert_eq!(page_two_result["matches"][0]["seq"], 2);

    let invalid = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &mcp_session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "search_memory",
                "arguments": {
                    "session_id": trace_session_id,
                    "pattern": "01020304",
                    "offset": 0,
                    "limit": 0
                }
            }
        }))
        .send()
        .await
        .expect("invalid search request");
    let invalid_body = parse_mcp_json(&invalid.text().await.expect("invalid search body"));
    assert_eq!(invalid_body["result"]["isError"], true);

    cancel.cancel();
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(root);
}
