//! TraceToolHandler 工具实现的单元测试（tools 子模块）。

use super::*;
use trace_core::memory_search::{MemorySearchOptions, MemorySearchResult, MemorySearchRw};

/// 预算预检必须是已证明的保守上界：找到恰好通过预检的最大 pattern，
/// 用真实 serializer 验证响应（含 JSON 字符串转义后的外层尺寸）不超预算。
#[test]
fn memory_search_response_budget_covers_actual_serialization() {
    let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"nop\"\n";
    let probe = |len: usize| MemorySearchOptions {
        pattern: vec![0xab; len],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 1,
    };
    let mut max_ok = 0usize;
    let mut lo = 1usize;
    let mut hi = 8 * 1024 * 1024;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        if trace_core::memory_search::search_memory(
            trace.as_bytes(),
            trace_parser::types::TraceFormat::Unidbg,
            probe(mid),
        )
        .is_ok()
        {
            max_ok = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    assert!(max_ok > 0, "some pattern size must be accepted");
    assert!(
        trace_core::memory_search::search_memory(
            trace.as_bytes(),
            trace_parser::types::TraceFormat::Unidbg,
            probe(max_ok + 1),
        )
        .is_err(),
        "pattern size {} must exceed the budget",
        max_ok + 1
    );

    let result = MemorySearchResult {
        matches: vec![trace_core::memory_search::MemorySearchMatch {
            address: u64::MAX,
            seq: u32::MAX,
            size: max_ok as u32,
            bytes: vec![0xab; max_ok],
            rw: MemorySearchRw::Write,
        }],
        total: u32::MAX,
        offset: u32::MAX,
        limit: 1,
        has_more: true,
    };
    let body = format_memory_search_result(result);
    const BUDGET: usize = 8 * 1024 * 1024;
    assert!(
        body.len() <= BUDGET,
        "inner JSON {} bytes exceeds budget at accepted pattern size {}",
        body.len(),
        max_ok
    );
    // MCP 外层把工具结果作为 JSON 字符串嵌入：引号/反斜杠会转义膨胀，
    // 预检必须连这个上界也覆盖。
    let escaped = body.len() + body.bytes().filter(|b| matches!(b, b'"' | b'\\')).count();
    assert!(
        escaped <= BUDGET,
        "escaped outer size {} exceeds budget at accepted pattern size {}",
        escaped,
        max_ok
    );
    // 验收证据必须覆盖真实序列化：构造完整的 JSON-RPC 成功封套，
    // 让 serde_json 实际执行转义，而不是只手工估算一层。
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": body}],
            "isError": false,
        }
    });
    let wire = serde_json::to_string(&envelope).expect("serialize envelope");
    assert!(
        wire.len() <= BUDGET,
        "full JSON-RPC envelope {} bytes exceeds budget at accepted pattern size {}",
        wire.len(),
        max_ok
    );
}
