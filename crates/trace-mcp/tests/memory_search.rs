use serde_json::json;

use trace_mcp::types::{MemoryRangeRequest, SearchMemoryRequest, SeqRangeRequest};

#[test]
fn search_memory_request_has_structured_ranges_and_defaults() {
    let request: SearchMemoryRequest = serde_json::from_value(json!({
        "pattern": "aa bb cc",
        "seq_range": {"start": 4, "end": 9},
        "memory_range": {"address": "0x1000", "size": 16}
    }))
    .expect("request schema");
    assert_eq!(request.pattern, "aa bb cc");
    assert_eq!(
        request.seq_range,
        Some(SeqRangeRequest { start: 4, end: 9 })
    );
    assert_eq!(
        request.memory_range,
        Some(MemoryRangeRequest {
            address: "0x1000".to_string(),
            size: 16,
        })
    );
    assert_eq!(request.offset, 0);
    assert_eq!(request.limit, 50);
}

#[test]
fn search_memory_request_rejects_unknown_fields() {
    let result = serde_json::from_value::<SearchMemoryRequest>(json!({
        "pattern": "aa",
        "unexpected": true
    }));
    assert!(result.is_err());
}
