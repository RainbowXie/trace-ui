use trace_core::api_types::TargetHistorySelectionDto;
#[test]
fn target_history_selection_strict_fields_and_rw() {
    for raw in [
        r#"{"seq":1,"seq":2,"address":"0x3000","size":4,"rw":"write"}"#,
        r#"{"seq":1,"address":"0x3000","size":4,"rw":"other"}"#,
        r#"{"seq":1,"address":"0x3000","size":4,"rw":"read","extra":0}"#,
    ] {
        assert!(serde_json::from_str::<TargetHistorySelectionDto>(raw).is_err());
    }
}
