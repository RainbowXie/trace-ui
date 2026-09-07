//! FunctionCallRecord 的 trace-ui 事实查询公共行为。
//!
//! 这组测试先固定调用方真正需要的边界：请求一份已确认 Activation 时，
//! provider 必须一次返回同一 Activation 的 anchors、ABI、完整执行块序列、
//! direct 读写、External Call Event 与 unresolved，避免状态机跨多个分页查询
//! 拼出不一致快照。

use super::*;

#[test]
fn confirmed_activation_returns_a_complete_function_fact_bundle() {
    let (engine, sid) = setup_session(&get_trace_path());
    let activation = engine
        .get_activation_tree(&sid, 0, 100)
        .expect("activation tree")
        .activations
        .into_iter()
        .find(|item| item.call_seq == 10)
        .expect("sample has the nested call activation");

    let bundle = engine
        .get_function_facts(&sid, activation.call_seq, activation.entry_seq)
        .expect("function facts");

    assert_eq!(bundle.function, "libmetasec_ov.so+0x2ea90");
    assert_eq!(bundle.trace_anchors.call.seq, 10);
    assert_eq!(bundle.trace_anchors.entry.seq, 11);
    assert_eq!(bundle.trace_anchors.exit.seq, 14);
    assert_eq!(bundle.trace_anchors.resume.seq, 18);
    assert!(!bundle.abi.arguments.is_empty());
    assert!(!bundle.abi.returns.is_empty());
    assert_eq!(
        bundle
            .executed_block_sequence
            .iter()
            .map(|block| block.entry_seq)
            .collect::<Vec<_>>(),
        vec![11]
    );
    assert!(bundle.memory_reads.is_empty());
    assert!(bundle.global_reads.is_empty());
    assert!(bundle.memory_writes.is_empty());
    assert!(bundle.global_writes.is_empty());
    assert!(bundle.external_call_events.is_empty());
    assert!(bundle.unresolved.is_empty());

    engine.close_session(&sid).unwrap();
}
