use super::budget::Budget;
use super::budget::*;
use crate::api_types::*;
use std::collections::BTreeMap;
fn fixture() -> FunctionFactBundleDto {
    let anchor = |seq| FunctionAnchorDto {
        seq,
        offset: "App+0x0".into(),
    };
    FunctionFactBundleDto {
        function: "App+0x0".into(),
        trace_anchors: FunctionTraceAnchorsDto {
            call: anchor(0),
            entry: anchor(1),
            exit: anchor(2),
            resume: anchor(3),
        },
        abi: FunctionAbiDto {
            entry_sp: None,
            arguments: BTreeMap::new(),
            stack_arguments: Vec::new(),
            returns: BTreeMap::new(),
        },
        executed_block_sequence: Vec::new(),
        memory_reads: Vec::new(),
        global_reads: Vec::new(),
        memory_writes: Vec::new(),
        global_writes: Vec::new(),
        external_call_events: Vec::new(),
        unresolved: Vec::new(),
    }
}
fn context() -> FunctionFactContext<'static> {
    let trace = FactSourceReference {
        artifact: "traces/a\"é.json",
        pointer: "/a~1b\n",
    };
    FunctionFactContext {
        trace,
        activation: FactActivationSelector {
            trace,
            function: "App+0x0",
            call_seq: 0,
            entry_seq: 1,
        },
    }
}
#[test]
fn exact_pretty_item_deltas_empty_nonempty_escape_and_sequences() {
    let mut dto = fixture();
    let ctx = context();
    let mut budget = Budget::new(ctx, &dto).unwrap();
    for seq in [9, 10001] {
        let block = ExecutedBlockEntryDto {
            block: "App+0x10".into(),
            entry_seq: seq,
        };
        budget
            .item(&block, 2, dto.executed_block_sequence.is_empty())
            .unwrap();
        dto.executed_block_sequence.push(block);
        budget.verify(ctx, &dto).unwrap();
    }
    let slot = FunctionStackArgumentDto {
        offset: 16,
        size: 8,
        value: None,
        read_seqs: vec![9, 10001],
    };
    budget.item(&slot, 3, true).unwrap();
    dto.abi.stack_arguments.push(slot);
    budget.verify(ctx, &dto).unwrap();
    let gap = FunctionFactUnresolvedDto {
        kind: "unsupported_instruction".into(),
        seqs: vec![3, 999],
        location: Some("quote\"slash\\tab\tunicodeé".into()),
        detail: "line\nnext".into(),
    };
    budget.item(&gap, 2, true).unwrap();
    dto.unresolved.push(gap);
    budget.verify(ctx, &dto).unwrap();
    let mut out = Vec::new();
    write_function_fact_projection(ctx, &dto, &mut out).unwrap();
    assert_eq!(out.len() as u64, budget.used_for_test());
    assert!(out.starts_with(b"{\n  \"trace\":"));
    assert_eq!(out.last(), Some(&b'\n'));
}
#[test]
fn injected_exact_boundary_refuses_before_materialization() {
    let dto = fixture();
    let ctx = context();
    let mut budget = Budget::new(ctx, &dto).unwrap();
    let item = ExecutedBlockEntryDto {
        block: "App+0x0".into(),
        entry_seq: 1000,
    };
    let cost = budget.item_cost(&item, 2, true).unwrap();
    budget.limit_for_test(budget.used_for_test() + cost - 1);
    assert!(budget.item(&item, 2, true).is_err());
    let mut exact = Budget::new(ctx, &dto).unwrap();
    exact.limit_for_test(exact.used_for_test() + cost);
    exact.item(&item, 2, true).unwrap();
}
