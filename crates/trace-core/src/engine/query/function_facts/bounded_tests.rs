use super::budget::*;
use crate::{BuildOptions, TraceEngine};
use std::io::Write;
use std::sync::atomic::AtomicBool;
#[test]
fn tiny_internal_budget_refuses_whole_generation_and_exact_size_succeeds() {
    let path = std::env::temp_dir().join(format!("facts-budget-{}.log", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(b"[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 str x0, [x2]; x0=0x7 x2=0x8000 mem_w=0x8000\n[App] 0x204!0x204 ret\n[App] 0x104!0x104 nop\n").unwrap();
    let engine = TraceEngine::new();
    let sid = engine
        .create_session_from_file(file, "inherited-fd:budget-test")
        .unwrap()
        .session_id;
    engine
        .build_index(
            &sid,
            BuildOptions {
                force_rebuild: true,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    let trace = FactSourceReference {
        artifact: "traces/t.json",
        pointer: "/trace",
    };
    let ctx = FunctionFactContext {
        trace,
        activation: FactActivationSelector {
            trace,
            function: "App+0x200",
            call_seq: 0,
            entry_seq: 1,
        },
    };
    let cancel = AtomicBool::new(false);
    let result = engine
        .get_function_facts_bounded(&sid, ctx, &[], &cancel)
        .unwrap();
    let mut bytes = Vec::new();
    let exact = write_function_fact_projection(ctx, &result, &mut bytes).unwrap();
    assert!(engine
        .build_function_facts_bounded(&sid, ctx, &[], &cancel, exact - 1)
        .is_err());
    let result = engine
        .build_function_facts_bounded(&sid, ctx, &[], &cancel, exact)
        .unwrap();
    let mut again = Vec::new();
    write_function_fact_projection(ctx, &result, &mut again).unwrap();
    assert_eq!(again, bytes);
    assert!(matches!(
        engine.get_function_facts_bounded(&sid, ctx, &[], &AtomicBool::new(true)),
        Err(crate::TraceError::Cancelled)
    ));
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn immediate_gap_keeps_missing_dependency_coverage_conservative() {
    let tree = crate::query::activation::ActivationBuilder::new().finish(0);
    // No ownership lookup may run when dependency coverage is unavailable.
    let owner = &tree.activations[0];
    let line = "[App] 0x200!0x200 mov x0, #1; x0=0x0 -> x0=0x1";
    assert!(super::immediate_gap(
        &tree,
        owner,
        &[],
        None,
        false,
        1,
        line
    ));
    let relevant = super::fact_work::Fixed::<super::fact_work::Dependency>::new().unwrap();
    assert!(super::immediate_gap(
        &tree,
        owner,
        &[],
        Some(&relevant),
        false,
        1,
        line
    ));
}
