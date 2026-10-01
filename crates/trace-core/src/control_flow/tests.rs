use crate::{
    control_flow::{render_dot, types::*},
    TraceEngine,
};
fn line(pc: u64, instruction: &str) -> String {
    format!("[tiny.so] 0x{pc:x}!0x{pc:x} {instruction}\n")
}
fn session(engine: &TraceEngine, text: &str) -> String {
    let path = std::env::temp_dir().join(format!("cfg-test-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, text).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let session = engine
        .create_session_from_file(file, "inherited-fd:3")
        .unwrap();
    std::fs::remove_file(path).unwrap();
    session.session_id
}
fn full() -> CfgPage {
    CfgPage {
        offset: 0,
        limit: 10_000,
    }
}
#[test]
fn multi_function_loop_call_resume_and_fd_identity() {
    let engine = TraceEngine::new();
    let instructions = [
        (0x100, "bl #0x200"),
        (0x200, "mov x0, x1"),
        (0x204, "bl #0x300"),
        (0x300, "add x0, x0, #1"),
        (0x304, "ret"),
        (0x208, "cbnz x0, #0x208"),
        (0x208, "cbnz x0, #0x208"),
        (0x20c, "bl #0x900"),
        (0x210, "retaa"),
        (0x104, "nop"),
    ];
    let text: String = instructions.iter().map(|(pc, i)| line(*pc, i)).collect();
    let id = session(&engine, &text);
    engine.build_control_flow_index(&id).unwrap();
    assert!(!engine.get_session_info(&id).unwrap().index_ready);
    let cfg = engine
        .get_activation_cfg(&id, 0, 1, "tiny.so+0x200", full(), full())
        .unwrap();
    assert_eq!(cfg.total_occurrences, 5);
    assert!(!cfg.blocks.iter().any(|b| b.site == "tiny.so+0x300"));
    let loop_block = cfg
        .blocks
        .iter()
        .find(|b| b.site == "tiny.so+0x208")
        .unwrap();
    assert_eq!(loop_block.count, 2);
    assert!(cfg
        .edges
        .iter()
        .any(|e| e.from == loop_block.id && e.to == loop_block.id && e.count == 1));
    assert!(cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::CallResume));
    let dot = render_dot(&cfg).unwrap();
    assert!(dot.contains("cbnz x0"));
    assert_eq!(
        dot,
        render_dot(
            &engine
                .get_function_cfg(&id, "tiny.so+0x200", full(), full())
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        engine
            .get_cfg_occurrence_for_seq(&id, 3)
            .unwrap()
            .unwrap()
            .activation_id,
        2
    );
    assert!(engine
        .get_activation_cfg(&id, 0, 1, "tiny.so+0x300", full(), full())
        .is_err());
    let other = session(&engine, &line(0x100, "nop"));
    engine.build_control_flow_index(&other).unwrap();
    assert!(engine
        .get_function_cfg(&other, "tiny.so+0x200", full(), full())
        .is_err());
}
#[test]
fn late_target_across_activations_variants_paging_and_truncation() {
    let engine = TraceEngine::new();
    let instructions = [
        (0x100, "bl #0x200"),
        (0x200, "nop"),
        (0x204, "mov x0, #1"),
        (0x208, "ret"),
        (0x104, "nop"),
        (0x108, "bl #0x200"),
        (0x200, "b #0x204"),
        (0x204, "mov x0, #2"),
        (0x208, "ret"),
        (0x10c, "nop"),
        (0x110, "bl #0x200"),
        (0x200, "nop"),
    ];
    let mut text: String = instructions.iter().map(|(pc, i)| line(*pc, i)).collect();
    text.insert_str(
        text.find(&line(0x204, "mov x0, #1")).unwrap(),
        "call func: annotation(0x1)\n",
    );
    let id = session(&engine, &text);
    engine.build_control_flow_index(&id).unwrap();
    let cfg = engine
        .get_function_cfg(&id, "tiny.so+0x200", full(), full())
        .unwrap();
    assert_eq!(cfg.activations.len(), 2);
    assert_eq!(cfg.total_occurrences, 4);
    let b = cfg
        .blocks
        .iter()
        .find(|b| b.site == "tiny.so+0x204")
        .unwrap();
    assert_eq!(b.count, 2);
    assert_eq!(b.representatives.len(), 2);
    assert_eq!(b.representatives[0].start_seq, 3);
    let paged = engine
        .get_function_cfg(
            &id,
            "tiny.so+0x200",
            CfgPage {
                offset: 1,
                limit: 1,
            },
            CfgPage {
                offset: 2,
                limit: 1,
            },
        )
        .unwrap();
    assert_eq!(paged.total_occurrences, cfg.total_occurrences);
    assert_eq!(paged.occurrences.len(), 1);
    assert!(render_dot(&paged).is_err());
    assert!(engine.get_cfg_occurrence_for_seq(&id, 2).unwrap().is_none());
    assert!(engine
        .get_activation_cfg(&id, 11, 12, "tiny.so+0x200", full(), full())
        .is_err());
}
#[test]
fn repository_gumtrace_sample_cfg_and_dot() {
    let engine = TraceEngine::new();
    let text = include_str!("../../../../example-trace-gumtrace.txt");
    let id = session(&engine, text);
    engine.build_control_flow_index(&id).unwrap();
    let cfg = engine
        .get_activation_cfg(&id, 1, 2, "libmetasec_ov.so+0x143438", full(), full())
        .unwrap();
    assert!(cfg.total_blocks > 0);
    assert!(cfg.total_occurrences >= cfg.total_blocks);
    assert!(render_dot(&cfg)
        .unwrap()
        .contains("libmetasec_ov.so+0x143438"));
    println!(
        "repository sample: {} blocks, {} occurrences, {} edges",
        cfg.total_blocks,
        cfg.total_occurrences,
        cfg.edges.len()
    );
}
#[test]
fn recursive_same_callsite_ownership_and_unidbg() {
    let engine = TraceEngine::new();
    let instructions = [
        (0x100, "bl #0x200"),
        (0x200, "bl #0x200"),
        (0x200, "bl #0x900"),
        (0x204, "ret"),
        (0x204, "ret"),
        (0x104, "nop"),
    ];
    let text: String = instructions
        .iter()
        .map(|(pc, insn)| {
            format!("[00:00:00 000][tiny.so 0x{pc:x}] [00000000] 0x{pc:x}: \"{insn}\"\n")
        })
        .collect();
    let id = session(&engine, &text);
    engine.build_control_flow_index(&id).unwrap();
    let cfg = engine
        .get_function_cfg(&id, "tiny.so+0x200", full(), full())
        .unwrap();
    assert_eq!(cfg.activations.len(), 2);
    assert_eq!(
        engine
            .get_cfg_occurrence_for_seq(&id, 3)
            .unwrap()
            .unwrap()
            .activation_id,
        2
    );
    assert_eq!(
        engine
            .get_cfg_occurrence_for_seq(&id, 4)
            .unwrap()
            .unwrap()
            .activation_id,
        1
    );
    assert_eq!(cfg.total_occurrences, 4);
}
#[test]
fn invalid_and_cancelled_builds_publish_nothing() {
    let engine = TraceEngine::new();
    let id = session(&engine, "unrecognized dropped line\n");
    assert!(engine.build_control_flow_index(&id).is_err());
    let cancel = std::sync::atomic::AtomicBool::new(true);
    assert!(super::ControlFlowIndex::build(
        line(0x100, "nop").as_bytes(),
        &cancel,
        |_| Some("tiny.so+0x100".into()),
        |_| Some(0x100)
    )
    .is_err());
}
