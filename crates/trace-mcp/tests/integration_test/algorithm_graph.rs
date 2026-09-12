use super::*;

#[test]
fn graph_facts_preserve_cross_activation_multi_producer_and_control_edges() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x07fc!0x07fc mov x3, #3; x3=0x0 -> x3=0x3",
        "[App] 0x0800!0x0800 bl #0x1000; x1=0x2 x3=0x3 x4=0x4000 sp=0x5000",
        "[App] 0x1000!0x1000 bl #0x2000; x1=0x2 x3=0x3 x4=0x4000 sp=0x5000",
        "[App] 0x2000!0x2000 add x0, x1, #1; x1=0x2 sp=0x5000 -> x0=0x3",
        "[App] 0x2004!0x2004 ret; x0=0x3 sp=0x5000",
        "[App] 0x1004!0x1004 cmp x0, #3; x0=0x3 nzcv=0x0 -> nzcv=0x6",
        "[App] 0x1008!0x1008 b.eq #0x1010; nzcv=0x6",
        "[App] 0x1010!0x1010 add x2, x0, x3; x0=0x3 x3=0x3 -> x2=0x6",
        "[App] 0x1014!0x1014 str x2, [x4]; x2=0x6 x4=0x4000 ; mem[WRITE] abs=0x4000 x2=0x6",
        "[App] 0x1018!0x1018 ret; x0=0x3 sp=0x5000",
        "[App] 0x0804!0x0804 mov x5, x0; x0=0x3 -> x5=0x3",
    ]);

    let facts = engine
        .get_algorithm_graph_facts(&sid, 8, 0x4000, 8, Some("write"))
        .expect("algorithm graph facts");

    assert_eq!(facts.target_seq, 8);
    assert_eq!(
        facts.activations.len(),
        2,
        "root caller and child are retained"
    );
    assert_eq!(facts.call_edges.len(), 1);
    assert_eq!(facts.call_edges[0].callee.entry_seq, 3);
    assert!(
        facts.dependency_edges.iter().any(|edge| {
            edge.producer.seq == 3
                && edge.consumer.seq == 7
                && edge.kind == "data"
                && edge
                    .producer
                    .activation
                    .as_ref()
                    .map(|owner| owner.entry_seq)
                    == Some(3)
                && edge
                    .consumer
                    .activation
                    .as_ref()
                    .map(|owner| owner.entry_seq)
                    == Some(2)
        }),
        "callee return producer must remain connected to the caller consumer"
    );
    assert!(
        facts.dependency_edges.iter().any(|edge| {
            edge.producer.seq == 6 && edge.consumer.seq == 7 && edge.kind == "control"
        }),
        "control dependency must not be silently converted to data or dropped"
    );
    let producers = facts
        .dependency_edges
        .iter()
        .filter(|edge| edge.consumer.seq == 7 && edge.kind == "data")
        .map(|edge| edge.producer.seq)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        producers.len() >= 2,
        "all data producers of the add must be preserved"
    );

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn graph_facts_preserve_pair_half_labels() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1",
        "[App] 0x1004!0x1004 mov x1, #2; x1=0x0 -> x1=0x2",
        "[App] 0x1008!0x1008 mov x4, #0x4000; x4=0x0 -> x4=0x4000",
        "[App] 0x100c!0x100c stp x0, x1, [x4]; x0=0x1 x1=0x2 x4=0x4000 ; mem[WRITE] abs=0x4000 x0=0x1 x1=0x2",
        "[App] 0x1010!0x1010 ldp x2, x3, [x4]; x4=0x4000 ; mem[READ] abs=0x4000 x2=0x1 x3=0x2 -> x2=0x1 x3=0x2",
    ]);

    let facts = engine
        .get_algorithm_graph_facts(&sid, 4, 0x4000, 16, Some("read"))
        .expect("algorithm graph facts");
    let parts = facts
        .dependency_edges
        .iter()
        .filter(|edge| edge.consumer.seq == 4)
        .filter_map(|edge| edge.pair_part.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        parts.contains("half1"),
        "pair parts: {:?}; edges: {:?}",
        parts,
        facts.dependency_edges
    );
    assert!(parts.contains("half2"), "pair parts: {:?}", parts);

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
