use super::*;
use trace_core::{GraphActivationSelectorDto, GraphMechanicalEndpointDto, GraphTraceReferenceDto};

fn selector(
    function: &str,
    call_seq: u32,
    entry_seq: u32,
    exit_seq: u32,
    resume_seq: u32,
) -> GraphActivationSelectorDto {
    GraphActivationSelectorDto {
        trace: GraphTraceReferenceDto {
            artifact: "request.json".to_owned(),
            pointer: "/trace_files/0".to_owned(),
        },
        function: function.to_owned(),
        call_seq,
        entry_seq,
        exit_seq,
        resume_seq,
    }
}

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
    let caller = selector("App+0x1000", 1, 2, 9, 10);
    let callee = selector("App+0x2000", 2, 3, 4, 5);

    let facts = engine
        .get_algorithm_graph_facts(
            &sid,
            8,
            0x4000,
            8,
            Some("write"),
            &[caller.clone(), callee.clone()],
        )
        .expect("algorithm graph facts");

    assert_eq!(facts.target_seq, 8);
    assert_eq!(facts.activations, vec![caller.clone(), callee.clone()]);
    assert_eq!(facts.call_edges.len(), 1);
    assert_eq!(facts.call_edges[0].callee, callee);
    assert!(facts.dependency_edges.iter().any(|edge| {
        matches!(
            &edge.producer,
            GraphMechanicalEndpointDto::Instruction { seq: 3, owner }
                if owner.function == "App+0x2000"
        ) && matches!(
            &edge.consumer,
            GraphMechanicalEndpointDto::Instruction { seq: 7, owner }
                if owner.function == "App+0x1000"
        ) && edge.kind == "data"
    }));
    assert!(facts.dependency_edges.iter().any(|edge| {
        edge.consumer.seq() == Some(7) && edge.producer.seq() == Some(6) && edge.kind == "control"
    }));
    let producers = facts
        .dependency_edges
        .iter()
        .filter(|edge| edge.consumer.seq() == Some(7) && edge.kind == "data")
        .filter_map(|edge| edge.producer.seq())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(producers.len() >= 2);

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn graph_facts_reject_unowned_pair_boundaries_without_activation_selectors() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1",
        "[App] 0x1004!0x1004 mov x1, #2; x1=0x0 -> x1=0x2",
        "[App] 0x1008!0x1008 mov x4, #0x4000; x4=0x0 -> x4=0x4000",
        "[App] 0x100c!0x100c stp x0, x1, [x4]; x0=0x1 x1=0x2 x4=0x4000 ; mem[WRITE] abs=0x4000 x0=0x1 x1=0x2",
        "[App] 0x1010!0x1010 ldp x2, x3, [x4]; x4=0x4000 ; mem[READ] abs=0x4000 x2=0x1 x3=0x2 -> x2=0x1 x3=0x2",
    ]);

    let error = engine
        .get_algorithm_graph_facts(&sid, 4, 0x4000, 16, Some("read"), &[])
        .expect_err("unowned boundaries cannot be published without a record selector");
    assert!(matches!(error, trace_core::TraceError::InvalidArgument(_)));

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn graph_facts_echo_full_selectors_and_map_external_return_to_event_endpoint() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x5004!0x5004 bl #0x1000; sp=0x3030",
        "[App] 0x1000!0x1000 mov x0, #0x11; x0=0x0 -> x0=0x11",
        "[App] 0x1004!0x1004 bl #0x3000; x0=0x11 sp=0x3030",
        "call func: extfoo(0x11)",
        "ret: 0x99",
        "[App] 0x1008!0x1008 mov x2, x0; x0=0x99 -> x2=0x99",
        "[App] 0x100c!0x100c str x2, [x4]; x2=0x99 x4=0x4000 ; mem[WRITE] abs=0x4000 x2=0x99",
        "[App] 0x1010!0x1010 ret; sp=0x3030",
        "[App] 0x5008!0x5008 mov x0, x0; x0=0x99 -> x0=0x99",
    ]);
    let owner = selector("App+0x1000", 0, 1, 7, 8);

    let facts = engine
        .get_algorithm_graph_facts(
            &sid,
            6,
            0x4000,
            8,
            Some("write"),
            std::slice::from_ref(&owner),
        )
        .expect("algorithm graph facts");

    assert_eq!(facts.activations, vec![owner.clone()]);
    assert!(
        facts.dependency_edges.iter().any(|edge| {
            matches!(
                &edge.producer,
                GraphMechanicalEndpointDto::ExternalCallEvent {
                    owner: endpoint_owner,
                    event_index: 0,
                    call_seq: 2,
                    resume_seq: 5,
                } if endpoint_owner == &owner
            ) && matches!(
                &edge.consumer,
                GraphMechanicalEndpointDto::Instruction { seq: 5, owner: endpoint_owner }
                    if endpoint_owner == &owner
            )
        }),
        "external ret producer must become an Event endpoint: {:?}",
        facts.dependency_edges
    );
    assert_eq!(facts.external_call_events.len(), 1);
    assert_eq!(facts.external_call_events[0].owner, owner);
    assert_eq!(facts.external_call_events[0].event_index, 0);

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn graph_facts_materialize_a_target_related_dynamic_source() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x5000!0x5000 bl #0x1000; sp=0x3000",
        "[App] 0x1000!0x1000 ldr x0, [x1]; x1=0x6000 ; mem[READ] abs=0x6000 x0=0x42 -> x0=0x42",
        "[App] 0x1004!0x1004 str x0, [x4]; x0=0x42 x4=0x4000 ; mem[WRITE] abs=0x4000 x0=0x42",
        "[App] 0x1008!0x1008 ret; sp=0x3000",
        "[App] 0x5004!0x5004 mov x0, x0; x0=0x42 -> x0=0x42",
    ]);
    let owner = selector("App+0x1000", 0, 1, 3, 4);

    let facts = engine
        .get_algorithm_graph_facts(
            &sid,
            2,
            0x4000,
            8,
            Some("write"),
            std::slice::from_ref(&owner),
        )
        .expect("algorithm graph facts");

    assert!(facts.dependency_edges.iter().any(|edge| {
        matches!(
            &edge.producer,
            GraphMechanicalEndpointDto::DynamicSource {
                owner: endpoint_owner,
                seq: 1,
                ..
            } if endpoint_owner == &owner
        ) && matches!(
            &edge.consumer,
            GraphMechanicalEndpointDto::Instruction { seq: 2, owner: endpoint_owner }
                if endpoint_owner == &owner
        )
    }));

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn graph_facts_exclude_an_independent_root_event() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x5000!0x5000 bl #0x1000; sp=0x3000",
        "[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1",
        "[App] 0x1004!0x1004 bl #0x3000; x0=0x1 sp=0x3000",
        "call func: relevant(0x1)",
        "ret: 0x7",
        "[App] 0x1008!0x1008 str x0, [x4]; x0=0x7 x4=0x4000 ; mem[WRITE] abs=0x4000 x0=0x7",
        "[App] 0x100c!0x100c ret; sp=0x3000",
        "[App] 0x5004!0x5004 bl #0x2000; sp=0x3000",
        "[App] 0x2000!0x2000 mov x0, #2; x0=0x0 -> x0=0x2",
        "[App] 0x2004!0x2004 bl #0x4000; x0=0x2 sp=0x3000",
        "call func: unrelated(0x2)",
        "ret: 0x8",
        "[App] 0x2008!0x2008 mov x1, x0; x0=0x8 -> x1=0x8",
        "[App] 0x200c!0x200c ret; sp=0x3000",
        "[App] 0x5008!0x5008 mov x0, x0; x0=0x8 -> x0=0x8",
    ]);
    let relevant = selector("App+0x1000", 0, 1, 6, 7);
    let unrelated = selector("App+0x2000", 7, 8, 13, 14);

    let facts = engine
        .get_algorithm_graph_facts(
            &sid,
            5,
            0x4000,
            8,
            Some("write"),
            &[relevant.clone(), unrelated],
        )
        .expect("algorithm graph facts");

    assert_eq!(facts.activations, vec![relevant.clone()]);
    assert_eq!(facts.external_call_events.len(), 1);
    assert_eq!(facts.external_call_events[0].owner, relevant);
    assert_eq!(facts.external_call_events[0].call_seq, 2);

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}

#[test]
fn graph_facts_reject_duplicate_or_mismatched_selectors() {
    let (engine, sid, path) = function_facts::setup_inline_trace(&[
        "[App] 0x5000!0x5000 bl #0x1000; sp=0x3000",
        "[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1",
        "[App] 0x1004!0x1004 str x0, [x4]; x0=0x1 x4=0x4000 ; mem[WRITE] abs=0x4000 x0=0x1",
        "[App] 0x1008!0x1008 ret; sp=0x3000",
        "[App] 0x5004!0x5004 mov x0, x0; x0=0x1 -> x0=0x1",
    ]);
    let valid = selector("App+0x1000", 0, 1, 3, 4);

    assert!(engine
        .get_algorithm_graph_facts(
            &sid,
            2,
            0x4000,
            8,
            Some("write"),
            &[valid.clone(), valid.clone()],
        )
        .is_err());
    let mut mismatched = valid;
    mismatched.function = "App+0x2000".to_owned();
    assert!(engine
        .get_algorithm_graph_facts(&sid, 2, 0x4000, 8, Some("write"), &[mismatched],)
        .is_err());

    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).expect("remove inline trace");
}
