use std::io::Write;
use std::sync::atomic::AtomicBool;
use trace_core::engine::{
    write_function_fact_projection, FactActivationSelector, FactSourceReference,
    FunctionFactContext,
};
use trace_core::{BuildOptions, TraceEngine};

fn compare(trace: &str, modules: &[String]) -> serde_json::Value {
    let path = std::env::temp_dir().join(format!("facts-bounded-{}.log", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(trace.as_bytes()).unwrap();
    let engine = TraceEngine::new();
    let sid = engine
        .create_session_from_file(file, "inherited-fd:facts-bounded-test")
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
    let source = FactSourceReference {
        artifact: "traces/escaped\"name.json",
        pointer: "/a~1b",
    };
    let context = FunctionFactContext {
        trace: source,
        activation: FactActivationSelector {
            trace: source,
            function: "App+0x200",
            call_seq: 0,
            entry_seq: 1,
        },
    };
    let old = engine
        .get_function_facts_for_modules(&sid, 0, 1, modules)
        .unwrap();
    let bounded = engine
        .get_function_facts_bounded(&sid, context, modules, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&old).unwrap(),
        serde_json::to_value(&bounded).unwrap()
    );
    let mut bytes = Vec::new();
    let size = write_function_fact_projection(context, &bounded, &mut bytes).unwrap();
    assert_eq!(size as usize, bytes.len());
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v.get("function").is_none());
    assert!(v.get("trace_anchors").is_none());
    assert!(v.get("anchors").is_some());
    assert!(bytes.ends_with(b"\n"));
    assert!(!bytes.ends_with(b"\n\n"));
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
    serde_json::to_value(&bounded).unwrap()
}
#[test]
fn unchanged_small_fields_and_unknown_bytes() {
    compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 mov x0, #1 -> x0=0x1\n[App] 0x204!0x204 stp x0, x1, [x2]; x0=0x1 x2=0x8000 mem_w=0x8000\n[App] 0x208!0x208 str x3, [x2]; x2=0x8000 mem_w=0x8000\n[App] 0x20c!0x20c ret\n[App] 0x104!0x104 nop\n", &[]);
    compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 ldr x0, [x1]; x1=0x7000 mem_r=0x7000 -> x0=0x7\n[App] 0x204!0x204 str x0, [x2]; x0=0x7 x2=0x8000 mem_w=0x8000\n[App] 0x208!0x208 ldr x0, [x1]; x1=0x7000 mem_r=0x7000 -> x0=0x8\n[App] 0x20c!0x20c str x0, [x3]; x0=0x8 x3=0x9000 mem_w=0x9000\n[App] 0x210!0x210 ret\n[App] 0x104!0x104 nop\n", &[]);
    compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 ldr x0, [x1]; x1=0x7000 mem_r=0x7000 -> x0=0x7\n[App] 0x204!0x204 str x0, [x2]; x0=0x7 x2=0x8000 mem_w=0x8000\n[App] 0x208!0x208 ret\n[App] 0x104!0x104 nop\n", &[]);
    compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 str x3, [x2]; x2=0x8000 mem_w=0x8000\n[App] 0x204!0x204 ret\n[App] 0x104!0x104 nop\n", &[]);
}
#[test]
fn unknown_writes_revoke_final_contributions_in_both_queries() {
    for (later, expected) in [
        ("st4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x1]; x1=0x7000 mem_w=0x7000", 0),
        ("st4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x1]; x1=0x7040 mem_w=0x7040", 1),
        ("stxr w2, x3, [x1]; x1=0x7000 mem_w=0x7000", 0),
        ("stxr w2, x3, [x1]; x1=0x7008 mem_w=0x7008", 1),
        ("stxr w2, x3, [x1]; x1=0x7000 mem_w=0x7000 -> w2=0x1", 1),
        ("unknown_store [x1]; x1=0x7100 mem_w=0x7100", 0),
        ("st4 {v0.16b-v3.16b}, [x1]; x1=0x7100 mem_w=0x7100", 0),
        ("st4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x1]; x1=0xfffffffffffffff0 mem_w=0xfffffffffffffff0", 0),
    ] {
        let trace = format!("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 str x0, [x1]; x0=0x1122334455667788 x1=0x7000 mem_w=0x7000\n[App] 0x204!0x204 {later}\n[App] 0x208!0x208 ret\n[App] 0x104!0x104 nop\n");
        let facts = compare(&trace, &[]);
        assert_eq!(facts["memory_writes"].as_array().unwrap().len(), expected, "{later}: {facts}");
        if expected == 1 {
            assert_eq!(facts["memory_writes"][0]["bytes"], "8877665544332211");
            assert_eq!(facts["memory_writes"][0]["write_seqs"], serde_json::json!([1]));
        }
    }
    let restored = compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 str x0, [x1]; x0=0x11 x1=0x7000 mem_w=0x7000\n[App] 0x204!0x204 st4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x1]; x1=0x7000 mem_w=0x7000\n[App] 0x208!0x208 str x0, [x1]; x0=0x22 x1=0x7000 mem_w=0x7000\n[App] 0x20c!0x20c ret\n[App] 0x104!0x104 nop\n", &[]);
    assert_eq!(restored["memory_writes"][0]["bytes"], "2200000000000000");
    assert_eq!(restored["memory_writes"][0]["write_seqs"], serde_json::json!([3]));
}

#[test]
fn stack_reads_and_external_event() {
    compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 ldr x0, [sp]; sp=0x9000 mem_r=0x9000 -> x0=0x7\n[App] 0x204!0x204 bl #0x900\n[App] 0x208!0x208 ret\n[App] 0x104!0x104 nop\n", &[]);
}
#[test]
fn repeated_covering_writes_have_small_final_output() {
    let mut trace = "[App] 0x100!0x100 bl #0x200\n".to_owned();
    for i in 0..128 {
        trace.push_str(&format!(
            "[App] 0x{:x}!0x{:x} str x0, [x2]; x0=0x{:x} x2=0x8000 mem_w=0x8000\n",
            0x200 + i * 4,
            0x200 + i * 4,
            i
        ));
    }
    trace.push_str("[App] 0x400!0x400 ret\n[App] 0x104!0x104 nop\n");
    compare(&trace, &[]);
}
#[test]
fn real_global_address_chain() {
    compare("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 adrp x2, #0x1000 -> x2=0x1000\n[App] 0x204!0x204 add x2, x2, #0x10 -> x2=0x1010\n[App] 0x208!0x208 str x0, [x2]; x0=0x7 x2=0x1010 mem_w=0x1010\n[App] 0x20c!0x20c ret\n[App] 0x104!0x104 nop\n", &["App".into()]);
}

#[test]
fn immediate_sources_share_old_and_bounded_mechanical_gate() {
    for op in [
        "mov w0, #4294967295",
        "mov x0, #1",
        "movk x0, #1",
        "mov x0, #1, lsl #16",
        "mov x0, #4294967296",
    ] {
        let result = compare(&format!("[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 {op}; x0=0x0 -> x0=0x1\n[App] 0x204!0x204 movz x9, #99; x9=0x0 -> x9=0x63\n[App] 0x208!0x208 str x0, [x2]; x0=0x1 x2=0x8000 mem_w=0x8000\n[App] 0x20c!0x20c ret\n[App] 0x104!0x104 nop\n"), &[]);
        let gaps = result["unresolved"].as_array().unwrap();
        assert!(
            !gaps
                .iter()
                .any(|g| g["seqs"] == serde_json::json!([2])
                    && g["kind"] == "unsupported_instruction"),
            "dead literal: {result}"
        );
        let expected_gap = matches!(op, "movk x0, #1" | "mov x0, #1, lsl #16");
        assert_eq!(
            gaps.iter()
                .any(|g| g["seqs"] == serde_json::json!([1])
                    && g["kind"] == "unsupported_instruction"),
            expected_gap,
            "{op}: {result}"
        );
    }
}
