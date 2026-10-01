#![cfg(unix)]

use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};
use trace_core::engine::{
    write_function_fact_projection, FactActivationSelector, FactSourceReference, FunctionFactContext,
};

fn run(trace: &File, request: &[u8]) -> Output {
    let staged = unsafe { libc::fcntl(trace.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    assert!(staged >= 0);
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    command.args(["--function-facts-helper", "--trace-fd", "3"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(staged, 3) < 0 { return Err(std::io::Error::last_os_error()); }
            Ok(())
        });
    }
    let spawned = command.spawn();
    unsafe { libc::close(staged); }
    let mut child = spawned.unwrap();
    child.stdin.take().unwrap().write_all(request).unwrap();
    child.wait_with_output().unwrap()
}

fn request() -> serde_json::Value {
    let source = serde_json::json!({"artifact":"traces/trace.json","pointer":"/trace~1source"});
    serde_json::json!({"kind":"function_facts_bounded", "trace":source,
        "activation":{"trace":source,"function":"App+0x200","call_seq":0,"entry_seq":1},
        "target_modules":[]})
}

#[test]
fn bounded_fd_helper_matches_legacy_and_formal_projection() {
    let path = std::env::temp_dir().join(format!("bounded-helper-{}.log", std::process::id()));
    let mut trace = std::fs::OpenOptions::new().create_new(true).read(true).write(true).open(&path).unwrap();
    trace.write_all(b"[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 mov x0, #1 -> x0=0x1\n[App] 0x204!0x204 ret\n[App] 0x104!0x104 nop\n").unwrap();
    let old = run(&trace, br#"{"call_seq":0,"entry_seq":1,"function":"App+0x200","target_modules":[]}"#);
    assert!(old.status.success(), "{}", String::from_utf8_lossy(&old.stderr));
    let new = run(&trace, &serde_json::to_vec(&request()).unwrap());
    assert!(new.status.success(), "{}", String::from_utf8_lossy(&new.stderr));
    assert_eq!(old.stdout, new.stdout);
    assert!(new.stdout.ends_with(b"\n"));
    assert!(!new.stdout.ends_with(b"\n\n"));
    let engine = trace_core::TraceEngine::new();
    let sid = engine.create_session_from_file(trace.try_clone().unwrap(), "inherited-fd:helper-projection-test").unwrap().session_id;
    engine.build_index(&sid, trace_core::BuildOptions { force_rebuild: true, skip_strings: true }, None).unwrap();
    let source = FactSourceReference { artifact: "traces/trace.json", pointer: "/trace~1source" };
    let context = FunctionFactContext { trace: source, activation: FactActivationSelector {
        trace: source, function: "App+0x200", call_seq: 0, entry_seq: 1,
    }};
    let dto = engine.get_function_facts_bounded(&sid, context, &[], &std::sync::atomic::AtomicBool::new(false)).unwrap();
    assert_eq!(serde_json::to_value(&dto).unwrap(), serde_json::from_slice::<serde_json::Value>(&new.stdout).unwrap());
    let mut projection = Vec::new();
    let logical = write_function_fact_projection(context, &dto, &mut projection).unwrap();
    assert_eq!(logical as usize, projection.len());
    let mut formal = serde_json::to_value(dto).unwrap();
    let object = formal.as_object_mut().unwrap();
    object.remove("function");
    let anchors = object.remove("trace_anchors").unwrap();
    object.insert("anchors".into(), anchors);
    object.insert("trace".into(), request()["trace"].clone());
    object.insert("activation".into(), request()["activation"].clone());
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&projection).unwrap(), formal);
    assert!(projection.starts_with(b"{\n  \"trace\": "));
    assert!(projection.ends_with(b"\n"));
    assert_ne!(projection.len(), new.stdout.len());

    for (field, value) in [
        ("budget", serde_json::json!(1)),
        ("call_seq", serde_json::json!(0)),
        ("target_modules", serde_json::json!(["App", "App"])),
        ("target_modules", serde_json::json!(["bad/module"])),
        ("kind", serde_json::json!("unknown")),
    ] {
        let mut bad = request();
        bad[field] = value;
        rejected(&trace, &serde_json::to_vec(&bad).unwrap());
    }
    for (field, value) in [
        ("trace", serde_json::json!({"artifact":"traces/other.json","pointer":""})),
        ("function", serde_json::json!("App+0x204")),
        ("entry_seq", serde_json::json!(2)),
        ("call_seq", serde_json::json!(1)),
        ("indent", serde_json::json!(2)),
    ] {
        let mut bad = request();
        bad["activation"][field] = value;
        rejected(&trace, &serde_json::to_vec(&bad).unwrap());
    }
    for pointer in ["/bad~2", "not-a-pointer"] {
        let mut bad = request();
        bad["trace"]["pointer"] = pointer.into();
        bad["activation"]["trace"]["pointer"] = pointer.into();
        rejected(&trace, &serde_json::to_vec(&bad).unwrap());
    }
    for field in ["trace", "activation", "target_modules"] {
        let mut bad = request();
        bad.as_object_mut().unwrap().remove(field);
        rejected(&trace, &serde_json::to_vec(&bad).unwrap());
    }
    let encoded = serde_json::to_string(&request()).unwrap();
    for addition in [r#""kind":"function_facts_bounded","#,
        r#""target_modules":[],"#,
        r#""trace":{"artifact":"traces/trace.json","pointer":"/trace~1source"},"#] {
        rejected(&trace, format!("{{{addition}{}", &encoded[1..]).as_bytes());
    }
    let duplicate_nested = encoded.replace("\"call_seq\":0", "\"call_seq\":0,\"call_seq\":0");
    rejected(&trace, duplicate_nested.as_bytes());
    for artifact in ["../trace.json", "/traces/trace.json", "traces/trace.log"] {
        let mut bad = request();
        bad["trace"]["artifact"] = artifact.into();
        bad["activation"]["trace"]["artifact"] = artifact.into();
        rejected(&trace, &serde_json::to_vec(&bad).unwrap());
    }
    let mut unknown_source = request();
    unknown_source["trace"]["verified"] = true.into();
    rejected(&trace, &serde_json::to_vec(&unknown_source).unwrap());
    // No resume boundary: the new kind must fail rather than use legacy facts.
    let truncated_path = path.with_extension("truncated.log");
    std::fs::write(&truncated_path, b"[App] 0x100!0x100 bl #0x200\n[App] 0x200!0x200 mov x0, #1 -> x0=0x1\n").unwrap();
    rejected(&File::open(&truncated_path).unwrap(), &serde_json::to_vec(&request()).unwrap());
    std::fs::remove_file(truncated_path).unwrap();
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
}

fn rejected(trace: &File, request: &[u8]) {
    let out = run(trace, request);
    assert!(!out.status.success(), "unexpected success for {}", String::from_utf8_lossy(request));
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.is_empty());
}
