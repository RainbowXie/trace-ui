#![cfg(unix)]

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

unsafe extern "C" {
    fn dup2(oldfd: RawFd, newfd: RawFd) -> i32;
    fn close(fd: RawFd) -> i32;
    fn fcntl(fd: RawFd, cmd: i32, arg: i32) -> i32;
}

const F_DUPFD_CLOEXEC: i32 = 1030;

fn stage_fd(fd: RawFd) -> RawFd {
    let staged = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 5) };
    assert!(
        staged >= 0,
        "stage fd: {:?}",
        std::io::Error::last_os_error()
    );
    staged
}

fn spawn_fact_helper(
    trace_fd: RawFd,
    trace_arg: &str,
    request: &[u8],
    extra_args: &[String],
) -> Output {
    let staged_trace = stage_fd(trace_fd);
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    unsafe {
        command
            .args(["--function-facts-helper", "--trace-fd", trace_arg])
            .args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(move || {
                if dup2(staged_trace, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
    }
    let spawned = command.spawn();
    unsafe {
        close(staged_trace);
    }
    let mut child = spawned.expect("spawn helper");
    let mut stdin = child.stdin.take().expect("helper stdin");
    stdin.write_all(request).expect("control request");
    drop(stdin);
    child.wait_with_output().expect("helper output")
}

#[test]
fn address_provenance_real_queries() {
    let dir = std::env::temp_dir().join(format!("address-provenance-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("trace.log");
    let query = br#"{"kind":"address_provenance","call_seq":1,"entry_seq":2,"function":"App+0x200","target_modules":[]}"#;
    let run = |body: &str| {
        let raw = format!("[App] 0x1100!0x100 mov x0, x1 ; x1=0x3000 -> x0=0x3000\n[App] 0x1104!0x104 bl #0x1200 ; sp=0x8000\n{body}[App] 0x1108!0x108 nop\n");
        std::fs::write(&path, raw).unwrap();
        let fd = std::fs::File::open(&path).unwrap();
        let out = run_fact_helper(fd.as_raw_fd(), query);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    let ok = run("[App] 0x1200!0x200 add x8, x0, #8 ; x0=0x3000 -> x8=0x3008\n[App] 0x1204!0x204 str x0, [x8] ; x0=0x3000 x8=0x3008 mem_w=0x3008\n[App] 0x1208!0x208 ret\n");
    assert_eq!(ok["coverage"]["complete"], true, "{ok}");
    assert_eq!(ok["accesses"][0]["origin_anchor"]["register"], "x0");
    assert_eq!(ok["accesses"][0]["integer_delta"], 8);
    assert_eq!(ok["accesses"][0]["address_operand"], "[x8]");
    assert_eq!(
        ok["accesses"][0]["definition_steps"][0]["source_operand"],
        "x0, #8"
    );
    let frame = run("[App] 0x1200!0x200 stp x29, x30, [sp, #-32]! ; sp=0x8000 x29=0x11 x30=0x1108 mem_w=0x7fe0 -> sp=0x7fe0\n[App] 0x1204!0x204 mov x29, sp ; sp=0x7fe0 -> x29=0x7fe0\n[App] 0x1208!0x208 str x0, [sp, #16] ; sp=0x7fe0 x0=0x3000 mem_w=0x7ff0\n[App] 0x120c!0x20c ldr x8, [x29, #16] ; sp=0x7fe0 x29=0x7fe0 mem_r=0x7ff0 -> x8=0x3000\n[App] 0x1210!0x210 ldp x29, x30, [sp], #32 ; sp=0x7fe0 mem_r=0x7fe0 -> sp=0x8000 x29=0x11 x30=0x1108\n[App] 0x1214!0x214 ret ; sp=0x8000\n");
    assert_eq!(frame["coverage"]["complete"], true, "{frame}");
    assert_eq!(frame["frames"][0]["balanced"], true, "{frame}");
    assert_eq!(frame["frames"][0]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(frame["accesses"][0]["size"], 16);
    assert_eq!(frame["accesses"][0]["frame_access"]["live_frame_start"], "0x7fe0");
    assert_eq!(frame["accesses"][3]["frame_access"]["live_frame_start"], "0x7fe0");
    assert_eq!(frame["accesses"][3]["frame_access"]["post_sp"], "0x8000");
    for access in frame["accesses"].as_array().unwrap() {
        assert_eq!(access["frame_access"]["within_live_frame"], true, "{frame}");
    }
    let nested_frame = run("[App] 0x1200!0x200 sub sp, sp, #32 ; sp=0x8000 -> sp=0x7fe0\n[App] 0x1204!0x204 bl #0x1400 ; sp=0x7fe0\n[App] 0x1400!0x400 sub sp, sp, #16 ; sp=0x7fe0 -> sp=0x7fd0\n[App] 0x1404!0x404 str x0, [sp] ; sp=0x7fd0 x0=0x3000 mem_w=0x7fd0\n[App] 0x1408!0x408 add sp, sp, #16 ; sp=0x7fd0 -> sp=0x7fe0\n[App] 0x140c!0x40c ret ; sp=0x7fe0\n[App] 0x1208!0x208 add sp, sp, #32 ; sp=0x7fe0 -> sp=0x8000\n[App] 0x120c!0x20c ret ; sp=0x8000\n");
    assert_eq!(nested_frame["coverage"]["complete"], true, "{nested_frame}");
    assert_eq!(nested_frame["frames"].as_array().unwrap().len(), 2);
    assert_eq!(nested_frame["accesses"][0]["frame_access"]["owner_entry_seq"], 4);
    assert_eq!(nested_frame["accesses"][0]["frame_access"]["live_frame_end"], "0x7fe0");
    let argument = run("[App] 0x1200!0x200 sub sp, sp, #32 ; sp=0x8000 -> sp=0x7fe0\n[App] 0x1204!0x204 str x0, [sp, #32] ; sp=0x7fe0 x0=0x3000 mem_w=0x8000\n[App] 0x1208!0x208 add sp, sp, #32 ; sp=0x7fe0 -> sp=0x8000\n[App] 0x120c!0x20c ret ; sp=0x8000\n");
    assert_eq!(argument["accesses"][0]["frame_access"]["within_live_frame"], false);
    let negative = run("[App] 0x1200!0x200 sub sp, sp, #32 ; sp=0x8000 -> sp=0x7fe0\n[App] 0x1204!0x204 str x0, [sp, #-8] ; sp=0x7fe0 x0=0x3000 mem_w=0x7fd8\n[App] 0x1208!0x208 add sp, sp, #32 ; sp=0x7fe0 -> sp=0x8000\n[App] 0x120c!0x20c ret ; sp=0x8000\n");
    assert_eq!(negative["frames"][0]["balanced"], true, "{negative}");
    assert_eq!(negative["accesses"][0]["frame_access"]["within_live_frame"], false);
    let copied = run("[App] 0x1200!0x200 mov x29, sp ; sp=0x8000 -> x29=0x8000\n[App] 0x1204!0x204 sub sp, sp, #32 ; sp=0x8000 -> sp=0x7fe0\n[App] 0x1208!0x208 mov sp, x29 ; sp=0x7fe0 x29=0x8000 -> sp=0x8000\n[App] 0x120c!0x20c ret ; sp=0x8000\n");
    assert_eq!(copied["frames"][0]["balanced"], true, "{copied}");
    for body in [
        "[App] 0x1200!0x200 sub sp, sp, x8 ; sp=0x8000 x8=0x20 -> sp=0x7fe0\n[App] 0x1204!0x204 ret ; sp=0x8000\n",
        "[App] 0x1200!0x200 sub sp, sp, #32 ; sp=0x8000 -> sp=0x7fe0\n[App] 0x1204!0x204 ret ; sp=0x7fe0\n",
        "[App] 0x1200!0x200 mov x29, sp ; sp=0x8000 -> x29=0x8000\n[App] 0x1204!0x204 mov x29, #0x8000 ; -> x29=0x8000\n[App] 0x1208!0x208 mov sp, x29 ; sp=0x8000 x29=0x8000 -> sp=0x8000\n[App] 0x120c!0x20c ret ; sp=0x8000\n",
    ] {
        let rejected = run(body);
        assert_eq!(rejected["coverage"]["complete"], false, "{rejected}");
        assert_eq!(rejected["frames"][0]["balanced"], false, "{rejected}");
    }
    let blob = run("[App] 0x1200!0x200 ldr x8, [x0] ; x0=0x3000 mem_r=0x3000 -> x8=0x3000\n[App] 0x1204!0x204 str x0, [x8] ; x0=0x3000 x8=0x3000 mem_w=0x3000\n[App] 0x1208!0x208 ret\n");
    assert_eq!(blob["coverage"]["complete"], false);
    assert!(blob["accesses"][1]["origin_anchor"].is_null());
    let data = run("[App] 0x1200!0x200 mov x8, #0x3000 -> x8=0x3000\n[App] 0x1204!0x204 str x0, [x8] ; x0=0x3000 x8=0x3000 mem_w=0x3000\n[App] 0x1208!0x208 ret\n");
    assert_eq!(data["coverage"]["complete"], false);
    assert!(data["accesses"][0]["origin_anchor"].is_null());
    let stack = run("[App] 0x1200!0x200 ldr x8, [sp] ; sp=0x8000 mem_r=0x8000 -> x8=0x3000\n[App] 0x1204!0x204 ldr w9, [x8] ; x8=0x3000 sp=0x8000 mem_r=0x3000 -> w9=0x41\n[App] 0x1208!0x208 ret ; sp=0x8000\n");
    assert_eq!(stack["coverage"]["complete"], true, "{stack}");
    assert_eq!(
        stack["accesses"][1]["origin_anchor"]["kind"],
        "stack_argument"
    );
    let overwritten = run("[App] 0x1200!0x200 str x0, [sp] ; x0=0x3000 sp=0x8000 mem_w=0x8000\n[App] 0x1204!0x204 ldr x8, [sp] ; sp=0x8000 mem_r=0x8000 -> x8=0x3000\n[App] 0x1208!0x208 ldr w9, [x8] ; x8=0x3000 mem_r=0x3000 -> w9=0x41\n[App] 0x120c!0x20c ret\n");
    assert_eq!(overwritten["coverage"]["complete"], false);
    assert!(overwritten["accesses"][2]["origin_anchor"].is_null());
    let callee = run("[App] 0x1200!0x200 mov x8, x0 ; x0=0x3000 -> x8=0x3000\n[App] 0x1204!0x204 bl #0x1400\n[App] 0x1400!0x400 ldr w9, [x8] ; x8=0x3000 mem_r=0x3000 -> w9=0x41\n[App] 0x1404!0x404 ret\n[App] 0x1208!0x208 ret\n");
    assert_eq!(callee["coverage"]["complete"], true, "{callee}");
    assert_eq!(callee["accesses"][0]["seq"], 4);
    assert_eq!(callee["accesses"][0]["origin_anchor"]["seq"], 2);
    let rewritten = run("[App] 0x1200!0x200 mov x8, x0 ; x0=0x3000 -> x8=0x3000\n[App] 0x1204!0x204 mov w8, #0x3000 -> w8=0x3000\n[App] 0x1208!0x208 ldr w9, [x8] ; x8=0x3000 mem_r=0x3000 -> w9=0x41\n[App] 0x120c!0x20c ret\n");
    assert_eq!(rewritten["coverage"]["complete"], false);
    let external = run("[App] 0x1200!0x200 bl #0x9000\n[App] 0x1204!0x204 ldr w9, [x0] ; x0=0x3000 mem_r=0x3000 -> w9=0x41\n[App] 0x1208!0x208 ret\n");
    assert_eq!(external["coverage"]["complete"], false);
    assert!(external["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["kind"] == "external_boundary"));
    for bad in [
        String::from_utf8(query.to_vec()).unwrap().replace(
            "\"target_modules\":[]",
            "\"target_modules\":[\"App\",\"App\"]",
        ),
        String::from_utf8(query.to_vec())
            .unwrap()
            .replace("\"entry_seq\":2", "\"entry_seq\":2,\"entry_seq\":2"),
        String::from_utf8(query.to_vec())
            .unwrap()
            .replace("App+0x200", "App+0x201"),
        String::from_utf8(query.to_vec())
            .unwrap()
            .replace("\"target_modules\":[]", "\"target_modules\":[],\"extra\":1"),
    ] {
        let fd = std::fs::File::open(&path).unwrap();
        let out = run_fact_helper(fd.as_raw_fd(), bad.as_bytes());
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
    std::fs::write(&path, "[App] 0x1100!0x100 nop\n[App] 0x1104!0x104 bl #0x1200\n[App] 0x1200!0x200 adrp x8, #0x5000 ; -> x8=0x5000\n[App] 0x1204!0x204 add x8, x8, #8 ; x8=0x5000 -> x8=0x5008\n[App] 0x1208!0x208 ldr w9, [x8] ; x8=0x5008 mem_r=0x5008 -> w9=0x41\n[App] 0x120c!0x20c ret\n[App] 0x1108!0x108 nop\n").unwrap();
    let fd = std::fs::File::open(&path).unwrap();
    let global_query = String::from_utf8(query.to_vec())
        .unwrap()
        .replace("\"target_modules\":[]", "\"target_modules\":[\"App\"]");
    let out = run_fact_helper(fd.as_raw_fd(), global_query.as_bytes());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let global: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(global["coverage"]["complete"], true, "{global}");
    assert_eq!(
        global["accesses"][0]["origin_anchor"]["global"],
        "App+0x4000"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn runtime_mapping_real_queries() {
    let root = std::env::temp_dir().join(format!("runtime-mapping-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("trace.log");
    let valid = "[App] 0x1100!0x100 nop\n[App] 0x1104!0x104 bl #0x1200\n[App] 0x1200!0x200 nop\n[App] 0x1204!0x204 ret\n[App] 0x1108!0x108 nop\n[Other] 0x9100!0x100 nop\n";
    let request = br#"{"kind":"runtime_mapping","call_seq":1,"entry_seq":2,"function":"App+0x200","target_modules":["Other","App"]}"#;
    std::fs::write(&path, valid).unwrap();
    let trace = std::fs::File::open(&path).unwrap();
    let out = run_fact_helper(trace.as_raw_fd(), request);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["target_modules"], serde_json::json!(["App", "Other"]));
    assert_eq!(body["exit_seq"], 3);
    assert_eq!(body["resume_seq"], 4);
    assert_eq!(body["mappings"][0]["runtime_base"], "0x1000");
    assert_eq!(body["mappings"][1]["runtime_base"], "0x9000");
    assert_eq!(
        body["mappings"][0]["source"],
        serde_json::json!({"seq":0,"runtime_pc":"0x1100","stable_offset":"0x100"})
    );
    assert_eq!(body["mappings"][1]["source"]["seq"], 5);
    drop(trace);
    for bad_request in [
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("App+0x200", "App+0x201"),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"entry_seq\":2", "\"entry_seq\":3"),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"Other\",\"App\"", "\"App\",\"App\""),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"Other\"", "\"Missing\""),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"Other\"", "\"../Other\""),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"kind\":\"runtime_mapping\"", "\"kind\":\"unknown\""),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"call_seq\":1", "\"call_seq\":1,\"call_seq\":1"),
        String::from_utf8(request.to_vec())
            .unwrap()
            .replace("\"call_seq\":1", "\"extra\":true,\"call_seq\":1"),
    ] {
        let trace = std::fs::File::open(&path).unwrap();
        let out = run_fact_helper(trace.as_raw_fd(), bad_request.as_bytes());
        assert!(!out.status.success(), "must reject {bad_request}");
        assert!(out.stdout.is_empty());
    }
    for (line, error) in [
        ("[Other] 0x9204!0x104 nop\n", "inconsistent runtime bases"),
        ("[Other] 0x10!0x100 nop\n", "below its stable offset"),
    ] {
        std::fs::write(&path, format!("{valid}{line}")).unwrap();
        let trace = std::fs::File::open(&path).unwrap();
        let out = run_fact_helper(trace.as_raw_fd(), request);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn run_fact_helper(trace_fd: RawFd, request: &[u8]) -> Output {
    spawn_fact_helper(trace_fd, "3", request, &[])
}

#[test]
fn helper_rejects_missing_trace_fd() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    let output = command
        .arg("--function-facts-helper")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn helper");
    assert!(!output.status.success(), "missing --trace-fd must fail");
    assert!(output.stdout.is_empty(), "stdout must be empty on failure");
}

#[test]
fn helper_rejects_standard_descriptor() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-fact-std-desc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    std::fs::write(&trace_path, "[App] 0x1000!0x1000 nop\n").expect("trace");
    let trace = std::fs::File::open(&trace_path).expect("open trace");

    let output = spawn_fact_helper(trace.as_raw_fd(), "0", b"{}", &[]);
    assert!(!output.status.success(), "trace-fd 0 must fail");
    assert!(output.stdout.is_empty(), "stdout must be empty on failure");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_rejects_invalid_json_request() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-fact-invalid-req-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    std::fs::write(&trace_path, "[App] 0x1000!0x1000 nop\n").expect("trace");
    let trace = std::fs::File::open(&trace_path).expect("open trace");

    let output = run_fact_helper(trace.as_raw_fd(), b"not-valid-json");
    assert!(!output.status.success(), "malformed json must fail");
    assert!(output.stdout.is_empty(), "stdout must be empty on failure");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_rejects_unknown_fields_in_request() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-fact-unknown-field-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    std::fs::write(&trace_path, "[App] 0x1000!0x1000 nop\n").expect("trace");
    let trace = std::fs::File::open(&trace_path).expect("open trace");

    let output = run_fact_helper(
        trace.as_raw_fd(),
        b"{\"call_seq\":0,\"entry_seq\":1,\"unexpected_key\":true}",
    );
    assert!(!output.status.success(), "unknown fields must fail closed");
    assert!(output.stdout.is_empty(), "stdout must be empty on failure");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_returns_facts_for_valid_activation() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-fact-valid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    std::fs::write(
        &trace_path,
        "[App] 0x1000!0x1000 mov x0, #0x11; x0=0x0 sp=0x3000 -> x0=0x11\n\
         [App] 0x1004!0x1004 bl #0x2000; x0=0x11 sp=0x3000\n\
         [App] 0x2000!0x2000 mov x0, #0x42; x0=0x11 sp=0x3000 -> x0=0x42\n\
         [App] 0x2004!0x2004 ret; x0=0x42 sp=0x3000\n\
         [App] 0x1008!0x1008 mov x0, #0x99; x0=0x42 sp=0x3000 -> x0=0x99\n",
    )
    .expect("trace");
    let trace = std::fs::File::open(&trace_path).expect("open trace");

    let output = run_fact_helper(trace.as_raw_fd(), b"{\"call_seq\":1,\"entry_seq\":2}\n");
    assert!(
        output.status.success(),
        "valid activation must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("\"function\":\"App+0x2000\""),
        "body must contain function site: {body}"
    );
    assert!(
        body.contains("\"trace_anchors\""),
        "body must contain trace_anchors: {body}"
    );
    assert!(body.contains("\"abi\""), "body must contain abi: {body}");
    assert!(
        body.contains("\"executed_block_sequence\""),
        "body must contain executed_block_sequence: {body}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_rejects_unresolved_activation_fail_closed() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-fact-unresolved-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    std::fs::write(
        &trace_path,
        "[App] 0x1000!0x1000 bl #0x2000; sp=0x3000\n\
         [App] 0x2000!0x2000 mov x0, #0x1; sp=0x3000\n",
    )
    .expect("trace");
    let trace = std::fs::File::open(&trace_path).expect("open trace");

    let output = run_fact_helper(trace.as_raw_fd(), b"{\"call_seq\":0,\"entry_seq\":1}\n");
    assert!(
        !output.status.success(),
        "unclosed/truncated activation must fail closed"
    );
    assert!(output.stdout.is_empty(), "stdout must be empty on failure");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_operates_on_inherited_fd_without_pathname() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-fact-fd-only-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    std::fs::write(
        &trace_path,
        "[App] 0x1000!0x1000 mov x0, #0x11; x0=0x0 sp=0x3000 -> x0=0x11\n\
         [App] 0x1004!0x1004 bl #0x2000; x0=0x11 sp=0x3000\n\
         [App] 0x2000!0x2000 mov x0, #0x42; x0=0x11 sp=0x3000 -> x0=0x42\n\
         [App] 0x2004!0x2004 ret; x0=0x42 sp=0x3000\n\
         [App] 0x1008!0x1008 mov x0, #0x99; x0=0x42 sp=0x3000 -> x0=0x99\n",
    )
    .expect("trace");
    let trace = std::fs::File::open(&trace_path).expect("open trace");

    // 在磁盘上重命名文件，证明 helper 仅使用继承的 fd，不按原路径重新打开
    let moved_path = root.join("trace.log.moved");
    std::fs::rename(&trace_path, &moved_path).expect("rename trace file");

    let output = run_fact_helper(trace.as_raw_fd(), b"{\"call_seq\":1,\"entry_seq\":2}\n");
    assert!(
        output.status.success(),
        "helper on inherited fd must succeed even if pathname changed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(body.contains("\"function\":\"App+0x2000\""));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_runs_on_real_gumtrace_sample() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let trace_path = format!("{manifest_dir}/../../example-trace-gumtrace.txt");
    let trace = std::fs::File::open(&trace_path).expect("open example gumtrace");

    let output = run_fact_helper(trace.as_raw_fd(), b"{\"call_seq\":1,\"entry_seq\":2}\n");
    assert!(
        output.status.success(),
        "fact helper on real gumtrace sample must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(body.contains("\"function\":\"libmetasec_ov.so+0x143438\""));
    assert!(body.contains("\"trace_anchors\""));
    assert!(body.contains("\"abi\""));
    assert!(body.contains("\"executed_block_sequence\""));

    let json_val: serde_json::Value = serde_json::from_str(&body).expect("parse JSON");
    let writes = json_val["memory_writes"]
        .as_array()
        .expect("memory_writes array");
    assert!(!writes.is_empty(), "real sample should have memory writes");
    for w in writes {
        assert!(
            w.get("write_seqs").is_some(),
            "write must have write_seqs: {w}"
        );
        assert!(w.get("seqs").is_none(), "write must NOT have seqs: {w}");
        if w["bytes"].is_null() {
            let addr = w["address"].as_str().unwrap();
            let unres = json_val["unresolved"].as_array().expect("unresolved array");
            assert!(
                unres.iter().any(|u| u["location"] == addr && u["kind"] == "missing_memory_definition"),
                "bytes=null write must have matching missing_memory_definition unresolved for {addr}"
            );
        }
    }
}
