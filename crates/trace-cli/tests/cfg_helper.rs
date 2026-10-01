#![cfg(unix)]
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

fn run(trace: &File, request: serde_json::Value) -> Output {
    let staged = unsafe { libc::fcntl(trace.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    assert!(staged >= 0);
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    command
        .args(["--cfg-helper", "--trace-fd", "3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(staged, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = command.spawn();
    unsafe {
        libc::close(staged);
    }
    let mut child = spawned.unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}
fn json(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn cfg_helper_real_trace_json_pages_dot_and_strict_failures() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example-trace-gumtrace.txt");
    let trace = File::open(path).unwrap();
    let function = "libmetasec_ov.so+0x143438";
    let request = serde_json::json!({"query":"activation","function":function,
        "call_seq":1,"entry_seq":2,"format":"json",
        "blocks":{"offset":0,"limit":1},"occurrences":{"offset":0,"limit":1}});
    let page = json(run(&trace, request.clone()));
    assert_eq!(page["function"], function);
    assert_eq!(page["call_seq"], 1);
    assert_eq!(page["entry_seq"], 2);
    assert_eq!(page["view"]["total_blocks"], 7);
    assert_eq!(page["view"]["blocks"].as_array().unwrap().len(), 1);
    assert_eq!(page["view"]["occurrences"].as_array().unwrap().len(), 1);
    let mut next = request.clone();
    next["blocks"]["offset"] = 1.into();
    assert_ne!(
        page["view"]["blocks"][0]["id"],
        json(run(&trace, next))["view"]["blocks"][0]["id"]
    );
    let dot_request = serde_json::json!({"query":"activation","function":function,
        "call_seq":1,"entry_seq":2,"format":"dot"});
    let dot = json(run(&trace, dot_request.clone()));
    assert!(dot["dot"].as_str().unwrap().starts_with("digraph cfg"));
    assert_eq!(dot, json(run(&trace, dot_request)));
    let aggregated = json(run(
        &trace,
        serde_json::json!({"query":"function", "function":function,
        "format":"json", "blocks":{"offset":0,"limit":10},"occurrences":{"offset":0,"limit":0}}),
    ));
    assert_eq!(aggregated["view"]["total_blocks"], 7);
    assert!(aggregated.get("call_seq").is_none());
    let mut wrong_anchor = request.clone();
    wrong_anchor["entry_seq"] = 3.into();
    let mut wrong_function = request.clone();
    wrong_function["function"] = "other+0x1".into();
    let mut unknown = request.clone();
    unknown["session_id"] = "guess".into();
    let mut null_page = request;
    null_page["blocks"] = serde_json::Value::Null;
    for invalid in [wrong_anchor, wrong_function, unknown, null_page] {
        let output = run(&trace, invalid);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() <= 16_500);
    }
    let writable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../example-trace-gumtrace.txt"),
        )
        .unwrap();
    let output = run(
        &writable,
        serde_json::json!({"query":"function","function":function,"format":"dot"}),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("read-only"));
}
