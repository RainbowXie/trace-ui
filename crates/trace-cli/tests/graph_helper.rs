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

fn run_graph_helper(trace_fd: RawFd, request: &[u8]) -> Output {
    let staged = unsafe { fcntl(trace_fd, F_DUPFD_CLOEXEC, 5) };
    assert!(
        staged >= 0,
        "stage fd: {:?}",
        std::io::Error::last_os_error()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    unsafe {
        command
            .args(["--algorithm-graph-helper", "--trace-fd", "3"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(move || {
                if dup2(staged, 3) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
    }
    let spawned = command.spawn();
    unsafe {
        close(staged);
    }
    let mut child = spawned.expect("spawn helper");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(request).expect("write request");
    drop(stdin);
    child.wait_with_output().expect("wait helper")
}

#[test]
fn graph_helper_reads_inherited_fd_and_echoes_complete_activation_selectors() {
    let path = std::env::temp_dir().join(format!(
        "trace-ui-graph-helper-{}-valid.log",
        std::process::id()
    ));
    std::fs::write(
        &path,
        "[App] 0x5000!0x5000 bl #0x1000; sp=0x3000\n[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1\n[App] 0x1004!0x1004 str x0, [x1]; x0=0x1 x1=0x1000 ; mem[WRITE] abs=0x1000 x0=0x1\n[App] 0x1008!0x1008 ret; sp=0x3000\n[App] 0x5004!0x5004 mov x0, x0; x0=0x1 -> x0=0x1\n",
    )
    .expect("trace");
    let trace = std::fs::File::open(&path).expect("open trace");
    let output = run_graph_helper(
        trace.as_raw_fd(),
        br#"{"target_seq":2,"target_address":4096,"target_size":8,"target_rw":"write","activations":[{"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x1000","call_seq":0,"entry_seq":1,"exit_seq":3,"resume_seq":4}]}"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json response");
    assert_eq!(value["target_seq"], 2);
    assert_eq!(value["target"]["kind"], "instruction");
    assert_eq!(
        value["target"]["owner"]["trace"]["pointer"],
        "/trace_files/0"
    );
    assert_eq!(value["activations"][0]["function"], "App+0x1000");
    assert!(value["content_identity"]
        .as_str()
        .is_some_and(|identity| !identity.is_empty()));
    std::fs::remove_file(path).expect("remove trace");
}

#[test]
fn graph_helper_rejects_unknown_control_fields_without_partial_stdout() {
    let path = std::env::temp_dir().join(format!(
        "trace-ui-graph-helper-{}-unknown.log",
        std::process::id()
    ));
    std::fs::write(&path, "[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1\n").expect("trace");
    let trace = std::fs::File::open(&path).expect("open trace");
    let output = run_graph_helper(
        trace.as_raw_fd(),
        br#"{"target_seq":0,"target_address":4096,"target_size":8,"target_rw":null,"activations":[],"nodes":[]}"#,
    );
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "helper must never publish partial facts"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
    std::fs::remove_file(path).expect("remove trace");
}

fn immediate_response(
    trace_text: &str,
    target: u32,
    exit: u32,
    extra: serde_json::Value,
) -> serde_json::Value {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "immediate-{}-{}.log",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, trace_text).unwrap();
    let trace = std::fs::File::open(&path).unwrap();
    let mut owners = vec![
        serde_json::json!({"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x1000","call_seq":0,"entry_seq":1,"exit_seq":exit,"resume_seq":exit+1}),
    ];
    if !extra.is_null() {
        owners.push(extra);
    }
    let request = serde_json::to_vec(&serde_json::json!({"target_seq":target,"target_address":4096,"target_size":8,"target_rw":"write","activations":owners})).unwrap();
    let output = run_graph_helper(trace.as_raw_fd(), &request);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_file(path).unwrap();
    serde_json::from_slice(&output.stdout).unwrap()
}

fn origins(response: &serde_json::Value) -> Vec<&serde_json::Value> {
    response["dependency_edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["producer"]["kind"] == "instruction_immediate")
        .collect()
}

#[test]
fn same_block_literals_keep_real_instruction_producers_and_dead_literals_are_absent() {
    for second in ["1", "2"] {
        let trace = format!("[App] 0x5000!0x5000 bl #0x1000\n[App] 0x1000!0x1000 mov x0, #1 -> x0=0x1\n[App] 0x1004!0x1004 mov x2, #{second} -> x2=0x2\n[App] 0x1008!0x1008 mov x9, #99 -> x9=0x63\n[App] 0x100c!0x100c add x0, x0, x2; x0=0x1 x2=0x2 -> x0=0x3\n[App] 0x1010!0x1010 str x0, [x1]; x0=0x3 x1=0x1000 mem_w=0x1000\n[App] 0x1014!0x1014 ret\n[App] 0x5004!0x5004 nop\n");
        let value = immediate_response(&trace, 5, 6, serde_json::Value::Null);
        let sources = origins(&value);
        assert_eq!(sources.len(), 2, "{value}");
        for (edge, seq) in sources.iter().zip([1, 2]) {
            assert_eq!(edge["producer"]["seq"], seq);
            assert_eq!(edge["consumer"]["kind"], "instruction");
            assert_eq!(edge["consumer"]["seq"], seq);
            assert_eq!(edge["producer"]["block"]["entry_seq"], 1);
            assert_eq!(edge["producer"]["block_index"], 0);
        }
        assert!(value["dependency_edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["producer"]["kind"] == "instruction"
                && e["producer"]["seq"] == 2
                && e["consumer"]["seq"] == 4));
        assert!(
            value["unresolved"].as_array().unwrap().is_empty(),
            "{value}"
        );
    }
}

#[test]
fn loop_occurrences_keep_distinct_block_entries() {
    let value = immediate_response("[App] 0x5000!0x5000 bl #0x1000\n[App] 0x1000!0x1000 mov x0, #1 -> x0=0x1\n[App] 0x1004!0x1004 mov x2, x0; x0=0x1 -> x2=0x1\n[App] 0x1008!0x1008 b #0x1000\n[App] 0x1000!0x1000 mov x0, #1 -> x0=0x1\n[App] 0x1004!0x1004 add x0, x0, x2; x0=0x1 x2=0x1 -> x0=0x2\n[App] 0x1008!0x1008 str x0, [x1]; x0=0x2 x1=0x1000 mem_w=0x1000\n[App] 0x100c!0x100c ret\n[App] 0x5004!0x5004 nop\n", 6, 7, serde_json::Value::Null);
    let sources = origins(&value);
    assert_eq!(sources.len(), 2, "{value}");
    assert_eq!(sources[0]["producer"]["block"]["entry_seq"], 1);
    assert_eq!(sources[1]["producer"]["block"]["entry_seq"], 4);
    assert_eq!(sources[1]["producer"]["block_index"], 1);
}

#[test]
fn nested_owner_is_not_bound_to_callers_block() {
    let extra = serde_json::json!({"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x2000","call_seq":2,"entry_seq":3,"exit_seq":4,"resume_seq":5});
    let value = immediate_response("[App] 0x5000!0x5000 bl #0x1000\n[App] 0x1000!0x1000 nop\n[App] 0x1004!0x1004 bl #0x2000\n[App] 0x2000!0x2000 mov x0, #7 -> x0=0x7\n[App] 0x2004!0x2004 ret\n[App] 0x1008!0x1008 str x0, [x1]; x0=0x7 x1=0x1000 mem_w=0x1000\n[App] 0x100c!0x100c ret\n[App] 0x5004!0x5004 nop\n", 5, 6, extra);
    let sources = origins(&value);
    assert_eq!(sources.len(), 1, "{value}");
    assert_eq!(sources[0]["producer"]["owner"]["function"], "App+0x2000");
    assert_eq!(sources[0]["producer"]["block"]["entry_seq"], 3);
}

#[test]
fn unsupported_immediate_keeps_target_gap() {
    for op in [
        "mov x0, #1, lsl #16",
        "movk x0, #1",
        "movz x0, #1",
        "mov x0, #-1",
    ] {
        let trace = format!("[App] 0x5000!0x5000 bl #0x1000\n[App] 0x1000!0x1000 {op} -> x0=0x1\n[App] 0x1004!0x1004 str x0, [x1]; x0=0x1 x1=0x1000 mem_w=0x1000\n[App] 0x1008!0x1008 ret\n[App] 0x5004!0x5004 nop\n");
        let value = immediate_response(&trace, 2, 3, serde_json::Value::Null);
        assert!(origins(&value).is_empty());
        assert!(
            value["unresolved"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["kind"] == "unsupported_instruction"),
            "{op}: {value}"
        );
    }
}
