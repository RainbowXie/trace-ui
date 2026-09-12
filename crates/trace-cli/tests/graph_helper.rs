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
fn graph_helper_reads_inherited_fd_and_returns_mechanical_facts() {
    let path = std::env::temp_dir().join(format!(
        "trace-ui-graph-helper-{}-valid.log",
        std::process::id()
    ));
    std::fs::write(
        &path,
        "[App] 0x1000!0x1000 mov x0, #1; x0=0x0 -> x0=0x1\n[App] 0x1004!0x1004 str x0, [x1]; x0=0x1 x1=0x1000 ; mem[WRITE] abs=0x1000 x0=0x1\n",
    )
    .expect("trace");
    let trace = std::fs::File::open(&path).expect("open trace");
    let output = run_graph_helper(
        trace.as_raw_fd(),
        br#"{"target_seq":1,"target_address":4096,"target_size":8,"target_rw":"write"}"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json response");
    assert_eq!(value["target_seq"], 1);
    assert_eq!(value["dependency_edges"][0]["producer"]["seq"], 0);
    assert!(value["content_identity"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
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
        br#"{"target_seq":0,"target_address":4096,"target_size":8,"target_rw":null,"nodes":[]}"#,
    );
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "helper must never publish partial facts"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
    std::fs::remove_file(path).expect("remove trace");
}
