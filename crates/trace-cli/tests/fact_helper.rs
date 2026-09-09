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
