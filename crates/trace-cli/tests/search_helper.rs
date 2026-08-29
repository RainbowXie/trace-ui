#![cfg(unix)]

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

unsafe extern "C" {
    fn dup2(oldfd: RawFd, newfd: RawFd) -> i32;
    fn close(fd: RawFd) -> i32;
    fn fcntl(fd: RawFd, cmd: i32, arg: i32) -> i32;
    fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
}

/// Linux F_DUPFD_CLOEXEC：分配一个 >= 5 的空闲 fd 并复制源 fd。
const F_DUPFD_CLOEXEC: i32 = 1030;

/// 在父进程里为 trace/pattern fd 分配中转 fd，返回 (staged_trace, staged_pattern)。
///
/// 不能用固定编号中转（早期版本用 30/31）：并行测试把源 fd 编号推上去后，
/// 中转编号可能与另一个源 fd 相同，close 中转 fd 会误关源 fd（EBADF）。
/// F_DUPFD_CLOEXEC 让内核分配与两个源都不冲突的新 fd。
fn stage_fds(trace_fd: RawFd, pattern_fd: RawFd) -> (RawFd, RawFd) {
    // SAFETY: fcntl(F_DUPFD_CLOEXEC) 只复制当前有效的源 fd。
    let staged_trace = unsafe { fcntl(trace_fd, F_DUPFD_CLOEXEC, 5) };
    assert!(
        staged_trace >= 0,
        "stage trace fd: {:?}",
        std::io::Error::last_os_error()
    );
    // SAFETY: 同上。
    let staged_pattern = unsafe { fcntl(pattern_fd, F_DUPFD_CLOEXEC, 5) };
    assert!(
        staged_pattern >= 0,
        "stage pattern fd: {:?}",
        std::io::Error::last_os_error()
    );
    (staged_trace, staged_pattern)
}

fn spawn_helper(
    trace_fd: RawFd,
    pattern_fd: RawFd,
    trace_arg: &str,
    pattern_arg: &str,
    request: &[u8],
    extra_args: &[String],
) -> Output {
    let (staged_trace, staged_pattern) = stage_fds(trace_fd, pattern_fd);
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    unsafe {
        command
            .args([
                "--search-memory-helper",
                "--trace-fd",
                trace_arg,
                "--pattern-fd",
                pattern_arg,
            ])
            .args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(move || {
                // SAFETY: 中转 fd 由父进程持有直至 spawn 完成，子进程 fork 后必然有效；
                // dup2 到目标 fd 会清除 close-on-exec。
                if dup2(staged_trace, 3) == -1 || dup2(staged_pattern, 4) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
    }
    let spawned = command.spawn();
    // SAFETY: spawn 已返回，中转 fd 的使命结束。
    unsafe {
        close(staged_trace);
        close(staged_pattern);
    }
    let mut child = spawned.expect("spawn helper");
    let mut stdin = child.stdin.take().expect("helper stdin");
    stdin.write_all(request).expect("control request");
    drop(stdin);
    child.wait_with_output().expect("helper output")
}

fn run_helper(trace_fd: RawFd, pattern_fd: RawFd, request: &[u8]) -> Output {
    run_helper_with_cli_fds(trace_fd, pattern_fd, "3", "4", request)
}

fn run_helper_with_cli_fds(
    trace_fd: RawFd,
    pattern_fd: RawFd,
    trace_arg: &str,
    pattern_arg: &str,
    request: &[u8],
) -> Output {
    spawn_helper(trace_fd, pattern_fd, trace_arg, pattern_arg, request, &[])
}

#[test]
fn inherited_fd_search_helper_reads_trace_and_pattern_without_a_pathname() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    ).expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");
    let trace_fd = trace.as_raw_fd();
    let pattern_fd = pattern.as_raw_fd();

    let output = run_helper(trace_fd, pattern_fd, b"{\"offset\":0,\"limit\":1}\n");
    assert!(output.status.success(), "stderr: {:?}", output.stderr);
    let body = String::from_utf8(output.stdout).expect("utf8 response");
    assert!(
        body.contains("\"content_identity\":"),
        "response identity missing: {body}"
    );
    assert!(body.contains("\"matches\""), "response: {body}");
    assert!(body.contains("\"address\":8192"), "response: {body}");
    assert!(body.contains("\"size\":4"), "response: {body}");
    assert!(
        !body.contains("01020304"),
        "helper must not materialize pattern bytes: {body}"
    );

    let second_output = run_helper(trace_fd, pattern_fd, b"{\"offset\":1,\"limit\":1}\n");
    assert!(
        second_output.status.success(),
        "second page stderr: {:?}",
        second_output.stderr
    );
    let second_body = String::from_utf8(second_output.stdout).expect("second response utf8");
    assert!(
        second_body.contains("\"seq\":2"),
        "second page: {second_body}"
    );
    let identity = body
        .split("\"content_identity\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("first identity");
    assert!(
        second_body.contains(&format!("\"content_identity\":\"{identity}\"")),
        "content identity changed between pages"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn inherited_fd_helper_rejects_fifo_and_unknown_control_fields() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-reject-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    let fifo_path = root.join("pattern.fifo");
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    )
    .expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");
    let fifo_c = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).expect("fifo path");
    assert_eq!(unsafe { mkfifo(fifo_c.as_ptr(), 0o600) }, 0, "mkfifo");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");
    let fifo = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(0x800)
        .open(&fifo_path)
        .expect("open fifo");

    let fifo_output = run_helper(
        trace.as_raw_fd(),
        fifo.as_raw_fd(),
        b"{\"offset\":0,\"limit\":50}\n",
    );
    assert!(!fifo_output.status.success());
    assert!(String::from_utf8_lossy(&fifo_output.stderr).contains("not a regular file"));

    let invalid_output = run_helper(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        b"{\"offset\":0,\"limit\":50,\"unexpected\":true}\n",
    );
    assert!(!invalid_output.status.success());
    assert!(String::from_utf8_lossy(&invalid_output.stderr).contains("invalid helper request"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn inherited_fd_helper_rejects_alias_and_standard_descriptors() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-fd-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    )
    .expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");

    let aliased = run_helper_with_cli_fds(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        "3",
        "3",
        br#"{"offset":0,"limit":1}"#,
    );
    assert!(!aliased.status.success());
    assert!(
        String::from_utf8_lossy(&aliased.stderr).contains("must be different"),
        "stderr: {:?}",
        aliased.stderr
    );

    let stdin_fd = run_helper_with_cli_fds(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        "0",
        "4",
        br#"{"offset":0,"limit":1}"#,
    );
    assert!(!stdin_fd.status.success());
    assert!(
        String::from_utf8_lossy(&stdin_fd.stderr).contains("reserved"),
        "stderr: {:?}",
        stdin_fd.stderr
    );

    let stdout_fd = run_helper_with_cli_fds(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        "3",
        "1",
        br#"{"offset":0,"limit":1}"#,
    );
    assert!(!stdout_fd.status.success());
    assert!(
        String::from_utf8_lossy(&stdout_fd.stderr).contains("reserved"),
        "stderr: {:?}",
        stdout_fd.stderr
    );

    let _ = std::fs::remove_dir_all(root);
}

fn run_helper_with_args(
    trace_fd: RawFd,
    pattern_fd: RawFd,
    request: &[u8],
    extra_args: &[String],
) -> Output {
    spawn_helper(trace_fd, pattern_fd, "3", "4", request, extra_args)
}

#[test]
fn helper_reuses_verified_fingerprint_on_the_second_page() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-fingerprint-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    let log_path = root.join("fingerprint.log");
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    )
    .expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");

    let log_args = || {
        vec![
            "--fingerprint-log".to_string(),
            log_path.to_string_lossy().into_owned(),
        ]
    };
    let first = run_helper_with_args(
        std::fs::File::open(&trace_path).expect("trace").as_raw_fd(),
        std::fs::File::open(&pattern_path)
            .expect("pattern")
            .as_raw_fd(),
        b"{\"offset\":0,\"limit\":1}\n",
        &log_args(),
    );
    assert!(
        first.status.success(),
        "first page stderr: {:?}",
        first.stderr
    );
    let second = run_helper_with_args(
        std::fs::File::open(&trace_path).expect("trace").as_raw_fd(),
        std::fs::File::open(&pattern_path)
            .expect("pattern")
            .as_raw_fd(),
        b"{\"offset\":1,\"limit\":1}\n",
        &log_args(),
    );
    assert!(
        second.status.success(),
        "second page stderr: {:?}",
        second.stderr
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("\"seq\":2"));

    let log =
        std::fs::read_to_string(&log_path).expect("fingerprint log must record hash decisions");
    let entries: Vec<&str> = log.lines().collect();
    assert_eq!(
        entries,
        ["computed", "reused"],
        "second page must reuse the verified fingerprint, not re-hash the trace"
    );

    // 原地重写后签名变化：下一页必须重新 hash 并返回新内容的结果。
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    )
    .expect("rewrite trace");
    let third = run_helper_with_args(
        std::fs::File::open(&trace_path).expect("trace").as_raw_fd(),
        std::fs::File::open(&pattern_path)
            .expect("pattern")
            .as_raw_fd(),
        b"{\"offset\":0,\"limit\":1}\n",
        &log_args(),
    );
    assert!(
        third.status.success(),
        "third page stderr: {:?}",
        third.stderr
    );
    let body = String::from_utf8_lossy(&third.stdout);
    assert!(
        body.contains("\"total\":1"),
        "rewritten trace must be re-scanned: {body}"
    );
    assert!(body.contains("\"seq\":1"), "rewritten trace result: {body}");
    let log = std::fs::read_to_string(&log_path).expect("fingerprint log");
    assert_eq!(
        log.lines().count(),
        3,
        "in-place rewrite must not reuse the old fingerprint"
    );
    assert!(log.lines().nth(2) == Some("computed"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_fails_closed_on_garbage_trace_instead_of_empty_total() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-garbage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    // 普通文本（模拟误把 Cargo.toml 之类的文件当 trace）：不得返回 total=0。
    std::fs::write(
        &trace_path,
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\n",
    )
    .expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");

    let output = run_helper(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        b"{\"offset\":0,\"limit\":1}\n",
    );
    assert!(
        !output.status.success(),
        "garbage trace must fail: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("recognizable instruction"),
        "stderr must explain the failure: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_fails_closed_on_empty_trace() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-empty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    std::fs::write(&trace_path, "").expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");

    let output = run_helper(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        b"{\"offset\":0,\"limit\":1}\n",
    );
    assert!(
        !output.status.success(),
        "empty trace must fail: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_returns_zero_total_for_valid_trace_without_matches() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-nomatch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    // 合法 Unidbg trace（有指令行）但没有匹配：total=0 是合法结果。
    std::fs::write(
        &trace_path,
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
    )
    .expect("trace");
    std::fs::write(&pattern_path, [9u8, 9, 9, 9]).expect("pattern");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");

    let output = run_helper(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        b"{\"offset\":0,\"limit\":1}\n",
    );
    assert!(
        output.status.success(),
        "valid trace without matches must succeed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("\"matches\":[]") && body.contains("\"total\":0"),
        "valid trace without matches must report total=0: {body}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn helper_finds_matches_in_gumtrace_with_many_leading_special_lines() {
    let root = std::env::temp_dir().join(format!(
        "trace-ui-helper-gum-special-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    let trace_path = root.join("trace.log");
    let pattern_path = root.join("pattern.bin");
    let mut trace = String::new();
    for i in 0..25 {
        trace.push_str(&format!(
            "call func: f{i}(0x1000)\nargs0: 0x1000\nret: 0x1\n"
        ));
    }
    trace.push_str(
        "[lib.so] 0x7522f46438!0x143438 str w0, [x1]; w0=0x04030201 x1=0x2000 mem_w=0x2000\n",
    );
    std::fs::write(&trace_path, trace).expect("trace");
    std::fs::write(&pattern_path, [1u8, 2, 3, 4]).expect("pattern");
    let trace = std::fs::File::open(&trace_path).expect("open trace");
    let pattern = std::fs::File::open(&pattern_path).expect("open pattern");

    let output = run_helper(
        trace.as_raw_fd(),
        pattern.as_raw_fd(),
        b"{\"offset\":0,\"limit\":1}\n",
    );
    assert!(
        output.status.success(),
        "gumtrace with leading special lines must work: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("\"total\":1") && body.contains("\"seq\":75"),
        "gumtrace match must be found after special lines: {body}"
    );

    let _ = std::fs::remove_dir_all(root);
}
