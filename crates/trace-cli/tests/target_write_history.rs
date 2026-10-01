#![cfg(unix)]
use std::{
    io::Write,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
};
unsafe extern "C" {
    fn dup2(old: i32, new: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    fn close(fd: i32) -> i32;
}
fn run(raw: &str, request: serde_json::Value) -> std::process::Output {
    let path = std::env::temp_dir().join(format!(
        "target-history-{}-{:?}.log",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, raw).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let fd = unsafe { fcntl(file.as_raw_fd(), 1030, 5) };
    assert!(fd >= 5);
    let mut command = Command::new(env!("CARGO_BIN_EXE_trace-cli"));
    command
        .args(["--function-facts-helper", "--trace-fd", "3"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    unsafe {
        close(fd);
    }
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    std::fs::remove_file(path).unwrap();
    out
}
fn request(selected: u32, rw: Option<&str>, capture: u32) -> serde_json::Value {
    serde_json::json!({"kind":"target_write_history","call_seq":1,"entry_seq":2,"function":"App+0x200","target_modules":["App"],"selected":{"seq":selected,"address":"0x3000","size":4,"rw":rw},"capture_seq":capture})
}
fn query(raw: &str, selected: u32, rw: Option<&str>, capture: u32) -> serde_json::Value {
    let out = run(raw, request(selected, rw, capture));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn trace(body: &str, caller_body: &str) -> String {
    format!("[App] 0x1000!0x0 bl #0x1100\n[App] 0x1100!0x100 bl #0x1200\n{body}[App] 0x1104!0x104 nop\n{caller_body}[App] 0x110c!0x10c ret\n[App] 0x1004!0x4 nop\n")
}
#[test]
fn target_history_partial_writes_overwrites_and_boundaries() {
    let raw=trace("[App] 0x1200!0x200 str w0, [x1]; w0=0x04030201 x1=0x3000 mem_w=0x3000\n[App] 0x1204!0x204 strh w0, [x1]; w0=0x0605 x1=0x3002 mem_w=0x3002\n[App] 0x1208!0x208 ldr w0, [x1]; x1=0x3000 mem_r=0x3000 -> w0=0x06050201\n[App] 0x120c!0x20c str w0, [x1]; w0=0x08070605 x1=0x3000 mem_w=0x3000\n[App] 0x1210!0x210 ret\n", "[App] 0x1108!0x108 str w0, [x1]; w0=0x09090909 x1=0x3000 mem_w=0x3000\n");
    let v = query(&raw, 4, Some("read"), 5);
    assert_eq!(v["coverage"]["complete"], true, "{v}");
    assert_eq!(
        v["selected_snapshot"]["bytes"],
        serde_json::json!([1, 2, 5, 6])
    );
    assert_eq!(
        v["capture_snapshot"]["bytes"],
        serde_json::json!([1, 2, 5, 6])
    );
    assert_eq!(v["writes"].as_array().unwrap().len(), 2); // capture's own write excluded
    assert_eq!(v["writes"][1]["write_offset"], 0);
    assert_eq!(v["writes"][1]["target_offset"], 2);
    let v = query(&raw, 5, Some("write"), 6);
    assert_eq!(v["coverage"]["complete"], true, "{v}");
    assert_eq!(v["writes"].as_array().unwrap().len(), 3); // overwritten intermediate write retained
    assert_eq!(v["selected_snapshot"]["phase"], "after_instruction");
    let v = query(&raw, 5, Some("write"), 5);
    assert_eq!(v["coverage"]["complete"], false);
    assert_eq!(
        v["selected_snapshot"]["bytes"],
        serde_json::json!([5, 6, 7, 8])
    );
    assert_eq!(
        v["capture_snapshot"]["bytes"],
        serde_json::json!([1, 2, 5, 6])
    );
    let v = query(&raw, 4, Some("read"), 9);
    assert_eq!(v["coverage"]["complete"], false, "{v}");
    assert_eq!(
        v["capture_snapshot"]["bytes"],
        serde_json::json!([9, 9, 9, 9])
    );
    assert_eq!(v["writes"][3]["owner"]["in_root_closure"], false);
    let v = query(&raw, 4, None, 6);
    assert!(v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["kind"] == "observation_phase_unknown"));
    let v = query(&raw, 3, Some("write"), 6);
    assert!(v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["kind"] == "selected_occurrence_mismatch"));
}
#[test]
fn target_history_unknown_then_only_partial_repair() {
    let raw=trace("[App] 0x1200!0x200 str w0, [x1]; w0=0x04030201 x1=0x3000 mem_w=0x3000\n[App] 0x1204!0x204 str w0, [x1]; x1=0x3000 mem_w=0x3000\n[App] 0x1208!0x208 strh w0, [x1]; w0=0x0605 x1=0x3002 mem_w=0x3002\n[App] 0x120c!0x20c ldr w0, [x1]; x1=0x3000 mem_r=0x3000\n[App] 0x1210!0x210 ret\n", "");
    let v = query(&raw, 5, Some("read"), 6);
    assert_eq!(v["coverage"]["complete"], false);
    assert_eq!(
        v["capture_snapshot"]["bytes"],
        serde_json::json!([null, null, 5, 6])
    );
    assert_eq!(
        v["writes"][1]["bytes"],
        serde_json::json!([null, null, null, null])
    );
}
#[test]
fn target_history_mapping_and_control_rejections() {
    let raw=trace("[App] 0x1200!0x200 str w0, [x1]; w0=0x04030201 x1=0x3000 mem_w=0x3000\n[App] 0x1204!0x204 ldr w0, [x1]; x1=0x3000 mem_r=0x3000 -> w0=0x04030201\n[App] 0x1208!0x208 ret\n", "");
    let conflict = raw.replace("0x1204!0x204", "0x2204!0x204");
    let out = run(&conflict, request(3, Some("read"), 4));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("inconsistent runtime bases"));
    let bad_read = raw.replace("-> w0=0x04030201", "-> w0=0x04030209");
    let v = query(&bad_read, 3, Some("read"), 4);
    assert!(v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["kind"] == "selected_read_conflicts_with_history"));
    let mut req = request(3, Some("read"), 4);
    req["selected"]["address"] = serde_json::json!("0x03000");
    assert!(!run(&raw, req).status.success());
    let mut req = request(3, Some("read"), 4);
    req["extra"] = serde_json::json!(0);
    assert!(!run(&raw, req).status.success());
    let mut req = request(3, Some("read"), 4);
    req["selected"]["size"] = serde_json::json!(1048577);
    assert!(!run(&raw, req).status.success());
}
#[test]
fn target_history_external_without_hook_is_gap() {
    let raw=trace("[App] 0x1200!0x200 str w0, [x1]; w0=0x04030201 x1=0x3000 mem_w=0x3000\n[App] 0x1204!0x204 bl #0x9000\n[App] 0x1208!0x208 ldr w0, [x1]; x1=0x3000 mem_r=0x3000\n[App] 0x120c!0x20c ret\n", "");
    let v = query(&raw, 4, Some("read"), 5);
    assert!(v["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["kind"] == "external_effect_unobserved"));
    assert_eq!(v["coverage"]["complete"], false);
}
