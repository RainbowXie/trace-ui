use super::*;
use crate::scanner::CONTROL_DEP_BIT;

fn mov_line(rd: &str, val: u64) -> String {
    format!(
        r#"[00:00:00 001][lib.so 0x100] [d2800000] 0x40000100: "mov {rd}, #{val}" => {rd}=0x{val:x}"#,
    )
}

fn add_line(rd: &str, rn: &str, rm: &str) -> String {
    format!(
        r#"[00:00:00 001][lib.so 0x108] [8b000000] 0x40000108: "add {rd}, {rn}, {rm}" {rn}=0x1 {rm}=0x2 => {rd}=0x3"#,
    )
}

fn str_line(rt: &str, base: &str, abs: u64) -> String {
    format!(
        r#"[00:00:00 001][lib.so 0x10c] [f9000000] 0x4000010c: "str {rt}, [{base}, #0x10]" ; mem[WRITE] abs=0x{abs:x} {rt}=0x3 {base}=0x{:x} => {rt}=0x3"#,
        abs - 0x10,
    )
}

fn ldr_line(rt: &str, base: &str, abs: u64) -> String {
    format!(
        r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr {rt}, [{base}, #0x10]" ; mem[READ] abs=0x{abs:x} {base}=0x{:x} => {rt}=0x3"#,
        abs - 0x10,
    )
}

#[test]
fn test_scan_chunk_single_chunk_register_chain() {
    // Build a simple trace: mov x8, mov x9, add x0 = x8 + x9
    let lines = [
        mov_line("x8", 5),
        mov_line("x9", 10),
        add_line("x0", "x8", "x9"),
    ];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: false,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    // Basic counts
    assert_eq!(result.end_line, 3);
    assert_eq!(result.boundary.final_parsed_count, 3);

    // add x0 (line 2) should depend on mov x8 (line 0) and mov x9 (line 1)
    let row2 = result.deps.row(2);
    assert!(row2.contains(&0), "add should depend on mov x8 (line 0)");
    assert!(row2.contains(&1), "add should depend on mov x9 (line 1)");

    // No unresolved items since all defs are local
    assert!(result.unresolved_reg_uses.is_empty());
    assert!(result.unresolved_loads.is_empty());
}

#[test]
fn test_scan_chunk_memory_dependency() {
    let lines = [
        mov_line("x8", 42),
        str_line("x8", "sp", 0xbffff010),
        ldr_line("x0", "sp", 0xbffff010),
    ];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: true,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    // ldr (line 2) should depend on str (line 1) via memory
    let row2 = result.deps.row(2);
    assert!(row2.contains(&1), "ldr should depend on str via memory");

    // No unresolved loads
    assert!(result.unresolved_loads.is_empty());
}

#[test]
fn test_scan_chunk_unresolved_register() {
    // Single line using x8 which was never defined in this chunk
    let lines = [add_line("x0", "x8", "x9")];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: true,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    // x8 and x9 have no local def → should be unresolved
    assert!(
        result.unresolved_reg_uses.len() >= 2,
        "should have unresolved reg uses for x8 and x9, got {}",
        result.unresolved_reg_uses.len()
    );
}

#[test]
fn test_scan_chunk_unresolved_load() {
    // A load from memory that was never written in this chunk
    let lines = [ldr_line("x0", "sp", 0xbffff010)];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: true,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    // Fully unresolved load
    assert_eq!(
        result.unresolved_loads.len(),
        1,
        "should have 1 unresolved load"
    );
    assert_eq!(result.unresolved_loads[0].addr, 0xbffff010);
}

#[test]
fn test_scan_chunk_with_start_line() {
    // Test that line numbering starts at start_line
    let lines = [mov_line("x8", 5), mov_line("x9", 10)];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 100,
            format: TraceFormat::Unidbg,
            data_only: false,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    assert_eq!(result.start_line, 100);
    assert_eq!(result.end_line, 102);
    assert_eq!(result.boundary.final_line_count, 102);

    // reg_last_def should use global line numbers
    assert_eq!(
        result.boundary.final_reg_last_def.get(&RegId::X8),
        Some(&100)
    );
    assert_eq!(
        result.boundary.final_reg_last_def.get(&RegId::X9),
        Some(&101)
    );
}

#[test]
fn test_scan_chunk_calltree_events() {
    let lines = [
        r#"[00:00:00 001][lib.so 0x100] [94000000] 0x40000100: "bl #0x40000200" => x30=0x40000104"#
            .to_string(),
    ];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: false,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    // Should have CallTreeEvent::SetRootAddr, LineAddr, and Call
    let has_root = result
        .call_tree_events
        .iter()
        .any(|e| matches!(e, CallTreeEvent::SetRootAddr { .. }));
    let has_call = result
        .call_tree_events
        .iter()
        .any(|e| matches!(e, CallTreeEvent::Call { .. }));
    assert!(has_root, "should emit SetRootAddr");
    assert!(has_call, "should emit Call event for bl");
}

#[test]
fn test_scan_chunk_control_dep_tracking() {
    let lines = [
            r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
            r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
            mov_line("x0", 42),
        ];
    let trace = lines.join("\n");
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: false,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );

    // b.eq sets first_local_cond_branch
    assert_eq!(result.first_local_cond_branch, Some(1));

    // mov x0 (line 2) should have control dep on b.eq (line 1)
    let row2 = result.deps.row(2);
    assert!(
        row2.contains(&(1 | CONTROL_DEP_BIT)),
        "mov should have control dep on b.eq"
    );
}

#[test]
fn test_scan_chunk_external_return_redefines_x0() {
    let trace = concat!(
            "[Snapchat] 0x104a374d0!0x7af4d0 ldr x0, [sp, #0x130]; x0=0x1 sp=0x16d40e810 mem_r=0x16d40e940 -> x0=0x2812eaa70 \n",
            "[Snapchat] 0x104a374d4!0x7af4d4 blr x8; x8=0x19efbf170 \n",
            "call func: sel_registerName()\n",
            "ret: 0x1a19a3a19\n",
            "[Snapchat] 0x104a374d8!0x7af4d8 adrp x13, #0x110fbf000; x13=0x110fbfeb0 -> x13=0x110fbf000 \n",
            "[Snapchat] 0x104a374dc!0x7af4dc add x13, x13, #0xeb0; x13=0x110fbf000 x13=0x110fbf000 -> x13=0x110fbfeb0 \n",
            "[Snapchat] 0x104a374e0!0x7af4e0 str x0, [sp, #0xe0]; x0=0x1a19a3a19 sp=0x16d40e810 mem_w=0x16d40e8f0 \n",
        );
    let data = trace.as_bytes();

    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Gumtrace,
            data_only: true,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );
    let deps = result.deps.row(6);

    assert!(deps.contains(&3));
    assert!(!deps.contains(&0));
}

#[test]
fn test_scan_chunk_empty_trace() {
    let data = b"";
    let result = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            format: TraceFormat::Unidbg,
            data_only: false,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );
    assert_eq!(result.start_line, 0);
    assert_eq!(result.end_line, 0);
    assert!(result.deps.is_empty());
}
