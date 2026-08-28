//! scanner 单元测试。

use super::*;
use smallvec::SmallVec;
use trace_parser::insn_class::InsnClass;
use trace_parser::types::RegId;

// =========================================================================
// Test trace line builders
// =========================================================================

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

// =========================================================================
// Test: simple register chain
// =========================================================================

#[test]
fn test_simple_register_chain() {
    let lines = [
        mov_line("x8", 5),
        mov_line("x9", 10),
        add_line("x0", "x8", "x9"),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, false).unwrap();

    assert_eq!(state.line_count, 3);
    // add x0 should have last def at line 2
    assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&2));
    // add x0, x8, x9 depends on mov x8 (line 0) and mov x9 (line 1)
    assert!(
        state.deps.row(2).contains(&0),
        "add should depend on mov x8"
    );
    assert!(
        state.deps.row(2).contains(&1),
        "add should depend on mov x9"
    );
}

// =========================================================================
// Test: memory dependency (store -> load)
// =========================================================================

#[test]
fn test_memory_dependency() {
    let lines = [
        mov_line("x8", 42),
        str_line("x8", "sp", 0xbffff010),
        ldr_line("x0", "sp", 0xbffff010),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, false).unwrap();

    // ldr (line 2) depends on str (line 1) via memory
    assert!(
        state.deps.row(2).contains(&1),
        "ldr should depend on str via memory"
    );
    // str (line 1) depends on mov x8 (line 0) via register
    assert!(
        state.deps.row(1).contains(&0),
        "str should depend on mov x8 via register"
    );
}

// =========================================================================
// Test: control dependency (cmp -> b.eq -> next instruction)
// =========================================================================

#[test]
fn test_control_dependency() {
    let lines = [
        r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
        r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
        mov_line("x0", 1),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, false).unwrap();

    // b.eq (line 1) is a conditional branch -> sets lastCondBranch
    // mov x0 (line 2) should have control dep on b.eq (line 1), tagged with CONTROL_DEP_BIT
    assert!(
        state.deps.row(2).contains(&(1 | CONTROL_DEP_BIT)),
        "mov after b.eq should have control dep (tagged with CONTROL_DEP_BIT)"
    );
}

// =========================================================================
// Test: data_only mode disables control deps
// =========================================================================

#[test]
fn test_data_only_no_control_dep() {
    let lines = [
        r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
        r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
        mov_line("x0", 1),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, true).unwrap();

    // In data_only mode, no control dependency edge from b.eq to mov
    assert!(
        !state.deps.row(2).contains(&1),
        "data_only should suppress control deps"
    );
}

// =========================================================================
// Test: b.eq itself depends on cmp via nzcv register
// =========================================================================

#[test]
fn test_cond_branch_depends_on_flag_setter() {
    let lines = [
        r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
        r#"[00:00:00 001][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#.to_string(),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, false).unwrap();

    // b.eq (line 1) USEs nzcv, which was DEF'd by cmp (line 0)
    assert!(
        state.deps.row(1).contains(&0),
        "b.eq should depend on cmp via nzcv"
    );
}

// =========================================================================
// Test: regLastDef is updated correctly
// =========================================================================

#[test]
fn test_reg_last_def_updated() {
    let lines = [
        mov_line("x8", 1),
        mov_line("x8", 2), // overwrites x8
        mov_line("x0", 3),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, false).unwrap();

    // x8 last def should be line 1 (second mov)
    assert_eq!(state.reg_last_def.get(&RegId::X8), Some(&1));
    // x0 last def should be line 2
    assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&2));
}

// =========================================================================
// Test: unparseable lines are skipped
// =========================================================================

#[test]
fn test_unparseable_lines_skipped() {
    let lines = [
        "random log line that doesn't match".to_string(),
        mov_line("x0", 42),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, false).unwrap();

    assert_eq!(state.line_count, 2);
    // The unparseable line has empty deps
    assert!(state.deps.row(0).is_empty());
    // mov x0 at line 1 has no deps (no prior defs)
    assert!(state.deps.row(1).is_empty());
    assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&1));
}

// =========================================================================
// Test: push_unique deduplication
// =========================================================================

#[test]
fn test_push_unique_dedup() {
    let mut sv: SmallVec<[u32; 4]> = SmallVec::new();
    push_unique(&mut sv, 5);
    push_unique(&mut sv, 5);
    push_unique(&mut sv, 3);
    push_unique(&mut sv, 5);
    assert_eq!(sv.as_slice(), &[5, 3]);
}

// =========================================================================
// Test: SimdLaneLoad refinement (ld1 lane → read-modify-write)
// =========================================================================

#[test]
fn test_simd_lane_load_refinement() {
    let lines = [
        r#"[00:00:00 001][lib.so 0x100] [4f000400] 0x40000100: "movi v0.4s, #0" => q0=0x0"#.to_string(),
        r#"[00:00:00 001][lib.so 0x104] [0d401de0] 0x40000104: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x100"#.to_string(),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, true).unwrap();

    // ld1 lane (line 1) should depend on movi (line 0) via v0 old value (read-modify-write)
    assert!(
        state.deps.row(1).contains(&0),
        "ld1 lane should depend on prior v0 def (read-modify-write)"
    );
}

// =========================================================================
// Test: SysRegNzcvRead refinement (mrs x0, nzcv → USE=nzcv)
// =========================================================================

#[test]
fn test_sysreg_nzcv_read_refinement() {
    let lines = [
        r#"[00:00:00 001][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#.to_string(),
        r#"[00:00:00 001][lib.so 0x304] [d53b4200] 0x40000304: "mrs x0, nzcv" nzcv=0x80000000 => x0=0x80000000"#.to_string(),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string(&trace, true).unwrap();

    // mrs nzcv (line 1) should depend on cmp (line 0) via nzcv
    assert!(
        state.deps.row(1).contains(&0),
        "mrs x0, nzcv should depend on cmp via nzcv register"
    );
}

// =========================================================================
// Test: scan_with_range — start_seq only
// =========================================================================

#[test]
fn test_scan_with_start_seq() {
    let lines = [
        mov_line("x8", 5),
        mov_line("x9", 10),
        add_line("x0", "x8", "x9"),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string_with_range(&trace, false, 2, None).unwrap();

    assert_eq!(state.line_count, 3);
    assert!(state.deps.row(0).is_empty());
    assert!(state.deps.row(1).is_empty());
    assert!(state.deps.row(2).is_empty()); // no prior defs in range
    assert_eq!(state.reg_last_def.get(&RegId::X0), Some(&2));
    assert_eq!(state.reg_last_def.get(&RegId::X8), None);
}

// =========================================================================
// Test: scan_with_range — end_seq only
// =========================================================================

#[test]
fn test_scan_with_end_seq() {
    let lines = [
        mov_line("x8", 5),
        mov_line("x9", 10),
        add_line("x0", "x8", "x9"),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string_with_range(&trace, false, 0, Some(1)).unwrap();

    assert_eq!(state.line_count, 3);
    assert_eq!(state.reg_last_def.get(&RegId::X8), Some(&0));
    assert_eq!(state.reg_last_def.get(&RegId::X9), Some(&1));
    assert_eq!(state.reg_last_def.get(&RegId::X0), None);
    assert!(state.deps.row(2).is_empty());
}

// =========================================================================
// Test: @LINE target validation — register DEF valid
// =========================================================================

#[test]
fn test_scan_reg_at_line_valid() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    let lines = [mov_line("x8", 5)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(0u32, vec![LineTarget::Reg(RegId::X8)]);

    let state = scan_from_string_with_targets(&trace, false, 0, None, &targets).unwrap();
    assert_eq!(
        state.resolved_targets.get(&(0, LineTarget::Reg(RegId::X8))),
        Some(&0),
        "should resolve to same line when DEF is present"
    );
}

// =========================================================================
// Test: @LINE target validation — register DEF invalid
// =========================================================================

#[test]
fn test_scan_reg_at_line_invalid() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    let lines = [mov_line("x8", 5)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(0u32, vec![LineTarget::Reg(RegId::X0)]);

    let result = scan_from_string_with_targets(&trace, false, 0, None, &targets);
    assert!(result.is_err(), "should fail: line 0 does not DEF x0");
}

// =========================================================================
// Test: @LINE target validation — memory STORE valid
// =========================================================================

#[test]
fn test_scan_mem_at_line_valid() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    let lines = [str_line("x8", "sp", 0xbffff010)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(0u32, vec![LineTarget::Mem(0xbffff010)]);

    let state = scan_from_string_with_targets(&trace, false, 0, None, &targets).unwrap();
    assert_eq!(
        state
            .resolved_targets
            .get(&(0, LineTarget::Mem(0xbffff010))),
        Some(&0),
        "should resolve to same line when STORE is present"
    );
}

// =========================================================================
// Test: @LINE target validation — memory STORE invalid
// =========================================================================

#[test]
fn test_scan_mem_at_line_invalid() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    let lines = [str_line("x8", "sp", 0xbffff010)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(0u32, vec![LineTarget::Mem(0xdeadbeef)]);

    let result = scan_from_string_with_targets(&trace, false, 0, None, &targets);
    assert!(
        result.is_err(),
        "should fail: line 0 does not STORE to 0xdeadbeef"
    );
}

// =========================================================================
// Test: @LINE target validation — line out of range
// =========================================================================

#[test]
fn test_scan_line_target_out_of_range() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    let lines = [mov_line("x8", 5)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(999u32, vec![LineTarget::Reg(RegId::X8)]);

    let result = scan_from_string_with_targets(&trace, false, 0, None, &targets);
    assert!(result.is_err(), "should fail: line 999 out of range");
}

// =========================================================================
// Test: @LINE fallback — register DEF not at target line, resolves to prior
// =========================================================================

#[test]
fn test_scan_reg_at_line_fallback() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    // line 0: mov x8 (DEFs x8), line 1: str x8 (USEs x8)
    let lines = [mov_line("x8", 5), str_line("x8", "sp", 0x100)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(1u32, vec![LineTarget::Reg(RegId::X8)]);

    let state = scan_from_string_with_targets(&trace, true, 0, None, &targets).unwrap();
    let resolved = state.resolved_targets.get(&(1, LineTarget::Reg(RegId::X8)));
    assert_eq!(resolved, Some(&0));
}

// =========================================================================
// Test: @LINE fallback — memory STORE not at target line, resolves to prior
// =========================================================================

#[test]
fn test_scan_mem_at_line_fallback() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    // line 0: str x8 to 0x100, line 1: mov x9 (no mem op)
    let lines = [str_line("x8", "sp", 0x100), mov_line("x9", 10)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(1u32, vec![LineTarget::Mem(0x100)]);

    let state = scan_from_string_with_targets(&trace, true, 0, None, &targets).unwrap();
    let resolved = state.resolved_targets.get(&(1, LineTarget::Mem(0x100)));
    assert_eq!(resolved, Some(&0));
}

// =========================================================================
// Test: @LINE fallback — no prior DEF exists, should error
// =========================================================================

#[test]
fn test_scan_reg_at_line_no_prior_def() {
    use std::collections::HashMap;
    use trace_parser::types::LineTarget;

    let lines = [mov_line("x9", 5)];
    let trace = lines.join("\n");
    let mut targets = HashMap::new();
    targets.insert(0u32, vec![LineTarget::Reg(RegId::X8)]);

    let result = scan_from_string_with_targets(&trace, true, 0, None, &targets);
    assert!(result.is_err());
}

// =========================================================================
// Test: scan_with_range — start_seq and end_seq
// =========================================================================

#[test]
fn test_scan_with_start_and_end_seq() {
    let lines = [
        mov_line("x8", 5),
        mov_line("x9", 10),
        add_line("x0", "x8", "x9"),
    ];
    let trace = lines.join("\n");
    let state = scan_from_string_with_range(&trace, false, 1, Some(1)).unwrap();

    assert_eq!(state.line_count, 3);
    assert_eq!(state.reg_last_def.get(&RegId::X9), Some(&1));
    assert_eq!(state.reg_last_def.get(&RegId::X8), None);
    assert_eq!(state.reg_last_def.get(&RegId::X0), None);
}

#[test]
fn test_scan_empty_trace() {
    let state = scan_from_string("", false).unwrap();
    assert_eq!(state.line_count, 0);
    assert!(state.deps.is_empty());
}

#[test]
fn test_scan_blank_lines_only() {
    let trace = "\n\n\n";
    let state = scan_from_string(trace, false).unwrap();
    assert_eq!(state.line_count, 3);
}

#[test]
fn test_scan_unparseable_lines() {
    let trace = "this is not a valid trace line\nanother bad line";
    let state = scan_from_string(trace, false).unwrap();
    assert_eq!(state.line_count, 2);
    assert!(state.deps.row(0).is_empty());
    assert!(state.deps.row(1).is_empty());
}

#[test]
fn test_mem_access_width_simd_multi_reg() {
    use trace_parser::types::{Mnemonic, Operand, ParsedLine};

    /// 构建一个含寄存器操作数和 base_reg 的最小 ParsedLine
    fn make_line(mnemonic: &str, regs: &[RegId], base: RegId) -> ParsedLine {
        ParsedLine {
            mnemonic: Mnemonic::new(mnemonic),
            operands: regs.iter().map(|&r| Operand::Reg(r)).collect(),
            base_reg: Some(base),
            ..Default::default()
        }
    }

    // ld1 {v0, v1}, [x0] — 2 个数据寄存器 × 16 = 32
    let line = make_line("ld1", &[RegId::V0, RegId::V1, RegId::X0], RegId::X0);
    assert_eq!(mem_access_width(InsnClass::SimdLoad, 16, &line), 32);

    // ld1 {v0, v1, v2, v3}, [x0] — 4 个数据寄存器 × 16 = 64
    let line = make_line(
        "ld1",
        &[RegId::V0, RegId::V1, RegId::V2, RegId::V3, RegId::X0],
        RegId::X0,
    );
    assert_eq!(mem_access_width(InsnClass::SimdLoad, 16, &line), 64);

    // ldr q0, [x0] — 单寄存器，不触发多寄存器扩展
    let line = make_line("ldr", &[RegId::V0, RegId::X0], RegId::X0);
    assert_eq!(mem_access_width(InsnClass::SimdLoad, 16, &line), 16);

    // ldp x0, x1, [x2] — 配对指令，8 × 2 = 16
    let line = make_line("ldp", &[RegId::X0, RegId(1), RegId(2)], RegId(2));
    assert_eq!(mem_access_width(InsnClass::LoadPair, 8, &line), 16);

    // ldr x0, [x1] — 普通标量加载，宽度不变
    let line = make_line("ldr", &[RegId::X0, RegId(1)], RegId(1));
    assert_eq!(mem_access_width(InsnClass::LoadReg, 8, &line), 8);
}

#[test]
fn test_unknown_mnemonic_collected() {
    let trace =
        r#"[00:00:00 001][lib.so 0x100] [d2800000] 0x40000100: "xyzzy v0, v1, v2" => v0=0x0"#;
    let state = scan_from_string(trace, true).unwrap();
    assert_eq!(state.unknown_mnemonics.len(), 1);
    let (first_line, count) = state.unknown_mnemonics.get("xyzzy").unwrap();
    assert_eq!(*first_line, 0);
    assert_eq!(*count, 1);
}

#[test]
fn test_known_nop_not_collected() {
    let trace = r#"[00:00:00 001][lib.so 0x100] [d5033f9f] 0x40000100: "dmb ish""#;
    let state = scan_from_string(trace, true).unwrap();
    assert!(state.unknown_mnemonics.is_empty());
}

// =========================================================================
// Test: init_mem_loads — load from never-stored address is marked
// =========================================================================

#[test]
fn test_init_mem_load_marked() {
    let trace = r#"[00:00:00 001][lib.so 0x100] [f9400be0] 0x40000100: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#;
    let state = scan_from_string(trace, true).unwrap();
    assert!(
        state.init_mem_loads[0],
        "load from never-stored address should be marked"
    );
}

// =========================================================================
// Test: init_mem_loads — load from previously-stored address is NOT marked
// =========================================================================

#[test]
fn test_stored_mem_load_not_marked() {
    let trace = [
        r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
        r#"[00:00:00 001][lib.so 0x104] [f9000be8] 0x40000104: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0x2a sp=0xbffff000 => x8=0x2a"#,
        r#"[00:00:00 001][lib.so 0x108] [f9400be0] 0x40000108: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#,
    ].join("\n");
    let state = scan_from_string(&trace, true).unwrap();
    assert!(
        !state.init_mem_loads[2],
        "load from previously-stored address should NOT be marked"
    );
}
