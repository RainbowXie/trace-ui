use super::*;
use crate::types::*;

#[test]
fn test_parse_standard_computation() {
    let raw = r#"[22:39:18 210][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "add");
    assert_eq!(line.operands.len(), 3);
    assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
    assert_eq!(line.operands[1].as_reg(), Some(RegId::X8));
    assert_eq!(line.operands[2].as_reg(), Some(RegId::X9));
    assert!(line.has_arrow);
    assert!(line.mem_op.is_none());
}

#[test]
fn test_parse_memory_write() {
    let raw = r#"[22:39:18 210][lib.so 0x10c] [f9000be8] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "str");
    assert_eq!(line.operands.len(), 2); // x8, sp
    assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
    assert_eq!(line.operands[1].as_reg(), Some(RegId::SP));
    assert_eq!(line.base_reg, Some(RegId::SP));
    let mem = line.mem_op.as_ref().unwrap();
    assert!(mem.is_write);
    assert_eq!(mem.abs, 0xbffff010);
    assert_eq!(mem.elem_width, 8); // x register → 8 bytes
}

#[test]
fn test_parse_memory_read() {
    let raw = r#"[22:39:18 210][lib.so 0x110] [f9400fe0] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "ldr");
    let mem = line.mem_op.as_ref().unwrap();
    assert!(!mem.is_write);
    assert_eq!(mem.abs, 0xbffff010);
}

#[test]
fn test_parse_mov_pure() {
    let raw = r#"[22:39:18 210][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "mov");
    assert_eq!(line.operands.len(), 2);
    assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
    assert!(matches!(line.operands[1], Operand::Imm(5)));
    assert!(line.has_arrow);
}

#[test]
fn test_parse_branch_no_arrow() {
    let raw = r#"[22:39:18 210][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "b");
    assert!(!line.has_arrow);
}

#[test]
fn test_parse_cmp_nzcv() {
    let raw = r#"[22:39:18 210][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "cmp");
    assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
    assert_eq!(line.operands[1].as_reg(), Some(RegId::X9));
}

#[test]
fn test_parse_cond_branch() {
    let raw =
        r#"[22:39:18 210][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "b.eq");
    assert!(!line.has_arrow);
}

#[test]
fn test_parse_invalid_line() {
    assert!(parse_line("").is_none());
    assert!(parse_line("some random log line").is_none());
}

#[test]
fn test_parse_w_register_width() {
    let raw = r#"[22:39:18 210][lib.so 0x10c] [b9001008] 0x4000010c: "str w8, [x0, #0x10]" ; mem[WRITE] abs=0xbffff010 w8=0xf x0=0xbffff000 => w8=0xf"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().unwrap();
    assert_eq!(mem.elem_width, 4); // w register → 4 bytes
}

// Additional edge-case tests

#[test]
fn test_parse_imm_hex() {
    assert_eq!(parse_imm("0x10"), Some(0x10));
    assert_eq!(parse_imm("0xFF"), Some(0xFF));
    assert_eq!(parse_imm("-0x1"), Some(-1));
}

#[test]
fn test_parse_imm_decimal() {
    assert_eq!(parse_imm("5"), Some(5));
    assert_eq!(parse_imm("-3"), Some(-3));
    assert_eq!(parse_imm("0"), Some(0));
}

#[test]
fn test_split_operands_simple() {
    let result = split_operands("x8, x9, x10");
    assert_eq!(result.as_slice(), &["x8", " x9", " x10"]);
}

#[test]
fn test_split_operands_with_brackets() {
    let result = split_operands("[sp, #0x10]");
    assert_eq!(result.as_slice(), &["[sp, #0x10]"]);
}

#[test]
fn test_split_operands_reg_and_bracket() {
    let result = split_operands("x8, [sp, #0x10]");
    assert_eq!(result.as_slice(), &["x8", " [sp, #0x10]"]);
}

#[test]
fn test_determine_elem_width_byte_mnemonics() {
    assert_eq!(determine_elem_width("ldrb", None), 1);
    assert_eq!(determine_elem_width("strb", None), 1);
    assert_eq!(determine_elem_width("ldarb", None), 1);
}

#[test]
fn test_determine_elem_width_half_mnemonics() {
    assert_eq!(determine_elem_width("ldrh", None), 2);
    assert_eq!(determine_elem_width("strh", None), 2);
}

#[test]
fn test_determine_elem_width_by_prefix() {
    assert_eq!(determine_elem_width("ldr", Some(b'w')), 4);
    assert_eq!(determine_elem_width("ldr", Some(b'x')), 8);
    assert_eq!(determine_elem_width("ldr", Some(b's')), 4);
    assert_eq!(determine_elem_width("ldr", Some(b'd')), 8);
    assert_eq!(determine_elem_width("ldr", Some(b'q')), 16);
}

#[test]
fn test_ldpsw_elem_width_is_4() {
    // ldpsw loads 32-bit words (sign-extended to 64-bit x registers)
    // elem_width should be 4, not 8 from the x register prefix
    assert_eq!(determine_elem_width("ldpsw", Some(b'x')), 4);
}

#[test]
fn test_parse_pre_post_arrow_regs() {
    let raw = r#"[22:39:18 210][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#;
    let line = parse_line_full(raw).expect("should parse");
    let pre = line.pre_arrow_regs.as_ref().unwrap();
    let post = line.post_arrow_regs.as_ref().unwrap();
    assert!(pre.iter().any(|(r, v)| *r == RegId::X9 && *v == 0xa));
    assert!(pre.iter().any(|(r, v)| *r == RegId::X8 && *v == 0x5));
    assert!(post.iter().any(|(r, v)| *r == RegId::X8 && *v == 0xf));
    assert!(!post.iter().any(|(r, _)| *r == RegId::X9));
}

#[test]
fn test_parse_no_arrow_all_pre() {
    let raw = r#"[22:39:18 210][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#;
    let line = parse_line(raw).expect("should parse");
    assert!(!line.has_arrow);
    assert!(line.post_arrow_regs.is_none());
}

#[test]
fn test_parse_cmp_nzcv_arrow_split() {
    let raw = r#"[22:39:18 210][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#;
    let line = parse_line_full(raw).expect("should parse");
    let pre = line.pre_arrow_regs.as_ref().unwrap();
    let post = line.post_arrow_regs.as_ref().unwrap();
    assert_eq!(pre.len(), 2);
    assert_eq!(post.len(), 1);
    assert!(post.iter().any(|(r, _)| *r == RegId::NZCV));
}

#[test]
fn test_parse_mnemonic_only_no_operands() {
    let raw = r#"[22:39:18 210][lib.so 0x100] [d503201f] 0x40000100: "nop""#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "nop");
    assert!(line.operands.is_empty());
    assert!(!line.has_arrow);
}

#[test]
fn test_parse_post_index_writeback() {
    // Post-index form: [sp], #0x10 — no '!' but sp is still modified
    let raw = r#"[00:00:00 001][lib.so 0x100] [a8c17bfd] 0x40000100: "ldp x29, x30, [sp], #0x10" ; mem[READ] abs=0xbffff000 x29=0x0 x30=0x0 sp=0xbffff000 => x29=0x0 x30=0x0 sp=0xbffff010"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "ldp");
    assert!(
        line.writeback,
        "post-index form should be detected as writeback"
    );
    assert_eq!(line.base_reg, Some(RegId::SP));
}

#[test]
fn test_parse_writeback() {
    let raw = r#"[22:39:18 210][lib.so 0x100] [a9bf7bfd] 0x40000100: "stp x29, x30, [sp, #-0x10]!" ; mem[WRITE] abs=0xbfffeff0 x29=0x0 x30=0x0 sp=0xbffff000 => x29=0x0"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "stp");
    assert!(line.writeback);
    assert_eq!(line.base_reg, Some(RegId::SP));
}

#[test]
fn test_parse_simd_lane_load() {
    let raw = r#"[00:00:00 001][lib.so 0x100] [0d401de0] 0x40000100: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x100"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "ld1");
    assert_eq!(line.operands.len(), 2);
    assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
    assert_eq!(line.operands[1].as_reg(), Some(RegId::X15));
    assert_eq!(line.lane_index, Some(1));
}

#[test]
fn test_parse_simd_full_store() {
    let raw = r#"[00:00:00 001][lib.so 0x100] [4c000000] 0x40000100: "st1 {v0.16b}, [x0]" ; mem[WRITE] abs=0x40500000 q0=0xff x0=0x40500000 => q0=0xff"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "st1");
    assert_eq!(line.operands.len(), 2);
    assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
    assert_eq!(line.operands[1].as_reg(), Some(RegId::X0));
    assert_eq!(line.lane_index, None);
}

#[test]
fn test_simd_v_prefix_store_value_extraction() {
    // st1 {v0.16b} 的操作数用 v 前缀，但 trace 中值用 q 前缀
    let raw = r#"[00:00:00 001][lib.so 0x100] [4c000000] 0x40000100: "st1 {v0.16b}, [x0]" ; mem[WRITE] abs=0x40500000 q0=0x00000000000000ff00000000000000aa x0=0x40500000"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem op");
    assert_eq!(mem.elem_width, 16);
    assert_eq!(mem.value_lo, Some(0x00000000000000aa));
    assert_eq!(mem.value_hi, Some(0x00000000000000ff));
}

#[test]
fn test_simd_v_prefix_load_value_extraction() {
    // ld1 {v0.16b} LOAD 场景：值在 => 之后
    let raw = r#"[00:00:00 001][lib.so 0x100] [4c400000] 0x40000100: "ld1 {v0.16b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 x0=0x40500000 => q0=0x00000000000000020000000000000001"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem op");
    assert_eq!(mem.elem_width, 16);
    assert_eq!(mem.value_lo, Some(0x0000000000000001));
    assert_eq!(mem.value_hi, Some(0x0000000000000002));
}

#[test]
fn test_simd_q_prefix_still_works() {
    // ldr q0 直接用 q 前缀，确保不被破坏
    let raw = r#"[00:00:00 001][lib.so 0x100] [3dc00000] 0x40000100: "ldr q0, [x0]" ; mem[READ] abs=0x40500000 x0=0x40500000 => q0=0x00000000000000030000000000000004"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem op");
    assert_eq!(mem.elem_width, 16);
    assert_eq!(mem.value_lo, Some(0x0000000000000004));
    assert_eq!(mem.value_hi, Some(0x0000000000000003));
}

#[test]
fn test_parse_simd_multi_reg() {
    let raw = r#"[00:00:00 001][lib.so 0x100] [4c402000] 0x40000100: "ld1 {v0.16b, v1.16b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 q1=0x0 x0=0x40500000 => q0=0x1 q1=0x2"#;
    let line = parse_line(raw).expect("should parse");
    assert_eq!(line.mnemonic.as_str(), "ld1");
    assert!(line.operands.len() >= 3);
    assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
    assert_eq!(line.operands[1].as_reg(), Some(RegId::V1));
    assert_eq!(line.operands[2].as_reg(), Some(RegId::X0));
    // 验证第二个寄存器的值被正确提取
    let mem = line.mem_op.as_ref().expect("should have mem_op");
    assert_eq!(mem.elem_width, 16);
    assert_eq!(mem.value_lo, Some(0x1));
    assert_eq!(mem.value_hi, Some(0x0));
    assert_eq!(
        mem.value2_lo,
        Some(0x2),
        "multi-reg ld1 second register value_lo"
    );
    assert_eq!(
        mem.value2_hi,
        Some(0x0),
        "multi-reg ld1 second register value_hi"
    );
}

#[test]
fn test_simd_8b_arrangement_elem_width() {
    // ld1 {v0.8b} 只加载 8 字节，elem_width 应为 8
    let raw = r#"[00:00:00 001][lib.so 0x100] [0c400000] 0x40000100: "ld1 {v0.8b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 x0=0x40500000 => q0=0x0807060504030201"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem_op");
    assert_eq!(mem.elem_width, 8, "ld1 {{v0.8b}} should have elem_width=8");
    // 应走 scalar 路径，值为低 64 位
    assert_eq!(mem.value, Some(0x0807060504030201));
    assert!(mem.value_lo.is_none());
    assert!(mem.value_hi.is_none());
}

#[test]
fn test_simd_lane_load_elem_width_and_value() {
    // ld1 {v0.s}[1] 只加载 4 字节到 lane 1，elem_width 应为 4
    // s[1] = bits[63:32]，构造 q0 使 bits[63:32] = 0xaabbccdd
    let raw = r#"[00:00:00 001][lib.so 0x100] [0d401de0] 0x40000100: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x0000000000000000aabbccdd00000000"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem_op");
    assert_eq!(mem.elem_width, 4, "lane load should have elem_width=4");
    // lane 1 of .s = bits[63:32] = 0xaabbccdd
    assert_eq!(mem.value, Some(0xaabbccdd), "should extract lane 1 value");
}

#[test]
fn test_simd_multi_reg_8b_arrangement() {
    // ld1 {v0.8b, v1.8b} 加载 16 字节（每个寄存器 8 字节）
    let raw = r#"[00:00:00 001][lib.so 0x100] [0c402000] 0x40000100: "ld1 {v0.8b, v1.8b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 q1=0x0 x0=0x40500000 => q0=0x0807060504030201 q1=0x100f0e0d0c0b0a09"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem_op");
    assert_eq!(mem.elem_width, 8);
    assert_eq!(mem.value, Some(0x0807060504030201));
    assert_eq!(
        mem.value2,
        Some(0x100f0e0d0c0b0a09),
        "second reg value for 8b multi-reg"
    );
}

#[test]
fn test_simd_lane_load_v_prefix_trace() {
    // 真实 trace 场景：SIMD 值用 v0=0x... 而非 q0=0x... 记录
    let raw = r#"[07:17:17 416][libtiny.so 0x5335a0] [4091400d] 0x405335a0: "ld1 {v0.s}[1], [x10]" ; mem[READ] abs=0xbfff9288 v0=0x87df82dd x10=0xbfff9288 => v0=0x5b168dc987df82dd"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().expect("should have mem_op");
    assert_eq!(mem.elem_width, 4, "lane load elem_width should be 4");
    // s[1] = bits[63:32] of 0x5b168dc987df82dd = 0x5b168dc9
    assert_eq!(
        mem.value,
        Some(0x5b168dc9),
        "should extract lane 1 value from v-prefix trace"
    );
}

#[test]
fn test_extract_lane_index_with_lane() {
    let (rest, lane, elem_width) = extract_lane_index("v0.s[1]");
    assert_eq!(rest, "v0.s");
    assert_eq!(lane, Some(1));
    assert_eq!(elem_width, Some(4));
}

#[test]
fn test_extract_lane_index_without_lane() {
    let (rest, lane, elem_width) = extract_lane_index("v0.16b");
    assert_eq!(rest, "v0.16b");
    assert_eq!(lane, None);
    assert_eq!(elem_width, None);
}

#[test]
fn test_extract_lane_index_no_dot() {
    let (rest, lane, elem_width) = extract_lane_index("x15");
    assert_eq!(rest, "x15");
    assert_eq!(lane, None);
    assert_eq!(elem_width, None);
}

#[test]
fn test_parse_line_empty_string() {
    assert!(parse_line("").is_none());
}

#[test]
fn test_parse_line_no_quotes() {
    let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: no_quotes_here"#;
    assert!(parse_line(line).is_none());
}

#[test]
fn test_parse_line_single_quote() {
    let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "incomplete"#;
    assert!(parse_line(line).is_none());
}

#[test]
fn test_parse_line_empty_mnemonic() {
    let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "" => x0=0x0"#;
    assert!(parse_line(line).is_none());
}

// =========================================================================
// Value extraction tests (pass-through pruning)
// =========================================================================

#[test]
fn test_store_value_extraction() {
    let raw = r#"[00:00:00 001][lib.so 0x10c] [f9000000] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().unwrap();
    assert!(mem.is_write);
    assert_eq!(mem.value, Some(0xf));
}

#[test]
fn test_load_value_extraction() {
    let raw = r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().unwrap();
    assert!(!mem.is_write);
    assert_eq!(mem.value, Some(0xf));
}

#[test]
fn test_strb_value_masking() {
    // strb w8 with full 32-bit value in trace → should mask to 1 byte
    let raw = r#"[00:00:00 001][lib.so 0x10c] [39000108] 0x4000010c: "strb w8, [x0, #0]" ; mem[WRITE] abs=0xbffff010 w8=0x8ecb0cc7 x0=0xbffff010 => w8=0x8ecb0cc7"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().unwrap();
    assert_eq!(mem.elem_width, 1);
    assert_eq!(mem.value, Some(0xc7));
}

#[test]
fn test_simd_value_none() {
    // q register (128-bit) → value should be None
    let raw = r#"[00:00:00 001][lib.so 0x100] [3dc00000] 0x40000100: "ldr q0, [x0]" ; mem[READ] abs=0x40500000 x0=0x40500000 => q0=0x12345678"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().unwrap();
    assert_eq!(mem.elem_width, 16);
    assert_eq!(mem.value, None);
}

#[test]
fn test_load_value_from_post_arrow_only() {
    // x0 appears before and after arrow with different values
    // LOAD should extract from post-arrow
    let raw = r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 x0=0xdead sp=0xbffff000 => x0=0xbeef"#;
    let line = parse_line(raw).expect("should parse");
    let mem = line.mem_op.as_ref().unwrap();
    assert_eq!(mem.value, Some(0xbeef));
}

#[test]
fn test_first_data_reg_name() {
    assert_eq!(data_reg_name_at("x8, [sp, #0x10]", 0), Some("x8"));
    assert_eq!(data_reg_name_at("w0, [x1]", 0), Some("w0"));
    assert_eq!(data_reg_name_at("q0, [x0]", 0), Some("q0"));
    assert_eq!(data_reg_name_at("{v0.16b}, [x0]", 0), Some("v0"));
    assert_eq!(data_reg_name_at("[sp, #0x10]", 0), None);
    assert_eq!(data_reg_name_at("", 0), None);
}

#[test]
fn test_find_reg_value_basic() {
    let line = b"x8=0xf sp=0xbffff000";
    assert_eq!(find_reg_value(line, b"x8", 0), Some(0xf));
    assert_eq!(find_reg_value(line, b"sp", 0), Some(0xbffff000));
}

#[test]
fn test_find_reg_value_no_prefix_collision() {
    // Searching for "x1" should not match "x10"
    let line = b" x10=0xaaa x1=0xbbb";
    assert_eq!(find_reg_value(line, b"x1", 0), Some(0xbbb));
}

#[test]
fn test_find_reg_value_not_found() {
    let line = b"x8=0xf";
    assert_eq!(find_reg_value(line, b"x9", 0), None);
}
