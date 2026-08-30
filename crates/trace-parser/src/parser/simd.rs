/// 从 SIMD 向量指令的排列说明符推导每个寄存器的访问宽度。
/// - 128-bit 排列 (16b/8h/4s/2d) → 16
/// - 64-bit 排列 (8b/4h/2s/1d) → 8
/// - 其他（lane 说明符如 .s、.d 等）→ None
pub(crate) fn simd_arrangement_total_width(operand_text: &str) -> Option<u8> {
    let first_tok = operand_text.split(',').next()?.trim();
    // 先剥 lane 下标再剥闭括号：单 lane 形式的首 token 形如 `{v0.16b}[2]`。
    let first_tok = first_tok
        .trim_start_matches('{')
        .split('[')
        .next()?
        .trim_end_matches('}')
        .trim();
    let arrangement = first_tok.split('.').nth(1)?;
    match arrangement {
        "16b" | "8h" | "4s" | "2d" => Some(16),
        "8b" | "4h" | "2s" | "1d" => Some(8),
        _ => None,
    }
}

/// 从排列说明符推导单个元素的字节宽度（b=1, h=2, s=4, d=8），
/// 即 st2-st4/ld2-ld4 lane 交错的粒度。
pub(crate) fn simd_arrangement_element_width(operand_text: &str) -> Option<u8> {
    let first_tok = operand_text.split(',').next()?.trim();
    let first_tok = first_tok
        .trim_start_matches('{')
        .split('[')
        .next()?
        .trim_end_matches('}')
        .trim();
    let arrangement = first_tok.split('.').nth(1)?;
    match arrangement.as_bytes().last()? {
        b'b' | b'B' => Some(1),
        b'h' | b'H' => Some(2),
        b's' | b'S' => Some(4),
        b'd' | b'D' => Some(8),
        _ => None,
    }
}

/// Infer memory access width from mnemonic and the first operand's raw register prefix.
///
/// The prefix must be captured BEFORE register normalization (w→x, d→v, etc.)
/// because it determines the access width:
/// - w → 4 bytes (32-bit)
/// - x → 8 bytes (64-bit)
/// - s → 4 bytes (single float)
/// - d → 8 bytes (double float)
/// - q → 16 bytes (128-bit vector)
/// - v → 16 bytes (full vector, default)
pub(crate) fn determine_elem_width(mnemonic: &str, first_reg_prefix: Option<u8>) -> u8 {
    match mnemonic {
        "ldrb" | "strb" | "ldrsb" | "ldarb" | "stlrb" | "ldurb" | "sturb" | "ldtrb" | "sttrb"
        | "ldaprb" | "stxrb" | "stlxrb" => 1,
        "ldrh" | "strh" | "ldrsh" | "ldarh" | "stlrh" | "ldurh" | "sturh" | "ldtrh" | "sttrh"
        | "ldaprh" | "stxrh" | "stlxrh" => 2,
        "ldrsw" | "ldursw" | "ldtrsw" | "ldpsw" => 4,
        _ => match first_reg_prefix {
            Some(b'w') => 4,
            Some(b'x') => 8,
            Some(b's') => 4,
            Some(b'd') => 8,
            Some(b'q') => 16,
            Some(b'v') => 16, // default full vector
            _ => 8,           // conservative default
        },
    }
}
