use super::scan::*;
use crate::types::*;
use memchr::memmem;
use smallvec::SmallVec;

/// 从文本中提取所有 `name=0xHEX` 寄存器值对（手写替换 REG_VAL_RE）。
///
/// 扫描 `=0x` 模式，向左提取寄存器名，向右提取十六进制值。
/// 128-bit SIMD 值溢出 u64 时截断为 0。
pub(crate) fn extract_reg_values(text: &str) -> SmallVec<[(RegId, u64); 4]> {
    let bytes = text.as_bytes();
    let mut result = SmallVec::new();
    let mut pos = 0;

    while pos + 3 <= bytes.len() {
        // 查找 "=0x" 模式
        let eq_pos = match memmem::find(&bytes[pos..], b"=0x") {
            Some(p) => pos + p,
            None => break,
        };

        // 向左提取寄存器名：连续的 ASCII 字母+数字
        let name_start = bytes[..eq_pos]
            .iter()
            .rposition(|b| !b.is_ascii_alphanumeric())
            .map(|p| p + 1)
            .unwrap_or(0);

        // 名字至少 2 字符（如 "x0"），且首字符为小写字母
        let name_bytes = &bytes[name_start..eq_pos];
        let valid_name = name_bytes.len() >= 2 && name_bytes[0].is_ascii_lowercase();

        // 向右提取十六进制值
        let val_start = eq_pos + 3; // 跳过 "=0x"
        let val_end = bytes[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(bytes.len());

        if valid_name {
            // SAFETY: name_bytes are already validated as ASCII alphanumeric above
            let name_str = unsafe { std::str::from_utf8_unchecked(name_bytes) };
            if let Some(reg) = parse_reg(name_str) {
                let val = parse_hex_u64(&bytes[val_start..val_end]).unwrap_or(0);
                result.push((reg, val));
            }
        }

        pos = val_end.max(eq_pos + 3); // 至少前进到 "=0x" 之后
    }

    result
}

/// Parse operand text (comma-separated), writing results directly into `out`.
///
/// Returns the first operand's raw register prefix byte (needed for memory access
/// width before register normalization, e.g., 'w' -> 4 bytes, 'x' -> 8 bytes).
///
/// Also populates `out.operands`, `out.base_reg`, and `out.lane_index`.
pub(crate) fn parse_operands_into(text: &str, out: &mut ParsedLine) -> Option<u8> {
    let mut first_reg_prefix: Option<u8> = None;

    if text.is_empty() {
        return first_reg_prefix;
    }

    let tokens = split_operands(text);

    for (i, token) in tokens.iter().enumerate() {
        let token = token.trim();

        // Strip curly braces (SIMD register list markers), zero allocation
        let token = token.trim_matches(['{', '}']);

        // Square brackets → memory address operand with base register
        if token.starts_with('[') {
            let inner = token
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('!');
            for part in inner.split(',') {
                let part = part.trim();
                if let Some(reg) = try_parse_reg_operand(part) {
                    if out.base_reg.is_none() {
                        out.base_reg = Some(reg);
                    }
                    out.operands.push(Operand::Reg(reg));
                }
            }
            continue;
        }

        // Extract lane index if present (e.g., "v0.s[1]" → "v0.s", Some(1))
        let (token, extracted_lane, extracted_elem_width) = extract_lane_index(token);
        if extracted_lane.is_some() {
            out.lane_index = extracted_lane;
            out.lane_elem_width = extracted_elem_width;
        }

        // Register operand
        if let Some(reg) = try_parse_reg_operand(token) {
            if i == 0 && first_reg_prefix.is_none() {
                first_reg_prefix = token.as_bytes().first().copied();
            }
            out.operands.push(Operand::Reg(reg));
            continue;
        }

        // Immediate (#0x1234, #-5, #123)
        if let Some(val_str) = token.strip_prefix('#') {
            if let Some(val) = parse_imm(val_str) {
                out.operands.push(Operand::Imm(val));
            }
            continue;
        }

        // Address literal (0x... as in branch targets)
        if token.starts_with("0x") || token.starts_with("0X") {
            if let Some(val) = parse_imm(token) {
                out.operands.push(Operand::Imm(val));
            }
            continue;
        }

        // Unrecognized tokens → skip (e.g., shift specifiers like "lsl #3")
    }

    first_reg_prefix
}

/// 按顶层逗号分割操作数，不分割方括号内的逗号。
/// 返回切片引用而非 String，零堆分配。
pub(crate) fn split_operands(text: &str) -> SmallVec<[&str; 6]> {
    let mut result = SmallVec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut bracket_depth: i32 = 0;

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => bracket_depth += 1,
            b']' => bracket_depth -= 1,
            b',' if bracket_depth == 0 => {
                result.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < text.len() {
        result.push(&text[start..]);
    }
    result
}

/// Try parsing a token as a register, stripping arrangement specifiers (e.g., v0.16b → v0).
fn try_parse_reg_operand(token: &str) -> Option<RegId> {
    let clean = token.split('.').next().unwrap_or(token);
    parse_reg(clean)
}

/// Extract lane index and element width from token like "v0.s[1]".
/// Returns (token without lane bracket, optional lane index, optional elem width in bytes).
pub(crate) fn extract_lane_index(token: &str) -> (&str, Option<u8>, Option<u8>) {
    if let Some(dot_pos) = token.find('.') {
        if let Some(bracket_start) = token[dot_pos..].find('[') {
            let abs_bracket = dot_pos + bracket_start;
            if let Some(bracket_end) = token[abs_bracket..].find(']') {
                let idx_str = &token[abs_bracket + 1..abs_bracket + bracket_end];
                if let Ok(idx) = idx_str.parse::<u8>() {
                    // Extract element width from arrangement specifier between '.' and '['.
                    // 单 lane 结构形式的说明符仍带着寄存器列表的闭括号（如
                    // `{v0.16b}[2]` 切出 `16b}`），先剥掉再按完整拼写匹配，
                    // 否则多字符排列（16b/4h/2s/2d）会解析失败。
                    let arrangement = token[dot_pos + 1..abs_bracket].trim_end_matches('}');
                    let elem_width = match arrangement {
                        "b" | "B" | "8b" | "16b" => Some(1u8),
                        "h" | "H" | "4h" | "8h" => Some(2u8),
                        "s" | "S" | "2s" | "4s" => Some(4u8),
                        "d" | "D" | "1d" | "2d" => Some(8u8),
                        _ => None,
                    };
                    return (&token[..abs_bracket], Some(idx), elem_width);
                }
            }
        }
    }
    (token, None, None)
}

/// Parse an immediate value from a string.
/// Handles hex (0x...), negative hex (-0x...), and decimal formats.
pub(crate) fn parse_imm(s: &str) -> Option<i64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok().map(|v| v as i64)
    } else if s.starts_with("-0x") || s.starts_with("-0X") {
        i64::from_str_radix(&s[3..], 16).ok().map(|v| -v)
    } else {
        s.parse::<i64>().ok()
    }
}
