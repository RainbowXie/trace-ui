use super::scan::*;
use memchr::memmem;
/// 从 `bytes[start_pos..]` 中查找 `reg_name=0xHEX` 模式，返回 HEX 部分的原始字节切片。
///
/// 确保寄存器名精确匹配（不会出现 "x1" 匹配到 "x10" 的前缀冲突），
/// 通过检查名字前一个字符不是字母数字、且名字后紧跟 "=0x"。
fn find_reg_hex_bytes<'a>(bytes: &'a [u8], reg_name: &[u8], start_pos: usize) -> Option<&'a [u8]> {
    let search = &bytes[start_pos..];
    let mut pos = 0;
    while pos + reg_name.len() + 3 <= search.len() {
        let found = memmem::find(&search[pos..], reg_name)?;
        let abs = pos + found;
        let eq_pos = abs + reg_name.len();
        // Check "=0x" follows
        if eq_pos + 3 <= search.len()
            && search[eq_pos] == b'='
            && search[eq_pos + 1] == b'0'
            && search[eq_pos + 2] == b'x'
        {
            // Verify the character before reg_name is not alphanumeric
            let char_before = if abs == 0 { b' ' } else { search[abs - 1] };
            if !char_before.is_ascii_alphanumeric() {
                let val_start = eq_pos + 3;
                let digit_count = search[val_start..]
                    .iter()
                    .take_while(|b| b.is_ascii_hexdigit())
                    .count();
                // 注解存在但值损坏（缺数字、或数字后紧跟字母数字垃圾）时不得
                // 取前缀猜值：整个寄存器查找按缺失处理，让调用方走 unknown。
                if digit_count == 0
                    || search
                        .get(val_start + digit_count)
                        .is_some_and(|b| b.is_ascii_alphanumeric())
                {
                    return None;
                }
                return Some(&search[val_start..val_start + digit_count]);
            }
        }
        pos = abs + 1;
    }
    None
}

/// Find `reg_name=0xHEX` in `bytes[start_pos..]`, return parsed hex value as u64.
///
/// Ensures exact register name match (no prefix collisions like "x1" matching "x10")
/// by checking the character before the name is not alphanumeric and "=0x" follows immediately.
pub(crate) fn find_reg_value(bytes: &[u8], reg_name: &[u8], start_pos: usize) -> Option<u64> {
    parse_hex_u64(find_reg_hex_bytes(bytes, reg_name, start_pos)?)
}

/// Find `reg_name=0xHEX` in `bytes[start_pos..]`, return parsed hex value as u128.
///
/// 用于 128-bit SIMD q 寄存器值的提取。
pub(crate) fn find_reg_value_u128(bytes: &[u8], reg_name: &[u8], start_pos: usize) -> Option<u128> {
    parse_hex_u128(find_reg_hex_bytes(bytes, reg_name, start_pos)?)
}

/// 将 SIMD 寄存器名的 v/d/s/b/h 前缀转换为 q 前缀。
/// unidbg trace 中 SIMD 寄存器值始终以 q 前缀记录（如 q0=0x...），
/// 但指令操作数可能使用其他前缀（如 v0、d0、s0）。
pub(crate) fn simd_reg_to_q_prefix(reg_name: &str) -> Option<String> {
    let first = reg_name.as_bytes().first()?;
    if matches!(first, b'v' | b'd' | b's' | b'b' | b'h') {
        Some(format!("q{}", &reg_name[1..]))
    } else {
        None
    }
}

/// 判断寄存器名是否为 SIMD 寄存器（v/d/s/b/h 前缀）。
pub(crate) fn is_simd_reg_name(name: &str) -> bool {
    matches!(
        name.as_bytes().first(),
        Some(b'v' | b'd' | b's' | b'b' | b'h')
    )
}

/// 查找 SIMD 寄存器的 u128 值，先尝试 q 前缀（unidbg 格式），
/// 再回退原始寄存器名（某些 trace 直接用 v0=0x... 记录）。
pub(crate) fn find_simd_reg_u128(bytes: &[u8], reg_name: &str, start_pos: usize) -> Option<u128> {
    let q_name = simd_reg_to_q_prefix(reg_name);
    q_name
        .as_deref()
        .and_then(|qn| find_reg_value_u128(bytes, qn.as_bytes(), start_pos))
        .or_else(|| find_reg_value_u128(bytes, reg_name.as_bytes(), start_pos))
}

/// 从 128-bit SIMD 寄存器值中提取标量值。
/// lane load 时提取指定 lane 的元素，64-bit 排列时返回低 64 位；
/// lane 下标越出寄存器范围时返回 None（该值未知，不得伪造）。
pub(crate) fn extract_simd_lane_value(
    full_u128: u128,
    elem_width: u8,
    lane_index: Option<u8>,
) -> Option<u64> {
    let Some(lane_idx) = lane_index else {
        return Some(full_u128 as u64);
    };
    let width = usize::from(elem_width.max(1));
    let offset = usize::from(lane_idx) * width;
    if elem_width == 0 || offset + width > 16 {
        return None;
    }
    // 按字节拷贝而非移位：避免 lane 巨大时的位移溢出 panic。
    let bytes = full_u128.to_le_bytes();
    let mut out = [0u8; 8];
    out[..width].copy_from_slice(&bytes[offset..offset + width]);
    Some(u64::from_le_bytes(out))
}
