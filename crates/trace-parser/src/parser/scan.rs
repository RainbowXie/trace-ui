use memchr::memmem;

/// 手动解析十六进制字节序列到 u64。
pub(crate) fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        result = result.checked_mul(16)?.checked_add(digit as u64)?;
    }
    Some(result)
}

/// 手动解析十六进制字节序列到 u128（用于 128-bit SIMD q 寄存器值）。
pub(crate) fn parse_hex_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u128 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u128,
            b'a'..=b'f' => (b - b'a' + 10) as u128,
            b'A'..=b'F' => (b - b'A' + 10) as u128,
            _ => return None,
        };
        val = val.checked_mul(16)?.checked_add(digit)?;
    }
    Some(val)
}

/// 从 `line[from..]` 中提取 mem[READ/WRITE] abs=0xADDR。
/// `from` 允许调用者跳过行首已扫描的部分，避免重复搜索。
/// Find mem_[READ/WRITE] with abs=0xADDR in unidbg format.
///
/// 与 gumtrace 相同的 fail-closed 规则：行内所有 mem[...] marker 都必须完整
/// 合法——标记名只接受 READ/WRITE 并立即闭括号；每个事件必须携带一个完整的
/// 十六进制地址（0x 前缀、至少一位数字、其后是非字母数字或行尾）。任何一处
/// 损坏都使整个事件失败，不能取前缀或静默跳过后续 marker。
pub(crate) fn find_mem_op_raw(line: &[u8], from: usize) -> Option<(bool, u64)> {
    let search = &line[from..];
    let mut first: Option<(bool, u64)> = None;
    let mut cursor = 0usize;
    loop {
        // 没有更多 mem[ marker：扫描结束，返回已收集的第一个事件。
        let Some(rel_pos) = memmem::find(&search[cursor..], b"mem[") else {
            break;
        };
        let pos = cursor + rel_pos;
        let tag = &search[pos + 4..];
        let tag_close = tag.iter().position(|&b| b == b']')?;
        let is_write = match &tag[..tag_close] {
            b"READ" => false,
            b"WRITE" => true,
            _ => return None,
        };
        let seg_start = pos + 4 + tag_close + 1;
        let after = search.get(seg_start..)?;
        let abs_rel = memmem::find(after, b"abs=0x")?;
        let digits = &after[abs_rel + 6..];
        let digit_count = digits.iter().take_while(|b| b.is_ascii_hexdigit()).count();
        if digit_count == 0 {
            return None;
        }
        // 地址必须被非字母数字（或行尾）终止；字母数字后缀不是地址的一部分。
        if digits
            .get(digit_count)
            .is_some_and(|b| b.is_ascii_alphanumeric())
        {
            return None;
        }
        let addr = parse_hex_u64(&digits[..digit_count])?;
        if first.is_none() {
            first = Some((is_write, addr));
        }
        cursor = seg_start + abs_rel + 6;
    }
    first
}
