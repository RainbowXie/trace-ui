//! trace 格式检测与指令行结构签名。
//!
//! unidbg 与 gumtrace 的“指令行长什么样”各自只有一条结构规则，由
//! detect_format、扫描侧可识别行统计与行解析三方共用，防止普通文本
//! （带引号的日志、`[x] ! "..."` 这类形似行）被误识别为合法 trace。

use crate::types::TraceFormat;

/// gumtrace 指令行的结构前缀：`[module] 0xABS!0xOFFSET `（模块名、空格、
/// 十六进制绝对地址、`!`、十六进制 offset、空格）。detect_format、扫描侧
/// 可识别行统计与行解析共用这一条规则，防止普通文本（如 `[x] ! "mov x0"`）
/// 被误识别为指令行。返回指令文本的起始下标。
pub(crate) fn gumtrace_instruction_prefix(line: &[u8]) -> Option<usize> {
    if line.first() != Some(&b'[') {
        return None;
    }
    let close = memchr::memchr(b']', line)?;
    // 模块名与绝对地址之间必须是 "] "。
    if line.get(close + 1) != Some(&b' ') {
        return None;
    }
    let abs_start = close + 2;
    let bang = memchr::memchr(b'!', &line[abs_start..])? + abs_start;
    if !is_hex_prefixed(&line[abs_start..bang]) {
        return None;
    }
    let offset_start = bang + 1;
    let space = memchr::memchr(b' ', &line[offset_start..])? + offset_start;
    if !is_hex_prefixed(&line[offset_start..space]) {
        return None;
    }
    Some(space + 1)
}

/// `0x` 前缀 + 至少一位、且全部是十六进制数字。
fn is_hex_prefixed(text: &[u8]) -> bool {
    text.len() > 2 && text.starts_with(b"0x") && text[2..].iter().all(u8::is_ascii_hexdigit)
}

/// unidbg 指令行的结构前缀：
/// `[HH:MM:SS NNN][module …] [thread-hex] 0xADDR: "`（时间戳括号、模块括号、
/// 空格+线程/上下文十六进制括号、空格+十六进制地址+冒号+空格+引号）。
/// 时间戳与毫秒/序号段之间接受空格或点（两种真实 unidbg 输出都存在）。
/// 返回反汇编文本引号的位置。detect_format、扫描侧可识别行统计与行解析
/// 共用这一条规则，防止 `[12:……] "任意文本"` 这类普通日志被误识别。
pub(crate) fn unidbg_instruction_prefix(line: &[u8]) -> Option<usize> {
    // [HH:MM:SS NNN] —— 位置 0..=13 是定长时间戳括号
    if line.len() < 14
        || line[0] != b'['
        || !line[1].is_ascii_digit()
        || !line[2].is_ascii_digit()
        || line[3] != b':'
        || !line[4].is_ascii_digit()
        || !line[5].is_ascii_digit()
        || line[6] != b':'
        || !line[7].is_ascii_digit()
        || !line[8].is_ascii_digit()
        || !matches!(line[9], b' ' | b'.')
        || !line[10..13].iter().all(|b: &u8| b.is_ascii_digit())
        || line[13] != b']'
    {
        return None;
    }
    // [module …]（紧跟时间戳括号，内容不限但非空）
    if line.get(14) != Some(&b'[') {
        return None;
    }
    let module_close = memchr::memchr(b']', &line[15..])? + 15;
    if module_close == 15 {
        return None;
    }
    // ` [<hex>]`（线程/上下文括号）
    let thread_open = module_close + 1;
    if line.get(thread_open) != Some(&b' ') || line.get(thread_open + 1) != Some(&b'[') {
        return None;
    }
    let thread_close = memchr::memchr(b']', &line[thread_open + 2..])? + thread_open + 2;
    if thread_close == thread_open + 2
        || !line[thread_open + 2..thread_close]
            .iter()
            .all(|b: &u8| b.is_ascii_hexdigit())
    {
        return None;
    }
    // ` 0xADDR: "`（地址括号外、冒号、空格、引号）
    let rest = line.get(thread_close + 1..)?.strip_prefix(b" 0x")?;
    let colon = memchr::memchr(b':', rest)?;
    if colon == 0 || !rest[..colon].iter().all(|b: &u8| b.is_ascii_hexdigit()) {
        return None;
    }
    if !rest[colon..].starts_with(b": \"") {
        return None;
    }
    // 引号的绝对位置 = thread_close+1 + 3（" 0x"）+ colon + 2（": "）
    Some(thread_close + 1 + 3 + colon + 2)
}

/// 判断一行是否带有指定格式的指令行结构签名。
/// detect_format 与扫描侧的可识别行统计必须使用同一条规则，防止两处
/// 判定漂移（扫描侧用它把“带引号的普通文本行”排除在可识别行之外）。
pub fn line_matches_format_signature(line: &[u8], format: TraceFormat) -> bool {
    if line.is_empty() {
        return false;
    }
    match format {
        // unidbg: [HH:MM:SS NNN][module] [thread] 0xADDR: "insn"
        TraceFormat::Unidbg => unidbg_instruction_prefix(line).is_some(),
        // gumtrace: [module] 0xABS!0xOFFSET <insn>
        TraceFormat::Gumtrace => gumtrace_instruction_prefix(line).is_some(),
    }
}

/// 从文件的前几行自动检测 trace 格式
pub fn detect_format(data: &[u8]) -> TraceFormat {
    let mut pos = 0;
    let mut checked = 0;
    while pos < data.len() && checked < 20 {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let line = &data[pos..end];

        if !line.is_empty() {
            if line_matches_format_signature(line, TraceFormat::Unidbg) {
                return TraceFormat::Unidbg;
            }
            if line_matches_format_signature(line, TraceFormat::Gumtrace) {
                return TraceFormat::Gumtrace;
            }
        }
        pos = end + 1;
        checked += 1;
    }
    // 前 20 行窗口内没有格式特征时回退全扫：gumtrace 函数入口区可以连续出现
    // 大量 call/args/ret 特殊行（不以 [ 开头），首条指令行可能在窗口之外。
    // 回退只识别 gumtrace 指令行签名（严格结构前缀），找不到再按 Unidbg
    // 默认处理；不可识别输入最终由扫描侧"无可识别指令行"拒绝。
    if gumtrace_instruction_signature_in(data) {
        return TraceFormat::Gumtrace;
    }
    TraceFormat::Unidbg // default
}

/// 在整个输入中查找 gumtrace 指令行签名（严格结构前缀）。
/// 只用于 detect_format 的窗口回退，不做逐行解析。
fn gumtrace_instruction_signature_in(data: &[u8]) -> bool {
    let mut pos = 0;
    loop {
        let end = match memchr::memchr(b'\n', &data[pos..]) {
            Some(rel) => pos + rel,
            None => data.len(),
        };
        let line = &data[pos..end];
        if line_matches_format_signature(line, TraceFormat::Gumtrace) {
            return true;
        }
        if end == data.len() {
            return false;
        }
        pos = end + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gumtrace::parse_line_gumtrace;

    #[test]
    fn test_detect_format_unidbg() {
        let data = br#"[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: "stp x29, x30, [sp, #-0x60]!""#;
        assert_eq!(detect_format(data), TraceFormat::Unidbg);
    }

    #[test]
    fn test_detect_format_gumtrace() {
        let data = b"[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 sub x0, x29, #0x80; x0=0x75150f2e20\n";
        assert_eq!(detect_format(data), TraceFormat::Gumtrace);
    }

    #[test]
    fn test_detect_format_gumtrace_when_special_lines_exceed_the_window() {
        // 函数入口区可以连续出现大量 call/args/ret 特殊行，首条指令行可能在
        // 前 20 行窗口之外。检测必须扫到第一条指令行，否则会误判为 Unidbg，
        // 整份合法 trace 被当作不可识别输入拒绝。
        let mut data = String::new();
        for i in 0..25 {
            data.push_str(&format!(
                "call func: f{i}(0x1000)\nargs0: 0x1000\nret: 0x1\n"
            ));
        }
        data.push_str(
            "[lib.so] 0x7522f46438!0x143438 str w0, [x1]; w0=0x04030201 x1=0x2000 mem_w=0x2000\n",
        );
        assert_eq!(detect_format(data.as_bytes()), TraceFormat::Gumtrace);
    }

    #[test]
    fn test_detect_format_special_lines_only_falls_back_to_unidbg() {
        // 全特殊行（无任何指令）没有可搜索内容：检测结果不重要，扫描侧
        // 必须按"无可识别指令行"拒绝，而不是返回空结果。
        let data = b"call func: f0(0x1000)\nargs0: 0x1000\nret: 0x1\n";
        assert_eq!(detect_format(data), TraceFormat::Unidbg);
    }

    #[test]
    fn test_gumtrace_signature_rejects_text_with_a_bare_bang() {
        // 审查回归：`[x] ! "mov x0, x1"` 这类普通文本此前同时通过签名
        // （`[` + `!`）与宽松解析，会被误识别为合法 Gumtrace 指令行。
        // 结构前缀必须是 `[module] 0xABS!0xOFFSET `（模块、空格、十六进制
        // 绝对地址、!、十六进制 offset、空格）。
        let garbage = b"[x] ! \"mov x0, x1\"";
        assert!(parse_line_gumtrace(std::str::from_utf8(garbage).unwrap()).is_none());
        assert!(!line_matches_format_signature(
            garbage,
            TraceFormat::Gumtrace
        ));
        // 缺空格 / 非十六进制地址 / 非十六进制 offset 同样拒绝
        assert!(!line_matches_format_signature(
            b"[mod]0x1!0x2 nop",
            TraceFormat::Gumtrace
        ));
        assert!(!line_matches_format_signature(
            b"[mod] zz!0x2 nop",
            TraceFormat::Gumtrace
        ));
        assert!(!line_matches_format_signature(
            b"[mod] 0x1!yy nop",
            TraceFormat::Gumtrace
        ));
        // 合法行保持识别
        let good = b"[lib.so] 0x7522f46438!0x143438 str w0, [x1]";
        assert!(line_matches_format_signature(good, TraceFormat::Gumtrace));
        assert!(parse_line_gumtrace(std::str::from_utf8(good).unwrap()).is_some());
    }

    #[test]
    fn test_unidbg_signature_rejects_log_text_with_quotes() {
        // 审查回归：普通日志行带引号内容，此前被当成合法 unidbg 指令行。
        let garbage =
            b"[12:this is ordinary application log text padded past forty bytes] \"hello world\"";
        assert!(!line_matches_format_signature(garbage, TraceFormat::Unidbg));
        assert_eq!(detect_format(garbage), TraceFormat::Unidbg); // 默认回退，扫描侧拒绝
                                                                 // 缺引号 / 非十六进制地址 / 缺线程括号同样拒绝
        assert!(!line_matches_format_signature(
            b"[00:00:00 001][lib.so 0x100] [0c400000] 0x40000100: mov x0",
            TraceFormat::Unidbg
        ));
        assert!(!line_matches_format_signature(
            b"[00:00:00 001][lib.so 0x100] [0c400000] 0xZZZZ: \"nop\"",
            TraceFormat::Unidbg
        ));
        assert!(!line_matches_format_signature(
            b"[00:00:00 001][lib.so 0x100] 0x40000100: \"nop\"",
            TraceFormat::Unidbg
        ));
        // 合法行（空格与点两种毫秒分隔）保持识别
        assert!(line_matches_format_signature(
            b"[00:00:00 001][lib.so 0x100] [0c400000] 0x40000100: \"nop\"",
            TraceFormat::Unidbg
        ));
        assert!(line_matches_format_signature(
            b"[22:39:18.210][lib.so 0x100] [8b090108] 0x40000108: \"add x8, x8, x9\"",
            TraceFormat::Unidbg
        ));
    }
}
