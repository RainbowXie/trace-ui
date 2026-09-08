//! raw trace 行的机械片段解析：助记符、操作数、访存注解与寄存器值。
//! 只做文本抽取，不做语义判断。

/// 从 raw 行提取助记符：`[module] 0xPC!0xOFF <mnemonic> ...`。
pub(super) fn line_mnemonic(line: &str) -> Option<&str> {
    let bang = line.find("!0x")?;
    let rest = &line[bang + 3..];
    let hex_end = rest.find(|c: char| !c.is_ascii_hexdigit())?;
    let rest = &rest[hex_end..].trim_start();
    let end = rest.find(|c: char| c.is_whitespace() || c == ';')?;
    Some(&rest[..end])
}

/// 从 raw 行提取 `mem_r=0x…` / `mem_w=0x…` 注解地址。
pub(super) fn line_mem_annotation(line: &str, key: &str) -> Option<u64> {
    let marker = format!("{key}=0x");
    let start = line.find(&marker)? + marker.len();
    let hex = &line[start..];
    let end = hex
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(hex.len());
    u64::from_str_radix(&hex[..end], 16).ok()
}

/// 提取箭头后目标寄存器的值：`-> x0=0x41`（指令执行后的状态）。
pub(super) fn arrow_register_value(line: &str, register: &str) -> Option<u64> {
    let arrow = line.find("-> ")? + 3;
    let tail = &line[arrow..];
    let pattern = format!("{register}=0x");
    let start = tail.find(&pattern)? + pattern.len();
    let hex = &tail[start..];
    let end = hex
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(hex.len());
    u64::from_str_radix(&hex[..end], 16).ok()
}

/// 分号与箭头之间的 pre-state 区段里提取 `xN=0x…`（写入值的来源寄存器）。
pub(super) fn prestate_register_value(line: &str, register: &str) -> Option<u64> {
    let semicolon = line.find(';')?;
    let region_end = line.find(" -> ").unwrap_or(line.len());
    let region = &line[semicolon..region_end];
    let pattern = format!("{register}=0x");
    let start = region.find(&pattern)? + pattern.len();
    let hex = &region[start..];
    let end = hex
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(hex.len());
    u64::from_str_radix(&hex[..end], 16).ok()
}

/// 操作数 `[base, #offset]` 中的基址寄存器名（sp/wsp/fp/x29 归一为 sp/fp）。
pub(super) fn base_register(operand: &str) -> Option<String> {
    let start = operand.find('[')?;
    let rest = &operand[start + 1..];
    let end = rest.find([',', ']'])?;
    let name = rest[..end].trim();
    match name {
        "sp" | "wsp" => Some("sp".to_string()),
        "x29" | "fp" => Some("fp".to_string()),
        other => Some(other.to_string()),
    }
}

/// 助记符 + 目标操作数 → 访存宽度（字节）。覆盖整数访存家族：普通/
/// 非缩放/穿透/原子/成对；向量寄存器（q/s/d 首字符）与未知助记符返回
/// None——调用方必须把这类访存按「宽度未知」保守处理，不能静默丢弃。
pub(super) fn access_width(mnemonic: &str, operand: &str) -> Option<u32> {
    let register = operand.trim().split(',').next()?.trim();
    let scalar = |width: u32| match register.chars().next()? {
        'x' => Some(width),
        'w' => Some(width / 2),
        _ => None,
    };
    let width =
        match mnemonic {
            // 字节/半字/带符号扩展家族（普通、非缩放 ldur*、穿透 ldtr*/sttr*）。
            "ldrb" | "ldrsb" | "strb" | "ldurb" | "ldursb" | "sturb" | "ldtrb" | "ldtrsb"
            | "sttrb" => 1,
            "ldrh" | "ldrsh" | "strh" | "ldurh" | "ldursh" | "sturh" | "ldtrh" | "ldtrsh"
            | "sttrh" => 2,
            "ldrsw" | "ldursw" | "ldtrsw" => 4,
            // 单寄存器普通/非缩放/穿透访存与原子（独占/LSE 均为标量宽度）。
            "ldur" | "str" | "stur" | "ldr" | "ldtr" | "sttr" | "ldar" | "ldarh" | "ldxr"
            | "ldaxr" | "stlr" | "stlxr" | "stxr" | "stxrb" => scalar(8)?,
            // 成对访存：两个标量寄存器，总宽 2×。
            "ldp" | "stp" | "ldnp" | "stnp" | "ldpsw" | "ldxp" | "stxp" => scalar(16)?,
            _ => return None,
        };
    Some(width)
}

/// 助记符之后的第一个操作数（目标寄存器，含余下操作数文本）。
/// 定位必须从 `!0x` 锚点出发重走助记符位置——从行首 find(助记符) 会在
/// 模块名含助记符子串（如 libstream… 含 "str"）时错位。
pub(super) fn first_operand(line: &str) -> Option<String> {
    let bang = line.find("!0x")?;
    let rest = &line[bang + 3..];
    let hex_end = rest.find(|c: char| !c.is_ascii_hexdigit())?;
    let after = rest[hex_end..].trim_start();
    // 跳过助记符本身。
    let mnemonic_end = after.find(|c: char| c.is_whitespace())?;
    let operand = after[mnemonic_end..].trim_start();
    let end = operand.find(';')?;
    Some(operand[..end].trim_end_matches(',').to_string())
}

/// u64 → 按地址递增（小端）的 lowercase hex 字节串。
pub(super) fn little_endian_hex(value: u64, size: u32) -> String {
    let bytes = value.to_le_bytes();
    let used = &bytes[..size as usize];
    used.iter().map(|byte| format!("{byte:02x}")).collect()
}
