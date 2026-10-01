//! raw trace 行的机械片段解析：助记符、操作数、访存注解与寄存器值。
//! 只做文本抽取，不做语义判断。

/// 独占 STORE 的执行结果：生产 parser 用 post-arrow 状态寄存器区分
/// 成功/失败，FunctionFact 必须消费同一权威信号，不能把失败 store 当
/// 成可能写入（会把真实外部读取静默吞掉）。
pub(super) enum ExclusiveStoreOutcome {
    /// 状态寄存器为 0：真实写入发生。
    Succeeded { width: u32 },
    /// 状态寄存器非 0：无任何内存效果。
    Failed,
    /// 无 post-arrow 状态：保守按未知宽度阻断。
    Unknown,
}

/// 从 raw 行提取助记符：`[module] 0xPC!0xOFF <mnemonic> ...`。
pub(super) fn line_mnemonic(line: &str) -> Option<&str> {
    trace_parser::strict_memory::instruction_parts(line).map(|(mnemonic, _)| mnemonic)
}

/// 助记符之后的第一个操作数（目标寄存器，含余下操作数文本）。
/// 定位必须从 `!0x` 锚点出发重走助记符位置——从行首 find(助记符) 会在
/// 模块名含助记符子串（如 libstream… 含 "str"）时错位。
pub(super) fn first_operand(line: &str) -> Option<String> {
    trace_parser::strict_memory::instruction_parts(line)
        .map(|(_, operand)| operand.trim_end_matches(',').to_string())
}

/// 从 raw 行提取 `mem_r=0x…` / `mem_w=0x…` 注解地址。
pub(crate) fn line_mem_annotation(line: &str, key: &str) -> Option<u64> {
    let (write, address) = trace_parser::strict_memory::memory_marker(line)?;
    ((key == "mem_w" && write) || (key == "mem_r" && !write)).then_some(address)
}

/// 提取箭头后目标寄存器的值：`-> x0=0x41`（指令执行后的状态）。
pub(super) fn arrow_register_value(line: &str, register: &str) -> Option<u64> {
    let arrow = line
        .find("-> ")
        .map(|position| position + 3)
        .or_else(|| line.find("=> ").map(|position| position + 3))?;
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
    let region_end = line
        .find(" -> ")
        .or_else(|| line.find(" => "))
        .unwrap_or(line.len());
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

/// 成对访存助记符：值横跨两个寄存器，单个 prestate/箭头值只覆盖一半，
/// 任何宽度（含 W-pair 的 8 字节）都不能据此产出 bytes/value。
pub(super) fn is_pair_access(mnemonic: &str) -> bool {
    // ldpsw 访存 8 字节但写两个寄存器（带符号扩展），箭头值只覆盖 Xt1
    // ——与 pair 同样不能产出完整 bytes。
    matches!(mnemonic, "ldp" | "stp" | "ldnp" | "stnp" | "ldxp" | "ldpsw")
}

/// 助记符与完整合法数据寄存器确定访存宽度，不采用默认宽度。
/// 覆盖整数、显式标量 SIMD 与成对访存；独占 STORE 成败另查 post 状态。
pub(crate) fn access_width(mnemonic: &str, operand: &str) -> Option<u32> {
    trace_parser::strict_memory::access_width(mnemonic, operand)
}

/// 独占 STORE 的成败判定：post-arrow 状态寄存器（首操作数 Ws）。
/// 成功宽度取自数据寄存器（第二个操作数）；pair 独占写横跨两个数据
/// 寄存器。
pub(super) fn exclusive_store_outcome(
    line: &str,
    mnemonic: &str,
    operand: &str,
) -> Option<ExclusiveStoreOutcome> {
    if !matches!(
        mnemonic,
        "stxrb" | "stlxrb" | "stxrh" | "stlxrh" | "stxr" | "stlxr" | "stxp" | "stlxp"
    ) {
        return None;
    }
    let Some(width) = access_width(mnemonic, operand) else {
        return Some(ExclusiveStoreOutcome::Unknown);
    };
    Some(
        match trace_parser::strict_memory::memory_op(line).and_then(|mem| mem.exclusive_status) {
            Some(0) => ExclusiveStoreOutcome::Succeeded { width },
            Some(_) => ExclusiveStoreOutcome::Failed,
            None => ExclusiveStoreOutcome::Unknown,
        },
    )
}
