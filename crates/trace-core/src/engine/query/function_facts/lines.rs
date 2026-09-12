//! raw trace 行的机械片段解析：助记符、操作数、访存注解与寄存器值。
//! 只做文本抽取，不做语义判断。

/// 独占 STORE 的执行结果：生产 parser 用 post-arrow 状态寄存器区分
/// 成功/失败，FunctionFact 必须消费同一权威信号，不能把失败 store 当
/// 成可能写入（会把真实外部读取静默吞掉）。
pub(super) enum ExclusiveStoreOutcome {
    /// 状态寄存器为 0：真实写入发生。
    Succeeded { width: u32, pair: bool },
    /// 状态寄存器非 0：无任何内存效果。
    Failed,
    /// 无 post-arrow 状态：保守按未知宽度阻断。
    Unknown,
}

/// 从 raw 行提取助记符：`[module] 0xPC!0xOFF <mnemonic> ...`。
pub(super) fn line_mnemonic(line: &str) -> Option<&str> {
    let bang = line.find("!0x")?;
    let rest = &line[bang + 3..];
    let hex_end = rest.find(|c: char| !c.is_ascii_hexdigit())?;
    let rest = &rest[hex_end..].trim_start();
    let end = rest.find(|c: char| c.is_whitespace() || c == ';')?;
    Some(&rest[..end])
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

/// 从 raw 行提取 `mem_r=0x…` / `mem_w=0x…` 注解地址。
pub(crate) fn line_mem_annotation(line: &str, key: &str) -> Option<u64> {
    let marker = format!("{key}=0x");
    let gumtrace_marker = match key {
        "mem_r" => Some("mem[READ] abs=0x"),
        "mem_w" => Some("mem[WRITE] abs=0x"),
        _ => None,
    };
    let (start, marker_len) = line
        .find(&marker)
        .map(|start| (start, marker.len()))
        .or_else(|| {
            gumtrace_marker.and_then(|marker| line.find(marker).map(|start| (start, marker.len())))
        })?;
    let start = start + marker_len;
    let hex = &line[start..];
    let end = hex
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(hex.len());
    u64::from_str_radix(&hex[..end], 16).ok()
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

/// 助记符 + 目标操作数 → 访存宽度（字节）。覆盖整数访存家族：普通/
/// 非缩放/穿透/原子 LOAD/成对；向量寄存器（q/s/d 首字符）、独占 STORE
/// 与未知助记符返回 None——调用方必须按「宽度未知」保守处理，不能静默
/// 丢弃。独占 STORE 走 exclusive_store_outcome（状态寄存器定成败）。
pub(crate) fn access_width(mnemonic: &str, operand: &str) -> Option<u32> {
    let register = operand.trim().split(',').next()?.trim();
    let scalar = |width: u32| match register.chars().next()? {
        'x' => Some(width),
        'w' => Some(width / 2),
        _ => None,
    };
    let width = match mnemonic {
        // 字节/半字/带符号扩展家族（普通、非缩放 ldur*、穿透 ldtr*/sttr*）。
        "ldrb" | "ldrsb" | "strb" | "ldurb" | "ldursb" | "sturb" | "ldtrb" | "ldtrsb" | "sttrb" => {
            1
        }
        "ldrh" | "ldrsh" | "strh" | "ldurh" | "ldursh" | "sturh" | "ldtrh" | "ldtrsh" | "sttrh"
        | "ldarh" => 2,
        "ldrsw" | "ldursw" | "ldtrsw" => 4,
        // 单寄存器普通/非缩放/穿透访存与原子 LOAD（首操作数=数据寄存器）。
        // ldpsw 实际访存 2×4=8 字节（带符号扩展后写两个 64 位寄存器）。
        "ldur" | "str" | "stur" | "ldr" | "ldtr" | "sttr" | "ldar" | "ldxr" | "ldaxr" | "stlr"
        | "ldpsw" => match register.chars().next()? {
            'q' => 16,
            'd' => 8,
            's' => 4,
            _ => scalar(8)?,
        },
        // 成对访存（ldxp 首操作数是数据寄存器；stp 家族首操作数同为
        // 数据寄存器）。支持 q/d/s 向量/浮点成对访存。
        "ldp" | "stp" | "ldnp" | "stnp" | "ldxp" => match register.chars().next()? {
            'q' => 32,
            'd' => 16,
            's' => 8,
            _ => scalar(16)?,
        },
        _ => return None,
    };
    Some(width)
}

/// 独占 STORE 的成败判定：post-arrow 状态寄存器（首操作数 Ws）。
/// 成功宽度取自数据寄存器（第二个操作数）；pair 独占写横跨两个数据
/// 寄存器。
pub(super) fn exclusive_store_outcome(
    line: &str,
    mnemonic: &str,
    operand: &str,
) -> Option<ExclusiveStoreOutcome> {
    let parts: Vec<&str> = operand.split(',').map(str::trim).collect();
    let status = parts.first().copied()?;
    let width = match mnemonic {
        "stxrb" | "stlxrb" => 1,
        "stxrh" | "stlxrh" => 2,
        "stxr" | "stlxr" => match parts.get(1)?.chars().next()? {
            'x' => 8,
            'w' => 4,
            _ => return None,
        },
        "stxp" | "stlxp" => {
            let width = match parts.get(1)?.chars().next()? {
                'x' => 8,
                'w' => 4,
                _ => return None,
            };
            return Some(match arrow_register_value(line, status)? {
                0 => ExclusiveStoreOutcome::Succeeded {
                    width: width * 2,
                    pair: true,
                },
                _ => ExclusiveStoreOutcome::Failed,
            })
            .or(Some(ExclusiveStoreOutcome::Unknown));
        }
        _ => return None,
    };
    Some(match arrow_register_value(line, status)? {
        0 => ExclusiveStoreOutcome::Succeeded { width, pair: false },
        _ => ExclusiveStoreOutcome::Failed,
    })
    .or(Some(ExclusiveStoreOutcome::Unknown))
}
