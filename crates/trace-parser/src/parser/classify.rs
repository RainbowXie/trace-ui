use super::operands::split_operands;
use crate::types::*;

/// 取内存操作的第 0 个数据寄存器原始名（未规范化），用于在 trace 文本中
/// 查找 `regname=0xHEX` 注解；exclusive store 会跳过状态寄存器。
pub(crate) fn first_memory_data_reg_name<'a>(
    mnemonic: &str,
    operand_text: &'a str,
) -> Option<&'a str> {
    memory_data_reg_name_at(mnemonic, operand_text, 0)
}

pub(crate) fn second_memory_data_reg_name<'a>(
    mnemonic: &str,
    operand_text: &'a str,
) -> Option<&'a str> {
    memory_data_reg_name_at(mnemonic, operand_text, 1)
}

/// 取第 index 个内存数据寄存器；exclusive store 的第一个操作数是状态寄存器，
/// 不参与内存字节，必须统一跳过。
pub(crate) fn memory_data_reg_name_at<'a>(
    mnemonic: &str,
    operand_text: &'a str,
    index: usize,
) -> Option<&'a str> {
    let status = usize::from(is_exclusive_store(mnemonic));
    data_reg_name_at(operand_text, index + status)
}

pub(crate) fn data_reg_name_at(operand_text: &str, index: usize) -> Option<&str> {
    let first_tok = operand_text.split(',').nth(index)?.trim();
    let first_tok = first_tok
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    let first_tok = first_tok.split('.').next()?; // strip arrangement specifier
                                                  // 零寄存器没有数字后缀，但它是一个合法的内存数据源（已知零值）。
    if first_tok == "xzr" || first_tok == "wzr" {
        return Some(first_tok);
    }
    let b = first_tok.as_bytes();
    if b.len() >= 2
        && matches!(b[0], b'w' | b'x' | b'q' | b'd' | b's' | b'b' | b'h' | b'v')
        && b[1..].iter().all(|c| c.is_ascii_digit())
    {
        Some(first_tok)
    } else {
        None
    }
}

/// 提取操作数中第二个数据寄存器名（用于 pair 指令如 ldp/stp）。
pub(crate) fn second_data_reg_name(operand_text: &str) -> Option<&str> {
    data_reg_name_at(operand_text, 1)
}

pub(crate) fn is_exclusive_pair_store(mn: &str) -> bool {
    matches!(mn, "stxp" | "stlxp")
}

/// 所有 exclusive store：第一个操作数是状态寄存器，不是写入内存的值。
pub(crate) fn is_exclusive_store(mn: &str) -> bool {
    is_exclusive_pair_store(mn)
        || matches!(
            mn,
            "stxr" | "stlxr" | "stxrb" | "stlxrb" | "stxrh" | "stlxrh"
        )
}

/// atomic/RMW 指令：内存最终字节是旧值与寄存器的运算结果，trace 的寄存器
/// 注解不足以精确恢复，replay 必须保守处理。
pub(crate) fn is_atomic_rmw(mn: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "swp", "cas", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
        "stadd", "stclr", "steor", "stset", "stsmax", "stsmin", "stumax", "stumin",
    ];
    PREFIXES.iter().any(|prefix| mn.starts_with(prefix))
}

/// atomic 指令的访问宽度：b/h 后缀优先，否则按数据寄存器位宽；casp 是双元素。
pub(crate) fn atomic_elem_width(mnemonic: &str, first_reg_prefix: Option<u8>) -> u8 {
    let base: u8 = if mnemonic.ends_with('b') {
        1
    } else if mnemonic.ends_with('h') {
        2
    } else {
        match first_reg_prefix {
            Some(b'x') => 8,
            _ => 4,
        }
    };
    if mnemonic.starts_with("casp") {
        base.saturating_mul(2)
    } else {
        base
    }
}

/// replicate load（ld1r-ld4r）：每个结构元素复制到目标寄存器的所有 lane，
/// 内存只读取每个寄存器的一个元素。
pub(crate) fn is_simd_replicate(mn: &str) -> bool {
    matches!(mn, "ld1r" | "ld2r" | "ld3r" | "ld4r")
}

/// 按 ARM64 内存语义对内存访问的字节布局分类。
pub(crate) fn classify_mem_layout(mnemonic: &str, operand_text: &str) -> MemLayout {
    if is_atomic_rmw(mnemonic) {
        return MemLayout::Atomic;
    }
    if is_simd_replicate(mnemonic) {
        return MemLayout::SimdLane;
    }
    // 单 lane 结构形式：lane 后缀紧跟寄存器列表的闭括号（}[n]），与寻址
    // 方括号区分。单寄存器（st1 {v0.16b}[2]）与多寄存器形式同样只写一个
    // 元素，不能按完整向量展开。
    if operand_text.contains("}[")
        && matches!(
            mnemonic,
            "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4"
        )
    {
        return MemLayout::SimdLane;
    }
    if is_simd_multi_reg(mnemonic, operand_text) {
        // st1/ld1 的多寄存器形式是寄存器级连续；st2-st4/ld2-ld4 按 lane 交错。
        return if matches!(mnemonic, "st2" | "st3" | "st4" | "ld2" | "ld3" | "ld4") {
            MemLayout::SimdInterleaved
        } else {
            MemLayout::SimdContiguous
        };
    }
    if is_exclusive_pair_store(mnemonic) {
        return MemLayout::ExclusivePair;
    }
    if is_exclusive_store(mnemonic) {
        return MemLayout::ExclusiveScalar;
    }
    if is_pair_mnemonic(mnemonic) {
        return MemLayout::Pair;
    }
    MemLayout::Scalar
}

/// 判断助记符是否为 pair 类指令（ldp/stp 及其变体）。
pub(crate) fn is_pair_mnemonic(mn: &str) -> bool {
    mn.starts_with("ldp")
        || mn.starts_with("stp")
        || mn.starts_with("ldnp")
        || mn.starts_with("stnp")
        || mn.starts_with("ldxp")
        || mn.starts_with("ldaxp")
        || mn.starts_with("stxp")
        || mn.starts_with("stlxp")
}

/// 判断是否为 SIMD 多寄存器指令（ld1-ld4/st1-st4 且操作数中有两个以上数据寄存器）。
pub(crate) fn is_simd_multi_reg(mnemonic: &str, operand_text: &str) -> bool {
    matches!(
        mnemonic,
        "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4"
    ) && second_data_reg_name(operand_text).is_some()
}

/// Count register-sized values covered by a pair or multi-register memory
/// operation.  The trace may omit one or more register values, but the address
/// range is still real and must be represented as unknown during replay.
pub(crate) fn memory_value_count(mnemonic: &str, operand_text: &str) -> u8 {
    if !is_pair_mnemonic(mnemonic)
        && !is_simd_multi_reg(mnemonic, operand_text)
        && !is_simd_replicate(mnemonic)
    {
        return 1;
    }
    let count = split_operands(operand_text)
        .into_iter()
        .take_while(|token| !token.trim_start().starts_with('['))
        .filter(|token| {
            let token = token.trim().trim_matches(['{', '}']);
            let token = token.split('.').next().unwrap_or(token);
            parse_reg(token).is_some()
        })
        .count();
    let status = usize::from(is_exclusive_pair_store(mnemonic));
    count.saturating_sub(status).clamp(1, 4) as u8
}
