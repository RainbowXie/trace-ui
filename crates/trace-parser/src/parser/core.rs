//! parse_line 入口与主解析循环。

use super::classify::*;
use super::operands::*;
use super::regs::*;
use super::scan::*;
use super::simd::*;
use crate::types::*;
use memchr::{memchr, memmem};
use smallvec::SmallVec;

/// Parse a trace line (lightweight mode for scan — skips arrow register extraction).
///
/// Returns `None` for lines that don't match the expected trace format
/// (empty lines, log lines without disassembly, etc.).
pub fn parse_line(raw: &str) -> Option<ParsedLine> {
    parse_line_inner(raw, false)
}

/// Parse a trace line (full mode for validate — includes arrow register extraction).
#[allow(dead_code)]
pub fn parse_line_full(raw: &str) -> Option<ParsedLine> {
    parse_line_inner(raw, true)
}

fn parse_line_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    // 1. 结构前缀（[HH:MM:SS NNN][module] [thread] 0xADDR: "）由与
    // detect_format/扫描统计共用的规则验证，直接给出反汇编引号位置；
    // 带引号的普通日志行（如 [12:…] "hello"）在这里被拒绝。
    let bytes = raw.as_bytes();
    let q1 = crate::gumtrace::unidbg_instruction_prefix(bytes)?;
    let q2 = memchr(b'"', &bytes[q1 + 1..]).map(|p| q1 + 1 + p)?;
    // SAFETY: trace lines are ASCII (ARM64 disassembly text)
    let disasm = unsafe { std::str::from_utf8_unchecked(&bytes[q1 + 1..q2]) };

    // 2. Split mnemonic and operand text
    let (mnemonic, operand_text) = match disasm.find(' ') {
        Some(pos) => (&disasm[..pos], disasm[pos + 1..].trim()),
        None => (disasm, ""),
    };

    // Reject empty mnemonic (e.g., from `""` in trace)
    if mnemonic.is_empty() {
        return None;
    }

    // 3. Parse operand list (searches only within operand_text — no full-line scan)
    let mut result_line = ParsedLine::default();
    let parsed_first_reg_prefix = parse_operands_into(operand_text, &mut result_line);
    let raw_first_reg_prefix = if is_exclusive_store(mnemonic) {
        first_memory_data_reg_name(mnemonic, operand_text)
            .and_then(|name| name.as_bytes().first().copied())
    } else {
        parsed_first_reg_prefix
    };

    // 4. Find arrow — search only from quote2 onward (not from line start)
    let tail = &bytes[q2..];
    let arrow_rel = memmem::find(tail, b" => ");
    let has_arrow = arrow_rel.is_some();

    let (pre_arrow_regs, post_arrow_regs);
    if extract_regs {
        if let Some(rel) = arrow_rel {
            let arrow_abs = q2 + rel;
            pre_arrow_regs = Some(Box::new(extract_reg_values(&raw[..arrow_abs])));
            post_arrow_regs = Some(Box::new(extract_reg_values(&raw[arrow_abs + 4..])));
        } else {
            pre_arrow_regs = Some(Box::new(extract_reg_values(raw)));
            post_arrow_regs = Some(Box::new(SmallVec::new()));
        }
    } else {
        pre_arrow_regs = None;
        post_arrow_regs = None;
    }

    // 5. Parse mem[READ/WRITE] — search from quote2 onward (mem always appears after disasm)
    let mem_op = find_mem_op_raw(bytes, q2).map(|(is_write, abs)| {
        let layout = classify_mem_layout(mnemonic, operand_text);
        let mut elem_width = if layout == MemLayout::Atomic {
            atomic_elem_width(mnemonic, raw_first_reg_prefix)
        } else {
            determine_elem_width(mnemonic, raw_first_reg_prefix)
        };
        // 5a. 修正 elem_width：lane load 用 lane 元素宽度，SIMD 向量用排列说明符宽度
        if let (Some(_), Some(lew)) = (result_line.lane_index, result_line.lane_elem_width) {
            elem_width = lew;
        } else if matches!(
            mnemonic,
            "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4"
        ) {
            if let Some(arr_width) = simd_arrangement_total_width(operand_text) {
                elem_width = arr_width;
            }
        }
        // 寄存器值搜索起始位置
        let search_start = if is_write {
            Some(q2)
        } else {
            arrow_rel.map(|rel| q2 + rel + 4)
        };
        // 5b. Extract first register value
        let (value, value_lo, value_hi) = if elem_width <= 8 {
            let v = first_memory_data_reg_name(mnemonic, operand_text).and_then(|reg_name| {
                // store 侧零寄存器是已知零；load 侧目标被丢弃，证明不了内存为零。
                if reg_name == "xzr" || reg_name == "wzr" {
                    return if is_write { Some(0) } else { None };
                }
                let ss = search_start?;
                if is_simd_reg_name(reg_name) {
                    // SIMD 寄存器：先尝试 q 前缀再回退原名，解析 u128 后提取位域
                    let full = find_simd_reg_u128(bytes, reg_name, ss)?;
                    extract_simd_lane_value(full, elem_width, result_line.lane_index)
                } else {
                    let raw_val = find_reg_value(bytes, reg_name.as_bytes(), ss)?;
                    let mask = if elem_width >= 8 {
                        u64::MAX
                    } else {
                        (1u64 << (elem_width as u32 * 8)) - 1
                    };
                    Some(raw_val & mask)
                }
            });
            (v, None, None)
        } else if elem_width == 16 {
            // 128-bit SIMD: 用 u128 解析后拆为 low/high 两个 u64
            let v128 = first_memory_data_reg_name(mnemonic, operand_text)
                .and_then(|reg_name| find_simd_reg_u128(bytes, reg_name, search_start?));
            match v128 {
                Some(val) => (None, Some(val as u64), Some((val >> 64) as u64)),
                None => (None, None, None),
            }
        } else {
            (None, None, None)
        };
        // Pair / multi-register SIMD：提取第二个寄存器的值
        let (value2, value2_lo, value2_hi) = if is_pair_mnemonic(mnemonic)
            || is_simd_multi_reg(mnemonic, operand_text)
        {
            if elem_width <= 8 {
                let v2 = second_memory_data_reg_name(mnemonic, operand_text).and_then(|reg_name| {
                    // store 侧零寄存器是已知零；load 侧目标被丢弃，证明不了内存为零。
                    if reg_name == "xzr" || reg_name == "wzr" {
                        return if is_write { Some(0) } else { None };
                    }
                    let ss = search_start?;
                    if is_simd_reg_name(reg_name) {
                        let full = find_simd_reg_u128(bytes, reg_name, ss)?;
                        extract_simd_lane_value(full, elem_width, None)
                    } else {
                        let raw_val = find_reg_value(bytes, reg_name.as_bytes(), ss)?;
                        let mask = if elem_width >= 8 {
                            u64::MAX
                        } else {
                            (1u64 << (elem_width as u32 * 8)) - 1
                        };
                        Some(raw_val & mask)
                    }
                });
                (v2, None, None)
            } else if elem_width == 16 {
                let v128 = second_memory_data_reg_name(mnemonic, operand_text)
                    .and_then(|reg_name| find_simd_reg_u128(bytes, reg_name, search_start?));
                match v128 {
                    Some(val) => (None, Some(val as u64), Some((val >> 64) as u64)),
                    None => (None, None, None),
                }
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };
        let value_count = memory_value_count(mnemonic, operand_text);
        // SIMD structure 指令的 replay 需要每个寄存器的完整 128-bit 值；
        // 既有 value/value2 字段的 lane 截取语义保持不变，供依赖分析使用。
        let (simd_values, simd_reg_bytes, simd_elem_bytes) = if matches!(
            layout,
            MemLayout::SimdContiguous | MemLayout::SimdInterleaved | MemLayout::SimdLane
        ) {
            let mut values = [None; 4];
            if let Some(ss) = search_start {
                for (index, slot) in values.iter_mut().enumerate().take(usize::from(value_count)) {
                    if let Some(name) = memory_data_reg_name_at(mnemonic, operand_text, index) {
                        *slot = find_simd_reg_u128(bytes, name, ss);
                    }
                }
            }
            (
                values,
                simd_arrangement_total_width(operand_text).unwrap_or(0),
                simd_arrangement_element_width(operand_text).unwrap_or(0),
            )
        } else {
            ([None; 4], 0, 0)
        };
        let exclusive_status = if matches!(
            layout,
            MemLayout::ExclusiveScalar | MemLayout::ExclusivePair
        ) {
            // exclusive store 是否真正写入由状态寄存器的 post-arrow 值决定：
            // 0 成功，非 0 失败（无内存效果），缺失则状态未知。
            // pre-arrow 的陈旧值和 wzr（写入被丢弃）都不能当状态。
            let post_start = arrow_rel.map(|rel| q2 + rel + 4);
            data_reg_name_at(operand_text, 0).and_then(|name| {
                if name == "xzr" || name == "wzr" {
                    return None;
                }
                find_reg_value(bytes, name.as_bytes(), post_start?)
            })
        } else {
            None
        };
        MemOp {
            is_write,
            abs,
            elem_width,
            value,
            value2,
            value_lo,
            value_hi,
            value2_lo,
            value2_hi,
            value_count,
            layout,
            simd_values,
            simd_reg_bytes,
            simd_elem_bytes,
            simd_lane: result_line.lane_index.unwrap_or(0),
            exclusive_status,
        }
    });

    // 6. Detect writeback (searches only operand_text — no full-line scan)
    let op_bytes = operand_text.as_bytes();
    let writeback = memchr(b'!', op_bytes).is_some() || memmem::find(op_bytes, b"], #").is_some();

    result_line.mnemonic = Mnemonic::new(mnemonic);
    result_line.mem_op = mem_op;
    result_line.has_arrow = has_arrow;
    result_line.arrow_pos = arrow_rel.map(|rel| q2 + rel);
    result_line.writeback = writeback;
    result_line.pre_arrow_regs = pre_arrow_regs;
    result_line.post_arrow_regs = post_arrow_regs;

    Some(result_line)
}
