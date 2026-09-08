//! 栈参数三门合同的机械侧（ABI 位置 + entry SP + 实际读取）。

use std::collections::BTreeMap;

use crate::api_types::FunctionStackArgumentDto;

use super::blocks::OwnedInsn;
use super::lines::{access_width, arrow_register_value, base_register, line_mem_annotation};

/// 栈参数三门合同的机械侧：entry SP 及之上、SP/FP 基址寻址、本次实际
/// 读取、宽度可确认的单寄存器载荷。首次读取前被写回的槽保留读取证据
/// 但 value 为 null；多次读取合并 read_seqs；不确定值保持 null，不以
/// 零值或写后值补齐。
pub(super) fn collect_stack_arguments(
    owned: &[OwnedInsn],
    entry_sp: u64,
) -> Vec<FunctionStackArgumentDto> {
    // 写入追踪：宽度可解析的写按精确区间记录；宽度未知（向量/未覆盖助记符）
    // 的写按 UNKNOWN_WRITE_WIDTH 记录——任何与其重叠的读取都必须视为可能
    // 内产，value 置 null，不能把 callee 自己 spill 的值伪造成入口栈参数。
    const UNKNOWN_WRITE_WIDTH: u32 = 64; // SIMD 多寄存器 store（st4 {v0-v3}）最大单条访存
    let mut writes: Vec<(u64, u32, u32)> = Vec::new();
    for insn in owned {
        if let (Some(address), Some(mnemonic), Some(operand)) = (
            line_mem_annotation(&insn.line, "mem_w"),
            insn.mnemonic.as_deref(),
            insn.first_operand.as_deref(),
        ) {
            let size = access_width(mnemonic, operand).unwrap_or(UNKNOWN_WRITE_WIDTH);
            writes.push((address, size, insn.seq));
        }
    }
    let mut slots: BTreeMap<(u64, u32), (Option<u64>, Vec<u32>)> = BTreeMap::new();
    for insn in owned {
        let Some(address) = line_mem_annotation(&insn.line, "mem_r") else {
            continue;
        };
        // ABI 位置的机械证据：SP/FP 相对寻址才可能是 caller 栈参数区；
        // 其他基址（堆/数据指针）不属于栈参数，交给 memory facts。
        if address < entry_sp {
            continue;
        }
        let base_is_stack = insn
            .first_operand
            .as_deref()
            .and_then(base_register)
            .is_some_and(|base| base == "sp" || base == "fp");
        if !base_is_stack {
            continue;
        }
        let Some((mnemonic, operand)) = insn.mnemonic.as_deref().zip(insn.first_operand.as_deref())
        else {
            continue;
        };
        let Some(size) = access_width(mnemonic, operand) else {
            continue;
        };
        let written_before = writes.iter().any(|(waddress, wsize, wseq)| {
            *wseq < insn.seq
                && *waddress < address + u64::from(size)
                && address < *waddress + u64::from(*wsize)
        });
        let value = if written_before || size > 8 {
            // pair 读（ldp）横跨两个寄存器，单箭头值只覆盖一半——保持 null，
            // 与 dataflow 的守卫一致。
            None
        } else {
            insn.first_operand
                .as_deref()
                .and_then(|operand| operand.split(',').next())
                .and_then(|register| arrow_register_value(&insn.line, register.trim()))
        };
        let slot = slots
            .entry((address - entry_sp, size))
            .or_insert((value, Vec::new()));
        if slot.0.is_none() && value.is_some() {
            slot.0 = value;
        }
        slot.1.push(insn.seq);
    }
    slots
        .into_iter()
        .map(
            |((offset, size), (value, read_seqs))| FunctionStackArgumentDto {
                offset: offset as i64,
                size,
                value: value.map(|value| format!("0x{value:016x}")),
                read_seqs,
            },
        )
        .collect()
}
