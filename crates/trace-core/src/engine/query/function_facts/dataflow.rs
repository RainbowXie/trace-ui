//! producer→consumer 相关读写机械查询。

use std::collections::{BTreeMap, HashSet};

use crate::api_types::FunctionMemoryFactDto;

use super::blocks::OwnedInsn;
use super::lines::{
    access_width, arrow_register_value, line_mem_annotation, little_endian_hex,
    prestate_register_value,
};

/// producer→consumer 机械事实：
/// - 写入：owned 指令的 mem_w 按 (address,size) 聚合，bytes 取最终一次
///   写入的源寄存器 pre-state（小端），seqs 保留全部生产者；
/// - 读取：同一地址在本 Activation 内没有更早写入（外部来源）才进入；
///   bytes 取首次读取的目标寄存器值；已确认为栈参数的槽不重复进入
///   memory_reads（abi.stack_arguments 是它们的正式位置）；
/// - 写后读属内部数据流，两表都不进入。
pub(super) fn collect_memory_facts(
    owned: &[OwnedInsn],
    stack_slots: &HashSet<(u64, u32)>,
) -> (Vec<FunctionMemoryFactDto>, Vec<FunctionMemoryFactDto>) {
    #[derive(Default)]
    struct Slot {
        seqs: Vec<u32>,
        /// 最终写入值（写侧）/首次读取值（读侧）。
        value: Option<u64>,
        value_seq: u32,
    }
    let mut writes: BTreeMap<(u64, u32), Slot> = Default::default();
    let mut reads: BTreeMap<(u64, u32), Slot> = Default::default();
    let mut written_ranges: Vec<(u64, u32)> = Vec::new();
    for insn in owned {
        let Some((mnemonic, operand)) = insn.mnemonic.as_deref().zip(insn.first_operand.as_deref())
        else {
            continue;
        };
        let register = operand.split(',').next().unwrap_or("").trim();
        if let Some(address) = line_mem_annotation(&insn.line, "mem_w") {
            if let Some(size) = access_width(mnemonic, operand) {
                let value = prestate_register_value(&insn.line, register);
                let slot = writes.entry((address, size)).or_default();
                if slot.value.is_none() || insn.seq >= slot.value_seq {
                    slot.value = value;
                    slot.value_seq = insn.seq;
                }
                slot.seqs.push(insn.seq);
                written_ranges.push((address, size));
                continue;
            }
        }
        if let Some(address) = line_mem_annotation(&insn.line, "mem_r") {
            if let Some(size) = access_width(mnemonic, operand) {
                let internally_produced = written_ranges.iter().any(|(waddress, wsize)| {
                    *waddress < address + u64::from(size) && address < *waddress + u64::from(*wsize)
                });
                if !internally_produced {
                    let value = arrow_register_value(&insn.line, register);
                    let slot = reads.entry((address, size)).or_default();
                    if slot.value.is_none() {
                        slot.value = value;
                        slot.value_seq = insn.seq;
                    }
                    slot.seqs.push(insn.seq);
                }
            }
        }
    }
    let materialize = |map: BTreeMap<(u64, u32), Slot>| {
        map.into_iter()
            .map(|((address, size), slot)| FunctionMemoryFactDto {
                address: format!("0x{address:x}"),
                size,
                bytes: slot.value.map(|value| little_endian_hex(value, size)),
                seqs: slot.seqs,
            })
            .collect::<Vec<_>>()
    };
    let reads = reads
        .into_iter()
        .filter(|((address, size), _)| !stack_slots.contains(&(*address, *size)))
        .collect();
    (materialize(reads), materialize(writes))
}
