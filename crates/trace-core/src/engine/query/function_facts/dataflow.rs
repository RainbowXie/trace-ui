//! producer→consumer 相关读写机械查询：按既有依赖图从输出反向闭包筛选
//! 影响目标的读取；写入按字节粒度追踪最终贡献者。

use std::collections::{BTreeMap, HashSet};

use crate::api_types::{FunctionFactUnresolvedDto, FunctionMemoryFactDto};

use super::super::super::super::scanner::CONTROL_DEP_BIT;
use super::blocks::OwnedInsn;
use super::lines::{
    access_width, arrow_register_value, exclusive_store_outcome, is_pair_access,
    line_mem_annotation, little_endian_hex, prestate_register_value, ExclusiveStoreOutcome,
};

/// 宽度未知写入的保守阻断半径：SIMD 多寄存器 store（st4 {v0-v3}）是
/// arm64 最大单条访存（64 字节）。这是 ISA 机械事实而非对合法数据的
/// 领域上限——只约束内部数据流的排除范围。
const UNKNOWN_WRITE_WIDTH: u32 = 64;

/// 影响目标的读取集合：从输出（返回值生产者 + 最终写入者）沿依赖图
/// （deps.row = 消费者→生产者）反向闭包，只走本 Activation 窗口内的
/// 边——窗口外的生产者是外部输入（caller 提供），不属于本次调用的
/// 内部数据流。控制依赖边（CONTROL_DEP_BIT 标记）同样计入：控制了
/// 输出路径的读取也是影响目标的读取。
pub(super) fn relevant_seqs(
    state: &crate::session::SessionState,
    owned: &[OwnedInsn],
    return_producer: Option<u32>,
    write_winners: &[u32],
) -> HashSet<u32> {
    let mut relevant: HashSet<u32> = HashSet::new();
    let Some(deps) = state.deps_view() else {
        // 依赖索引缺失时不能声称任何读取相关——全部按不可判定处理，
        // 由调用方决定（读集合为空 + 不产生半吊子筛选结果）。
        return relevant;
    };
    let lower = owned.first().map(|insn| insn.seq).unwrap_or(0);
    let upper = owned.last().map(|insn| insn.seq + 1).unwrap_or(0);
    let mut stack: Vec<u32> = Vec::new();
    if let Some(seq) = return_producer {
        if seq >= lower && seq < upper {
            relevant.insert(seq);
            stack.push(seq);
        }
    }
    for winner in write_winners {
        if *winner >= lower && *winner < upper {
            relevant.insert(*winner);
            stack.push(*winner);
        }
    }
    while let Some(seq) = stack.pop() {
        for producer in deps.row(seq as usize) {
            let producer = producer & !CONTROL_DEP_BIT;
            if producer >= lower && producer < upper && relevant.insert(producer) {
                stack.push(producer);
            }
        }
    }
    relevant
}

/// 一条写入的机械结果。
enum WriteEffect {
    /// 失败的独占写：无内存效果，不参与任何追踪。
    None,
    /// 真实写入：宽度 + 值（pair/未知值 → None）。
    Applied { size: u32, value: Option<u64> },
    /// 宽度/成败未知：保守阻断重叠读取，不进输出。
    BlockOnly { size: u32 },
}

fn write_effect(insn: &OwnedInsn, mnemonic: &str, operand: &str) -> Option<WriteEffect> {
    let address = line_mem_annotation(&insn.line, "mem_w")?;
    let _ = address;
    // 独占 STORE：状态寄存器定成败；成功时值取数据寄存器（第二个操作数）
    // prestate，pair 独占写横跨两个寄存器保持 null。
    let effect = match exclusive_store_outcome(&insn.line, mnemonic, operand) {
        Some(ExclusiveStoreOutcome::Failed) => WriteEffect::None,
        Some(ExclusiveStoreOutcome::Succeeded { width, pair }) => {
            let value = if pair {
                None
            } else {
                operand
                    .split(',')
                    .nth(1)
                    .and_then(|register| prestate_register_value(&insn.line, register.trim()))
            };
            WriteEffect::Applied { size: width, value }
        }
        Some(ExclusiveStoreOutcome::Unknown) => WriteEffect::BlockOnly {
            size: UNKNOWN_WRITE_WIDTH,
        },
        None => match access_width(mnemonic, operand) {
            Some(size) => {
                let register = operand.split(',').next().unwrap_or("").trim();
                let value = if size > 8 || is_pair_access(mnemonic) {
                    None
                } else {
                    prestate_register_value(&insn.line, register)
                };
                WriteEffect::Applied { size, value }
            }
            None => WriteEffect::BlockOnly {
                size: UNKNOWN_WRITE_WIDTH,
            },
        },
    };
    Some(effect)
}

/// 字节粒度的最终写入追踪：每个地址记录 (值是否已知, 字节值, 最终生产者)。
/// 相邻、已知性一致的字节在物化时合并为范围；范围 seqs 保留对最终字节
/// 仍有贡献的全部生产者（合同 write_seqs 语义）。
/// 一个待合并的字节区间：起始地址、长度、字节值、是否全部已知、
/// 贡献者 seq 集合。
struct ByteRange {
    start: u64,
    size: u32,
    bytes: Vec<u8>,
    uniform_known: bool,
    seqs: Vec<u32>,
}

#[derive(Default)]
struct FinalByteMap {
    bytes: BTreeMap<u64, (bool, u8, u32)>,
}

impl FinalByteMap {
    fn apply(&mut self, address: u64, size: u32, value: Option<u64>, seq: u32) {
        let le = value.map(|value| value.to_le_bytes());
        for offset in 0..u64::from(size) {
            let slot = self
                .bytes
                .entry(address + offset)
                .or_insert((false, 0, seq));
            let (known, byte, winner) = slot;
            *winner = seq;
            match &le {
                Some(bytes) => {
                    *known = true;
                    *byte = bytes[offset as usize];
                }
                None => *known = false,
            }
        }
    }

    fn materialize(&self) -> Vec<FunctionMemoryFactDto> {
        let mut writes = Vec::new();
        let mut pending: Option<ByteRange> = None;
        for (&address, &(known, byte, winner)) in &self.bytes {
            match &mut pending {
                Some(range) => {
                    if address == range.start + u64::from(range.size)
                        && known == range.uniform_known
                    {
                        range.size += 1;
                        range.bytes.push(byte);
                        if !range.seqs.contains(&winner) {
                            range.seqs.push(winner);
                        }
                    } else {
                        writes.push(Self::emit(pending.take().expect("pending")));
                        pending = Some(ByteRange {
                            start: address,
                            size: 1,
                            bytes: vec![byte],
                            uniform_known: known,
                            seqs: vec![winner],
                        });
                    }
                }
                None => {
                    pending = Some(ByteRange {
                        start: address,
                        size: 1,
                        bytes: vec![byte],
                        uniform_known: known,
                        seqs: vec![winner],
                    });
                }
            }
        }
        if let Some(range) = pending {
            writes.push(Self::emit(range));
        }
        writes
    }

    fn emit(range: ByteRange) -> FunctionMemoryFactDto {
        let ByteRange {
            start,
            size,
            bytes,
            uniform_known,
            seqs,
        } = range;
        FunctionMemoryFactDto {
            address: format!("0x{start:x}"),
            size,
            // 范围内字节全部已知才产出 bytes；含未知字节的范围整体 null，
            // 不用部分字节冒充完整内容。
            bytes: (uniform_known)
                .then(|| bytes.iter().map(|byte| format!("{byte:02x}")).collect()),
            seqs,
        }
    }
}

/// 影响目标的相关读写与未覆盖访存缺口。
///
/// - 写入：字节粒度最终贡献（部分覆盖按字节拆分/合并），全部写入都是
///   调用方可观察输出，因此都进入 write_winners 并作为闭包种子；
/// - 读取：无更早本调用写入（外部来源）且属于影响目标闭包才进入；
/// - 已确认为栈参数的槽不重复进入 memory_reads；
/// - 影响目标但宽度未覆盖的访存产生 unsupported_instruction unresolved，
///   不得「空 reads + 空 unresolved」静默消失。
pub(super) fn collect_memory_facts(
    state: &crate::session::SessionState,
    owned: &[OwnedInsn],
    stack_slots: &HashSet<(u64, u32)>,
    return_producer: Option<u32>,
) -> (
    Vec<FunctionMemoryFactDto>,
    Vec<FunctionMemoryFactDto>,
    Vec<FunctionFactUnresolvedDto>,
) {
    let mut blocked: Vec<(u64, u32)> = Vec::new();
    let mut final_bytes = FinalByteMap::default();
    let mut write_winners: Vec<u32> = Vec::new();
    for insn in owned {
        let Some((mnemonic, operand)) = insn.mnemonic.as_deref().zip(insn.first_operand.as_deref())
        else {
            continue;
        };
        if let Some(address) = line_mem_annotation(&insn.line, "mem_w") {
            match write_effect(insn, mnemonic, operand) {
                Some(WriteEffect::None) => continue,
                Some(WriteEffect::Applied { size, value }) => {
                    final_bytes.apply(address, size, value, insn.seq);
                    write_winners.push(insn.seq);
                    blocked.push((address, size));
                    continue;
                }
                Some(WriteEffect::BlockOnly { size }) => {
                    blocked.push((address, size));
                    continue;
                }
                None => continue,
            }
        }
    }
    let relevant = relevant_seqs(state, owned, return_producer, &write_winners);

    let mut reads: BTreeMap<(u64, u32), (Option<u64>, Vec<u32>)> = BTreeMap::new();
    let mut unresolved: Vec<FunctionFactUnresolvedDto> = Vec::new();
    for insn in owned {
        let Some((mnemonic, operand)) = insn.mnemonic.as_deref().zip(insn.first_operand.as_deref())
        else {
            continue;
        };
        let Some(address) = line_mem_annotation(&insn.line, "mem_r") else {
            continue;
        };
        let size = match access_width(mnemonic, operand) {
            Some(size) => size,
            None => {
                // 宽度未覆盖：影响目标时必须留下结构化缺口，不得静默丢弃。
                if relevant.contains(&insn.seq) {
                    unresolved.push(FunctionFactUnresolvedDto {
                        kind: "unsupported_instruction".to_string(),
                        seqs: vec![insn.seq],
                        location: Some(format!("0x{address:x}")),
                        detail: format!("{mnemonic} 访存宽度未覆盖，无法产出读取事实"),
                    });
                }
                continue;
            }
        };
        let internally_produced = blocked.iter().any(|(waddress, wsize)| {
            *waddress < address + u64::from(size) && address < *waddress + u64::from(*wsize)
        });
        if internally_produced {
            continue;
        }
        let register = operand.split(',').next().unwrap_or("").trim();
        let value = if size > 8 || is_pair_access(mnemonic) {
            None
        } else {
            arrow_register_value(&insn.line, register)
        };
        let slot = reads.entry((address, size)).or_insert((value, Vec::new()));
        if slot.0.is_none() {
            slot.0 = value;
        }
        slot.1.push(insn.seq);
    }
    let memory_reads = reads
        .into_iter()
        .filter(|((address, size), (_, seqs))| {
            !stack_slots.contains(&(*address, *size))
                && seqs.iter().any(|seq| relevant.contains(seq))
        })
        .map(|((address, size), (value, seqs))| FunctionMemoryFactDto {
            address: format!("0x{address:x}"),
            size,
            bytes: value.map(|value| little_endian_hex(value, size)),
            seqs,
        })
        .collect();
    (memory_reads, final_bytes.materialize(), unresolved)
}
