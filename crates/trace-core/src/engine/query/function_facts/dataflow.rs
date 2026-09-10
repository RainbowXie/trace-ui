//! producer→consumer 相关读写机械查询：按既有依赖图从输出反向闭包筛选
//! 影响目标的读取；写入按字节粒度追踪最终贡献者。

use std::collections::{BTreeMap, HashSet};

use crate::api_types::{FunctionFactUnresolvedDto, FunctionMemoryReadDto, FunctionMemoryWriteDto};

use super::blocks::OwnedInsn;
use super::lines::{
    access_width, arrow_register_value, exclusive_store_outcome, is_pair_access,
    line_mem_annotation, prestate_register_value, ExclusiveStoreOutcome,
};
use crate::scanner::LINE_MASK;
use crate::utils::checked_mem_addr;

/// 宽度未知写入的保守阻断半径：SIMD 多寄存器 store（st4 {v0-v3}）是
/// arm64 最大单条访存（64 字节）。这是 ISA 机械事实而非对合法数据的
/// 领域上限——只约束内部数据流的排除范围。
const UNKNOWN_WRITE_WIDTH: u32 = 64;

/// 影响目标的读取集合：从输出（返回值生产者 + 最终写入者）沿依赖图
/// （deps.row = 消费者→生产者）反向闭包，只走本 Activation 窗口内的
/// 边——窗口外的生产者是外部输入（caller 提供），不属于本次调用的
/// 内部数据流。控制依赖边（CONTROL_DEP_BIT 标记）同样计入：控制了
/// 输出路径的读取也是影响目标的读取。
/// Some(闭包) = 依赖索引可用，相关性可判定；None = 依赖索引缺失，
/// 相关性不可判定（调用方必须把未覆盖访存全部转 unresolved，不得
/// 假装「与目标无关」而静默丢弃）。
pub(super) fn relevant_seqs(
    state: &crate::session::SessionState,
    owned: &[OwnedInsn],
    return_producer: Option<u32>,
    write_winners: &[u32],
) -> Option<HashSet<u32>> {
    let mut relevant: HashSet<u32> = HashSet::new();
    let deps = state.deps_view()?;
    let pair_split = state.pair_split_view();
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
        // 普通行：deps.row 给出全部生产者（寄存器 def / mem store def /
        // 控制依赖，高位带标记）。行内 seq 用 scanner 的 LINE_MASK 剥离
        // 标记位（控制依赖 bit29 / pair 半区 bit31 / 共享路径 bit30）。
        for producer in deps
            .row(seq as usize)
            .iter()
            .chain(deps.patch_row(seq as usize).iter())
        {
            let producer = producer & LINE_MASK;
            if producer >= lower && producer < upper && relevant.insert(producer) {
                stack.push(producer);
            }
        }
        // 成对访存的依赖在 pair_split（deps.row 对 pair 行恒空）：沿
        // shared/half1/half2 三条切片继续向上，否则 spill 链上游的读取
        // 会被静默漏掉。
        if let Some(split) = pair_split.as_ref().and_then(|view| view.get(&seq)) {
            for producer in split
                .shared
                .iter()
                .chain(split.half1_deps.iter())
                .chain(split.half2_deps.iter())
            {
                let producer = producer & LINE_MASK;
                if producer >= lower && producer < upper && relevant.insert(producer) {
                    stack.push(producer);
                }
            }
        }
    }
    Some(relevant)
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
/// 相邻且已知性一致的字节在物化时合并；未知范围还必须 winner 相同才合并——
/// 否则 gumtrace 只能对整段取 max(last_write)，中间时点 capture 无法只补已完成字节（ISSUE-H9）。
/// 已知范围可跨 winner 合并：最终字节已由 trace 确定，capture 只作核对，不再需要逐字节时点。
struct ByteRange {
    start: u64,
    size: u32,
    bytes: Vec<u8>,
    uniform_known: bool,
    last_winner: u32,
    seqs: Vec<u32>,
}

#[derive(Default)]
struct FinalByteMap {
    bytes: BTreeMap<u64, (bool, u8, u32)>,
}

impl FinalByteMap {
    fn apply(&mut self, address: u64, size: u32, value: Option<u64>, seq: u32) -> bool {
        // 无法形成完整半开范围时整条放弃，禁止把已写下的前缀当成 known write（ISSUE-H15）。
        if size == 0 {
            return false;
        }
        if checked_mem_addr(address, u64::from(size) - 1).is_none() {
            return false;
        }
        let le = value.map(|value| value.to_le_bytes());
        for offset in 0..u64::from(size) {
            let byte_addr = address + offset;
            let slot = self.bytes.entry(byte_addr).or_insert((false, 0, seq));
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
        true
    }

    fn materialize(&self) -> Vec<FunctionMemoryWriteDto> {
        let mut writes = Vec::new();
        let mut pending: Option<ByteRange> = None;
        for (&address, &(known, byte, winner)) in &self.bytes {
            match &mut pending {
                Some(range) => {
                    let contiguous = checked_mem_addr(range.start, u64::from(range.size))
                        == Some(address)
                        && known == range.uniform_known;
                    // 未知范围按最终写入者拆段；已知范围可跨 winner 合并。
                    let same_owner = known || winner == range.last_winner;
                    if contiguous && same_owner {
                        range.size += 1;
                        range.bytes.push(byte);
                        range.last_winner = winner;
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
                            last_winner: winner,
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
                        last_winner: winner,
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

    fn emit(range: ByteRange) -> FunctionMemoryWriteDto {
        let ByteRange {
            start,
            size,
            bytes,
            uniform_known,
            last_winner: _,
            seqs,
        } = range;
        FunctionMemoryWriteDto {
            address: format!("0x{start:x}"),
            size,
            // 范围内字节全部已知才产出 bytes；含未知字节的范围整体 null，
            // 不用部分字节冒充完整内容。
            bytes: (uniform_known)
                .then(|| bytes.iter().map(|byte| format!("{byte:02x}")).collect()),
            write_seqs: seqs,
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
    Vec<FunctionMemoryReadDto>,
    Vec<FunctionMemoryWriteDto>,
    Vec<FunctionFactUnresolvedDto>,
) {
    // (address, size, seq)：只有更早的重叠写才算本调用内部生产（ISSUE-H10）。
    let mut blocked: Vec<(u64, u32, u32)> = Vec::new();
    let mut final_bytes = FinalByteMap::default();
    let mut write_winners: Vec<u32> = Vec::new();
    let mut write_unresolved: Vec<FunctionFactUnresolvedDto> = Vec::new();
    for insn in owned {
        let Some((mnemonic, operand)) = insn.mnemonic.as_deref().zip(insn.first_operand.as_deref())
        else {
            continue;
        };
        if let Some(address) = line_mem_annotation(&insn.line, "mem_w") {
            match write_effect(insn, mnemonic, operand) {
                Some(WriteEffect::None) => continue,
                Some(WriteEffect::Applied { size, value }) => {
                    if final_bytes.apply(address, size, value, insn.seq) {
                        write_winners.push(insn.seq);
                        blocked.push((address, size, insn.seq));
                    } else {
                        // 无法 emit known write，但仍按声明宽度挡住后续短读（ISSUE-H16）。
                        blocked.push((address, size, insn.seq));
                        write_unresolved.push(FunctionFactUnresolvedDto {
                            kind: "unsupported_instruction".to_string(),
                            seqs: vec![insn.seq],
                            location: Some(format!("0x{address:x}")),
                            detail: format!("{mnemonic} 写入访存地址加宽度溢出，拒绝该写入事实"),
                        });
                    }
                    continue;
                }
                Some(WriteEffect::BlockOnly { size }) => {
                    blocked.push((address, size, insn.seq));
                    write_unresolved.push(FunctionFactUnresolvedDto {
                        kind: "unsupported_instruction".to_string(),
                        seqs: vec![insn.seq],
                        location: Some(format!("0x{address:x}")),
                        detail: format!(
                            "{mnemonic} 写入访存宽度未覆盖，已保守阻断后续读取并记录缺口"
                        ),
                    });
                    continue;
                }
                None => continue,
            }
        }
    }
    let relevant = relevant_seqs(state, owned, return_producer, &write_winners);
    // 相关性可判定时，未覆盖的「影响目标」读取才转 unresolved；依赖索引
    // 缺失（None）时全部未覆盖访存都保留为 unresolved——不能因索引缺失
    // 把缺口伪装成「与目标无关」。
    let is_relevant = |seq: u32| match &relevant {
        Some(set) => set.contains(&seq),
        None => true,
    };

    let mut observations: Vec<FunctionMemoryReadDto> = Vec::new();
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
                if is_relevant(insn.seq) {
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
        if !is_relevant(insn.seq) {
            continue;
        }
        if stack_slots.contains(&(address, size)) {
            continue;
        }
        let register = operand.split(',').next().unwrap_or("").trim();
        let value = if size > 8 || is_pair_access(mnemonic) {
            None
        } else {
            arrow_register_value(&insn.line, register)
        };
        observations.extend(external_read_ranges(
            address,
            size,
            insn.seq,
            value,
            &blocked,
            &mut unresolved,
        ));
    }
    let memory_reads = normalize_memory_reads(observations);

    let memory_writes = final_bytes.materialize();

    // 冻结合同要求：任何 bytes = null 的读写记录都必须有对应的 unresolved 证据
    for read in &memory_reads {
        if read.bytes.is_none() {
            unresolved.push(FunctionFactUnresolvedDto {
                kind: "missing_memory_definition".to_string(),
                seqs: read.read_seqs.clone(),
                location: Some(read.address.clone()),
                detail: format!("内存读取 {} 字节值未完全确定", read.address),
            });
        }
    }
    for write in &memory_writes {
        if write.bytes.is_none() {
            unresolved.push(FunctionFactUnresolvedDto {
                kind: "missing_memory_definition".to_string(),
                seqs: write.write_seqs.clone(),
                location: Some(write.address.clone()),
                detail: format!("内存写入 {} 字节值未完全确定", write.address),
            });
        }
    }

    unresolved.extend(write_unresolved);
    (memory_reads, memory_writes, unresolved)
}

fn write_covers_byte(waddress: u64, wsize: u32, byte: u64) -> bool {
    // 用偏移而不是排他终点：完整写到 u64::MAX 时 MAX+1 溢出，不能因此把已写下的字节当成外部。
    if byte < waddress {
        return false;
    }
    byte - waddress < u64::from(wsize)
}

/// ISSUE-H12：按字节判断该读取前是否已有本调用写入。只输出外部来源连续子范围；
/// 无法安全重建外部字节时 bytes 置 null 并留下 unresolved，不得把内部字节标成入口输入。
fn external_read_ranges(
    address: u64,
    size: u32,
    seq: u32,
    value: Option<u64>,
    blocked: &[(u64, u32, u32)],
    unresolved: &mut Vec<FunctionFactUnresolvedDto>,
) -> Vec<FunctionMemoryReadDto> {
    let le = value.map(|value| value.to_le_bytes());
    let mut external: Vec<(u64, Option<u8>)> = Vec::new();
    let mut overflow = false;
    for offset in 0..u64::from(size) {
        let Some(byte) = checked_mem_addr(address, offset) else {
            overflow = true;
            break;
        };
        let internal = blocked.iter().any(|(waddress, wsize, wseq)| {
            *wseq < seq && write_covers_byte(*waddress, *wsize, byte)
        });
        if internal {
            continue;
        }
        let known = le.as_ref().map(|bytes| bytes[offset as usize]);
        external.push((byte, known));
    }
    if overflow {
        unresolved.push(FunctionFactUnresolvedDto {
            kind: "unsupported_instruction".to_string(),
            seqs: vec![seq],
            location: Some(format!("0x{address:x}")),
            detail: "访存地址加宽度溢出，拒绝该读取事实".to_string(),
        });
        return Vec::new();
    }
    if external.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = external[0].0;
    let mut bytes: Vec<Option<u8>> = vec![external[0].1];
    for window in external.windows(2) {
        let (prev, next) = (window[0].0, window[1].0);
        if checked_mem_addr(prev, 1) == Some(next) {
            bytes.push(window[1].1);
            continue;
        }
        ranges.push(emit_external_read(start, &bytes, seq));
        start = next;
        bytes = vec![window[1].1];
    }
    ranges.push(emit_external_read(start, &bytes, seq));
    ranges
}

fn emit_external_read(start: u64, bytes: &[Option<u8>], seq: u32) -> FunctionMemoryReadDto {
    let all_known = bytes.iter().all(Option::is_some);
    FunctionMemoryReadDto {
        address: format!("0x{start:x}"),
        size: bytes.len() as u32,
        bytes: all_known.then(|| {
            bytes
                .iter()
                .map(|byte| format!("{:02x}", byte.expect("known")))
                .collect()
        }),
        read_seqs: vec![seq],
    }
}

/// ISSUE-H13：相同 address/size/bytes 合并 read_seqs；不同动态值压成一条 bytes=null，
/// 并保留不可被单时点 capture 整体补齐的 unresolved。
fn normalize_memory_reads(observations: Vec<FunctionMemoryReadDto>) -> Vec<FunctionMemoryReadDto> {
    let mut by_range: BTreeMap<(u64, u32), Vec<FunctionMemoryReadDto>> = BTreeMap::new();
    for read in observations {
        let Ok(addr) = crate::parse_hex_addr(&read.address) else {
            continue;
        };
        by_range.entry((addr, read.size)).or_default().push(read);
    }
    let mut out = Vec::new();
    for ((addr, size), mut group) in by_range {
        group.sort_by_key(|read| read.read_seqs.first().copied().unwrap_or(0));
        let same_bytes = group.windows(2).all(|pair| pair[0].bytes == pair[1].bytes);
        let mut seqs: Vec<u32> = group
            .iter()
            .flat_map(|read| read.read_seqs.iter().copied())
            .collect();
        seqs.sort_unstable();
        seqs.dedup();
        let bytes = if same_bytes {
            group.first().and_then(|read| read.bytes.clone())
        } else {
            None
        };
        out.push(FunctionMemoryReadDto {
            address: format!("0x{addr:x}"),
            size,
            bytes,
            read_seqs: seqs,
        });
    }
    out
}
