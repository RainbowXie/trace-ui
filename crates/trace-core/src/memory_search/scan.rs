//! 稀疏字节状态与按序扫描：核心 replay 循环与匹配状态转移。

use std::collections::{BTreeSet, HashMap, HashSet};

use trace_parser::{
    gumtrace, parser,
    types::{MemLayout, MemOp, TraceFormat},
};

use super::{
    validate_options, validate_public_response_budget, CachePage, MemoryOccurrence,
    MemorySearchOptions, MemorySearchResult, MemorySearchRw, ANCHOR_SIZE,
};
use crate::error::{Result, TraceError};

#[derive(Clone, Copy)]
pub(crate) struct ByteValue {
    pub(crate) value: u8,
    pub(crate) known: bool,
}

impl ByteValue {
    fn unknown() -> Self {
        Self {
            value: 0,
            known: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct SparseMemory {
    bytes: HashMap<u64, ByteValue>,
}

impl SparseMemory {
    fn get(&self, address: u64) -> ByteValue {
        self.bytes
            .get(&address)
            .copied()
            .unwrap_or_else(ByteValue::unknown)
    }

    pub(crate) fn set(&mut self, address: u64, value: ByteValue) {
        if value.known {
            self.bytes.insert(address, value);
        } else {
            // Keeping explicit unknown entries would only consume memory and
            // has the same observable meaning as an absent sparse byte.
            self.bytes.remove(&address);
        }
    }

    fn matches(&self, address: u64, pattern: &[u8]) -> bool {
        pattern.iter().enumerate().all(|(offset, expected)| {
            let Some(addr) = address.checked_add(offset as u64) else {
                return false;
            };
            let actual = self.get(addr);
            actual.known && actual.value == *expected
        })
    }

    fn anchor_key(&self, address: u64, anchor_len: usize) -> Option<u64> {
        let mut key = 0u64;
        for i in 0..anchor_len {
            let addr = address.checked_add(i as u64)?;
            let byte = self.get(addr);
            if !byte.known {
                return None;
            }
            key |= (byte.value as u64) << (i * 8);
        }
        Some(key)
    }
}

pub(crate) struct SearchState<'a> {
    pub(crate) memory: SparseMemory,
    anchor_len: usize,
    anchor_key: u64,
    /// Starts whose current bytes equal this search's fixed anchor.  Keeping
    /// only the target bucket avoids a map/bucket for every observed value in
    /// a large trace.
    pub(crate) anchor_positions: BTreeSet<u64>,
    active_matches: HashSet<u64>,
    pattern: &'a [u8],
}

impl<'a> SearchState<'a> {
    pub(crate) fn new(pattern: &'a [u8]) -> Self {
        let anchor_len = pattern.len().min(ANCHOR_SIZE);
        let mut anchor_key = 0u64;
        for (i, byte) in pattern[..anchor_len].iter().enumerate() {
            anchor_key |= (*byte as u64) << (i * 8);
        }
        Self {
            memory: SparseMemory::default(),
            anchor_len,
            anchor_key,
            anchor_positions: BTreeSet::new(),
            active_matches: HashSet::new(),
            pattern,
        }
    }

    fn candidate_range(&self, start: u64, size: usize) -> Option<(u64, u64)> {
        let last = start.checked_add(size.checked_sub(1)? as u64)?;
        let back = self.pattern.len().checked_sub(1)? as u64;
        Some((start.saturating_sub(back), last))
    }

    fn collect_candidates(&self, range: (u64, u64), output: &mut BTreeSet<u64>) {
        output.extend(self.anchor_positions.range(range.0..=range.1).copied());
    }

    fn update_anchor_position(&mut self, start: u64) {
        let Some(key) = self.memory.anchor_key(start, self.anchor_len) else {
            self.anchor_positions.remove(&start);
            return;
        };
        if key == self.anchor_key {
            self.anchor_positions.insert(start);
        } else {
            self.anchor_positions.remove(&start);
        }
    }

    pub(crate) fn update_anchor_positions_around(&mut self, address: u64) {
        for delta in 0..self.anchor_len {
            let Some(start) = address.checked_sub(delta as u64) else {
                continue;
            };
            self.update_anchor_position(start);
        }
    }

    // Filters and the occurrence sink travel together through every replay;
    // grouping them into a struct would only obscure the event loop.
    #[allow(clippy::too_many_arguments)]
    fn process_event(
        &mut self,
        address: u64,
        values: &[ByteValue],
        seq: u32,
        rw: MemorySearchRw,
        seq_range: Option<(u32, u32)>,
        memory_range: Option<(u64, u64)>,
        sink: &mut impl FnMut(MemoryOccurrence) -> Result<()>,
    ) -> Result<()> {
        if values.is_empty() {
            return Ok(());
        }
        let mut candidates = BTreeSet::new();
        let Some(range) = self.candidate_range(address, values.len()) else {
            return Err(TraceError::ParseError {
                line: Some(seq),
                detail: "memory access range overflows u64".to_string(),
            });
        };
        // Capture old anchors too, otherwise a changed anchor would make an
        // already-active match impossible to retire.
        self.collect_candidates(range, &mut candidates);

        for (offset, value) in values.iter().copied().enumerate() {
            let byte_address =
                address
                    .checked_add(offset as u64)
                    .ok_or_else(|| TraceError::ParseError {
                        line: Some(seq),
                        detail: "memory access range overflows u64".to_string(),
                    })?;
            // A missing read value means the trace did not expose a new
            // observation; retain any previously known state.  A missing
            // write value is different: the write happened, but its bytes are
            // unknown, so it must invalidate any prior match.
            if value.known || rw == MemorySearchRw::Write {
                self.memory.set(byte_address, value);
            }
            self.update_anchor_positions_around(byte_address);
        }

        self.collect_candidates(range, &mut candidates);
        for start in candidates {
            let is_match = self.memory.matches(start, self.pattern);
            let was_match = self.active_matches.contains(&start);
            if is_match {
                self.active_matches.insert(start);
                if !was_match
                    && seq_range.is_none_or(|(first, last)| seq >= first && seq <= last)
                    && memory_range.is_none_or(|(first, last)| {
                        start >= first
                            && start
                                .checked_add(self.pattern.len() as u64)
                                .is_some_and(|end| end <= last)
                    })
                {
                    sink(MemoryOccurrence {
                        address: start,
                        seq,
                        rw,
                    })?;
                }
            } else {
                self.active_matches.remove(&start);
            }
        }
        Ok(())
    }
}

/// Search raw trace bytes in sequence order.
pub fn search_memory(
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
) -> Result<MemorySearchResult> {
    validate_options(&options)?;
    validate_public_response_budget(&options)?;
    let page = scan_memory_page(data, format, &options)?;
    super::cached::paginate_page(page, &options)
}

pub(crate) fn scan_memory_page(
    data: &[u8],
    format: TraceFormat,
    options: &MemorySearchOptions,
) -> Result<CachePage> {
    let mut page = Vec::new();
    let mut total = 0u64;
    scan_memory_with_sink(data, format, options, |occurrence| {
        let index = total;
        total = total.saturating_add(1);
        let page_end = u64::from(options.offset).saturating_add(u64::from(options.limit));
        if index >= u64::from(options.offset) && index < page_end {
            page.push(occurrence);
        }
        Ok(())
    })?;
    let total = u32::try_from(total)
        .map_err(|_| TraceError::InvalidArgument("too many memory search matches".to_string()))?;
    let end = u64::from(options.offset)
        .saturating_add(u64::from(options.limit))
        .min(u64::from(total));
    Ok(CachePage {
        total,
        matches: page,
        has_more: end < u64::from(total),
    })
}

pub(crate) fn scan_memory_with_sink(
    data: &[u8],
    format: TraceFormat,
    options: &MemorySearchOptions,
    mut sink: impl FnMut(MemoryOccurrence) -> Result<()>,
) -> Result<()> {
    let mut state = SearchState::new(&options.pattern);

    for (seq_index, line_bytes) in data.split(|byte| *byte == b'\n').enumerate() {
        let seq = u32::try_from(seq_index).map_err(|_| TraceError::ParseError {
            line: None,
            detail: "trace contains more than u32::MAX sequence lines".to_string(),
        })?;
        let line_bytes = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
        let Ok(line) = std::str::from_utf8(line_bytes) else {
            return Err(TraceError::ParseError {
                line: Some(seq),
                detail: "trace line is not valid UTF-8".to_string(),
            });
        };
        let contains_memory_event = match format {
            TraceFormat::Unidbg => line_bytes.windows(4).any(|window| window == b"mem["),
            TraceFormat::Gumtrace => line_bytes
                .windows(6)
                .any(|window| window == b"mem_w=" || window == b"mem_r="),
        };
        let parsed = match format {
            TraceFormat::Unidbg => parser::parse_line(line),
            TraceFormat::Gumtrace => gumtrace::parse_line_gumtrace(line),
        };
        let Some(parsed) = parsed else {
            if contains_memory_event {
                return Err(TraceError::ParseError {
                    line: Some(seq),
                    detail: "malformed memory event".to_string(),
                });
            }
            continue;
        };
        let Some(mem) = parsed.mem_op.as_ref() else {
            if contains_memory_event {
                return Err(TraceError::ParseError {
                    line: Some(seq),
                    detail: "malformed memory event".to_string(),
                });
            }
            continue;
        };
        let rw = if mem.is_write {
            MemorySearchRw::Write
        } else {
            MemorySearchRw::Read
        };
        let values = expand_mem_op(mem);
        state.process_event(
            mem.abs,
            &values,
            seq,
            rw,
            options.seq_range,
            options.memory_range,
            &mut sink,
        )?;
    }
    Ok(())
}

// ── MemOp 字节展开 ──

fn expand_mem_op(mem: &MemOp) -> Vec<ByteValue> {
    match mem.layout {
        // atomic/RMW 的最终字节是旧值与寄存器的运算结果，trace 注解不足以精确
        // 恢复：write 使整个访问范围失效，read 不覆盖已有已知值（两者都表现
        // 为全部 unknown）。
        MemLayout::Atomic => {
            let mut result = Vec::new();
            append_unknown(&mut result, mem.elem_width);
            result
        }
        // exclusive store 是否真正写入由状态寄存器决定：失败（非 0）对内存
        // 没有任何影响（不写字节也不失效）；状态未知时保守失效整个范围。
        MemLayout::ExclusiveScalar | MemLayout::ExclusivePair => match mem.exclusive_status {
            Some(0) => expand_scalar_or_pair(mem),
            Some(_) => Vec::new(),
            None => {
                let mut result = Vec::new();
                for _ in 0..mem.value_count.max(1) {
                    append_unknown(&mut result, mem.elem_width);
                }
                result
            }
        },
        // 单 lane structure / replicate load：每个寄存器只贡献一个元素。
        // replicate 的注解值在所有 lane 相同，lane 0 即内存字节。
        MemLayout::SimdLane => {
            let mut result = Vec::new();
            let elem = usize::from(mem.simd_elem_bytes);
            if elem == 0 {
                // 元素宽度不可得时不得猜：整个访问范围 unknown。
                for _ in 0..mem.value_count.max(1) {
                    append_unknown(&mut result, mem.elem_width);
                }
                return result;
            }
            for slot in 0..usize::from(mem.value_count) {
                append_simd_lane(
                    &mut result,
                    mem.simd_values[slot],
                    usize::from(mem.simd_lane) * elem,
                    elem,
                );
            }
            result
        }
        // 多寄存器 st1/ld1：每个寄存器的内容连续摆放。
        MemLayout::SimdContiguous => {
            let mut result = Vec::new();
            for slot in 0..usize::from(mem.value_count) {
                append_simd_reg(&mut result, mem.simd_values[slot], mem.simd_reg_bytes);
            }
            result
        }
        // st2-st4/ld2-ld4：同一 lane 的各寄存器元素相邻，按 lane 交错。
        MemLayout::SimdInterleaved => {
            let mut result = Vec::new();
            let reg_bytes = usize::from(mem.simd_reg_bytes);
            let elem = usize::from(mem.simd_elem_bytes);
            if reg_bytes == 0 || elem == 0 || elem > reg_bytes {
                // 排列信息不完整时不得猜布局：整个访问范围 unknown。
                append_unknown(&mut result, mem.elem_width);
                for _ in 1..mem.value_count {
                    append_unknown(&mut result, mem.elem_width);
                }
                return result;
            }
            let count = usize::from(mem.value_count);
            for lane in 0..(reg_bytes / elem) {
                for slot in 0..count {
                    append_simd_lane(&mut result, mem.simd_values[slot], lane * elem, elem);
                }
            }
            result
        }
        _ => expand_scalar_or_pair(mem),
    }
}

fn expand_scalar_or_pair(mem: &MemOp) -> Vec<ByteValue> {
    let mut result = Vec::new();
    if mem.elem_width <= 8 {
        append_scalar(&mut result, mem.elem_width, mem.value);
    } else {
        // 128-bit values use lo/hi instead of value.  Missing lanes stay
        // unknown; they must not be replaced with zero or omitted.
        append_wide(&mut result, mem.value_lo, mem.value_hi);
    }

    for slot in 1..mem.value_count {
        if slot == 1 {
            if mem.elem_width <= 8 {
                append_scalar(&mut result, mem.elem_width, mem.value2);
            } else {
                append_wide(&mut result, mem.value2_lo, mem.value2_hi);
            }
        } else {
            // Parser currently extracts at most two register values.  Any
            // remaining register slots are still part of the real access;
            // preserve their width as unknown rather than dropping them.
            append_unknown(&mut result, mem.elem_width);
        }
    }
    // A known scalar with a missing pair must still occupy the pair's byte
    // range when parser metadata says this is a pair.  The parser exposes no
    // separate pair width; callers only receive bytes it could actually read.
    result
}

/// 追加一个 SIMD 寄存器的低 reg_bytes 字节；缺失的寄存器值保持 unknown。
fn append_simd_reg(output: &mut Vec<ByteValue>, value: Option<u128>, reg_bytes: u8) {
    let bytes = value.map(u128::to_le_bytes);
    output.extend((0..usize::from(reg_bytes)).map(|i| match bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

/// 追加一个 SIMD 寄存器在某个 lane 上的元素字节；缺失的值或越出 16 字节
/// 寄存器的 lane 偏移都保持 unknown，不得伪造已知字节。
fn append_simd_lane(output: &mut Vec<ByteValue>, value: Option<u128>, offset: usize, width: usize) {
    let bytes = value.map(u128::to_le_bytes);
    for i in offset..offset.saturating_add(width) {
        output.push(match bytes.as_ref().and_then(|b| b.get(i)).copied() {
            Some(byte) => ByteValue {
                value: byte,
                known: true,
            },
            None => ByteValue::unknown(),
        });
    }
}

fn append_scalar(output: &mut Vec<ByteValue>, width: u8, value: Option<u64>) {
    let width = usize::from(width.min(8));
    if width == 0 {
        return;
    }
    let bytes = value.map(u64::to_le_bytes);
    output.extend((0..width).map(|i| match bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

fn append_wide(output: &mut Vec<ByteValue>, low: Option<u64>, high: Option<u64>) {
    let low_bytes = low.map(u64::to_le_bytes);
    let high_bytes = high.map(u64::to_le_bytes);
    output.extend((0..8).map(|i| match low_bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
    output.extend((0..8).map(|i| match high_bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

fn append_unknown(output: &mut Vec<ByteValue>, width: u8) {
    let bytes = if width <= 8 { usize::from(width) } else { 16 };
    output.extend((0..bytes).map(|_| ByteValue::unknown()));
}
