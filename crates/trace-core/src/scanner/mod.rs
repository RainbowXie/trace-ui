use anyhow::Result;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use trace_parser::insn_class::InsnClass;
use trace_parser::types::*;

mod pass1;
#[cfg(test)]
mod tests;

pub use pass1::scan_pass1_bytes_with_progress;

/// Flat array mapping RegId → last DEF line index.
///
/// Uses `u32::MAX` as sentinel for "no definition seen". Provides the same
/// `.get()` / `.insert()` API as HashMap for drop-in replacement.
/// 98 entries × 4 bytes = 392 bytes — fits in a few cache lines.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RegLastDef(#[serde(with = "big_array")] [u32; RegId::COUNT]);

mod big_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use trace_parser::types::RegId;

    pub fn serialize<S: Serializer>(arr: &[u32; RegId::COUNT], s: S) -> Result<S::Ok, S::Error> {
        arr.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u32; RegId::COUNT], D::Error> {
        let v = Vec::<u32>::deserialize(d)?;
        v.try_into().map_err(|v: Vec<u32>| {
            serde::de::Error::custom(format!(
                "expected {} elements, got {}",
                RegId::COUNT,
                v.len()
            ))
        })
    }
}

impl Default for RegLastDef {
    fn default() -> Self {
        Self::new()
    }
}

impl RegLastDef {
    const NO_DEF: u32 = u32::MAX;

    pub fn new() -> Self {
        Self([Self::NO_DEF; RegId::COUNT])
    }

    pub fn get(&self, reg: &RegId) -> Option<&u32> {
        let val = &self.0[reg.0 as usize];
        if *val != Self::NO_DEF {
            Some(val)
        } else {
            None
        }
    }

    pub fn insert(&mut self, reg: RegId, line: u32) {
        self.0[reg.0 as usize] = line;
    }

    /// Get raw inner array (for merge phase).
    #[allow(dead_code)]
    pub fn inner(&self) -> &[u32; RegId::COUNT] {
        &self.0
    }

    /// Get mutable raw inner array (for merge phase).
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut [u32; RegId::COUNT] {
        &mut self.0
    }
}

/// State accumulated during Pass 1 forward scan.
///
/// Tracks:
/// - `reg_last_def`: line index of the last DEF for each register
/// - `mem_last_def`: line index of the last DEF for each memory byte address
/// - `last_cond_branch`: line index of the most recent conditional branch
/// - `deps`: per-line dependency edges (line indices this line depends on)
/// - `line_count`: total number of lines processed
///
/// Bit 标记：dep 行号的高位表示 pair 指令的到达路径。
/// 24M 行远不到 2^30，所以 bit 30-31 可以安全复用。
///
/// - PAIR_HALF2_BIT (bit 31): 到达 pair 指令的第二半区（half2 数据）
/// - PAIR_SHARED_BIT (bit 30): 到达 pair 指令的共享路径（writeback base）
/// - 无标记: 到达 pair 指令的第一半区（half1 数据）
pub const PAIR_HALF2_BIT: u32 = 0x80000000;
pub const PAIR_SHARED_BIT: u32 = 0x40000000;
pub const CONTROL_DEP_BIT: u32 = 0x20000000;
pub const LINE_MASK: u32 = 0x1FFFFFFF;

/// Pair 指令（ldp/stp）的分半依赖。
/// 将内存依赖和源寄存器依赖按半区拆分，以提高切片精度。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PairSplitDeps {
    /// 共享依赖（base reg、control dep）
    pub shared: SmallVec<[u32; 2]>,
    /// 第一个寄存器的专属依赖（mem 半区1 或 source reg1）
    pub half1_deps: SmallVec<[u32; 4]>,
    /// 第二个寄存器的专属依赖（mem 半区2 或 source reg2）
    pub half2_deps: SmallVec<[u32; 4]>,
}

/// mem_last_def 的紧凑存储：扫描期间用 HashMap（快速插入），
/// compact 后转为排序数组（节省内存，二分查找）。
#[derive(serde::Serialize, serde::Deserialize)]
pub enum MemLastDef {
    Map(FxHashMap<u64, (u32, u64)>),
    Sorted(Vec<(u64, u32, u64)>),
}

impl Default for MemLastDef {
    fn default() -> Self {
        Self::Map(FxHashMap::default())
    }
}

impl MemLastDef {
    /// 查找地址对应的 (line, value)。返回拷贝。
    pub fn get(&self, addr: &u64) -> Option<(u32, u64)> {
        match self {
            Self::Map(m) => m.get(addr).copied(),
            Self::Sorted(v) => v
                .binary_search_by_key(addr, |(a, _, _)| *a)
                .ok()
                .map(|i| (v[i].1, v[i].2)),
        }
    }

    /// 扫描期间插入（仅 Map 模式）
    pub fn insert(&mut self, addr: u64, value: (u32, u64)) {
        match self {
            Self::Map(m) => {
                m.insert(addr, value);
            }
            Self::Sorted(_) => panic!("cannot insert into compacted MemLastDef"),
        }
    }

    /// 返回条目数
    pub fn len(&self) -> usize {
        match self {
            Self::Map(m) => m.len(),
            Self::Sorted(v) => v.len(),
        }
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 压缩为排序数组，释放 HashMap 开销
    pub fn compact(&mut self) {
        if let Self::Map(m) = self {
            let mut sorted: Vec<(u64, u32, u64)> = m
                .drain()
                .map(|(addr, (line, val))| (addr, line, val))
                .collect();
            sorted.sort_unstable_by_key(|(addr, _, _)| *addr);
            *self = Self::Sorted(sorted);
        }
    }
}

/// 紧凑依赖图存储（CSR 格式）。
///
/// 使用 offsets + data 两个连续数组代替 `Vec<SmallVec<[u32; 4]>>`，
/// 消除每行 24 字节的 SmallVec 开销，至少节省 4 字节/行。
///
/// - `offsets[i]` = 第 i 行的依赖在 `data` 中的起始索引
/// - 第 i 行的依赖 = `data[offsets[i]..offsets[i+1]]`
/// - `offsets` 长度 = 行数 + 1（末尾哨兵）
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CompactDeps {
    pub offsets: Vec<u32>,
    pub data: Vec<u32>,
}

impl CompactDeps {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            offsets: Vec::new(),
            data: Vec::new(),
        }
    }

    pub fn with_capacity(estimated_lines: usize, estimated_deps: usize) -> Self {
        Self {
            offsets: Vec::with_capacity(estimated_lines + 1),
            data: Vec::with_capacity(estimated_deps),
        }
    }

    /// 开始新的一行。必须在 push_unique 之前调用。
    #[inline]
    pub fn start_row(&mut self) {
        self.offsets.push(self.data.len() as u32);
    }

    /// 向当前行添加依赖（去重）。
    #[inline]
    pub fn push_unique(&mut self, val: u32) {
        let start = *self.offsets.last().unwrap() as usize;
        if !self.data[start..].contains(&val) {
            self.data.push(val);
        }
    }

    /// 获取第 i 行的依赖切片。
    #[inline]
    pub fn row(&self, i: usize) -> &[u32] {
        let start = self.offsets[i] as usize;
        let end = if i + 1 < self.offsets.len() {
            self.offsets[i + 1] as usize
        } else {
            self.data.len()
        };
        &self.data[start..end]
    }

    /// 总依赖边数。
    pub fn total_deps(&self) -> usize {
        self.data.len()
    }

    /// 行数。
    #[allow(dead_code)]
    pub fn num_rows(&self) -> usize {
        self.offsets.len()
    }

    /// 是否没有任何行。
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// 收缩内部存储以释放多余内存。
    #[allow(dead_code)]
    pub fn shrink_to_fit(&mut self) {
        self.data.shrink_to_fit();
        self.offsets.shrink_to_fit();
    }

    /// 判断第 i 行是否有依赖。
    #[allow(dead_code)]
    pub fn row_is_empty(&self, i: usize) -> bool {
        self.row(i).is_empty()
    }

    /// 第 i 行是否包含某个依赖值。
    #[allow(dead_code)]
    pub fn row_contains(&self, i: usize, val: &u32) -> bool {
        self.row(i).contains(val)
    }

    /// Create from raw parts (for merge phase).
    #[allow(dead_code)]
    pub fn from_raw(offsets: Vec<u32>, data: Vec<u32>) -> Self {
        Self { offsets, data }
    }

    /// Accessor for offsets slice (for flat conversion).
    pub fn offsets_slice(&self) -> &[u32] {
        &self.offsets
    }

    /// Accessor for data slice (for flat conversion).
    pub fn data_slice(&self) -> &[u32] {
        &self.data
    }

    /// Number of dependency edges for row i.
    #[allow(dead_code)]
    pub fn row_len(&self, i: usize) -> usize {
        let start = self.offsets[i] as usize;
        let end = if i + 1 < self.offsets.len() {
            self.offsets[i + 1] as usize
        } else {
            self.data.len()
        };
        end - start
    }
}

/// Storage for dependency graph — either a single CompactDeps (from single-threaded
/// scan or legacy cache) or chunked format from parallel scan that avoids the
/// expensive O(n) rebuild_compact_deps.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum DepsStorage {
    /// Single merged CompactDeps (from single-threaded scan or cache).
    Single(CompactDeps),
    /// Chunked from parallel scan — keeps per-chunk CompactDeps as-is.
    Chunked {
        chunks: Vec<CompactDeps>,
        chunk_start_lines: Vec<u32>,
        /// Cross-chunk patch deps grouped by source line, sorted by line number.
        /// Each entry is (global_line, deps_for_that_line).
        patch_groups: Vec<(u32, Vec<u32>)>,
    },
}

impl DepsStorage {
    /// Get the base (intra-chunk) deps for a line.
    #[inline]
    pub fn row(&self, global_line: usize) -> &[u32] {
        match self {
            DepsStorage::Single(cd) => cd.row(global_line),
            DepsStorage::Chunked {
                chunks,
                chunk_start_lines,
                ..
            } => {
                let line = global_line as u32;
                let chunk_idx = match chunk_start_lines.binary_search(&line) {
                    Ok(i) => i,
                    Err(i) => i.saturating_sub(1),
                };
                let local = global_line - chunk_start_lines[chunk_idx] as usize;
                chunks[chunk_idx].row(local)
            }
        }
    }

    /// Get cross-chunk patch deps for a line. Returns empty slice if none.
    #[inline]
    pub fn patch_row(&self, global_line: usize) -> &[u32] {
        match self {
            DepsStorage::Single(_) => &[],
            DepsStorage::Chunked { patch_groups, .. } => {
                let line = global_line as u32;
                match patch_groups.binary_search_by_key(&line, |&(l, _)| l) {
                    Ok(idx) => &patch_groups[idx].1,
                    Err(_) => &[],
                }
            }
        }
    }

    /// Total dependency edge count.
    pub fn total_deps(&self) -> usize {
        match self {
            DepsStorage::Single(cd) => cd.total_deps(),
            DepsStorage::Chunked {
                chunks,
                patch_groups,
                ..
            } => {
                let base: usize = chunks.iter().map(|c| c.total_deps()).sum();
                let patches: usize = patch_groups.iter().map(|(_, v)| v.len()).sum();
                base + patches
            }
        }
    }

    /// Number of rows (lines).
    #[allow(dead_code)]
    pub fn num_rows(&self) -> usize {
        match self {
            DepsStorage::Single(cd) => cd.num_rows(),
            DepsStorage::Chunked { chunks, .. } => chunks.iter().map(|c| c.num_rows()).sum(),
        }
    }

    /// Whether there are no rows.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        match self {
            DepsStorage::Single(cd) => cd.is_empty(),
            DepsStorage::Chunked { chunks, .. } => chunks.iter().all(|c| c.is_empty()),
        }
    }

    /// Start a new row (only valid for Single variant, used during scan).
    #[inline]
    pub fn start_row(&mut self) {
        match self {
            DepsStorage::Single(cd) => cd.start_row(),
            DepsStorage::Chunked { .. } => panic!("cannot start_row on Chunked DepsStorage"),
        }
    }

    /// Push a unique dep to the current row (only valid for Single variant, used during scan).
    #[inline]
    pub fn push_unique(&mut self, val: u32) {
        match self {
            DepsStorage::Single(cd) => cd.push_unique(val),
            DepsStorage::Chunked { .. } => panic!("cannot push_unique on Chunked DepsStorage"),
        }
    }

    /// Check if a row contains a specific dep value (base + patches).
    #[allow(dead_code)]
    pub fn row_contains(&self, i: usize, val: &u32) -> bool {
        self.row(i).contains(val) || self.patch_row(i).contains(val)
    }

    /// Check if a row has no deps (base + patches).
    #[allow(dead_code)]
    pub fn row_is_empty(&self, i: usize) -> bool {
        self.row(i).is_empty() && self.patch_row(i).is_empty()
    }

    /// Wrap a CompactDeps as DepsStorage::Single.
    pub fn single(cd: CompactDeps) -> Self {
        DepsStorage::Single(cd)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ScanState {
    pub reg_last_def: RegLastDef,
    pub mem_last_def: MemLastDef,
    pub last_cond_branch: Option<u32>,
    pub deps: DepsStorage,
    pub line_count: u32,
    /// 成功解析的指令行数（parse_line 返回 Some 的次数）
    pub parsed_count: u32,
    /// 包含 mem[WRITE]/mem[READ] + abs= 的行数
    pub mem_op_count: u32,
    /// Maps (@LINE, target) → resolved line index (may differ from original if fallback occurred).
    pub resolved_targets: FxHashMap<(u32, LineTarget), u32>,
    /// 未知助记符统计：助记符 → (首次出现行号 0-based, 出现次数)
    pub unknown_mnemonics: FxHashMap<String, (u32, u32)>,
    /// 标记从初始内存（trace 前状态）加载的行。
    pub init_mem_loads: bitvec::prelude::BitVec,
    /// Pair 指令的分半依赖（仅 LoadPair/StorePair 行有条目）。
    pub pair_split: FxHashMap<u32, PairSplitDeps>,
}

impl ScanState {
    /// 扫描完成后压缩数据结构，释放仅扫描期间使用的字段。
    pub fn compact(&mut self) {
        self.mem_last_def.compact();
        self.last_cond_branch = None;
        self.resolved_targets = FxHashMap::default();
        self.unknown_mnemonics = FxHashMap::default();
    }
}

/// Push `val` into a SmallVec only if not already present (dedup).
pub fn push_unique<A: smallvec::Array<Item = u32>>(deps: &mut SmallVec<A>, val: u32) {
    if !deps.contains(&val) {
        deps.push(val);
    }
}

/// Scan from an in-memory string (for testing).
#[allow(dead_code)]
pub fn scan_from_string(trace: &str, data_only: bool) -> Result<ScanState> {
    scan_from_string_with_targets(trace, data_only, 0, None, &Default::default())
}

/// Scan from an in-memory string with range limiting.
#[allow(dead_code)]
pub fn scan_from_string_with_range(
    trace: &str,
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
) -> Result<ScanState> {
    scan_from_string_with_targets(trace, data_only, start_seq, end_seq, &Default::default())
}

/// Scan from an in-memory string with full options (range + @LINE targets).
#[allow(dead_code)]
pub fn scan_from_string_with_targets(
    trace: &str,
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
    line_targets: &std::collections::HashMap<u32, Vec<LineTarget>>,
) -> Result<ScanState> {
    scan_pass1_bytes(
        trace.as_bytes(),
        data_only,
        start_seq,
        end_seq,
        line_targets,
        false,
        false,
    )
}

/// Core Pass 1: forward scan building the dependency graph.
///
/// Operates directly on a byte slice (from mmap or string) using memchr to
/// find newlines. No read_line syscalls, no UTF-8 validation, no buffer copies.
///
/// For each line:
/// 1. Parse the trace line
/// 2. Classify the instruction
/// 3. Determine DEF/USE sets
/// 4. Record data dependencies (register + memory) and control dependencies
/// 5. Update regLastDef, memLastDef, lastCondBranch
///
/// `start_seq` and `end_seq` limit the range of lines that are actually
/// parsed/classified. Lines outside `[start_seq, end_seq]` still get an
/// empty deps entry to maintain index alignment.
///
/// Use this directly when the caller already has the mmap and wants to reuse it later.
#[allow(dead_code)]
pub fn scan_pass1_bytes(
    data: &[u8],
    data_only: bool,
    start_seq: u32,
    end_seq: Option<u32>,
    line_targets: &std::collections::HashMap<u32, Vec<LineTarget>>,
    profile: bool,
    no_prune: bool,
) -> Result<ScanState> {
    scan_pass1_bytes_with_progress(
        data,
        Pass1Options {
            data_only,
            start_seq,
            end_seq,
            line_targets,
            profile,
            no_prune,
        },
        None,
    )
}

/// pass1 扫描的选项集合，避免 `scan_pass1_bytes_with_progress` 堆积位置参数。
pub struct Pass1Options<'a> {
    pub data_only: bool,
    pub start_seq: u32,
    pub end_seq: Option<u32>,
    pub line_targets: &'a std::collections::HashMap<u32, Vec<LineTarget>>,
    pub profile: bool,
    pub no_prune: bool,
}

/// 计算内存访问的总宽度（字节）。
///
/// - 配对指令 (ldp/stp): `elem_width * 2`
/// - SIMD 多寄存器 (ld1 {v0,v1,...}): `elem_width * 数据寄存器数`
/// - 其它: `elem_width`
pub fn mem_access_width(
    class: InsnClass,
    elem_width: u8,
    line: &trace_parser::types::ParsedLine,
) -> u8 {
    match class {
        InsnClass::LoadPair | InsnClass::StorePair => elem_width.saturating_mul(2),
        InsnClass::SimdLoad | InsnClass::SimdStore => {
            // 统计 base_reg 之前的寄存器操作数数量（即数据寄存器）
            let data_reg_count = line.base_reg.map_or(1u8, |base| {
                line.operands
                    .iter()
                    .take_while(|op: &&trace_parser::types::Operand| op.as_reg() != Some(base))
                    .filter(|op: &&trace_parser::types::Operand| op.as_reg().is_some())
                    .count() as u8
            });
            elem_width.saturating_mul(data_reg_count.max(1))
        }
        _ => elem_width,
    }
}
