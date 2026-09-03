use crate::query::activation::ActivationTree;
use crate::query::call_tree::CallTree;
use crate::scanner::RegLastDef;
use memmap2::Mmap;
use std::sync::Arc;
use trace_parser::types::RegId;

use super::bitvec::{BitView, FlatBitVec};
use super::cache_format::{SectionReader, SectionWriter};
use super::deps::{DepsRawSlices, DepsView, FlatDeps};
use super::line_index::{LineIndexArchive, LineIndexView};
use super::mem_access::FlatMemAccessRecord;
use super::mem_access::{FlatMemAccess, MemAccessView};
use super::mem_last_def::{FlatMemLastDef, MemLastDefView};
use super::pair_split::{FlatPairSplit, PairSplitView};
use super::reg_checkpoints::{FlatRegCheckpoints, RegCheckpointsView};
use super::scan_view::ScanView;

pub const HEADER_LEN: usize = 64;

// ── Phase2Archive ────────────────────────────────────────────────────────────

pub struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTree,
    /// Confirmed Activation 树（含 bypassed 调用集合），与 CallTree 同模式缓存
    pub activation_tree: ActivationTree,
}

impl Phase2Archive {
    /// Serialize to section-based binary format.
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // MemAccess: sections 0-2
        w.write_slice(&self.mem_accesses.addrs); // 0
        w.write_slice(&self.mem_accesses.offsets); // 1
        w.write_slice(&self.mem_accesses.records); // 2
                                                   // RegCheckpoints: sections 3-5
        w.write_u32(self.reg_checkpoints.interval); // 3
        w.write_u32(self.reg_checkpoints.count); // 4
        w.write_slice(&self.reg_checkpoints.data); // 5
                                                   // CallTree: section 6 (bincode, eagerly deserialized on load)
        let ct_bytes = bincode::serialize(&self.call_tree).unwrap();
        w.write_bytes(&ct_bytes); // 6
                                  // ActivationTree: section 7 (bincode, eagerly deserialized on load)
        let at_bytes = bincode::serialize(&self.activation_tree).unwrap();
        w.write_bytes(&at_bytes); // 7
        w.finish()
    }

    /// Reconstruct views from mmap'd section data.
    /// `data` = &mmap[HEADER_LEN..] (after 64-byte cache header)
    pub fn views_from_sections(data: &[u8]) -> Option<Phase2Views<'_>> {
        let r = SectionReader::new(data)?;
        // V6 缓存（magic TCACHE06）布局固定为恰好 8 个 section；
        // 不等于 8 = 损坏/截断缓存，整体判 miss 触发重扫重建，
        // fail-closed：不能接受半新半旧布局（ActivationTree 永久缺失）。
        // 旧 V4/更早缓存在 cache.rs 的 magic 校验处已 miss，不会到达这里。
        if r.num_sections() != 8 {
            return None;
        }
        // typed slice 安全预检：不满足 = 损坏缓存整体 miss。
        // 元素大小/对齐与写入路径（write_to_sections）一一对应：
        // 0 addrs u64、1 offsets u32(CSR)、2 records 24B 结构体（对齐 8）、
        // 3/4 interval/count u32 单值（非零）、5 reg checkpoints u64 数组。
        // 数组 section 空合法；6/7 bincode 字节不预检（反序列化时 miss）。
        let rec_size = std::mem::size_of::<FlatMemAccessRecord>();
        let rec_align = std::mem::align_of::<FlatMemAccessRecord>();
        if !r.is_valid_typed(0, 8)
            || !r.is_valid_typed(1, 4)
            || !r.is_valid_typed_align(2, rec_size, rec_align)
            || !r.is_valid_single(3, 4)
            || !r.is_valid_single(4, 4)
            || !r.is_valid_typed(5, 8)
        {
            return None;
        }
        Some(Phase2Views {
            mem_accesses: MemAccessView::from_raw(r.slice(0), r.slice(1), r.slice(2)),
            reg_checkpoints: RegCheckpointsView::from_raw(r.u32_val(3), r.u32_val(4), r.slice(5)),
            call_tree_bytes: r.bytes(6),
            activation_tree_bytes: Some(r.bytes(7)),
        })
    }
}

pub struct Phase2Views<'a> {
    pub mem_accesses: MemAccessView<'a>,
    pub reg_checkpoints: RegCheckpointsView<'a>,
    pub call_tree_bytes: &'a [u8], // bincode bytes, deserialize on demand
    /// 新缓存才携带；旧缓存没有 ActivationTree（重建索引后可用）
    pub activation_tree_bytes: Option<&'a [u8]>,
}

// ── ScanArchive ──────────────────────────────────────────────────────────────

pub struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u32>, // [u32; 98] serialized as Vec
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

impl ScanArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // FlatDeps: sections 0-7
        w.write_slice(&self.deps.chunk_start_lines); // 0
        w.write_slice(&self.deps.chunk_offsets_start); // 1
        w.write_slice(&self.deps.chunk_data_start); // 2
        w.write_slice(&self.deps.all_offsets); // 3
        w.write_slice(&self.deps.all_data); // 4
        w.write_slice(&self.deps.patch_lines); // 5
        w.write_slice(&self.deps.patch_offsets); // 6
        w.write_slice(&self.deps.patch_data); // 7
                                              // FlatMemLastDef: sections 8-10
        w.write_slice(&self.mem_last_def.addrs); // 8
        w.write_slice(&self.mem_last_def.lines); // 9
        w.write_slice(&self.mem_last_def.values); // 10
                                                  // FlatPairSplit: sections 11-13
        w.write_slice(&self.pair_split.keys); // 11
        w.write_slice(&self.pair_split.seg_offsets); // 12
        w.write_slice(&self.pair_split.data); // 13
                                              // FlatBitVec: sections 14-15
        w.write_slice(&self.init_mem_loads.data); // 14
        w.write_u32(self.init_mem_loads.len); // 15
                                              // Metadata: sections 16-19
        w.write_slice(&self.reg_last_def_inner); // 16
        w.write_u32(self.line_count); // 17
        w.write_u32(self.parsed_count); // 18
        w.write_u32(self.mem_op_count); // 19
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<ScanViews<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 20 {
            return None;
        }
        // typed slice 安全预检：全部 section 对齐/整除/非零，不满足整体 miss。
        // 元素大小与写入路径一一对应：FlatDeps 0-7 全 u32、
        // mem_last_def 8 addrs u64 / 9 lines u32 / 10 values u64、
        // pair_split 11-13 u32、init_mem_loads 14 data u8 + 15 len u32 单值、
        // 16 reg_last_def_inner u32、17-19 计数 u32 单值。
        // typed slice 安全预检：不满足 = 损坏缓存整体 miss。
        // 数组 section（元素与写入路径一一对应）空合法；
        // 单值 section（15 len、17-19 计数）要求非零。
        for (idx, elem) in [
            (0usize, 4usize),
            (1, 4),
            (2, 4),
            (3, 4),
            (4, 4),
            (5, 4),
            (6, 4),
            (7, 4),
            (8, 8),
            (9, 4),
            (10, 8),
            (11, 4),
            (12, 4),
            (13, 4),
            (14, 1),
            (16, 4),
        ] {
            if !r.is_valid_typed(idx, elem) {
                return None;
            }
        }
        for idx in [15usize, 17, 18, 19] {
            if !r.is_valid_single(idx, 4) {
                return None;
            }
        }
        Some(ScanViews {
            deps: DepsView::from_raw(DepsRawSlices {
                chunk_start_lines: r.slice(0),
                chunk_offsets_start: r.slice(1),
                chunk_data_start: r.slice(2),
                all_offsets: r.slice(3),
                all_data: r.slice(4),
                patch_lines: r.slice(5),
                patch_offsets: r.slice(6),
                patch_data: r.slice(7),
            }),
            mem_last_def: MemLastDefView::from_raw(r.slice(8), r.slice(9), r.slice(10)),
            pair_split: PairSplitView::from_raw(r.slice(11), r.slice(12), r.slice(13)),
            init_mem_loads: BitView::from_raw(r.slice(14), r.u32_val(15)),
            reg_last_def_inner: r.slice(16),
            line_count: r.u32_val(17),
            parsed_count: r.u32_val(18),
            mem_op_count: r.u32_val(19),
        })
    }
}

#[allow(dead_code)]
pub struct ScanViews<'a> {
    pub deps: DepsView<'a>,
    pub mem_last_def: MemLastDefView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub reg_last_def_inner: &'a [u32],
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

// ── LineIndexArchive sections ────────────────────────────────────────────────

impl LineIndexArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        w.write_slice(&self.sampled_offsets); // 0
        w.write_u32(self.total); // 1
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<LineIndexView<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 2 {
            return None;
        }
        // 0 sampled_offsets u64 数组（空合法）、1 total u32 单值（非零）
        if !r.is_valid_typed(0, 8) || !r.is_valid_single(1, 4) {
            return None;
        }
        Some(LineIndexView::from_raw(r.slice(0), r.u32_val(1)))
    }
}

// ── CachedStore ──────────────────────────────────────────────────────────────

pub enum CachedStore<A> {
    Owned(A),
    Mapped(Arc<Mmap>),
}

// ── CachedStore<Phase2Archive> ───────────────────────────────────────────────

impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_accesses
            }
        }
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_checkpoints
            }
        }
    }

    pub fn deserialize_call_tree(&self) -> Option<CallTree> {
        match self {
            Self::Owned(a) => Some(a.call_tree.clone()),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..])?;
                bincode::deserialize(views.call_tree_bytes).ok()
            }
        }
    }

    pub fn deserialize_activation_tree(&self) -> Option<ActivationTree> {
        match self {
            Self::Owned(a) => Some(a.activation_tree.clone()),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..])?;
                // 结构变更后旧缓存反序列化失败时不 panic：返回 None 让 session
                // 进入 IndexNotReady；缓存版本号（MAGIC_V6）机制在下次重建时
                // 自然修复。
                views
                    .activation_tree_bytes
                    .and_then(|b| bincode::deserialize(b).ok())
            }
        }
    }
}

// ── CachedStore<ScanArchive> ─────────────────────────────────────────────────

impl CachedStore<ScanArchive> {
    pub fn deps_view(&self) -> DepsView<'_> {
        match self {
            Self::Owned(a) => a.deps.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.deps
            }
        }
    }

    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> {
        match self {
            Self::Owned(a) => a.mem_last_def.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_last_def
            }
        }
    }

    pub fn pair_split_view(&self) -> PairSplitView<'_> {
        match self {
            Self::Owned(a) => a.pair_split.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.pair_split
            }
        }
    }

    pub fn init_mem_loads_view(&self) -> BitView<'_> {
        match self {
            Self::Owned(a) => a.init_mem_loads.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.init_mem_loads
            }
        }
    }

    pub fn line_count(&self) -> u32 {
        match self {
            Self::Owned(a) => a.line_count,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.line_count
            }
        }
    }

    pub fn reg_last_def_inner(&self) -> &[u32] {
        match self {
            Self::Owned(a) => &a.reg_last_def_inner,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_last_def_inner
            }
        }
    }

    pub fn deserialize_reg_last_def(&self) -> RegLastDef {
        let inner = self.reg_last_def_inner();
        let mut rld = RegLastDef::new();
        for (i, &v) in inner.iter().enumerate().take(RegId::COUNT) {
            if v != u32::MAX {
                rld.insert(RegId(i as u8), v);
            }
        }
        rld
    }

    pub fn scan_view(&self) -> ScanView<'_> {
        ScanView {
            deps: self.deps_view(),
            pair_split: self.pair_split_view(),
            line_count: self.line_count(),
        }
    }
}

// ── CachedStore<LineIndexArchive> ────────────────────────────────────────────

impl CachedStore<LineIndexArchive> {
    pub fn total_lines(&self) -> u32 {
        self.view().total_lines()
    }

    pub fn view(&self) -> LineIndexView<'_> {
        match self {
            Self::Owned(a) => a.view(),
            Self::Mapped(mmap) => {
                LineIndexArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap()
            }
        }
    }
}
