//! 有界内存控制流索引；不读取路径缓存、不构建动态数据依赖。
mod scan;
pub mod types;
mod view;
use crate::error::Result;
use crate::flat::line_index::LineIndexArchive;
use crate::query::activation::ActivationTree;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::AtomicBool;
pub use view::render_dot;

/// 小型内存实现的明确容量；不是十亿行磁盘缓存实现。
pub const MAX_TRACE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TRACE_LINES: usize = 500_000;
#[derive(Clone, Copy)]
pub(crate) struct Occurrence {
    pub start: u32,
    pub end: u32,
    pub block: u32,
    pub activation: u32,
    pub outgoing: types::CfgEdgeKind,
}
pub struct ControlFlowIndex {
    pub(crate) lines: LineIndexArchive,
    pub(crate) tree: ActivationTree,
    pub(crate) functions: BTreeMap<String, Vec<u32>>,
    pub(crate) blocks: Vec<String>,
    pub(crate) occurrences: Vec<Occurrence>,
    pub(crate) ranges: Vec<std::ops::Range<usize>>,
    pub(crate) site: fn(&str) -> Option<String>,
}
impl ControlFlowIndex {
    pub(crate) fn build(
        data: &[u8],
        cancel: &AtomicBool,
        site: fn(&str) -> Option<String>,
        pc: fn(&str) -> Option<u64>,
    ) -> Result<Self> {
        scan::build(data, cancel, site, pc)
    }
}
#[cfg(test)]
mod tests;
