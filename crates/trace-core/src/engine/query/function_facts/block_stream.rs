//! Allocation-independent owned instruction and executed-block scans.
//!
//! This is only the block component, not a bounded FunctionFactBundle builder.
//! The sink must reserve the actual formal envelope before retaining each item.
//! Retroactive block starts are resolved from one collected transfer-target list
//! (two linear passes) instead of re-scanning the window per instruction.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;

use super::super::activation::stable_site;
use super::blocks::is_control_transfer;

/// All text borrows the retained mmap under the session read lock. A canonical
/// site is generated for one instruction only; no raw-line copies are retained.
pub(super) struct BorrowedOwnedInsn<'a> {
    pub(super) seq: u32,
    pub(super) site: String,
    pub(super) line: &'a str,
}

impl BorrowedOwnedInsn<'_> {
    fn transfer(&self) -> bool {
        trace_parser::strict_memory::instruction_parts(self.line)
            .is_some_and(|(mnemonic, _)| is_control_transfer(mnemonic))
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(TraceError::Cancelled)
    } else {
        Ok(())
    }
}

/// 单行工作区上限：解析器与模块索引共用同一条资源边界。
pub(super) const RAW_LINE_LIMIT: usize = 1024 * 1024;

/// 越界行是资源错误而不是逻辑错误：两条路径必须报出同一段文本。
pub(super) fn oversize_error() -> TraceError {
    TraceError::Internal("function facts raw-line working memory resource limit exceeded".into())
}

// LineIndex strips LF and optional CR before returning this slice.
pub(super) fn check_raw(raw: &[u8]) -> Result<()> {
    check_raw_limit(raw, RAW_LINE_LIMIT)
}
fn check_raw_limit(raw: &[u8], limit: usize) -> Result<()> {
    if raw.len() > limit {
        return Err(oversize_error());
    }
    Ok(())
}

pub(super) fn scan_owned(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    visit: impl FnMut(BorrowedOwnedInsn<'_>) -> Result<bool>,
) -> Result<()> {
    scan_owned_impl(state, tree, activation, cancel, true, visit)
}

struct RawCursor<'a> {
    remaining: &'a [u8],
}
impl<'a> RawCursor<'a> {
    fn new(raw: &'a [u8], offset: usize) -> Result<Self> {
        Ok(Self {
            remaining: raw.get(offset..).ok_or_else(|| {
                TraceError::InvalidArgument("fact line offset outside trace".into())
            })?,
        })
    }
    fn next(&mut self) -> Result<&'a [u8]> {
        if self.remaining.is_empty() {
            return Err(TraceError::InvalidArgument(
                "fact raw range exceeds trace".into(),
            ));
        }
        let (line, consumed) = match memchr::memchr(b'\n', self.remaining) {
            Some(end) => (&self.remaining[..end], end + 1),
            None => (self.remaining, self.remaining.len()),
        };
        self.remaining = &self.remaining[consumed..];
        Ok(line.strip_suffix(b"\r").unwrap_or(line))
    }
}

/// 窗口内第一个 call_seq 落在窗口内的 `all_by_call` 下标。
///
/// `all_by_call` 已按 call_seq 严格递增：二分跳过后再顺序推进就是
/// entry 升序（嵌套/先后关系与 entry 同序）。原实现对窗口内每一行都遍历
/// 全部 activations（vbxk 样本 33,498 个节点），使窗口扫描退化为
/// O(W × |activations|)。
fn first_call_at_or_after(tree: &ActivationTree, seq: u32) -> usize {
    let ids = &tree.all_by_call;
    let mut lo = 0usize;
    let mut hi = ids.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        // 窗口第一个指令本身可能就是子调用指令：下界是 >= entry_seq，
        // 不是 > entry_seq。
        if tree.activations[ids[mid] as usize].call_seq < seq {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn scan_owned_impl(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    resource_bound: bool,
    mut visit: impl FnMut(BorrowedOwnedInsn<'_>) -> Result<bool>,
) -> Result<()> {
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let offset = index
        .line_byte_offset(&state.mmap, activation.entry_seq)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| TraceError::InvalidArgument("fact entry missing".into()))?;
    let mut cursor = RawCursor::new(&state.mmap, offset)?;
    // 严格包含区间直接从 all_by_call 的窗口前缀推进，不再为每次调用分配
    // 区间表：区间是 laminar 的，内层 exit 一定小于外层，所以「所有已开始
    // 且尚未结束的区间」等价于一个最大的 exit 标量（开括号栈的退化形式），
    // 同理也不再分配 open 栈。
    let ids = &tree.all_by_call;
    let mut next_nested = first_call_at_or_after(tree, activation.entry_seq);
    let mut skip_until_exit: Option<u32> = None;
    for seq in activation.entry_seq..=activation.exit_seq {
        check_cancel(cancel)?;
        // Advance before ownership filtering: skipped children and special rows
        // still occupy raw seqs. Repeated scans must not redo sampled lookups.
        let raw = cursor.next()?;
        while let Some(&id) = ids.get(next_nested) {
            let other = &tree.activations[id as usize];
            // 被严格包含的 activation 的 call 必在窗口内；再往后不可能命中。
            if other.call_seq > activation.exit_seq || other.entry_seq > seq {
                break;
            }
            next_nested += 1;
            // Same strict-contained interval rule as owned_instructions, including
            // unresolved nested activations, now driven by the call-sequence index.
            if other.id != activation.id
                && other.entry_seq > activation.entry_seq
                && other.exit_seq < activation.exit_seq
                && other.exit_seq >= seq
            {
                skip_until_exit =
                    Some(skip_until_exit.map_or(other.exit_seq, |exit| exit.max(other.exit_seq)));
            }
        }
        if skip_until_exit.is_some_and(|exit| exit >= seq) {
            continue;
        }
        if resource_bound {
            check_raw(raw)?;
        }
        let line =
            std::str::from_utf8(raw).map_err(|error| TraceError::Internal(error.to_string()))?;
        let Some(site) = stable_site(line) else {
            if trace_parser::gumtrace::parse_special_line(line).is_some() {
                continue;
            }
            return Err(TraceError::InvalidArgument(format!(
                "seq {seq} 缺少稳定 module+offset"
            )));
        };
        if !visit(BorrowedOwnedInsn { seq, site, line })? {
            break;
        }
    }
    Ok(())
}

pub(super) fn stream_executed_blocks(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    sink: impl FnMut(&str, u32) -> Result<()>,
) -> Result<()> {
    stream_blocks_impl(state, tree, activation, cancel, true, sink)
}
fn stream_blocks_impl(
    state: &SessionState,
    tree: &ActivationTree,
    activation: &ConfirmedActivation,
    cancel: &AtomicBool,
    resource_bound: bool,
    mut sink: impl FnMut(&str, u32) -> Result<()>,
) -> Result<()> {
    // 第一遍只收集「紧跟在控制转移之后」的落点 site：原来对每条指令重跑一遍
    // 窗口扫描（O(W²)）只是为了回答同一个问题。收集后第二遍用二分查询，
    // 观测序列与重新扫描完全一致。
    let mut observed: Vec<String> = Vec::new();
    {
        let mut previous_transfer = false;
        scan_owned_impl(state, tree, activation, cancel, resource_bound, |insn| {
            let transfer = insn.transfer();
            if previous_transfer {
                observed.push(insn.site);
            }
            previous_transfer = transfer;
            Ok(true)
        })?;
    }
    observed.sort_unstable();
    observed.dedup();

    let mut first = true;
    let mut previous_transfer = false;
    scan_owned_impl(state, tree, activation, cancel, resource_bound, |insn| {
        let starts = first || previous_transfer || observed.binary_search(&insn.site).is_ok();
        if starts {
            check_cancel(cancel)?;
            sink(&insn.site, insn.seq)?;
            check_cancel(cancel)?;
        }
        first = false;
        previous_transfer = insn.transfer();
        Ok(true)
    })
}

#[cfg(test)]
mod resource_tests {
    #[test]
    fn raw_cursor_advances_every_row_including_skipped_and_final_rows() {
        let raw = "entry\r\nchild\n\r\nμ special\nresume".as_bytes();
        let mut cursor = super::RawCursor::new(raw, 0).unwrap();
        assert_eq!(cursor.next().unwrap(), b"entry");
        assert_eq!(cursor.next().unwrap(), b"child");
        assert_eq!(cursor.next().unwrap(), b"");
        assert_eq!(cursor.next().unwrap(), "μ special".as_bytes());
        assert_eq!(cursor.next().unwrap(), b"resume");
        assert!(cursor.next().is_err());
        assert!(super::RawCursor::new(raw, raw.len() + 1).is_err());
        let mut terminated = super::RawCursor::new(b"a\n", 0).unwrap();
        assert_eq!(terminated.next().unwrap(), b"a");
        assert!(terminated.next().is_err());
    }
    #[test]
    fn raw_resource_boundary_checks_borrowed_bytes() {
        assert!(super::check_raw_limit(b"12345678", 8).is_ok());
        let error = super::check_raw_limit(b"123456789", 8).unwrap_err();
        assert!(
            matches!(error, crate::error::TraceError::Internal(message) if message == "function facts raw-line working memory resource limit exceeded")
        );
    }
}

impl crate::engine::TraceEngine {
    /// Visit the exact executed block sequence without retaining owned raw lines
    /// or the set of observed branch targets. The callback's site is valid only
    /// during the call. An error stops immediately; already accepted items are
    /// not a complete result. This API neither builds nor budgets the full facts
    /// bundle. It holds the retained session read lock throughout all passes.
    /// As with existing retained-mmap queries, callers must keep the underlying
    /// trace immutable: a session lock does not prevent external file writes.
    /// The caller is responsible for FD identity verification before/after use.
    pub fn visit_function_executed_blocks(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        cancel: &AtomicBool,
        sink: impl FnMut(&str, u32) -> Result<()>,
    ) -> Result<()> {
        check_cancel(cancel)?;
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let activation = tree
            .activations
            .iter()
            .find(|item| item.call_seq == call_seq && item.entry_seq == entry_seq)
            .ok_or_else(|| TraceError::InvalidArgument("Activation selector not found".into()))?;
        if activation.id == 0
            || activation.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= activation.exit_seq
                && activation.exit_seq < activation.resume_seq
                && activation.resume_seq < state.total_lines)
        {
            return Err(TraceError::InvalidArgument(
                "block stream requires a closed Confirmed Activation".into(),
            ));
        }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        for seq in [
            call_seq,
            entry_seq,
            activation.exit_seq,
            activation.resume_seq,
        ] {
            check_cancel(cancel)?;
            let line = index
                .get_line(&state.mmap, seq)
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .ok_or_else(|| TraceError::InvalidArgument("block boundary missing".into()))?;
            let site = stable_site(line).ok_or_else(|| {
                TraceError::InvalidArgument("block boundary lacks stable instruction site".into())
            })?;
            if trace_parser::strict_memory::instruction_parts(line).is_none()
                || (seq == entry_seq && site != function)
            {
                return Err(TraceError::InvalidArgument(
                    "block selector boundary mismatch".into(),
                ));
            }
        }
        stream_blocks_impl(&state, tree, activation, cancel, false, sink)
    }
}
