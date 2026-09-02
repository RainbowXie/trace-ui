//! Confirmed Activation：由 `call → entry → exit → resume` 确认的函数调用激活记录。
//!
//! 与 CallTreeNode 的区别：CallTreeNode 在 RET 时出栈，不能处理"通过未记录函数体后
//! 直接恢复到 callsite + 4"的调用。Confirmed Activation 用 `expected_resume` 确认
//! 边界：BL/BLR 创建 candidate，下一条实际指令决定 candidate 是否进入 active
//! Activation；每次读取指令前检查当前 PC 是否到达栈顶调用的 expected_resume。

use serde::{Deserialize, Serialize};

/// 一次已确认的函数调用激活。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedActivation {
    pub id: u32,
    pub func_addr: u64,
    #[serde(default)]
    pub func_name: Option<String>,
    /// BL/BLR 指令的 seq
    pub call_seq: u32,
    /// 第一条属于 child 的指令 seq
    pub entry_seq: u32,
    /// 最后一条属于 child 的指令 seq
    pub exit_seq: u32,
    /// 恢复到 callsite + 4 的地址（expected_resume）
    pub expected_resume: u64,
    /// 恢复到 callsite + 4 的 seq（即 expected_resume 命中的 seq）
    pub resume_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    /// 是否未闭合（trace 截断、丢行或无法归属）
    pub unresolved: bool,
}

/// 待确认的调用候选：BL/BLR 创建，等待下一条指令确认。
#[derive(Debug, Clone)]
pub(crate) struct ActivationCandidate {
    pub call_seq: u32,
    /// callsite + 4（BL/BLR 的下一条指令地址）
    pub expected_resume: u64,
    pub func_addr: u64,
    pub parent_id: u32,
}

/// Confirmed Activation 构建器。
///
/// 核心规则：
/// 1. BL/BLR 创建带 `expected_resume = callsite + 4` 的 candidate。
/// 2. 下一条实际指令决定 candidate 是没有记录函数体，还是进入 active Activation。
/// 3. 每次读取指令前检查当前 PC 是否到达栈顶调用的 `expected_resume`。
/// 4. 到达 resume 时，用前一条属于 child 的指令作为 exit。
/// 5. `B`、`BR` 和 `RET` 本身不负责弹出 Activation。
/// 6. nested call 使用同一调用栈规则。
/// 7. 未闭合、丢行或无法归属的 candidate 保留 unresolved 状态。
pub struct ActivationBuilder {
    activations: Vec<ConfirmedActivation>,
    /// 当前活跃的调用栈（activation id）
    active_stack: Vec<u32>,
    /// 待确认的 candidate（BL/BLR 创建，下一条指令确认）
    pending: Option<ActivationCandidate>,
    next_id: u32,
    /// 当前活跃的 activation id（0 = root）
    current_id: u32,
}

impl Default for ActivationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivationBuilder {
    pub fn new() -> Self {
        let root = ConfirmedActivation {
            id: 0,
            func_addr: 0,
            func_name: None,
            call_seq: 0,
            entry_seq: 0,
            exit_seq: u32::MAX,
            expected_resume: 0,
            resume_seq: u32::MAX,
            parent_id: None,
            children_ids: Vec::new(),
            unresolved: false,
        };
        Self {
            activations: vec![root],
            active_stack: Vec::new(),
            pending: None,
            next_id: 1,
            current_id: 0,
        }
    }

    /// 设置根节点的地址（用 trace 第一行的实际指令地址）
    pub fn set_root_addr(&mut self, addr: u64) {
        self.activations[0].func_addr = addr;
    }

    /// BL/BLR 指令：创建 candidate，等待下一条指令确认。
    ///
    /// `callsite_addr` 是 BL/BLR 指令的地址，`target_addr` 是调用目标地址。
    pub fn on_call(&mut self, call_seq: u32, callsite_addr: u64, target_addr: u64) {
        // 如果之前有 pending candidate 且没有确认，标记为 unresolved
        if let Some(candidate) = self.pending.take() {
            self.resolve_candidate(candidate, call_seq, None, true);
        }

        self.pending = Some(ActivationCandidate {
            call_seq,
            expected_resume: callsite_addr + 4,
            func_addr: target_addr,
            parent_id: self.current_id,
        });
    }

    /// 每条指令读取前调用：检查当前 PC 是否到达栈顶调用的 expected_resume。
    ///
    /// 返回：如果到达了 resume，返回 Some(resume_seq)。
    pub fn check_resume(&mut self, current_pc: u64, current_seq: u32) -> Option<u32> {
        // 检查是否有 pending candidate 需要确认
        if let Some(candidate) = self.pending.take() {
            if current_pc == candidate.expected_resume {
                // 没有记录函数体：candidate 直接恢复到 callsite + 4
                self.resolve_candidate(candidate, current_seq, None, false);
                return Some(current_seq);
            } else {
                // 进入 active Activation：第一条指令确认
                let entry_seq = current_seq;
                self.resolve_candidate(candidate, entry_seq, Some(current_seq), false);
                return None;
            }
        }

        // 检查当前活跃的 Activation 是否到达 resume
        if let Some(&active_id) = self.active_stack.last() {
            let active = &self.activations[active_id as usize];
            if current_pc == active.expected_resume {
                let parent_id = active.parent_id.unwrap_or(0);
                // 到达 resume：用前一条属于 child 的指令作为 exit
                let exit_seq = current_seq.saturating_sub(1);
                self.activations[active_id as usize].exit_seq = exit_seq;
                self.activations[active_id as usize].resume_seq = current_seq;
                self.active_stack.pop();
                self.current_id = parent_id;
                return Some(current_seq);
            }
        }

        None
    }

    /// RET 指令：不直接弹出 Activation，只记录可能的 exit。
    pub fn on_ret(&mut self, seq: u32) {
        // RET 本身不负责弹出 Activation。弹出由 check_resume 的 expected_resume 确认。
        // 但 RET 可以作为 exit_seq 的候选。
        if let Some(&active_id) = self.active_stack.last() {
            self.activations[active_id as usize].exit_seq = seq;
        }
    }

    /// 确认 candidate：要么没有记录函数体（entry=None），要么进入 active Activation。
    fn resolve_candidate(
        &mut self,
        candidate: ActivationCandidate,
        confirm_seq: u32,
        entry_seq: Option<u32>,
        unresolved: bool,
    ) {
        let id = self.next_id;
        self.next_id += 1;

        let activation = ConfirmedActivation {
            id,
            func_addr: candidate.func_addr,
            func_name: None,
            call_seq: candidate.call_seq,
            entry_seq: entry_seq.unwrap_or(confirm_seq),
            exit_seq: if unresolved { u32::MAX } else { confirm_seq },
            expected_resume: candidate.expected_resume,
            resume_seq: if unresolved { u32::MAX } else { confirm_seq },
            parent_id: Some(candidate.parent_id),
            children_ids: Vec::new(),
            unresolved,
        };

        self.activations.push(activation);
        self.activations[candidate.parent_id as usize]
            .children_ids
            .push(id);

        if entry_seq.is_some() {
            // 进入 active Activation
            self.active_stack.push(id);
            self.current_id = id;
        }
    }

    /// 根据 entry_seq 查找 activation 并设置 func_name
    pub fn set_func_name_by_entry_seq(&mut self, entry_seq: u32, name: &str) {
        for activation in self.activations.iter_mut().rev() {
            if activation.entry_seq == entry_seq {
                activation.func_name = Some(name.to_string());
                return;
            }
        }
    }

    /// 更新当前 activation 的 func_addr（用于 BLR 后从下一行获取实际目标地址）
    pub fn update_current_func_addr(&mut self, addr: u64) {
        if self.current_id != 0 {
            self.activations[self.current_id as usize].func_addr = addr;
        }
    }

    /// 完成构建：标记未闭合的 activation 为 unresolved。
    pub fn finish(mut self, total_lines: u32) -> ActivationTree {
        // 处理未确认的 pending candidate
        if let Some(candidate) = self.pending.take() {
            self.resolve_candidate(candidate, total_lines.saturating_sub(1), None, true);
        }

        // 标记未闭合的 active activation 为 unresolved
        while let Some(active_id) = self.active_stack.pop() {
            self.activations[active_id as usize].unresolved = true;
            self.activations[active_id as usize].exit_seq = total_lines.saturating_sub(1);
            self.current_id = self.activations[active_id as usize].parent_id.unwrap_or(0);
        }

        self.activations[0].exit_seq = total_lines.saturating_sub(1);
        ActivationTree {
            activations: self.activations,
        }
    }
}

/// Confirmed Activation 树。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationTree {
    pub activations: Vec<ConfirmedActivation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_call_and_ret() {
        let mut b = ActivationBuilder::new();
        // BL at seq=5, callsite=0x1000, target=0x2000
        b.on_call(5, 0x1000, 0x2000);
        // Next instruction at seq=6, pc=0x2000 (entry to function)
        b.check_resume(0x2000, 6);
        // RET at seq=10
        b.on_ret(10);
        // Next instruction at seq=11, pc=0x1004 (resume to callsite+4)
        b.check_resume(0x1004, 11);
        let tree = b.finish(15);
        assert_eq!(tree.activations.len(), 2);
        assert_eq!(tree.activations[1].func_addr, 0x2000);
        assert_eq!(tree.activations[1].entry_seq, 6);
        assert_eq!(tree.activations[1].exit_seq, 10);
        assert_eq!(tree.activations[1].resume_seq, 11);
        assert!(!tree.activations[1].unresolved);
    }

    #[test]
    fn call_without_recorded_body() {
        let mut b = ActivationBuilder::new();
        // BL at seq=5, callsite=0x1000, target=0x2000
        b.on_call(5, 0x1000, 0x2000);
        // Next instruction at seq=6, pc=0x1004 (resume to callsite+4, no function body)
        b.check_resume(0x1004, 6);
        let tree = b.finish(10);
        assert_eq!(tree.activations.len(), 2);
        assert_eq!(tree.activations[1].entry_seq, 6);
        assert_eq!(tree.activations[1].exit_seq, 6);
        assert_eq!(tree.activations[1].resume_seq, 6);
        assert!(!tree.activations[1].unresolved);
    }

    #[test]
    fn nested_calls() {
        let mut b = ActivationBuilder::new();
        // BL at seq=5, callsite=0x1000, target=0x2000
        b.on_call(5, 0x1000, 0x2000);
        b.check_resume(0x2000, 6); // entry to first function
                                   // BL at seq=10, callsite=0x2000, target=0x3000
        b.on_call(10, 0x2000, 0x3000);
        b.check_resume(0x3000, 11); // entry to second function
        b.on_ret(15);
        b.check_resume(0x2004, 16); // resume to first function
        b.on_ret(20);
        b.check_resume(0x1004, 21); // resume to root
        let tree = b.finish(25);
        assert_eq!(tree.activations.len(), 3);
        assert_eq!(tree.activations[1].func_addr, 0x2000);
        assert_eq!(tree.activations[2].func_addr, 0x3000);
        assert!(!tree.activations[1].unresolved);
        assert!(!tree.activations[2].unresolved);
    }

    #[test]
    fn trace_truncation_marks_unresolved() {
        let mut b = ActivationBuilder::new();
        b.on_call(5, 0x1000, 0x2000);
        b.check_resume(0x2000, 6); // entry to function
                                   // trace ends without resume
        let tree = b.finish(10);
        assert_eq!(tree.activations.len(), 2);
        assert!(tree.activations[1].unresolved);
        assert_eq!(tree.activations[1].exit_seq, 9);
    }

    #[test]
    fn unconfirmed_candidate_marks_unresolved() {
        let mut b = ActivationBuilder::new();
        b.on_call(5, 0x1000, 0x2000);
        // another call before confirming the first
        b.on_call(10, 0x3000, 0x4000);
        b.check_resume(0x4000, 11); // entry to second function
        let tree = b.finish(15);
        // first candidate is unresolved
        assert!(tree.activations[1].unresolved);
        assert_eq!(tree.activations[2].func_addr, 0x4000);
    }
}
