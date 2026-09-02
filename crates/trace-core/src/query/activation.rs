//! Confirmed Activation：由 `call → entry → exit → resume` 确认的函数调用激活记录。
//!
//! 边界规则（正式设计 `docs/trace-ui/function-boundaries.md`）：
//! - `call`：caller 执行 BL/BLR 的位置（seq + callsite PC）。
//! - `entry`：call 后实际执行的第一条 callee 指令（seq + PC）。函数身份用 entry PC，
//!   不用 BL 立即数或 BLR 寄存器值（入口可能是 thunk/PLT，真实入口由实际执行决定）。
//! - `exit`：恢复到 caller 前实际执行的最后一条指令（seq + PC）。special line 和无法
//!   解析行占 seq 但不是指令，不能作为 entry/exit。
//! - `resume`：caller 的 expected resume 指令（callsite PC + 4）。
//!
//! `next PC == expected_resume` 的调用没有记录函数体，保存为 [`BypassedCall`]
//! （调用和返回事实），不生成 ConfirmedActivation，也不生成被调函数 CFG。
//!
//! 与 CallTreeNode 的区别：CallTreeNode 在 RET 时出栈，不能处理"未记录函数体后
//! 直接恢复到 callsite + 4"。本模型用 expected_resume 确认边界：BL/BLR 创建
//! candidate，下一条实际指令决定 candidate 是 bypassed 还是进入 active Activation；
//! 每条实际指令读取前检查当前 PC 是否到达栈顶的 expected_resume。

use serde::{Deserialize, Serialize};

/// 一次已确认的函数调用激活（实际观察到函数体）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedActivation {
    pub id: u32,
    /// 已确认入口 PC（call 后第一条实际执行的 callee 指令地址）
    pub func_addr: u64,
    #[serde(default)]
    pub func_name: Option<String>,
    /// BL/BLR 指令的 seq
    pub call_seq: u32,
    /// BL/BLR 指令的 PC（callsite）
    pub call_pc: u64,
    /// 第一条属于 child 的指令 seq
    pub entry_seq: u32,
    /// 第一条属于 child 的指令 PC（== func_addr）
    pub entry_pc: u64,
    /// 最后一条属于 child 的指令 seq
    pub exit_seq: u32,
    /// 最后一条属于 child 的指令 PC
    pub exit_pc: u64,
    /// expected resume 地址（callsite + 4）
    pub expected_resume: u64,
    /// resume 指令的 seq（expected_resume 命中时的 seq）
    pub resume_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    /// 未闭合原因。None = 已确认；Some = 截断/丢行/未到达 resume 等。
    pub unresolved_reason: Option<UnresolvedReason>,
}

/// 未闭合原因。只有 bool 无法区分截断与边界算法错误，审查要求可判定原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedReason {
    /// trace 结束时该 Activation 仍处于 active 状态（截断或 trace 本身不完整）
    TraceEndStillActive,
    /// call 后下一条实际指令 PC 既不是 expected_resume 也不是调用目标
    NextInsnNeitherEntryNorResume,
    /// candidate 被下一个 BL/BLR 直接取代（两个 call 之间没有实际指令）
    DisplacedByAnotherCall,
    /// trace 在 call 后立即结束，candidate 没有观察到下一条指令
    NoNextInsn,
}

/// 没有记录函数体的调用：只保存调用和返回事实。
///
/// 下一条实际指令 PC 直接等于 expected_resume（callsite + 4）时发生（例如 unidbg
/// 拦截调用）。这类调用不生成 ConfirmedActivation，也不生成被调函数 CFG
/// （cfg-generation.md 限制节）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassedCall {
    pub call_seq: u32,
    pub call_pc: u64,
    pub expected_resume: u64,
    /// 下一条实际指令 == expected_resume 的 seq，即返回到 caller 的 seq
    pub resume_seq: u32,
    /// 该调用发生时所在的 activation（None = 根上下文）
    pub parent_id: Option<u32>,
}

/// 待确认的调用候选：BL/BLR 创建，等待下一条实际指令确认。
///
/// 不保存 BL 立即数/BLR 寄存器值：函数身份只来自 entry 实际 PC，目标提示
/// 在旧模型中用于判断“下一条 == 调用目标”，新模型用“下一条 != expected_resume”
/// 判定，目标值没有用途。
#[derive(Debug, Clone)]
struct ActivationCandidate {
    call_seq: u32,
    call_pc: u64,
    /// callsite + 4
    expected_resume: u64,
    parent_id: u32,
}

/// 每条实际指令喂给 builder 的位置事实。
///
/// 特殊行（call func:/ret:/hexdump）与无法解析行占 seq 但不是指令，不产生本事件。
#[derive(Debug, Clone, Copy)]
pub struct InsnFact {
    pub seq: u32,
    pub pc: u64,
}

impl InsnFact {
    pub fn new(seq: u32, pc: u64) -> Self {
        Self { seq, pc }
    }
}

/// Confirmed Activation 构建器。
///
/// 规则（function-boundaries.md 确认规则 1–8）：
/// 1. 只有实际执行的 BL/BLR 创建 candidate。
/// 2. call 后下一条实际 PC 决定候选入口。
/// 3. B/BR/RET 不创建或结束 Activation。
/// 4. 执行流到达 candidate 的 expected_resume 时才确认边界。
/// 5. resume 前一条实际指令是 exit。
/// 6. 调用栈单线程维护：当前 trace 格式没有线程身份字段，session 显式按单线程处理。
/// 7. trace 截断、丢行或始终未到达 resume 时保持 unresolved。
/// 8. trace 从函数中部开始时根上下文为 trace_root（id 0）。
pub struct ActivationBuilder {
    activations: Vec<ConfirmedActivation>,
    /// 没有记录函数体的调用（单独保存，不进 activations）
    bypassed_calls: Vec<BypassedCall>,
    /// 当前活跃的调用栈（栈顶 = 最内层 child）。恒非空：至少含 root。
    active_stack: Vec<u32>,
    /// 最近一条实际指令。exit 取这里，不用 seq-1（special line 不算指令）。
    last_insn: Option<InsnFact>,
    pending: Option<ActivationCandidate>,
    next_id: u32,
}

impl Default for ActivationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivationBuilder {
    pub fn new() -> Self {
        // 根上下文 id 0：trace 从函数中部开始时它就是 trace_root——没有 call，
        // 指令从 seq 0 直接开始。expected_resume = 0 永不命中（PC 0 不是有效指令）。
        let root = ConfirmedActivation {
            id: 0,
            func_addr: 0,
            func_name: None,
            call_seq: 0,
            call_pc: 0,
            entry_seq: 0,
            entry_pc: 0,
            exit_seq: 0,
            exit_pc: 0,
            expected_resume: 0,
            resume_seq: 0,
            parent_id: None,
            children_ids: Vec::new(),
            unresolved_reason: None,
        };
        Self {
            activations: vec![root],
            bypassed_calls: Vec::new(),
            active_stack: vec![0],
            last_insn: None,
            pending: None,
            next_id: 1,
        }
    }

    /// 喂入一条实际指令。扫描器对每条解析成功的指令行调用（special line 与无法
    /// 解析行不调用）。返回本条指令归属的 activation id。
    pub fn on_insn(&mut self, fact: InsnFact) -> u32 {
        // 规则 4：先检查是否命中栈顶的 expected_resume，命中则闭合
        if self.check_resume(fact.pc, fact.seq).is_some() {
            self.last_insn = Some(fact);
            return self.current_id();
        }

        // 规则 2：pending candidate 由下一条实际指令确认
        if let Some(candidate) = self.pending.take() {
            if fact.pc == candidate.expected_resume {
                // 没有记录函数体：只保存调用事实，不伪造 ConfirmedActivation
                self.bypassed_calls.push(BypassedCall {
                    call_seq: candidate.call_seq,
                    call_pc: candidate.call_pc,
                    expected_resume: candidate.expected_resume,
                    resume_seq: fact.seq,
                    parent_id: (candidate.parent_id != 0).then_some(candidate.parent_id),
                });
            } else {
                // 下一条指令不等于 expected_resume → 进入 active Activation。
                // entry PC 就是这条指令的 PC（函数身份来源），target_hint 不作身份。
                self.activate_candidate(candidate, fact);
            }
        }

        self.last_insn = Some(fact);
        self.current_id()
    }

    /// BL/BLR 指令：创建 candidate，等待下一条实际指令确认。
    ///
    /// 不接受目标提示：函数身份只来自 entry 实际 PC（审查 CRITICAL 2），
    /// BL 立即数/BLR 寄存器值不进入模型。
    pub fn on_call(&mut self, call_seq: u32, call_pc: u64) {
        if let Some(candidate) = self.pending.take() {
            // 两个 call 之间没有任何实际指令：前一个 candidate 无法确认
            self.push_unresolved(candidate, UnresolvedReason::DisplacedByAnotherCall);
        }

        self.pending = Some(ActivationCandidate {
            call_seq,
            call_pc,
            expected_resume: call_pc + 4,
            parent_id: self.current_id(),
        });
    }

    /// 检查当前 PC 是否命中栈顶的 expected_resume；命中则闭合该 Activation。
    ///
    /// root 的 expected_resume 是 0，实际指令 PC 非 0，永不闭合（规则 8）。
    fn check_resume(&mut self, current_pc: u64, current_seq: u32) -> Option<u32> {
        let &active_id = self.active_stack.last()?;
        if self.activations[active_id as usize].expected_resume != current_pc {
            return None;
        }
        if active_id == 0 {
            return None;
        }

        // 规则 5：exit = resume 前一条实际指令（last_insn），不是 current_seq - 1
        let exit = self
            .last_insn
            .expect("active activation must have at least the entry insn");
        let activation = &mut self.activations[active_id as usize];
        activation.exit_seq = exit.seq;
        activation.exit_pc = exit.pc;
        activation.resume_seq = current_seq;
        self.active_stack.pop();
        Some(active_id)
    }

    /// candidate 确认为 active Activation。
    fn activate_candidate(&mut self, candidate: ActivationCandidate, entry: InsnFact) {
        let id = self.next_id;
        self.next_id += 1;
        let activation = ConfirmedActivation {
            id,
            func_addr: entry.pc, // 函数身份 = entry 实际 PC（稳定身份规则）
            func_name: None,
            call_seq: candidate.call_seq,
            call_pc: candidate.call_pc,
            entry_seq: entry.seq,
            entry_pc: entry.pc,
            exit_seq: entry.seq,
            exit_pc: entry.pc,
            expected_resume: candidate.expected_resume,
            resume_seq: 0,
            parent_id: Some(candidate.parent_id),
            children_ids: Vec::new(),
            unresolved_reason: None,
        };
        self.activations.push(activation);
        self.activations[candidate.parent_id as usize]
            .children_ids
            .push(id);
        self.active_stack.push(id);
    }

    /// 追加一条未确认的 activation 记录（保留调用事实 + 失败原因）。
    fn push_unresolved(&mut self, candidate: ActivationCandidate, reason: UnresolvedReason) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let activation = ConfirmedActivation {
            id,
            func_addr: 0, // 未观察到 entry，没有函数身份
            func_name: None,
            call_seq: candidate.call_seq,
            call_pc: candidate.call_pc,
            entry_seq: 0,
            entry_pc: 0,
            exit_seq: 0,
            exit_pc: 0,
            expected_resume: candidate.expected_resume,
            resume_seq: 0,
            parent_id: Some(candidate.parent_id),
            children_ids: Vec::new(),
            unresolved_reason: Some(reason),
        };
        self.activations.push(activation);
        self.activations[candidate.parent_id as usize]
            .children_ids
            .push(id);
        id
    }

    /// 当前栈顶 activation id（栈恒非空）。
    pub fn current_id(&self) -> u32 {
        *self.active_stack.last().unwrap_or(&0)
    }

    /// 完成构建：处理 pending、标记未闭合、返回树。
    pub fn finish(mut self, total_lines: u32) -> ActivationTree {
        if let Some(candidate) = self.pending.take() {
            self.push_unresolved(candidate, UnresolvedReason::NoNextInsn);
        }

        // 栈上未闭合的非 root activation：trace 截断
        while let Some(active_id) = self.active_stack.pop() {
            if active_id == 0 {
                continue;
            }
            let exit = self.last_insn.expect("active activation must have an insn");
            let activation = &mut self.activations[active_id as usize];
            activation.exit_seq = exit.seq;
            activation.exit_pc = exit.pc;
            activation.unresolved_reason = Some(UnresolvedReason::TraceEndStillActive);
        }

        self.activations[0].exit_seq = total_lines;
        ActivationTree {
            activations: self.activations,
            bypassed_calls: self.bypassed_calls,
        }
    }
}

/// Confirmed Activation 树 + bypassed 调用集合。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationTree {
    pub activations: Vec<ConfirmedActivation>,
    /// 没有记录函数体的调用（不参与 Confirmed Function 聚合）
    pub bypassed_calls: Vec<BypassedCall>,
}

impl ActivationTree {
    /// 按 seq 查询唯一归属的非 root Activation。
    ///
    /// 多层嵌套时返回最内层（seq 同时落在 parent 和 child range 时取 child，因为
    /// child range 是 parent 动态范围的真子集减去更深层）。已确认的 activation
    /// （unresolved_reason == None）才参与归属；unresolved 记录没有可信边界。
    pub fn activation_for_seq(&self, seq: u32) -> Option<&ConfirmedActivation> {
        let mut best: Option<&ConfirmedActivation> = None;
        for activation in &self.activations[1..] {
            if activation.unresolved_reason.is_some() {
                continue;
            }
            if seq < activation.entry_seq || seq > activation.exit_seq {
                continue;
            }
            // 取 range 最小（最内层）的一条
            let span = activation.exit_seq - activation.entry_seq;
            if best.is_none_or(|b| span < b.exit_seq - b.entry_seq) {
                best = Some(activation);
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(seq: u32, pc: u64) -> InsnFact {
        InsnFact::new(seq, pc)
    }

    #[test]
    fn simple_call_entry_exit_resume() {
        let mut b = ActivationBuilder::new();
        // root 指令
        assert_eq!(b.on_insn(fact(0, 0x1000)), 0);
        assert_eq!(b.on_insn(fact(1, 0x1004)), 0);
        // BL at seq=2, callsite=0x1008, target_hint=0x2000
        b.on_call(2, 0x1008);
        // entry：下一条实际指令在 callee（PC != 0x100C）
        let child = b.on_insn(fact(3, 0x2000));
        assert_ne!(child, 0);
        // callee 体
        b.on_insn(fact(4, 0x2004));
        // 最后一条 callee 指令 seq=5（PC 0x2008，比如 RET）
        b.on_insn(fact(5, 0x2008));
        // resume：PC == callsite+4
        b.on_insn(fact(6, 0x100C));
        let tree = b.finish(7);

        assert_eq!(tree.activations.len(), 2);
        let a = &tree.activations[1];
        assert_eq!(a.func_addr, 0x2000, "函数身份 = entry 实际 PC");
        assert_eq!(a.entry_seq, 3);
        assert_eq!(a.entry_pc, 0x2000);
        assert_eq!(a.exit_seq, 5, "exit = 前一条实际指令");
        assert_eq!(a.exit_pc, 0x2008);
        assert_eq!(a.resume_seq, 6);
        assert!(a.unresolved_reason.is_none());
        assert!(tree.bypassed_calls.is_empty());
        // 归属查询
        assert_eq!(tree.activation_for_seq(4).map(|a| a.id), Some(1));
        assert_eq!(
            tree.activation_for_seq(1).map(|a| a.id),
            None,
            "root 指令不归属任何非 root activation"
        );
    }

    #[test]
    fn call_without_recorded_body_is_bypassed_not_fake_activation() {
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        b.on_call(1, 0x1004);
        // 下一条实际指令直接是 expected_resume：无函数体
        b.on_insn(fact(2, 0x1008));
        b.on_insn(fact(3, 0x100C));
        let tree = b.finish(4);

        // 不伪造 ConfirmedActivation：只有 root
        assert_eq!(
            tree.activations.len(),
            1,
            "无函数体调用不得进入 ConfirmedActivation 集合"
        );
        // 调用事实单独保存
        assert_eq!(tree.bypassed_calls.len(), 1);
        let c = &tree.bypassed_calls[0];
        assert_eq!(c.call_seq, 1);
        assert_eq!(c.call_pc, 0x1004);
        assert_eq!(c.expected_resume, 0x1008);
        assert_eq!(c.resume_seq, 2);
        assert_eq!(c.parent_id, None);
    }

    #[test]
    fn nested_calls_innermost_ownership() {
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        // outer call
        b.on_call(1, 0x1004);
        let outer = b.on_insn(fact(2, 0x2000));
        b.on_insn(fact(3, 0x2004));
        // inner call from outer
        b.on_call(4, 0x2008);
        let inner = b.on_insn(fact(5, 0x3000));
        assert_ne!(inner, outer);
        b.on_insn(fact(6, 0x3004));
        // inner resume
        b.on_insn(fact(7, 0x200C));
        // outer 后续
        b.on_insn(fact(8, 0x2010));
        // outer resume
        b.on_insn(fact(9, 0x1008));
        let tree = b.finish(10);

        assert_eq!(tree.activations.len(), 3);
        let o = &tree.activations[1];
        let i = &tree.activations[2];
        assert!(o.unresolved_reason.is_none());
        assert!(i.unresolved_reason.is_none());
        assert_eq!(i.entry_seq, 5);
        assert_eq!(i.exit_seq, 6);
        assert_eq!(i.resume_seq, 7);
        assert_eq!(o.exit_seq, 8, "outer exit 是 resume 前最后一条实际指令");
        // 嵌套归属：最内层优先
        assert_eq!(tree.activation_for_seq(5).map(|a| a.id), Some(inner));
        assert_eq!(tree.activation_for_seq(8).map(|a| a.id), Some(outer));
    }

    #[test]
    fn b_br_ret_do_not_pop_activation() {
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        b.on_call(1, 0x1004);
        b.on_insn(fact(2, 0x2000));
        // B/BR 跳到别处（仍在 callee 上下文）
        b.on_insn(fact(3, 0x2F00));
        // RET（PC 无关，只有 expected_resume 命中才闭合）
        b.on_insn(fact(4, 0x2F04));
        // 仍未闭合：下一条不是 0x1008
        assert_eq!(b.on_insn(fact(5, 0x2F08)), b.current_id());
        // 正式 resume
        b.on_insn(fact(6, 0x1008));
        let tree = b.finish(7);

        let a = &tree.activations[1];
        assert!(a.unresolved_reason.is_none());
        assert_eq!(a.exit_seq, 5, "B/BR/RET 不弹出，exit 是 resume 前最后一条");
        assert_eq!(a.exit_pc, 0x2F08);
    }

    #[test]
    fn trace_truncation_marks_reason() {
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        b.on_call(1, 0x1004);
        b.on_insn(fact(2, 0x2000));
        b.on_insn(fact(3, 0x2004));
        // trace 在 resume 前结束
        let tree = b.finish(4);

        let a = &tree.activations[1];
        assert_eq!(
            a.unresolved_reason,
            Some(UnresolvedReason::TraceEndStillActive)
        );
        assert_eq!(a.exit_seq, 3, "截断时 exit 用最后观察到的指令");
    }

    #[test]
    fn pending_candidate_at_trace_end_marks_no_next_insn() {
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        b.on_call(1, 0x1004);
        // trace 在 call 后立即结束
        let tree = b.finish(2);

        let a = &tree.activations[1];
        assert_eq!(a.unresolved_reason, Some(UnresolvedReason::NoNextInsn));
        assert_eq!(a.func_addr, 0, "未观察到 entry，没有函数身份");
    }

    #[test]
    fn consecutive_calls_displace_pending() {
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        b.on_call(1, 0x1004);
        // 没有任何指令，直接另一个 call
        b.on_call(2, 0x1008);
        b.on_insn(fact(3, 0x3000));
        b.on_insn(fact(4, 0x100C));
        let tree = b.finish(5);

        assert_eq!(
            tree.activations[1].unresolved_reason,
            Some(UnresolvedReason::DisplacedByAnotherCall)
        );
        assert!(tree.activations[2].unresolved_reason.is_none());
    }

    #[test]
    fn special_lines_between_insns_do_not_break_exit() {
        // CRITICAL 3 回归：special line / 无法解析行占 seq 但不是指令。
        // 模拟：entry seq=3，中间 seq=4 是 special line（不喂 on_insn），
        // resume 前 last_insn 必须是 seq=5 的实际指令，而不是 seq-1=5 恰好相同的
        // 情况——再构造 resume seq=7（中间 seq=6 是 special line），exit 必须是 5。
        let mut b = ActivationBuilder::new();
        b.on_insn(fact(0, 0x1000));
        b.on_call(1, 0x1004);
        b.on_insn(fact(2, 0x2000));
        // seq=3: special line（不喂）
        b.on_insn(fact(4, 0x2004));
        // seq=5: special line（不喂）；seq=6: 特殊行之后 callee 最后一条实际指令
        b.on_insn(fact(6, 0x2008));
        // seq=7: 又一个 special line（不喂）；seq=8: resume
        b.on_insn(fact(8, 0x1008));
        let tree = b.finish(9);

        let a = &tree.activations[1];
        assert_eq!(
            a.exit_seq, 6,
            "exit 用最后一条实际指令，不是 resume_seq-1=7"
        );
        assert_eq!(a.resume_seq, 8);
    }
}
