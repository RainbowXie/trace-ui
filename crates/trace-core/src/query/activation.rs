//! Confirmed Activation：由 `call → entry → exit → resume` 确认的函数调用激活记录。
//!
//! 边界规则（正式设计 `docs/trace-ui/function-boundaries.md`）：
//! - `call`：caller 执行 BL/BLR 的位置（seq + callsite PC）。
//! - `entry`：call 后实际执行的第一条 callee 指令。函数身份 = entry 的稳定
//!   `module+offset`（在查询层由原始行解析；本结构保存 seq + PC 供解析）。
//! - `exit`：恢复到 caller 前实际执行的最后一条指令。special line 和无法解析行
//!   占 seq 但不是指令，不能作为 entry/exit。
//! - `resume`：caller 的 expected resume 指令（callsite PC + 4）。
//!
//! `next PC == expected_resume` 的调用没有记录函数体，保存为 [`BypassedCall`]
//! （调用和返回事实），不生成 ConfirmedActivation，也不生成被调函数 CFG。
//!
//! 身份说明：本结构保存的 PC 是 ASLR 运行时地址，是 trace 事实，不是对外身份。
//! 正式身份（`module+offset`、`<session>:call@<seq>`）在 engine 查询层由
//! LineIndex 回读原始行生成，见 `engine/query/activation.rs`。
//!
//! 与 CallTreeNode 的区别：CallTreeNode 在 RET 时出栈，不能处理"未记录函数体后
//! 直接恢复到 callsite + 4"。本模型用 expected_resume 确认边界。

use serde::{Deserialize, Serialize};

/// 一次已确认的函数调用激活（实际观察到函数体）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedActivation {
    pub id: u32,
    /// 已确认入口 PC（call 后第一条实际执行的 callee 指令地址）。
    /// 稳定身份（module+offset）由查询层从 entry_seq 原始行解析。
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

/// 未闭合原因。只有 bool 无法区分截断与边界算法错误。
///
/// 注意：正式状态机规定 `next PC != expected_resume → active(entry = next PC)`，
/// 即 call 后任何不等于 expected_resume 的下一条指令都成为 entry——因此不存在
/// "既不是 entry 也不是 resume" 的第四种状态，枚举只有以下三种。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedReason {
    /// trace 结束时该 Activation 仍处于 active 状态（截断或 trace 本身不完整）
    TraceEndStillActive,
    /// candidate 被下一个 BL/BLR 直接取代（两个 call 之间没有实际指令）
    DisplacedByAnotherCall,
    /// trace 在 call 后立即结束，candidate 没有观察到下一条指令
    NoNextInsn,
}

/// 没有记录函数体的调用：只保存调用和返回事实。
///
/// 下一条实际指令 PC 直接等于 expected_resume（callsite + 4）时发生（例如
/// JNI/unidbg 拦截调用）。这类调用不生成 ConfirmedActivation，也不生成被调
/// 函数 CFG（cfg-generation.md 限制节）。
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
/// 不保存 BL 立即数/BLR 寄存器值：函数身份只来自 entry 实际 PC。
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
/// 2. call 后下一条实际 PC 决定候选入口（== expected_resume → bypassed，
///    否则 → active，entry = 该指令）。
/// 3. B/BR/RET 不创建或结束 Activation。
/// 4. 执行流到达 candidate 的 expected_resume 时才确认边界。
/// 5. resume 前一条实际指令是 exit。
/// 6. 调用栈单线程维护：当前 trace 格式没有线程身份字段，session 显式按单线程处理。
/// 7. trace 截断、丢行或始终未到达 resume 时保持 unresolved。
/// 8. trace 从函数中部开始时根上下文为 trace_root（id 0）。
///
/// 指令处理顺序（审查反例修正）：pending candidate 先于 parent resume。
/// 递归调用复用同一 callsite 时，resume 指令的 PC 同时等于 candidate 和 parent
/// 的 expected_resume——该指令此刻是 candidate 的 resume（控制流仍在 parent
/// 激活内），不是 parent 的返回。candidate 消耗该指令后 parent 继续等待自己的
/// expected_resume。
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
            call_seq: u32::MAX, // 哨兵：root 没有 call，避免与 seq 0 的真实 call 冲突
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
        // 规则 2 优先：pending candidate 由下一条实际指令决定。
        // 该指令同时被 candidate 完全消耗——不再检查 parent 的 expected_resume
        //（递归同 callsite 场景，见类型文档）。
        if let Some(candidate) = self.pending.take() {
            if fact.pc == candidate.expected_resume {
                // 没有记录函数体：只保存调用事实，不伪造 ConfirmedActivation。
                // 本条指令在 caller（candidate 的 parent）上下文内继续执行。
                self.bypassed_calls.push(BypassedCall {
                    call_seq: candidate.call_seq,
                    call_pc: candidate.call_pc,
                    expected_resume: candidate.expected_resume,
                    resume_seq: fact.seq,
                    parent_id: (candidate.parent_id != 0).then_some(candidate.parent_id),
                });
            } else {
                // 下一条指令不等于 expected_resume → 进入 active Activation，
                // entry = 本条指令（函数身份来源）。
                self.activate_candidate(candidate, fact);
            }
            self.last_insn = Some(fact);
            return self.current_id();
        }

        // 无 pending：规则 4，检查是否命中栈顶的 expected_resume，命中则闭合。
        if self.check_resume(fact.pc, fact.seq).is_some() {
            self.last_insn = Some(fact);
            return self.current_id();
        }

        self.last_insn = Some(fact);
        self.current_id()
    }

    /// BL/BLR 指令：创建 candidate，等待下一条实际指令确认。
    ///
    /// 不接受目标提示：函数身份只来自 entry 实际 PC，
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
    /// 只在无 pending 时调用（见 `on_insn` 顺序说明）。
    /// root 的 expected_resume 是 0，实际指令 PC 非 0，永不闭合（规则 8）。
    fn check_resume(&mut self, current_pc: u64, current_seq: u32) -> Option<u32> {
        let &active_id = self.active_stack.last()?;
        if active_id == 0 {
            return None;
        }
        if self.activations[active_id as usize].expected_resume != current_pc {
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
            func_addr: entry.pc,
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

    /// 完成构建：处理 pending、标记未闭合、构建查询索引、返回树。
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

        // 查询索引：confirmed activation 按 entry_seq 严格递增（激活按时间顺序）。
        // debug_assert 防御未来改动破坏二分前提。
        let confirmed_ids: Vec<u32> = self
            .activations
            .iter()
            .filter(|a| a.id != 0 && a.unresolved_reason.is_none())
            .map(|a| a.id)
            .collect();
        debug_assert!(
            confirmed_ids
                .windows(2)
                .all(|w| self.activations[w[0] as usize].entry_seq
                    < self.activations[w[1] as usize].entry_seq),
            "confirmed activation entry_seq 必须按 id 严格递增"
        );

        ActivationTree {
            activations: self.activations,
            confirmed_ids,
            bypassed_calls: self.bypassed_calls,
        }
    }
}

/// Confirmed Activation 树 + bypassed 调用集合。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationTree {
    pub activations: Vec<ConfirmedActivation>,
    /// confirmed activation 的 id 索引，按 entry_seq 严格递增（二分查找用）
    pub confirmed_ids: Vec<u32>,
    /// 没有记录函数体的调用（不参与 Confirmed Function 聚合）。
    /// 按 call_seq 严格递增（确认顺序 = 调用顺序）。
    pub bypassed_calls: Vec<BypassedCall>,
}

impl ActivationTree {
    /// 按 seq 查询唯一归属的非 root Activation（最内层包含者）。
    ///
    /// confirmed activation 的 [entry_seq, exit_seq] 区间 laminar 嵌套，同时
    /// 包含 seq 的集合是一条祖先链，最内层 = entry_seq 最大者。二分定位后向前
    /// 找第一个 exit_seq >= seq 的记录。
    ///
    /// 复杂度：O(log n + k)，k = 包含者 entry 之后已闭合的兄弟调用数（典型很小）。
    /// resume 指令不属于 child 区间（exit < resume），归属 caller——这是设计：
    /// resume 在 caller 上下文执行。
    pub fn activation_for_seq(&self, seq: u32) -> Option<&ConfirmedActivation> {
        // 二分：最后一个 entry_seq <= seq 的 confirmed 位置
        let ids = &self.confirmed_ids;
        let mut lo = 0usize;
        let mut hi = ids.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.activations[ids[mid] as usize].entry_seq <= seq {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // 向前找第一个 exit_seq >= seq（最内层包含者）
        let mut i = lo;
        while i > 0 {
            i -= 1;
            let a = &self.activations[ids[i] as usize];
            if a.exit_seq >= seq {
                return Some(a);
            }
        }
        None
    }

    /// 按 call_seq 二分查找 bypassed 调用（call_seq 严格递增）。
    pub fn find_bypassed_by_call_seq(&self, call_seq: u32) -> Option<usize> {
        let calls = &self.bypassed_calls;
        let mut lo = 0usize;
        let mut hi = calls.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if calls[mid].call_seq < call_seq {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        calls.get(lo).filter(|c| c.call_seq == call_seq).map(|_| lo)
    }

    /// 在 owner（None = root 上下文）的直接 children 中找 call_seq == seq 的调用。
    ///
    /// children 数量 = 该函数的直接调用数（典型很小）；unresolved 子记录也算
    ///（其 call 行仍是调用指令）。
    pub fn find_child_call(&self, owner: Option<&ConfirmedActivation>, seq: u32) -> Option<u32> {
        let children = match owner {
            Some(a) => &a.children_ids,
            None => &self.activations[0].children_ids,
        };
        children
            .iter()
            .copied()
            .find(|&id| self.activations[id as usize].call_seq == seq)
    }

    /// 在 owner 的直接 children 中找 resume_seq == seq 的 confirmed 调用
    ///（该 seq 是 caller 上下文内执行的 resume 指令）。
    pub fn find_child_resume(&self, owner: Option<&ConfirmedActivation>, seq: u32) -> Option<u32> {
        let children = match owner {
            Some(a) => &a.children_ids,
            None => &self.activations[0].children_ids,
        };
        children.iter().copied().find(|&id| {
            let a = &self.activations[id as usize];
            a.unresolved_reason.is_none() && a.resume_seq == seq
        })
    }
}
