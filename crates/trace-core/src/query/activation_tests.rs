//! ActivationBuilder 状态机单元测试（含审查反例）。

use super::activation::*;

fn fact(seq: u32, pc: u64) -> InsnFact {
    InsnFact::new(seq, pc)
}

#[test]
fn simple_call_entry_exit_resume() {
    let mut b = ActivationBuilder::new();
    assert_eq!(b.on_insn(fact(0, 0x1000)), 0);
    assert_eq!(b.on_insn(fact(1, 0x1004)), 0);
    b.on_call(2, 0x1008);
    let child = b.on_insn(fact(3, 0x2000));
    assert_ne!(child, 0);
    b.on_insn(fact(4, 0x2004));
    b.on_insn(fact(5, 0x2008));
    b.on_insn(fact(6, 0x100C));
    let tree = b.finish(7);

    assert_eq!(tree.activations.len(), 2);
    let a = &tree.activations[1];
    assert_eq!(a.func_addr, 0x2000, "函数身份 = entry 实际 PC");
    assert_eq!(a.entry_seq, 3);
    assert_eq!(a.exit_seq, 5, "exit = 前一条实际指令");
    assert_eq!(a.resume_seq, 6);
    assert!(a.unresolved_reason.is_none());
    assert!(tree.bypassed_calls.is_empty());
    assert_eq!(tree.activation_for_seq(4).map(|a| a.id), Some(1));
    assert_eq!(tree.activation_for_seq(1).map(|a| a.id), None);
}

#[test]
fn call_without_recorded_body_is_bypassed_not_fake_activation() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
    b.on_insn(fact(2, 0x1008));
    b.on_insn(fact(3, 0x100C));
    let tree = b.finish(4);

    assert_eq!(tree.activations.len(), 1, "无函数体调用不得伪造 activation");
    assert_eq!(tree.bypassed_calls.len(), 1);
    let c = &tree.bypassed_calls[0];
    assert_eq!(c.call_seq, 1);
    assert_eq!(c.call_pc, 0x1004);
    assert_eq!(c.expected_resume, 0x1008);
    assert_eq!(c.resume_seq, 2);
    assert_eq!(c.parent_id, None);
}

/// 审查 CRITICAL 4 反例：递归调用复用同一 callsite，最内层被拦截。
///
/// parent 在 callsite 0x1004 调用自身（active）；child 在同一 callsite 0x1004
/// 再调用并被拦截（下一条直接 = callsite+4 = 0x1008）。该 PC 同时是 child
/// candidate 和 parent 的 expected_resume。正确行为：candidate 先消耗（bypassed），
/// parent 继续等待自己的 resume；parent 的后续指令归属 parent。
#[test]
fn recursive_callsite_pending_consumes_resume_before_parent() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    // parent call at callsite 0x1004 → active, entry 0x2000
    b.on_call(1, 0x1004);
    let parent = b.on_insn(fact(2, 0x2000));
    // child 递归调用：同一 callsite 0x1004（parent 内部再次 BL 到同地址）
    b.on_call(3, 0x1004);
    // 下一条直接回到 0x1008：child 的 expected_resume，也是 parent 的 expected_resume
    let owner = b.on_insn(fact(4, 0x1008));
    assert_eq!(
        owner, parent,
        "resume 行必须归属 parent（child 已 bypassed 消耗该候选）"
    );
    // parent 继续执行自己的指令
    b.on_insn(fact(5, 0x200C));
    // parent 的 resume：再次命中 0x1008（parent callsite+4）
    b.on_insn(fact(6, 0x1008));
    let tree = b.finish(7);

    // parent 确认闭合，不被提前关闭
    let p = tree
        .activations
        .iter()
        .find(|a| a.id == parent)
        .expect("parent activation");
    assert!(
        p.unresolved_reason.is_none(),
        "parent 不得被 child 的 resume 提前关闭"
    );
    assert_eq!(p.exit_seq, 5, "parent exit = 自己 resume 前最后一条指令");
    assert_eq!(p.resume_seq, 6);
    // child 是 bypassed，不进 activations
    assert_eq!(tree.bypassed_calls.len(), 1);
    assert_eq!(tree.bypassed_calls[0].call_seq, 3);
    assert_eq!(tree.bypassed_calls[0].resume_seq, 4);
    assert_eq!(tree.bypassed_calls[0].parent_id, Some(parent));
    assert_eq!(tree.activations.len(), 2, "root + parent");
}

/// 同一反例的 active 变体：child 递归调用后进入函数体再返回。
#[test]
fn recursive_callsite_child_active_then_parent_resumes_late() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004); // parent → active
    let parent = b.on_insn(fact(2, 0x2000));
    b.on_insn(fact(3, 0x2004));
    b.on_call(4, 0x1004); // child：同一 callsite → active（entry 不是 0x1008）
    let child = b.on_insn(fact(5, 0x2100));
    assert_ne!(child, parent);
    b.on_insn(fact(6, 0x2104));
    // child resume → 0x1008（同时是 parent 的 expected_resume！）
    let owner = b.on_insn(fact(7, 0x1008));
    // 该指令是 child 的 resume：child 闭合，指令归属 parent（caller）
    assert_eq!(owner, parent);
    // parent 继续
    b.on_insn(fact(8, 0x2008));
    // parent resume → 0x1008
    b.on_insn(fact(9, 0x1008));
    let tree = b.finish(10);

    let p = &tree.activations[parent as usize];
    let c = &tree.activations[child as usize];
    assert!(p.unresolved_reason.is_none());
    assert!(c.unresolved_reason.is_none());
    assert_eq!(c.exit_seq, 6);
    assert_eq!(c.resume_seq, 7, "child resume 是 seq 7");
    assert_eq!(p.exit_seq, 8, "parent 不被 child 的 resume 关闭");
    assert_eq!(p.resume_seq, 9);
}

#[test]
fn nested_calls_innermost_ownership() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
    let outer = b.on_insn(fact(2, 0x2000));
    b.on_insn(fact(3, 0x2004));
    b.on_call(4, 0x2008);
    let inner = b.on_insn(fact(5, 0x3000));
    assert_ne!(inner, outer);
    b.on_insn(fact(6, 0x3004));
    b.on_insn(fact(7, 0x200C));
    b.on_insn(fact(8, 0x2010));
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
    assert_eq!(o.exit_seq, 8);
    assert_eq!(tree.activation_for_seq(5).map(|a| a.id), Some(inner));
    assert_eq!(tree.activation_for_seq(8).map(|a| a.id), Some(outer));
    // resume 行归属 caller（outer 的 resume 是 inner 的指令区间外）
    assert_eq!(tree.activation_for_seq(7).map(|a| a.id), Some(outer));
}

#[test]
fn b_br_ret_do_not_pop_activation() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
    b.on_insn(fact(2, 0x2000));
    b.on_insn(fact(3, 0x2F00));
    b.on_insn(fact(4, 0x2F04));
    assert_eq!(b.on_insn(fact(5, 0x2F08)), b.current_id());
    b.on_insn(fact(6, 0x1008));
    let tree = b.finish(7);

    let a = &tree.activations[1];
    assert!(a.unresolved_reason.is_none());
    assert_eq!(a.exit_seq, 5);
    assert_eq!(a.exit_pc, 0x2F08);
}

#[test]
fn trace_truncation_marks_reason() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
    b.on_insn(fact(2, 0x2000));
    b.on_insn(fact(3, 0x2004));
    let tree = b.finish(4);

    let a = &tree.activations[1];
    assert_eq!(
        a.unresolved_reason,
        Some(UnresolvedReason::TraceEndStillActive)
    );
    assert_eq!(a.exit_seq, 3);
}

#[test]
fn pending_candidate_at_trace_end_marks_no_next_insn() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
    let tree = b.finish(2);

    let a = &tree.activations[1];
    assert_eq!(a.unresolved_reason, Some(UnresolvedReason::NoNextInsn));
    assert_eq!(a.func_addr, 0);
}

#[test]
fn consecutive_calls_displace_pending() {
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
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
    let mut b = ActivationBuilder::new();
    b.on_insn(fact(0, 0x1000));
    b.on_call(1, 0x1004);
    b.on_insn(fact(2, 0x2000));
    // seq=3: special line（不喂）
    b.on_insn(fact(4, 0x2004));
    // seq=5: special line（不喂）
    b.on_insn(fact(6, 0x2008));
    // seq=7: special line（不喂）；seq=8: resume
    b.on_insn(fact(8, 0x1008));
    let tree = b.finish(9);

    let a = &tree.activations[1];
    assert_eq!(a.exit_seq, 6, "exit 用最后一条实际指令");
    assert_eq!(a.resume_seq, 8);
}

/// seq 0 的真实调用（root 的第一行就是 BL）不被哨兵吞掉。
#[test]
fn call_at_seq_zero_is_found() {
    let mut b = ActivationBuilder::new();
    // trace 直接从 BL 开始（root 无前置指令）
    b.on_call(0, 0x1000);
    let child = b.on_insn(fact(1, 0x2000));
    assert_ne!(child, 0);
    b.on_insn(fact(2, 0x2004));
    b.on_insn(fact(3, 0x1004));
    let tree = b.finish(4);

    let a = &tree.activations[1];
    assert_eq!(a.call_seq, 0, "seq 0 的真实调用必须可查");
    assert!(a.unresolved_reason.is_none());
    assert_eq!(tree.find_child_call(None, 0), Some(1));
}

/// 二分查找在大规模 activation 上正确（性能 + 正确性回归）。
#[test]
fn activation_for_seq_binary_search_on_many_activations() {
    let mut b = ActivationBuilder::new();
    // root 指令 + 1000 个顺序调用，每个 3 条指令
    b.on_insn(fact(0, 0x1000));
    let mut expected = Vec::new();
    for i in 0..1000u32 {
        let call_seq = 1 + i * 4;
        b.on_call(call_seq, 0x1004 + (i as u64) * 0x10);
        let id = b.on_insn(fact(call_seq + 1, 0x2000));
        b.on_insn(fact(call_seq + 2, 0x2004));
        let owner = b.on_insn(fact(call_seq + 3, 0x1004 + (i as u64) * 0x10 + 4));
        assert_eq!(owner, 0, "顺序调用的 resume 归 root");
        expected.push((id, call_seq + 1, call_seq + 2));
    }
    let tree = b.finish(4002);

    for (id, entry, exit) in &expected {
        assert_eq!(tree.activation_for_seq(*entry).map(|a| a.id), Some(*id));
        assert_eq!(tree.activation_for_seq(*exit).map(|a| a.id), Some(*id));
    }
    // root 指令
    assert_eq!(tree.activation_for_seq(0).map(|a| a.id), None);
    // resume 行（exit+1）不归属 child
    let x0 = expected[0].2;
    assert_eq!(
        tree.activation_for_seq(x0 + 1).map(|a| a.id),
        None,
        "无嵌套时 resume 归 root"
    );
}

/// bypassed 二分查找。
#[test]
fn find_bypassed_by_call_seq_works() {
    let mut b = ActivationBuilder::new();
    for i in 0..100u32 {
        b.on_insn(fact(i * 3, 0x1000 + (i as u64) * 0x10));
        b.on_call(i * 3 + 1, 0x1004 + (i as u64) * 0x10);
        b.on_insn(fact(i * 3 + 2, 0x1008 + (i as u64) * 0x10)); // 直接 resume
    }
    let tree = b.finish(300);

    assert_eq!(tree.bypassed_calls.len(), 100);
    assert_eq!(tree.find_bypassed_by_call_seq(1), Some(0));
    assert_eq!(tree.find_bypassed_by_call_seq(4), Some(1));
    assert_eq!(tree.find_bypassed_by_call_seq(298), Some(99));
    assert_eq!(tree.find_bypassed_by_call_seq(2), None);
}
