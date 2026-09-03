//! Activation 查询随机化对拍回归测试。
//!
//! activation_for_seq（parent 链二分）与暴力最内层包含者扫描对拍。
//! 曾抓到的真实 bug：inner confirmed、outer TraceEndStillActive 的形态中
//! 链走到 unresolved outer 并返回其不可信区间。

use super::activation::*;

fn fact(seq: u32, pc: u64) -> InsnFact {
    InsnFact::new(seq, pc)
}

/// 200 个随机种子：call/bypassed/resume/普通指令混合，多层嵌套 + 截断。
/// 每个 seq 的归属查询必须与暴力扫描一致。
#[test]
fn activation_for_seq_matches_bruteforce_on_random_traces() {
    for seed in 0..200u64 {
        let mut b = ActivationBuilder::new();
        let mut rng = seed;
        let mut next_seq = 0u32;
        let mut stack: Vec<(u32, u64)> = vec![]; // (id, expected_resume)
        b.on_insn(fact(next_seq, 0x1000));
        next_seq += 1;

        for _ in 0..30 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let choice = rng % 10;
            if choice < 3 {
                let callsite = 0x5000 + next_seq as u64 * 4;
                b.on_call(next_seq, callsite);
                next_seq += 1;
                if rng % 2 == 0 {
                    let id = b.on_insn(fact(next_seq, 0x9000 + next_seq as u64 * 4));
                    stack.push((id, callsite + 4));
                    next_seq += 1;
                } else {
                    b.on_insn(fact(next_seq, callsite + 4));
                    next_seq += 1;
                }
            } else if choice < 5 && !stack.is_empty() {
                let (_, er) = stack.pop().unwrap();
                b.on_insn(fact(next_seq, er));
                next_seq += 1;
            } else {
                b.on_insn(fact(next_seq, 0x7000 + next_seq as u64 * 4));
                next_seq += 1;
            }
        }
        let tree = b.finish(next_seq);

        for seq in 0..next_seq {
            let chain = tree.activation_for_seq(seq);
            // 暴力：扫描全部 confirmed，取最内层包含者
            let mut brute: Option<&ConfirmedActivation> = None;
            for a in &tree.activations[1..] {
                if a.unresolved_reason.is_some() {
                    continue;
                }
                if seq >= a.entry_seq && seq <= a.exit_seq {
                    let better = brute
                        .is_none_or(|bb| a.exit_seq - a.entry_seq < bb.exit_seq - bb.entry_seq);
                    if better {
                        brute = Some(a);
                    }
                }
            }
            assert_eq!(
                chain.map(|a| a.id),
                brute.map(|a| a.id),
                "seed={seed} seq={seq}: parent-chain != bruteforce"
            );
        }
    }
}
