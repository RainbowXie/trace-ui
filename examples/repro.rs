// seed=3 复现，打印树结构分析
use trace_core::query::activation::*;

fn fact(seq: u32, pc: u64) -> InsnFact { InsnFact::new(seq, pc) }

fn main() {
    let mut b = ActivationBuilder::new();
    let mut rng: u64 = 3;
    let mut next_seq = 0u32;
    let mut stack: Vec<(u32, u64)> = vec![];
    b.on_insn(fact(next_seq, 0x1000 + next_seq as u64 * 4));
    next_seq += 1;

    for _ in 0..30 {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        let choice = rng % 10;
        if choice < 3 {
            let callsite = 0x5000 + next_seq as u64 * 4;
            b.on_call(next_seq, callsite);
            let cs = next_seq;
            next_seq += 1;
            if rng % 2 == 0 {
                let id = b.on_insn(fact(next_seq, 0x9000 + next_seq as u64 * 4));
                stack.push((id, callsite + 4));
                println!("seq {cs}: CALL → active id={id} entry_seq={next_seq}");
                next_seq += 1;
            } else {
                b.on_insn(fact(next_seq, callsite + 4));
                println!("seq {cs}: CALL → bypassed (resume seq {next_seq})");
                next_seq += 1;
            }
        } else if choice < 5 && !stack.is_empty() {
            let (id, er) = stack.pop().unwrap();
            b.on_insn(fact(next_seq, er));
            println!("seq {next_seq}: RESUME id={id}");
            next_seq += 1;
        } else {
            b.on_insn(fact(next_seq, 0x7000 + next_seq as u64 * 4));
            next_seq += 1;
        }
    }
    let tree = b.finish(next_seq);
    println!("\n=== activations:");
    for a in &tree.activations {
        println!("id={} parent={:?} call_seq={} entry={} exit={} resume={} unresolved={:?}",
            a.id, a.parent_id, a.call_seq, a.entry_seq, a.exit_seq, a.resume_seq,
            a.unresolved_reason.map(|r| format!("{r:?}")));
    }
    println!("\n=== confirmed_ids: {:?}", tree.confirmed_ids);
    println!("=== seq 29: chain={:?} brute=?",
        tree.activation_for_seq(29).map(|a| a.id));
}
