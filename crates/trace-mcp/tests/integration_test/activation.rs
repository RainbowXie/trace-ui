//! Confirmed Activation 端到端测试：engine build → 查询 → instruction ownership。
//!
//! 样本 example-trace-gumtrace.txt 的关键事实（seq 从 0 计，special line 占 seq）：
//! - seq 1: BL 0x7522f46438（callsite 0x7522e85ce4）→ entry seq 2
//! - seq 10: BL 0x7522e31a90（callsite 0x7522f46458）→ PLT thunk
//! - seq 11..=14: thunk 指令（adrp/ldr/add/br x17，最后一条 seq 14）
//! - seq 15..=17: call func:/args0:/ret: special lines（占 seq，不是指令）
//! - seq 18: resume 0x7522f4645c == callsite + 4
//!   → exit 必须是 seq 14（br x17），不是 seq 17（ret: special line）
//! - seq 54: BLR x8（callsite 0x7522f328a4）→ JNI 拦截，无函数体；
//!   seq 55..=58 special lines；seq 59 = 0x7522f328a8 == callsite + 4 → bypassed
//! - seq 62: BLR x8（callsite 0x7522f32fe8）→ NewStringUTF JNI 拦截 → bypassed

use super::*;

#[test]
fn test_activation_tree_on_example_trace() {
    let (engine, sid) = setup_session(&get_trace_path());
    let tree = engine
        .get_activation_tree(&sid)
        .expect("get_activation_tree");

    // root + 4 个确认 activation + 2 个 bypassed
    assert_eq!(tree.activations.len(), 5, "root + 4 confirmed");
    assert_eq!(
        tree.bypassed_calls.len(),
        2,
        "two JNI-intercepted BLR calls"
    );

    // 所有确认 activation：函数身份 = entry PC，entry <= exit < resume
    for a in &tree.activations {
        if a.unresolved_reason.is_none() && a.id != 0 {
            assert_eq!(
                a.func_addr, a.entry_pc,
                "func identity must come from the actual entry PC"
            );
            assert!(
                a.entry_seq <= a.exit_seq && a.exit_seq < a.resume_seq,
                "activation {} boundary order violated: entry={} exit={} resume={}",
                a.id,
                a.entry_seq,
                a.exit_seq,
                a.resume_seq
            );
        }
    }

    // 第一个调用：seq 1 BL → seq 2 entry
    let first = tree
        .activations
        .iter()
        .find(|a| a.call_seq == 1)
        .expect("BL at seq 1 must produce an activation");
    assert_eq!(first.entry_seq, 2);
    assert_eq!(first.entry_pc, "0x7522f46438");
    assert_eq!(first.call_pc, "0x7522e85ce4");
    assert_eq!(first.expected_resume, "0x7522e85ce8");

    // bypassed：JNI 拦截调用只保存调用事实
    assert_eq!(tree.bypassed_calls[0].call_seq, 54);
    assert_eq!(tree.bypassed_calls[0].call_pc, "0x7522f328a4");
    assert_eq!(tree.bypassed_calls[0].expected_resume, "0x7522f328a8");
    assert_eq!(tree.bypassed_calls[0].resume_seq, 59);
    assert_eq!(tree.bypassed_calls[1].call_seq, 62);
    assert_eq!(tree.bypassed_calls[1].resume_seq, 66);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_exit_is_last_real_insn_not_special_line() {
    let (engine, sid) = setup_session(&get_trace_path());

    // seq 10 BL（callsite 0x7522f46458）→ PLT thunk；seq 15..=17 是 special lines
    let tree = engine.get_activation_tree(&sid).unwrap();
    let act = tree
        .activations
        .iter()
        .find(|a| a.call_seq == 10)
        .expect("BL at seq 10");
    assert!(
        act.unresolved_reason.is_none(),
        "seq-10 call must be confirmed"
    );
    assert_eq!(
        act.exit_seq, 14,
        "exit must be the last real instruction (br x17 at seq 14), \
         not a special line at seq 15..=17"
    );
    assert_eq!(act.exit_pc, "0x7522e31a9c");
    assert_eq!(act.resume_seq, 18);

    // seq 14（br x17）属于该 activation，位置是 exit
    let owner = engine.get_instruction_owner(&sid, 14).unwrap();
    assert_eq!(owner.position, "exit");
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(act.id),
        "seq 14 must belong to the seq-10 activation"
    );

    // seq 16（args0: special line 之后的 seq）落在 inner exit 与 resume 之间、
    // 但仍在 outer activation [2, 47] 动态范围内：归属 outer（special line 不是
    // 指令，但位置上在 outer 的调用区间内；不归 inner）
    let owner = engine.get_instruction_owner(&sid, 16).unwrap();
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(1),
        "seq between inner exit and resume belongs to the outer activation"
    );
    assert_eq!(owner.position, "body");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_instruction_owner_positions() {
    let (engine, sid) = setup_session(&get_trace_path());

    // entry
    let owner = engine.get_instruction_owner(&sid, 2).unwrap();
    assert_eq!(owner.position, "entry");
    assert_eq!(
        owner.activation.as_ref().map(|a| a.entry_pc.clone()),
        Some("0x7522f46438".to_string())
    );

    // body
    let owner = engine.get_instruction_owner(&sid, 4).unwrap();
    assert_eq!(owner.position, "body");

    // call（BL 行本身归属 caller 侧；callee_id 指向被创建的 child）
    let owner = engine.get_instruction_owner(&sid, 10).unwrap();
    assert_eq!(owner.position, "call");
    assert_eq!(owner.callee_id, Some(2));
    // owner 是 caller（id=1，func 0x7522f46438）
    assert_eq!(
        owner.activation.as_ref().map(|a| a.id),
        Some(1),
        "BL row belongs to the caller-side activation"
    );

    // root 指令（seq 0，任何 activation 之前）
    let owner = engine.get_instruction_owner(&sid, 0).unwrap();
    assert_eq!(owner.position, "root");
    assert!(owner.activation.is_none());

    // 嵌套调用内部最内层归属：seq 12 在 thunk（activation 2）内部
    let owner = engine.get_instruction_owner(&sid, 12).unwrap();
    assert_eq!(owner.position, "body");
    assert_eq!(owner.activation.as_ref().map(|a| a.call_seq), Some(10));

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_activation_tree_survives_cache_reload() {
    // 缓存往返：build → close → 重开（命中 section cache）→ ActivationTree 仍在
    let path = get_trace_path();
    let (engine, sid) = setup_session(&path);
    let before = engine.get_activation_tree(&sid).expect("first build");
    engine.close_session(&sid).unwrap();

    let info = engine.create_session(&path).expect("reopen");
    let sid2 = info.session_id.clone();
    engine
        .build_index(
            &sid2,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("rebuild (cache hit)");
    let after = engine.get_activation_tree(&sid2).expect("after reload");

    assert_eq!(
        before.activations.len(),
        after.activations.len(),
        "activation count must survive cache round-trip"
    );
    assert_eq!(before.bypassed_calls.len(), after.bypassed_calls.len());
    for (a, b) in before.activations.iter().zip(after.activations.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.entry_seq, b.entry_seq);
        assert_eq!(a.exit_seq, b.exit_seq);
        assert_eq!(a.resume_seq, b.resume_seq);
        assert_eq!(a.unresolved_reason, b.unresolved_reason);
    }
    engine.close_session(&sid2).unwrap();
}
