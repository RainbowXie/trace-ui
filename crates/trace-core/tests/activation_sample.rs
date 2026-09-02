//! Confirmed Activation 真实样本验证（生产路径 scan_unified / scan_unified_parallel）。
//!
//! 默认 ignore：样本是本机 445MB 大文件，CI/其他环境不存在。本地验证：
//! `cargo test -p trace-core --test activation_sample -- --ignored`
//! （需设置 TRACE_UI_SAMPLE_TRACE 指向 gumtrace 格式 trace）。

use std::io::Read;

use trace_core::query::activation::UnresolvedReason;
use trace_core::scan_unified::scan_unified;

fn sample_path() -> Option<String> {
    std::env::var("TRACE_UI_SAMPLE_TRACE").ok()
}

/// 截取样本前 `lines` 行（避免 445MB 全量进测试）。
fn sample_head(path: &str, lines: usize) -> Vec<u8> {
    let mut file = std::fs::File::open(path).expect("sample trace must exist");
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 1 << 20];
    let mut count = 0usize;
    loop {
        let n = file.read(&mut chunk).expect("read sample");
        if n == 0 {
            break;
        }
        for &b in &chunk[..n] {
            if b == b'\n' {
                count += 1;
                if count == lines {
                    buf.push(b);
                    return buf;
                }
            }
            buf.push(b);
        }
    }
    buf
}

/// 生产路径（单线程 scan_unified）上的 Confirmed Activation 统计。
///
/// det1_trace.log 前 500000 行实测：114 BL + 1072 BLR = 1186 个调用；
/// 确认 activation 699，bypassed（无函数体）477，截断 10。
/// 699 + 477 + 10 = 1186 全部有归属，无静默丢失。
/// 旧模型把这 477 个无函数体调用伪造成 ConfirmedActivation。
#[test]
#[ignore = "需要本机样本：设置 TRACE_UI_SAMPLE_TRACE 指向真实 gumtrace trace"]
fn confirmed_activation_on_real_sample_scan_unified() {
    let Some(path) = sample_path() else {
        panic!("设置 TRACE_UI_SAMPLE_TRACE 后运行（--ignored）");
    };
    let data = sample_head(&path, 500_000);
    let result = scan_unified(&data, false, false, true, None).expect("scan must succeed");

    assert_eq!(result.scan_state.line_count, 500_000);
    assert_eq!(result.scan_state.parsed_count, 500_000);

    let tree = &result.phase2.activation_tree;
    let non_root: Vec<_> = tree.activations.iter().skip(1).collect();

    let confirmed = non_root
        .iter()
        .filter(|a| a.unresolved_reason.is_none())
        .count();
    let trace_end = non_root
        .iter()
        .filter(|a| a.unresolved_reason == Some(UnresolvedReason::TraceEndStillActive))
        .count();
    let no_next = non_root
        .iter()
        .filter(|a| a.unresolved_reason == Some(UnresolvedReason::NoNextInsn))
        .count();
    let displaced = non_root
        .iter()
        .filter(|a| a.unresolved_reason == Some(UnresolvedReason::DisplacedByAnotherCall))
        .count();

    // 调用总数守恒：每条 BL/BLR 恰好产生一条记录（confirmed / bypassed / unresolved）
    let total_calls = 114 + 1072;
    assert_eq!(
        confirmed + tree.bypassed_calls.len() + trace_end + no_next + displaced,
        total_calls,
        "每个调用必须有归属"
    );
    assert_eq!(confirmed, 699);
    assert_eq!(tree.bypassed_calls.len(), 477);
    assert_eq!(trace_end, 10);
    assert_eq!(no_next + displaced, 0);

    // 函数身份：confirmed activation 的 func_addr 必须来自 entry 实际 PC
    let bad_identity = non_root
        .iter()
        .filter(|a| a.unresolved_reason.is_none() && a.func_addr != a.entry_pc)
        .count();
    assert_eq!(bad_identity, 0);

    // 边界单调性：entry <= exit <= resume
    for a in &non_root {
        if a.unresolved_reason.is_some() {
            continue;
        }
        assert!(
            a.entry_seq <= a.exit_seq && a.exit_seq < a.resume_seq,
            "activation {} 边界乱序",
            a.id
        );
    }

    // bypassed：resume_seq 的 PC 必须等于 expected_resume（call_pc + 4）
    for c in &tree.bypassed_calls {
        assert_eq!(c.expected_resume, c.call_pc + 4);
        assert!(c.resume_seq > c.call_seq);
    }

    // 归属查询抽样：内层指令必须归属最内层 activation（二分正确性）
    for a in non_root.iter().filter(|a| a.unresolved_reason.is_none()) {
        if let Some(owner) = tree.activation_for_seq(a.entry_seq) {
            assert_eq!(owner.id, a.id, "entry 必须归属自身（最内层）");
        }
    }
}

/// 并行路径（chunk_scan + merge 重放）必须与单线程路径产生相同的 Activation 树。
#[test]
#[ignore = "需要本机样本：设置 TRACE_UI_SAMPLE_TRACE 指向真实 gumtrace trace"]
fn parallel_scan_matches_single_thread_on_real_sample() {
    let Some(path) = sample_path() else {
        panic!("设置 TRACE_UI_SAMPLE_TRACE 后运行（--ignored）");
    };
    let data = sample_head(&path, 200_000);
    let single = scan_unified(&data, false, false, true, None).expect("single scan");
    let parallel = trace_core::parallel::scan_unified_parallel(&data, false, false, true, None, 4)
        .expect("parallel scan");

    let s = &single.phase2.activation_tree;
    let p = &parallel.phase2.activation_tree;

    assert_eq!(s.activations.len(), p.activations.len());
    assert_eq!(s.bypassed_calls.len(), p.bypassed_calls.len());
    for (a, b) in s.activations.iter().zip(p.activations.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.func_addr, b.func_addr);
        assert_eq!(a.entry_seq, b.entry_seq);
        assert_eq!(a.exit_seq, b.exit_seq);
        assert_eq!(a.resume_seq, b.resume_seq);
        assert_eq!(a.unresolved_reason, b.unresolved_reason);
    }
    for (c, d) in s.bypassed_calls.iter().zip(p.bypassed_calls.iter()) {
        assert_eq!(c.call_seq, d.call_seq);
        assert_eq!(c.resume_seq, d.resume_seq);
    }
}
