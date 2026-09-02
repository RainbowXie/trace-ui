//! Confirmed Activation 集成测试：用真实 gumtrace 样本验证。

use std::fs::File;
use std::io::{BufRead, BufReader};

use trace_core::query::activation::ActivationBuilder;

const SAMPLE_PATH: &str = "/mnt/data/Work/Frida/frida-agent-example-17/project/snapchat_ios/logs/iter302_post_lstat_globaldiff/det1_trace.log";

/// 从 gumtrace 行提取 PC 地址。
fn extract_pc(line: &str) -> Option<u64> {
    // 格式：[Snapchat] 0x100059d80!0x59d80 stp x22, x21, [sp, #-0x30]!; ...
    let start = line.find("0x")?;
    let end = line[start..].find('!')? + start;
    u64::from_str_radix(&line[start + 2..end], 16).ok()
}

/// 从 gumtrace 行提取指令文本。
fn extract_insn(line: &str) -> Option<&str> {
    // 格式：[Snapchat] 0x100059d80!0x59d80 stp x22, x21, [sp, #-0x30]!; ...
    let start = line.find('!')? + 1;
    let start = line[start..].find(' ')?.checked_add(start + 1)?;
    let end = line[start..].find(';')? + start;
    Some(line[start..end].trim())
}

#[test]
fn confirmed_activation_with_real_sample() {
    let file = File::open(SAMPLE_PATH).expect("sample trace must exist");
    let reader = BufReader::new(file);

    let mut builder = ActivationBuilder::new();
    let mut line_count = 0_u32;
    let mut bl_count = 0_u32;
    let mut blr_count = 0_u32;
    let mut ret_count = 0_u32;
    let mut first_addr = None;

    for (i, line) in reader.lines().enumerate() {
        let line = line.expect("read line");
        if line.is_empty() {
            continue;
        }

        let Some(pc) = extract_pc(&line) else {
            continue;
        };
        let Some(insn) = extract_insn(&line) else {
            continue;
        };

        if first_addr.is_none() {
            first_addr = Some(pc);
            builder.set_root_addr(pc);
        }

        // 检查 resume（每条指令读取前）
        builder.check_resume(pc, i as u32);

        // 分类指令
        if insn.starts_with("bl ") {
            // BL: 目标地址是立即数操作数
            let target = insn
                .strip_prefix("bl #")
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(0);
            builder.on_call(i as u32, pc, target);
            bl_count += 1;
        } else if insn.starts_with("blr ") {
            // BLR: 目标地址在寄存器中，暂时用 0
            builder.on_call(i as u32, pc, 0);
            blr_count += 1;
        } else if insn.starts_with("ret") {
            builder.on_ret(i as u32);
            ret_count += 1;
        }

        line_count += 1;
        if line_count >= 10000 {
            break; // 只用前 10000 行做快速验证
        }
    }

    let tree = builder.finish(line_count);

    // 验证：应该有多个 activation
    assert!(
        tree.activations.len() > 1,
        "must have at least one activation"
    );

    // 验证：所有 activation 的 entry_seq <= exit_seq
    for activation in &tree.activations {
        if !activation.unresolved {
            assert!(
                activation.entry_seq <= activation.exit_seq,
                "activation {} has entry_seq {} > exit_seq {}",
                activation.id,
                activation.entry_seq,
                activation.exit_seq
            );
        }
    }

    println!("Lines processed: {}", line_count);
    println!("BL: {}, BLR: {}, RET: {}", bl_count, blr_count, ret_count);
    println!("Total activations: {}", tree.activations.len());
    println!(
        "Unresolved: {}",
        tree.activations.iter().filter(|a| a.unresolved).count()
    );
    println!(
        "Resolved: {}",
        tree.activations.iter().filter(|a| !a.unresolved).count()
    );
}
