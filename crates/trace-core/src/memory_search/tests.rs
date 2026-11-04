//! 纯逻辑单元测试：pattern 解析与 anchor 索引。

use std::sync::atomic::Ordering;

use super::parse_pattern_hex;
use super::scan::{expand_mem_op, ByteValue, SearchState};
use super::{
    search_memory, MemorySearchOptions, MemorySearchRw, MEMORY_LINE_PARSE_COUNT,
};
use crate::error::TraceError;
use trace_parser::types::TraceFormat;

/// 一行 unidbg 写入：指令文本使用真实宽度，注解名必须与数据寄存器同名。
fn store_line(mnemonic: &str, annotation: &str) -> String {
    format!(
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"{mnemonic}\" ; mem[WRITE] abs=0x3000 {annotation}\n"
    )
}

/// 一行不带任何内存标记的 unidbg 指令。
fn memory_free_line(mnemonic: &str) -> String {
    format!("[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"{mnemonic}\"\n")
}

fn search(trace: &str, pattern: Vec<u8>) -> super::MemorySearchResult {
    search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            pattern,
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 10,
        },
    )
    .expect("memory search")
}

/// 旧路径：每一行都完整解析。仅作为粗筛路径的逐字节对照。
fn reference_occurrences(
    trace: &str,
    format: TraceFormat,
    pattern: &[u8],
) -> Vec<(u64, u32, MemorySearchRw)> {
    let mut state = SearchState::new(pattern);
    let mut occurrences = Vec::new();
    for (index, raw) in trace.as_bytes().split(|byte| *byte == b'\n').enumerate() {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line = std::str::from_utf8(raw).expect("fixture is UTF-8");
        let parsed = match format {
            TraceFormat::Unidbg => trace_parser::parser::parse_line(line),
            TraceFormat::Gumtrace => trace_parser::gumtrace::parse_line_gumtrace(line),
        };
        let Some(parsed) = parsed else { continue };
        let Some(mem) = parsed.mem_op.as_ref() else {
            continue;
        };
        let rw = if mem.is_write {
            MemorySearchRw::Write
        } else {
            MemorySearchRw::Read
        };
        let values = expand_mem_op(mem);
        state
            .process_event(
                mem.abs,
                &values,
                index as u32,
                rw,
                None,
                None,
                &mut |occurrence| {
                    occurrences.push((occurrence.address, occurrence.seq, occurrence.rw));
                    Ok(())
                },
            )
            .expect("reference scan");
    }
    occurrences
}

fn fast_occurrences(result: &super::MemorySearchResult) -> Vec<(u64, u32, MemorySearchRw)> {
    result
        .matches
        .iter()
        .map(|item| (item.address, item.seq, item.rw))
        .collect()
}

#[test]
fn sixty_four_bit_store_matches_all_eight_bytes() {
    // 单条 str x 事件必须整体命中：拆分事件会伪造第二条序号和地址。
    let pattern = vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
    let trace = store_line("str x0, [x1]", "x0=0x1122334455667788");
    let result = search(&trace, pattern.clone());
    assert_eq!(result.total, 1);
    let hit = &result.matches[0];
    // size 由 pattern 长度回填（memory_search/cached.rs 的 paginate_page），8 说明命中的
    // 是 8 字节模式本身，而不是被截短的 4 字节前缀。
    assert_eq!(
        (hit.address, hit.seq, hit.size, hit.rw),
        (0x3000, 0, 8, MemorySearchRw::Write)
    );
    // 第 9 个字节落在事件范围之外，那里没有任何观测；若事件被放大成更宽
    // 的访问，这个 pattern 就会误命中，所以它同时守住“不得放大宽度”。
    let mut overlong = pattern;
    overlong.push(0x00);
    assert_eq!(search(&trace, overlong).total, 0);
}

#[test]
fn wide_value_under_w_name_stays_unknown() {
    // openspec 样例把 64 位值挂在 w0 名下属于夹具笔误（需求方已确认改用
    // x0=）。保留该错配作为 fail-closed 负例：注解名与数据寄存器不同名时
    // 整段访问值未知，不得据此伪造 x0 的 8 字节。
    let ambiguous = store_line("str x0, [x1]", "w0=0x1122334455667788");
    assert_eq!(
        search(&ambiguous, vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]).total,
        0
    );
    // 低 4 字节也不能命中：写入宽度是 8 字节，其值整体未知，不存在部分已知。
    assert_eq!(search(&ambiguous, vec![0x88, 0x77, 0x66, 0x55]).total, 0);
}

#[test]
fn narrow_stores_keep_their_own_width() {
    // size 恒等于 pattern 长度，短 pattern 命中因此证明不了事件宽度：strb 若被
    // 放大成 8 字节，[0x88, 0x00] 这类越界 pattern 仍会命中。每个窄事件都必须
    // 断言越界 pattern 不命中，才真正锁住 1/2/4 字节。
    for (mnemonic, value, inside, outside) in [
        ("strb w0, [x1]", 0x88u64, vec![0x88], vec![0x88, 0x00]),
        (
            "strh w0, [x1]",
            0x7788,
            vec![0x88, 0x77],
            vec![0x88, 0x77, 0x00],
        ),
        (
            "str w0, [x1]",
            0x55667788,
            vec![0x88, 0x77, 0x66, 0x55],
            vec![0x88, 0x77, 0x66, 0x55, 0x00],
        ),
    ] {
        let trace = store_line(mnemonic, &format!("w0={value:#x}"));
        let hit = search(&trace, inside.clone());
        assert_eq!(
            (hit.total, hit.matches[0].size, hit.matches[0].address),
            (1, inside.len() as u32, 0x3000)
        );
        assert_eq!(search(&trace, outside).total, 0);
    }
}

#[test]
fn pattern_parser_accepts_compact_and_spaced_hex() {
    assert_eq!(parse_pattern_hex("aabbcc").unwrap(), vec![0xaa, 0xbb, 0xcc]);
    assert_eq!(
        parse_pattern_hex("AA bb cc").unwrap(),
        vec![0xaa, 0xbb, 0xcc]
    );
}

#[test]
fn pattern_parser_rejects_odd_or_non_hex_input() {
    assert!(parse_pattern_hex("abc").is_err());
    assert!(parse_pattern_hex("aa:bb").is_err());
}

#[test]
fn anchor_index_keeps_only_positions_matching_the_requested_anchor() {
    let pattern = vec![0x11; 8];
    let mut state = SearchState::new(&pattern);
    for address in 0x1000..0x1800 {
        state.memory.set(
            address,
            ByteValue {
                value: 0x22,
                known: true,
            },
        );
        state.update_anchor_positions_around(address);
    }
    assert!(state.anchor_positions.is_empty());

    for address in 0x2000..0x2008 {
        state.memory.set(
            address,
            ByteValue {
                value: 0x11,
                known: true,
            },
        );
        state.update_anchor_positions_around(address);
    }
    assert_eq!(state.anchor_positions.len(), 1);
    assert!(state.anchor_positions.contains(&0x2000));
}

#[test]
fn coarse_filter_matches_full_parse_on_mixed_unidbg_trace() {
    // 指令行与内存行交错：粗筛不得丢掉事件，也不得因跳过解析改变 seq。
    let trace = format!(
        "{}{}{}{}{}",
        memory_free_line("add x0, x0, #1"),
        store_line("str x0, [x1]", "x0=0x1122334455667788"),
        memory_free_line("mov x1, x2"),
        store_line("strb w0, [x1]", "w0=0x44"),
        memory_free_line("nop"),
    );
    for pattern in [
        vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        vec![0x44],
    ] {
        let result = search(&trace, pattern.clone());
        assert_eq!(
            fast_occurrences(&result),
            reference_occurrences(&trace, TraceFormat::Unidbg, &pattern)
        );
        assert_eq!(result.total as usize, fast_occurrences(&result).len());
    }
}

#[test]
fn coarse_filter_matches_full_parse_on_mixed_gumtrace_trace() {
    let trace = "[App] 0x400000!0x0 bl #0x401000; x0=0x6000\n\
[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x6000 mem_r=0x6000 -> x9=0x1\n\
[App] 0x401008!0x1008 add x9, x9, #2; x9=0x1 -> x9=0x3\n\
[App] 0x40100c!0x100c str x9, [x3]; x9=0x3 x3=0x7000 mem_w=0x7000\n";
    let options = MemorySearchOptions {
        pattern: vec![0x01],
        seq_range: None,
        memory_range: None,
        offset: 0,
        limit: 10,
    };
    let result = search_memory(trace.as_bytes(), TraceFormat::Gumtrace, options).expect("search");
    assert_eq!(
        fast_occurrences(&result),
        reference_occurrences(trace, TraceFormat::Gumtrace, &[0x01])
    );
    assert_eq!(result.total as usize, fast_occurrences(&result).len());
}

#[test]
fn non_memory_lines_never_reach_the_instruction_parser() {
    let trace = format!(
        "{}{}{}{}{}",
        memory_free_line("add x0, x0, #1"),
        store_line("str x0, [x1]", "x0=0x1122334455667788"),
        memory_free_line("mov x1, x2"),
        store_line("strb w0, [x1]", "w0=0x44"),
        memory_free_line("nop"),
    );
    MEMORY_LINE_PARSE_COUNT.store(0, Ordering::SeqCst);
    search(&trace, vec![0x44]);
    assert_eq!(
        MEMORY_LINE_PARSE_COUNT.load(Ordering::SeqCst),
        2,
        "只有带内存标记的行才允许进入逐行解析器"
    );
}

#[test]
fn malformed_memory_line_still_fails_closed() {
    let trace = format!(
        "{}[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str x0, [x1]\" ; mem[WRITE] abs=0xZZ w0=0x1\n",
        memory_free_line("add x0, x0, #1"),
    );
    let error = search_memory(
        trace.as_bytes(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            pattern: vec![0x44],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 10,
        },
    )
    .expect_err("malformed memory event must fail closed");
    match error {
        TraceError::ParseError { detail, .. } => {
            assert!(detail.contains("malformed memory event"), "{detail}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn trace_without_recognizable_instruction_lines_still_errors() {
    // 无标记行现在只做签名计数；整份输入没有可识别行时仍必须报错，
    // 不能退化成空结果。
    let error = search_memory(
        b"members = [\"a\", \"b\"]\n".as_slice(),
        TraceFormat::Unidbg,
        MemorySearchOptions {
            pattern: vec![0x44],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 10,
        },
    )
    .expect_err("non-trace input must fail closed");
    match error {
        TraceError::ParseError { detail, .. } => {
            assert!(detail.contains("no recognizable instruction lines"), "{detail}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
