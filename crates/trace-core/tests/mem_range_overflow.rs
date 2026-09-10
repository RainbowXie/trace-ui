//! ISSUE-H14：访存地址加宽度必须 checked，越界不得 panic。

use trace_core::chunk_scan::{scan_chunk, ScanChunkConfig};
use trace_core::scan_unified::scan_unified;
use trace_parser::types::TraceFormat;

#[test]
fn max_address_load_does_not_panic_and_completes_scan() {
    let line = "[App] 0x1000!0x1000 ldr x0, [x8]; x8=0xffffffffffffffff mem_r=0xffffffffffffffff -> x0=0x1\n";
    let result = scan_unified(line.as_bytes(), false, false, true, None);
    assert!(
        result.is_ok(),
        "合法顶端地址不得让索引 panic：{}",
        result
            .as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    );
    let result = result.expect("scan");
    assert_eq!(result.scan_state.line_count, 1);
}

fn assert_scan_ok(label: &str, line: &str) {
    for skip_strings in [true, false] {
        let result = scan_unified(line.as_bytes(), false, false, skip_strings, None);
        assert!(
            result.is_ok(),
            "{label} skip_strings={skip_strings} 不得让索引 panic：{}",
            result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );
    }
    let data = line.as_bytes();
    let _chunk = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: data.len(),
            start_line: 0,
            format: TraceFormat::Gumtrace,
            data_only: false,
            no_prune: false,
            skip_strings: false,
            progress_cb: None,
        },
    );
}

#[test]
fn pair_and_simd_top_addresses_do_not_panic() {
    // ISSUE-H14：pair 第二半与 SIMD 高半用 abs+width 建索引，顶端地址必须 checked。
    assert_scan_ok(
        "stp @ u64::MAX",
        "[App] 0x1000!0x1000 stp x0, x1, [x8]; x8=0xffffffffffffffff mem_w=0xffffffffffffffff x0=0x1 x1=0x2\n",
    );
    assert_scan_ok(
        "ldp @ u64::MAX-8",
        "[App] 0x1000!0x1000 ldp x0, x1, [x8]; x8=0xfffffffffffffff8 mem_r=0xfffffffffffffff8 -> x0=0x1 x1=0x2\n",
    );
    assert_scan_ok(
        "str q @ u64::MAX",
        "[App] 0x1000!0x1000 str q0, [x8]; x8=0xffffffffffffffff mem_w=0xffffffffffffffff\n",
    );
    assert_scan_ok(
        "stp @ u64::MAX-8",
        "[App] 0x1000!0x1000 stp x0, x1, [x8]; x8=0xfffffffffffffff8 mem_w=0xfffffffffffffff8 x0=0x1 x1=0x2\n",
    );
}
