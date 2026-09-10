//! ISSUE-H14：访存地址加宽度必须 checked，越界不得 panic。

use trace_core::scan_unified::scan_unified;

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
