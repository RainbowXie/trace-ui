//! ISSUE-H14：访存地址加宽度必须 checked，越界不得 panic。

use std::sync::atomic::{AtomicU32, Ordering};

use trace_core::chunk_scan::{scan_chunk, ScanChunkConfig};
use trace_core::merge::merge_all_chunks;
use trace_core::scan_unified::scan_unified;
use trace_core::{BuildOptions, TraceEngine};
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

#[test]
fn two_chunk_merge_pair_top_address_does_not_panic() {
    // ISSUE-H14：>=10MiB 走 scan_unified_parallel → merge_all_chunks。
    // 第二 chunk 的 pair load 在顶端地址必须 checked，skip_strings 真假都不得 panic。
    let chunk0 = "[App] 0x1000!0x1000 mov x0, #0x1; x0=0x0 -> x0=0x1\n";
    let chunk1 = "[App] 0x1004!0x1004 ldp x0, x1, [x8]; x8=0xffffffffffffffff mem_r=0xffffffffffffffff -> x0=0x1 x1=0x2\n";
    let data = format!("{chunk0}{chunk1}");
    let bytes = data.as_bytes();
    let split = chunk0.len();
    for skip_strings in [true, false] {
        let c0 = scan_chunk(
            bytes,
            ScanChunkConfig {
                start_byte: 0,
                end_byte: split,
                start_line: 0,
                format: TraceFormat::Gumtrace,
                data_only: false,
                no_prune: false,
                skip_strings,
                progress_cb: None,
            },
        );
        let c1 = scan_chunk(
            bytes,
            ScanChunkConfig {
                start_byte: split,
                end_byte: bytes.len(),
                start_line: 1,
                format: TraceFormat::Gumtrace,
                data_only: false,
                no_prune: false,
                skip_strings,
                progress_cb: None,
            },
        );
        let merged = merge_all_chunks(
            vec![c0, c1],
            TraceFormat::Gumtrace,
            false,
            skip_strings,
            None,
            None,
        );
        assert!(
            merged.is_ok(),
            "两 chunk merge skip_strings={skip_strings} 不得 panic：{}",
            merged
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );
    }
}

fn setup_query_session(skip_strings: bool) -> (TraceEngine, String, std::path::PathBuf) {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "trace-ui-h14-query-{}-{}.log",
        std::process::id(),
        n
    ));
    std::fs::write(
        &path,
        "[App] 0x1000!0x1000 mov x0, #0x1; x0=0x0 -> x0=0x1\n",
    )
    .expect("write query fixture");
    let _guard = trace_core::cache::cache_dir_override_test_lock();
    let dir = std::env::temp_dir().join(format!(
        "trace-ui-h14-query-cache-{}-{}",
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create cache dir");
    trace_core::cache::set_cache_dir_override(Some(dir));
    let engine = TraceEngine::new();
    let sid = engine
        .create_session(path.to_str().expect("utf8"))
        .expect("session")
        .session_id;
    engine
        .build_index(
            &sid,
            BuildOptions {
                force_rebuild: true,
                skip_strings,
            },
            None,
        )
        .expect("build_index");
    (engine, sid, path)
}

#[test]
fn query_apis_top_address_return_error_not_panic() {
    // ISSUE-H14：生产查询面必须 checked；完整窗口无法形成时返回 TraceError。
    for skip_strings in [true, false] {
        let (engine, sid, path) = setup_query_session(skip_strings);
        for length in [16u32, 256] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.get_memory_at(&sid, u64::MAX, 0, length)
            }));
            let inner = result.unwrap_or_else(|_| {
                panic!(
                    "get_memory_at length={length} skip_strings={skip_strings} 不得 overflow panic"
                )
            });
            if length == 16 {
                assert!(inner.is_ok(), "对齐后 16 字节窗口落在可寻址末端，应成功");
            } else {
                assert!(
                    inner.is_err(),
                    "get_memory_at(u64::MAX, {length}) 越过地址空间必须 TraceError"
                );
            }
        }
        let xref = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.get_string_xrefs(&sid, u64::MAX, 16)
        }));
        let xref = xref.unwrap_or_else(|_| {
            panic!("get_string_xrefs skip_strings={skip_strings} 不得 overflow panic")
        });
        assert!(
            xref.is_err(),
            "get_string_xrefs(u64::MAX, 16) 无法形成完整范围"
        );
        engine.close_session(&sid).ok();
        let _ = std::fs::remove_file(path);
    }
}
