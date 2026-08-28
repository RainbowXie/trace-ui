//! 字符串 / 交叉引用 / 密码学扫描测试。

use super::*;

#[test]
fn test_get_strings() {
    let (engine, sid) = setup_session(&get_trace_path());

    let _result = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .expect("get_strings");
    // May or may not have strings depending on trace content
    // Just verify it doesn't error
    // get_strings should succeed (may have 0 strings in small trace)

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_scan_strings_after_skip() {
    let engine = Arc::new(TraceEngine::new());
    let info = engine
        .create_session(&get_trace_path())
        .expect("create_session");
    let sid = info.session_id.clone();

    // Build with skip_strings = true
    engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .expect("build_index skip_strings");

    // Now scan strings manually
    engine.scan_strings(&sid).expect("scan_strings");

    // Should be able to query strings now
    let _result = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .expect("get_strings after scan");
    // Verify it works without error

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_string_xrefs() {
    let (engine, sid) = setup_session(&get_trace_path());

    let strings = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .expect("get_strings");

    if !strings.strings.is_empty() {
        let s = &strings.strings[0];
        let addr_hex = s.addr.strip_prefix("0x").unwrap_or(&s.addr);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();
        let xrefs = engine
            .get_string_xrefs(&sid, addr, s.byte_len)
            .expect("get_string_xrefs");
        // xrefs may be empty if no cross-references, but should not error
        let _ = xrefs;
    }

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 密码学 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_scan_crypto_patterns() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Try cache first (should be None on first run)
    let _cached = engine.load_crypto_cache(&sid).expect("load_crypto_cache");
    let result = engine.scan_crypto(&sid).expect("scan_crypto");
    // Result should be valid (may have 0 matches for small trace)
    let _ = result;

    engine.close_session(&sid).unwrap();
}
