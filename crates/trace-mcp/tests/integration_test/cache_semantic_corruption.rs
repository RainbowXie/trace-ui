//! 缓存 section 的字节布局合法时，内部索引关系仍必须经过验证。

use super::*;
use sha2::{Digest, Sha256};

fn current_cache_dir() -> std::path::PathBuf {
    trace_core::cache::cache_dir().expect("setup_session 已设置隔离目录")
}

fn cache_file(path: &str, suffix: &str) -> std::path::PathBuf {
    current_cache_dir().join(format!(
        "{}{}",
        trace_core::cache::path_hash_for_test(path),
        suffix
    ))
}

fn section_entry(bytes: &[u8], index: usize) -> (usize, usize) {
    let base = 64 + 4 + index * 16;
    let offset = u64::from_le_bytes(bytes[base..base + 8].try_into().unwrap()) as usize;
    let length = u64::from_le_bytes(bytes[base + 8..base + 16].try_into().unwrap()) as usize;
    (offset, length)
}

fn set_section_length(bytes: &mut [u8], index: usize, length: u64) {
    let base = 64 + 4 + index * 16;
    bytes[base + 8..base + 16].copy_from_slice(&length.to_le_bytes());
}

fn refresh_section_digest(bytes: &mut [u8]) {
    let digest = Sha256::digest(&bytes[64..]);
    bytes[48..64].copy_from_slice(&digest[..16]);
}

fn build_after_mutation(path: &str, engine: &TraceEngine) -> trace_core::BuildResult {
    let info = engine.create_session(path).expect("reopen mutated cache");
    engine
        .build_index(
            &info.session_id,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("semantic corruption must miss and rescan")
}

#[test]
fn p2_csr_shape_corruption_triggers_rescan() {
    let path = get_trace_path();
    let (engine, sid, _guard) = setup_session_locked(&path);
    engine.close_session(&sid).unwrap();

    let file = cache_file(&path, ".p2.cache");
    let mut bytes = std::fs::read(&file).unwrap();
    let (_, addrs_len) = section_entry(&bytes, 0);
    let (_, offsets_len) = section_entry(&bytes, 1);
    assert!(
        addrs_len > 0 && offsets_len > 0,
        "fixture must exercise CSR data"
    );
    set_section_length(&mut bytes, 1, 0);
    refresh_section_digest(&mut bytes);
    std::fs::write(file, bytes).unwrap();

    let build = build_after_mutation(&path, &engine);
    assert!(!build.from_cache, "invalid p2 CSR must not be accepted");
}

#[test]
fn scan_parallel_array_corruption_triggers_rescan() {
    let path = get_trace_path();
    let (engine, sid, _guard) = setup_session_locked(&path);
    engine.close_session(&sid).unwrap();

    let file = cache_file(&path, ".scan.cache");
    let mut bytes = std::fs::read(&file).unwrap();
    let (_, addrs_len) = section_entry(&bytes, 8);
    let (_, lines_len) = section_entry(&bytes, 9);
    assert!(
        addrs_len > 0 && lines_len > 0,
        "fixture must exercise mem_last_def"
    );
    set_section_length(&mut bytes, 9, 0);
    refresh_section_digest(&mut bytes);
    std::fs::write(file, bytes).unwrap();

    let build = build_after_mutation(&path, &engine);
    assert!(
        !build.from_cache,
        "mismatched scan arrays must not be accepted"
    );
}

#[test]
fn lidx_missing_samples_with_nonzero_total_triggers_rescan() {
    let path = get_trace_path();
    let (engine, sid, _guard) = setup_session_locked(&path);
    engine.close_session(&sid).unwrap();

    let file = cache_file(&path, ".lidx.cache");
    let mut bytes = std::fs::read(&file).unwrap();
    let (_, samples_len) = section_entry(&bytes, 0);
    assert!(samples_len > 0, "fixture must contain a line-index sample");
    set_section_length(&mut bytes, 0, 0);
    refresh_section_digest(&mut bytes);
    std::fs::write(file, bytes).unwrap();

    let build = build_after_mutation(&path, &engine);
    assert!(!build.from_cache, "nonzero total requires sampled offsets");
}

#[test]
fn p2_record_payload_corruption_triggers_rescan() {
    let path = get_trace_path();
    let (engine, sid, _guard) = setup_session_locked(&path);
    engine.close_session(&sid).unwrap();

    let file = cache_file(&path, ".p2.cache");
    let mut bytes = std::fs::read(&file).unwrap();
    let (records_offset, records_len) = section_entry(&bytes, 2);
    assert!(
        records_len >= 24,
        "fixture must contain a memory-access record"
    );
    let first_record = 64 + records_offset;
    bytes[first_record + 21] = 0xff;
    std::fs::write(file, bytes).unwrap();

    let build = build_after_mutation(&path, &engine);
    assert!(
        !build.from_cache,
        "payload corruption that preserves section shape must not be accepted"
    );
}

#[test]
fn cross_cache_line_count_mismatch_triggers_rescan() {
    let path = get_trace_path();
    let (engine, sid, _guard) = setup_session_locked(&path);
    engine.close_session(&sid).unwrap();

    let file = cache_file(&path, ".lidx.cache");
    let mut bytes = std::fs::read(&file).unwrap();
    let (total_offset, total_len) = section_entry(&bytes, 1);
    assert_eq!(total_len, 4);
    let payload = 64 + total_offset;
    bytes[payload..payload + 4].copy_from_slice(&1u32.to_le_bytes());
    refresh_section_digest(&mut bytes);
    std::fs::write(file, bytes).unwrap();

    let build = build_after_mutation(&path, &engine);
    assert!(
        !build.from_cache,
        "scan and line-index metadata from different generations must not mix"
    );
}
