//! fingerprint 的内容绑定：fstat 签名命中不等于内容一致。

use std::fs::File;

use super::fingerprint::{
    fd_signature, fd_trace_hash_verified, fingerprint_path, FingerprintSource,
};
use super::{sha256, FINGERPRINT_MAGIC};
use crate::cache::cache_dir_override_test_lock;

const RAW: &str = "[App] 0x400000!0x0 bl #0x401000; x0=0x6000 sp=0x8000\n\
[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x6000 mem_r=0x6000 -> x9=0x1\n\
[App] 0x401008!0x1008 ret; x0=0x6000\n";

/// mtime/ctime 的纳秒精度在部分文件系统上只有 1-4ms 粒度：同毫秒内等长的
/// 原地改写会让签名完全不变。小文件必须用内容本身确认 fingerprint，否则
/// 会把旧内容的 hash 当成新内容的身份，后续查询会命中旧缓存。
#[test]
fn small_trace_fingerprint_is_confirmed_by_content_not_only_by_timestamps() {
    let _lock = cache_dir_override_test_lock();
    let dir = std::env::temp_dir().join(format!(
        "trace-ui-fingerprint-content-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    crate::cache::set_cache_dir_override(Some(dir.clone()));

    let trace_path = dir.join("trace.log");
    std::fs::write(&trace_path, RAW).unwrap();
    let file = File::open(&trace_path).unwrap();
    let data = std::fs::read(&trace_path).unwrap();
    assert!(data.len() <= 64 * 1024, "样本必须走小文件内容校验路径");
    let baseline = fd_signature(&file).unwrap();

    let mut decisions = Vec::new();
    let first = fd_trace_hash_verified(
        &file,
        &data,
        &baseline,
        Some(&mut |source| decisions.push(source)),
    )
    .unwrap();
    assert_eq!(decisions, [FingerprintSource::Computed]);
    assert_eq!(first, sha256(&data));

    // 伪造一条「签名相同、内容 hash 不同」的记录：这正是同毫秒内等长改写
    // 之后时间戳没有推进时会被命中的那种 fingerprint。
    let mut record = Vec::with_capacity(FINGERPRINT_MAGIC.len() + 32);
    record.extend_from_slice(FINGERPRINT_MAGIC);
    record.extend_from_slice(&[0xAB; 32]);
    let fingerprint = fingerprint_path(&baseline).unwrap();
    std::fs::write(&fingerprint, &record).unwrap();

    decisions.clear();
    let verified = fd_trace_hash_verified(
        &file,
        &data,
        &baseline,
        Some(&mut |source| decisions.push(source)),
    )
    .unwrap();
    assert_eq!(
        decisions,
        [FingerprintSource::Computed],
        "签名未变但内容 hash 不符时必须重算"
    );
    assert_eq!(verified, first);
    assert_eq!(
        &std::fs::read(&fingerprint).unwrap()[FINGERPRINT_MAGIC.len()..],
        &first,
        "重算后必须把真实内容 hash 写回 fingerprint"
    );

    // 内容确认之后才允许复用。
    decisions.clear();
    let reused = fd_trace_hash_verified(
        &file,
        &data,
        &baseline,
        Some(&mut |source| decisions.push(source)),
    )
    .unwrap();
    assert_eq!(reused, first);
    assert_eq!(decisions, [FingerprintSource::Reused]);

    crate::cache::set_cache_dir_override(None);
    let _ = std::fs::remove_dir_all(dir);
}
