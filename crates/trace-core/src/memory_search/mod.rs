//! Streaming byte-pattern search over the temporal memory state of a trace.
//!
//! The phase-2 memory index is address-oriented and therefore cannot express
//! the state transitions needed by target discovery.  This module deliberately
//! replays the raw trace in sequence order and keeps only sparse byte state.

use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest, Sha256};
use trace_parser::types::TraceFormat;

use crate::error::{Result, TraceError};

mod cache;
mod cached;
#[cfg(unix)]
mod fingerprint;
mod scan;

#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod tests;

pub(crate) use cached::search_memory_cached_with_trace_hash;
pub use cached::{search_memory_cached, search_memory_cached_occurrences};
#[cfg(unix)]
pub use fingerprint::{
    fd_signature, search_memory_fd_verified, search_memory_fd_verified_with_signature, FdSignature,
    FingerprintSource,
};
pub use scan::search_memory;

pub(crate) const MAX_PAGE_SIZE: u32 = 200;
const MAX_PATTERN_SIZE: usize = 64 * 1024 * 1024;
const MAX_PUBLIC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const ANCHOR_SIZE: usize = 8;
pub(crate) const CACHE_MAGIC: &[u8; 8] = b"TMSRCH01";
// v5：扫描语义变为 fail-closed（整份输入无可识别指令行即报错）。v4 及更早
// 的缓存条目可能是由旧语义写下的“total=0”，必须整体作废重扫。
pub(crate) const CACHE_COMPAT_VERSION: &[u8] = b"memory-search-v5";
/// header 字段区长度；其后紧跟 32 字节的字段区 SHA-256 摘要。
pub(crate) const CACHE_HEADER_LEN: usize = 120;
/// 摘要长度；损坏的 count/格式位/过滤器若未同步重算摘要即被拒绝并重建。
pub(crate) const CACHE_HEADER_DIGEST_LEN: usize = 32;
pub(crate) fn cache_header_total_len() -> u64 {
    (CACHE_HEADER_LEN + CACHE_HEADER_DIGEST_LEN) as u64
}
pub(crate) const CACHE_RECORD_LEN: usize = 16;
/// 每条 record 的完整性 tag 长度；tag 绑定 record 内容与其序号。
pub(crate) const CACHE_TAG_LEN: usize = 8;
/// 响应预算里每个 match 的固定 JSON 开销上界（键名、引号、转义余量）。
const PER_MATCH_ENVELOPE: usize = 512;
/// 响应预算里响应体外层字段的固定开销上界。
const RESPONSE_BASE_ENVELOPE: usize = 512;
/// staging 文件的最长存活时间：PID 被复用后靠它兜底回收。
pub(crate) const STAGING_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
#[cfg(unix)]
pub(crate) const FINGERPRINT_MAGIC: &[u8; 8] = b"TMSFPR01";

#[cfg(test)]
pub(crate) static SEARCH_SCAN_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static TRACE_HASH_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static CACHE_RECORD_READ_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySearchRw {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySearchOptions {
    pub pattern: Vec<u8>,
    /// Inclusive sequence range.
    pub seq_range: Option<(u32, u32)>,
    /// Half-open address range.
    pub memory_range: Option<(u64, u64)>,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemorySearchMatch {
    pub address: u64,
    pub seq: u32,
    pub size: u32,
    #[serde(serialize_with = "serialize_hex")]
    pub bytes: Vec<u8>,
    pub rw: MemorySearchRw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemorySearchResult {
    pub matches: Vec<MemorySearchMatch>,
    pub total: u32,
    pub offset: u32,
    pub limit: u32,
    pub has_more: bool,
}

/// A match occurrence without materialized pattern bytes.  This is the
/// bounded internal representation used when a caller already owns the
/// pattern (for example the fd adapter helper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemorySearchOccurrence {
    pub address: u64,
    pub seq: u32,
    pub size: u32,
    pub rw: MemorySearchRw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemorySearchOccurrenceResult {
    /// Stable identity derived from the complete trace content, pattern,
    /// filters, format, and cache compatibility version.
    pub content_identity: String,
    pub matches: Vec<MemorySearchOccurrence>,
    pub total: u32,
    pub offset: u32,
    pub limit: u32,
    pub has_more: bool,
}

/// Compact internal occurrence.  The pattern bytes are materialized only for
/// the response page; retaining them for every historical occurrence would
/// multiply memory by `matches × pattern_length`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryOccurrence {
    pub(crate) address: u64,
    pub(crate) seq: u32,
    pub(crate) rw: MemorySearchRw,
}

/// 扫描与缓存共用的完整结果页。
#[derive(Debug)]
pub(crate) struct CachePage {
    pub(crate) total: u32,
    pub(crate) matches: Vec<MemoryOccurrence>,
    pub(crate) has_more: bool,
}

impl serde::Serialize for MemorySearchRw {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::Read => "read",
            Self::Write => "write",
        })
    }
}

fn serialize_hex<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    serializer.serialize_str(&encoded)
}

/// Parse the compact or whitespace-separated hexadecimal request form.
pub fn parse_pattern_hex(input: &str) -> Result<Vec<u8>> {
    let mut digits = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(TraceError::InvalidArgument(
                "pattern must contain only hexadecimal digits and whitespace".to_string(),
            ));
        }
        digits.push(byte);
    }
    if digits.is_empty() || digits.len() % 2 != 0 {
        return Err(TraceError::InvalidArgument(
            "pattern must contain a non-empty even number of hexadecimal digits".to_string(),
        ));
    }
    if digits.len() / 2 > MAX_PATTERN_SIZE {
        return Err(TraceError::InvalidArgument(format!(
            "pattern exceeds the {} byte limit",
            MAX_PATTERN_SIZE
        )));
    }
    let mut pattern = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let high = hex_nibble(pair[0]).expect("validated hexadecimal digit");
        let low = hex_nibble(pair[1]).expect("validated hexadecimal digit");
        pattern.push((high << 4) | low);
    }
    Ok(pattern)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn validate_options(options: &MemorySearchOptions) -> Result<()> {
    if options.pattern.is_empty() {
        return Err(TraceError::InvalidArgument(
            "pattern must not be empty".to_string(),
        ));
    }
    if options.pattern.len() > MAX_PATTERN_SIZE {
        return Err(TraceError::InvalidArgument(format!(
            "pattern exceeds the {} byte limit",
            MAX_PATTERN_SIZE
        )));
    }
    if options.limit == 0 || options.limit > MAX_PAGE_SIZE {
        return Err(TraceError::InvalidArgument(format!(
            "limit must be between 1 and {}",
            MAX_PAGE_SIZE
        )));
    }
    if let Some((start, end)) = options.seq_range {
        if start > end {
            return Err(TraceError::InvalidArgument(
                "seq range start exceeds end".to_string(),
            ));
        }
    }
    if let Some((start, end)) = options.memory_range {
        if start >= end {
            return Err(TraceError::InvalidArgument(
                "memory range must be non-empty and half-open".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn trace_content_hash(data: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    TRACE_HASH_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    sha256(data)
}

pub(crate) fn compute_trace_content_hash(data: &[u8]) -> [u8; 32] {
    trace_content_hash(data)
}

pub(crate) fn ensure_trace_unchanged(data: &[u8], expected_hash: &[u8; 32]) -> Result<()> {
    let actual_hash = trace_content_hash(data);
    if &actual_hash != expected_hash {
        return Err(TraceError::CacheError(
            "trace changed during memory search; cache was not published".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn write_filter_key(hasher: &mut Sha256, options: &MemorySearchOptions) {
    match options.seq_range {
        Some((start, end)) => {
            hasher.update([1]);
            hasher.update(start.to_le_bytes());
            hasher.update(end.to_le_bytes());
        }
        None => hasher.update([0]),
    }
    match options.memory_range {
        Some((start, end)) => {
            hasher.update([1]);
            hasher.update(start.to_le_bytes());
            hasher.update(end.to_le_bytes());
        }
        None => hasher.update([0]),
    }
}

/// Compute the stable identity used by the complete-result cache and the
/// internal fd-helper response.  It deliberately contains no pathname.
pub fn memory_search_content_identity(
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
    format: TraceFormat,
    options: &MemorySearchOptions,
) -> String {
    let mut key = Sha256::new();
    key.update(CACHE_COMPAT_VERSION);
    key.update(trace_hash);
    key.update(pattern_hash);
    key.update([match format {
        TraceFormat::Unidbg => 0,
        TraceFormat::Gumtrace => 1,
    }]);
    write_filter_key(&mut key, options);
    format!("{:x}", key.finalize())
}

pub(crate) fn validate_public_response_budget(options: &MemorySearchOptions) -> Result<()> {
    // Public results hex-encode the pattern for every match.  The envelope is
    // a proven upper bound: a match object is the 2·len hex payload plus the
    // fixed JSON keys (address/seq/size/rw, each bounded by integer digit
    // counts), and the MCP transport nests the body as a JSON string whose
    // escaping can only grow the fixed ASCII syntax, never the hex digits.
    // The occurrence-only adapter intentionally bypasses this because it does
    // not materialize pattern bytes.
    let per_match = options
        .pattern
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(PER_MATCH_ENVELOPE))
        .ok_or_else(|| TraceError::InvalidArgument("search response is too large".to_string()))?;
    let maximum = per_match
        .checked_mul(options.limit as usize)
        .and_then(|size| size.checked_add(RESPONSE_BASE_ENVELOPE))
        .ok_or_else(|| TraceError::InvalidArgument("search response is too large".to_string()))?;
    if maximum > MAX_PUBLIC_RESPONSE_BYTES {
        return Err(TraceError::InvalidArgument(format!(
            "search response exceeds the {} byte limit; use the occurrence-only adapter for large patterns",
            MAX_PUBLIC_RESPONSE_BYTES
        )));
    }
    Ok(())
}

pub fn memory_cache_path(
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
    format: TraceFormat,
    options: &MemorySearchOptions,
) -> Option<PathBuf> {
    let cache_dir = crate::cache::cache_dir()?;
    Some(cache_dir.join(format!(
        "{}.memory-search.cache",
        memory_search_content_identity(trace_hash, pattern_hash, format, options)
    )))
}
