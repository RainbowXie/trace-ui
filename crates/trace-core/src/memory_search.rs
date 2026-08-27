//! Streaming byte-pattern search over the temporal memory state of a trace.
//!
//! The phase-2 memory index is address-oriented and therefore cannot express
//! the state transitions needed by target discovery.  This module deliberately
//! replays the raw trace in sequence order and keeps only sparse byte state.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use trace_parser::{
    gumtrace, parser,
    types::{MemLayout, MemOp, TraceFormat},
};

use crate::error::{Result, TraceError};

const MAX_PAGE_SIZE: u32 = 200;
const MAX_PATTERN_SIZE: usize = 64 * 1024 * 1024;
const MAX_PUBLIC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const ANCHOR_SIZE: usize = 8;
const CACHE_MAGIC: &[u8; 8] = b"TMSRCH01";
const CACHE_COMPAT_VERSION: &[u8] = b"memory-search-v3";
const CACHE_HEADER_LEN: usize = 120;
const CACHE_RECORD_LEN: usize = 16;
/// 每条 record 的完整性 tag 长度；tag 绑定 record 内容与其序号。
const CACHE_TAG_LEN: usize = 8;
/// 响应预算里每个 match 的固定 JSON 开销上界（键名、引号、转义余量）。
const PER_MATCH_ENVELOPE: usize = 512;
/// 响应预算里响应体外层字段的固定开销上界。
const RESPONSE_BASE_ENVELOPE: usize = 512;
/// staging 文件的最长存活时间：PID 被复用后靠它兜底回收。
const STAGING_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
const FINGERPRINT_MAGIC: &[u8; 8] = b"TMSFPR01";

#[cfg(test)]
static SEARCH_SCAN_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TRACE_HASH_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CACHE_RECORD_READ_COUNT: std::sync::atomic::AtomicUsize =
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
struct MemoryOccurrence {
    address: u64,
    seq: u32,
    rw: MemorySearchRw,
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

#[derive(Clone, Copy)]
struct ByteValue {
    value: u8,
    known: bool,
}

impl ByteValue {
    fn unknown() -> Self {
        Self {
            value: 0,
            known: false,
        }
    }
}

#[derive(Default)]
struct SparseMemory {
    bytes: HashMap<u64, ByteValue>,
}

impl SparseMemory {
    fn get(&self, address: u64) -> ByteValue {
        self.bytes
            .get(&address)
            .copied()
            .unwrap_or_else(ByteValue::unknown)
    }

    fn set(&mut self, address: u64, value: ByteValue) {
        if value.known {
            self.bytes.insert(address, value);
        } else {
            // Keeping explicit unknown entries would only consume memory and
            // has the same observable meaning as an absent sparse byte.
            self.bytes.remove(&address);
        }
    }

    fn matches(&self, address: u64, pattern: &[u8]) -> bool {
        pattern.iter().enumerate().all(|(offset, expected)| {
            let Some(addr) = address.checked_add(offset as u64) else {
                return false;
            };
            let actual = self.get(addr);
            actual.known && actual.value == *expected
        })
    }

    fn anchor_key(&self, address: u64, anchor_len: usize) -> Option<u64> {
        let mut key = 0u64;
        for i in 0..anchor_len {
            let addr = address.checked_add(i as u64)?;
            let byte = self.get(addr);
            if !byte.known {
                return None;
            }
            key |= (byte.value as u64) << (i * 8);
        }
        Some(key)
    }
}

struct SearchState<'a> {
    memory: SparseMemory,
    anchor_len: usize,
    anchor_key: u64,
    /// Starts whose current bytes equal this search's fixed anchor.  Keeping
    /// only the target bucket avoids a map/bucket for every observed value in
    /// a large trace.
    anchor_positions: BTreeSet<u64>,
    active_matches: HashSet<u64>,
    pattern: &'a [u8],
}

impl<'a> SearchState<'a> {
    fn new(pattern: &'a [u8]) -> Self {
        let anchor_len = pattern.len().min(ANCHOR_SIZE);
        let mut anchor_key = 0u64;
        for (i, byte) in pattern[..anchor_len].iter().enumerate() {
            anchor_key |= (*byte as u64) << (i * 8);
        }
        Self {
            memory: SparseMemory::default(),
            anchor_len,
            anchor_key,
            anchor_positions: BTreeSet::new(),
            active_matches: HashSet::new(),
            pattern,
        }
    }

    fn candidate_range(&self, start: u64, size: usize) -> Option<(u64, u64)> {
        let last = start.checked_add(size.checked_sub(1)? as u64)?;
        let back = self.pattern.len().checked_sub(1)? as u64;
        Some((start.saturating_sub(back), last))
    }

    fn collect_candidates(&self, range: (u64, u64), output: &mut BTreeSet<u64>) {
        output.extend(self.anchor_positions.range(range.0..=range.1).copied());
    }

    fn update_anchor_position(&mut self, start: u64) {
        let Some(key) = self.memory.anchor_key(start, self.anchor_len) else {
            self.anchor_positions.remove(&start);
            return;
        };
        if key == self.anchor_key {
            self.anchor_positions.insert(start);
        } else {
            self.anchor_positions.remove(&start);
        }
    }

    fn update_anchor_positions_around(&mut self, address: u64) {
        for delta in 0..self.anchor_len {
            let Some(start) = address.checked_sub(delta as u64) else {
                continue;
            };
            self.update_anchor_position(start);
        }
    }

    // Filters and the occurrence sink travel together through every replay;
    // grouping them into a struct would only obscure the event loop.
    #[allow(clippy::too_many_arguments)]
    fn process_event(
        &mut self,
        address: u64,
        values: &[ByteValue],
        seq: u32,
        rw: MemorySearchRw,
        seq_range: Option<(u32, u32)>,
        memory_range: Option<(u64, u64)>,
        sink: &mut impl FnMut(MemoryOccurrence) -> Result<()>,
    ) -> Result<()> {
        if values.is_empty() {
            return Ok(());
        }
        let mut candidates = BTreeSet::new();
        let Some(range) = self.candidate_range(address, values.len()) else {
            return Err(TraceError::ParseError {
                line: Some(seq),
                detail: "memory access range overflows u64".to_string(),
            });
        };
        // Capture old anchors too, otherwise a changed anchor would make an
        // already-active match impossible to retire.
        self.collect_candidates(range, &mut candidates);

        for (offset, value) in values.iter().copied().enumerate() {
            let byte_address =
                address
                    .checked_add(offset as u64)
                    .ok_or_else(|| TraceError::ParseError {
                        line: Some(seq),
                        detail: "memory access range overflows u64".to_string(),
                    })?;
            // A missing read value means the trace did not expose a new
            // observation; retain any previously known state.  A missing
            // write value is different: the write happened, but its bytes are
            // unknown, so it must invalidate any prior match.
            if value.known || rw == MemorySearchRw::Write {
                self.memory.set(byte_address, value);
            }
            self.update_anchor_positions_around(byte_address);
        }

        self.collect_candidates(range, &mut candidates);
        for start in candidates {
            let is_match = self.memory.matches(start, self.pattern);
            let was_match = self.active_matches.contains(&start);
            if is_match {
                self.active_matches.insert(start);
                if !was_match
                    && seq_range.is_none_or(|(first, last)| seq >= first && seq <= last)
                    && memory_range.is_none_or(|(first, last)| {
                        start >= first
                            && start
                                .checked_add(self.pattern.len() as u64)
                                .is_some_and(|end| end <= last)
                    })
                {
                    sink(MemoryOccurrence {
                        address: start,
                        seq,
                        rw,
                    })?;
                }
            } else {
                self.active_matches.remove(&start);
            }
        }
        Ok(())
    }
}

/// Search raw trace bytes in sequence order.
pub fn search_memory(
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
) -> Result<MemorySearchResult> {
    validate_options(&options)?;
    validate_public_response_budget(&options)?;
    let page = scan_memory_page(data, format, &options)?;
    paginate_page(page, &options)
}

fn scan_memory_page(
    data: &[u8],
    format: TraceFormat,
    options: &MemorySearchOptions,
) -> Result<CachePage> {
    let mut page = Vec::new();
    let mut total = 0u64;
    scan_memory_with_sink(data, format, options, |occurrence| {
        let index = total;
        total = total.saturating_add(1);
        let page_end = u64::from(options.offset).saturating_add(u64::from(options.limit));
        if index >= u64::from(options.offset) && index < page_end {
            page.push(occurrence);
        }
        Ok(())
    })?;
    let total = u32::try_from(total)
        .map_err(|_| TraceError::InvalidArgument("too many memory search matches".to_string()))?;
    let end = u64::from(options.offset)
        .saturating_add(u64::from(options.limit))
        .min(u64::from(total));
    Ok(CachePage {
        total,
        matches: page,
        has_more: end < u64::from(total),
    })
}

fn scan_memory_with_sink(
    data: &[u8],
    format: TraceFormat,
    options: &MemorySearchOptions,
    mut sink: impl FnMut(MemoryOccurrence) -> Result<()>,
) -> Result<()> {
    let mut state = SearchState::new(&options.pattern);

    for (seq_index, line_bytes) in data.split(|byte| *byte == b'\n').enumerate() {
        let seq = u32::try_from(seq_index).map_err(|_| TraceError::ParseError {
            line: None,
            detail: "trace contains more than u32::MAX sequence lines".to_string(),
        })?;
        let line_bytes = line_bytes.strip_suffix(b"\r").unwrap_or(line_bytes);
        let Ok(line) = std::str::from_utf8(line_bytes) else {
            return Err(TraceError::ParseError {
                line: Some(seq),
                detail: "trace line is not valid UTF-8".to_string(),
            });
        };
        let contains_memory_event = match format {
            TraceFormat::Unidbg => line_bytes.windows(4).any(|window| window == b"mem["),
            TraceFormat::Gumtrace => line_bytes
                .windows(6)
                .any(|window| window == b"mem_w=" || window == b"mem_r="),
        };
        let parsed = match format {
            TraceFormat::Unidbg => parser::parse_line(line),
            TraceFormat::Gumtrace => gumtrace::parse_line_gumtrace(line),
        };
        let Some(parsed) = parsed else {
            if contains_memory_event {
                return Err(TraceError::ParseError {
                    line: Some(seq),
                    detail: "malformed memory event".to_string(),
                });
            }
            continue;
        };
        let Some(mem) = parsed.mem_op.as_ref() else {
            if contains_memory_event {
                return Err(TraceError::ParseError {
                    line: Some(seq),
                    detail: "malformed memory event".to_string(),
                });
            }
            continue;
        };
        let rw = if mem.is_write {
            MemorySearchRw::Write
        } else {
            MemorySearchRw::Read
        };
        let values = expand_mem_op(mem);
        state.process_event(
            mem.abs,
            &values,
            seq,
            rw,
            options.seq_range,
            options.memory_range,
            &mut sink,
        )?;
    }
    Ok(())
}

/// Search with the complete-result disk cache used by the engine session API.
/// The cache contains no pagination state; every page is cut from the exact
/// result set after a successful scan and validation.
pub fn search_memory_cached(
    _file_path: &str,
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
) -> Result<MemorySearchResult> {
    validate_options(&options)?;
    validate_public_response_budget(&options)?;
    let trace_hash = trace_content_hash(data);
    search_memory_cached_with_trace_hash(data, format, options, trace_hash)
}

/// Search using a fingerprint established by the owning trace session.  The
/// session performs its O(1) file-identity checks around this call, allowing
/// pagination to reuse the already verified trace content identity without
/// hashing the complete mmap for every page.
pub(crate) fn search_memory_cached_with_trace_hash(
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
    trace_hash: [u8; 32],
) -> Result<MemorySearchResult> {
    validate_options(&options)?;
    validate_public_response_budget(&options)?;
    let pattern_hash = sha256(&options.pattern);
    let page = complete_cached_page(data, format, &options, &trace_hash, &pattern_hash)?;
    paginate_page(page, &options)
}

/// Search through the complete-result cache without cloning the pattern into
/// every response occurrence.  The caller must already possess the pattern;
/// this keeps helper output and memory bounded for large patterns.
pub fn search_memory_cached_occurrences(
    _file_path: &str,
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
) -> Result<MemorySearchOccurrenceResult> {
    validate_options(&options)?;
    let trace_hash = trace_content_hash(data);
    let pattern_hash = sha256(&options.pattern);
    let content_identity =
        memory_search_content_identity(&trace_hash, &pattern_hash, format, &options);
    let page = complete_cached_page(data, format, &options, &trace_hash, &pattern_hash)?;
    paginate_occurrences(page, &options, content_identity)
}

#[derive(Debug)]
struct CachePage {
    total: u32,
    matches: Vec<MemoryOccurrence>,
    has_more: bool,
}

fn complete_cached_page(
    data: &[u8],
    format: TraceFormat,
    options: &MemorySearchOptions,
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
) -> Result<CachePage> {
    let content_identity =
        memory_search_content_identity(trace_hash, pattern_hash, format, options);
    let Some(cache_path) = memory_cache_path(trace_hash, pattern_hash, format, options) else {
        let page = scan_memory_page(data, format, options)?;
        ensure_trace_unchanged(data, trace_hash)?;
        return Ok(page);
    };

    // 命中路径也必须回收遗留 staging，否则只读命中永远不清理。
    if let Some(parent) = cache_path.parent() {
        cleanup_stale_staging_files(parent)?;
    }

    if let Some(page) = load_cache_page(
        &cache_path,
        data.len() as u64,
        trace_hash,
        pattern_hash,
        format,
        options,
        &content_identity,
    ) {
        return Ok(page);
    }

    #[cfg(test)]
    SEARCH_SCAN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    stream_cache(
        &cache_path,
        data,
        data.len() as u64,
        trace_hash,
        pattern_hash,
        format,
        options,
        &content_identity,
    )?;
    load_cache_page(
        &cache_path,
        data.len() as u64,
        trace_hash,
        pattern_hash,
        format,
        options,
        &content_identity,
    )
    .ok_or_else(|| {
        TraceError::CacheError("newly written memory cache failed validation".to_string())
    })
}

fn paginate_page(page: CachePage, options: &MemorySearchOptions) -> Result<MemorySearchResult> {
    let matches = page
        .matches
        .iter()
        .map(|item| MemorySearchMatch {
            address: item.address,
            seq: item.seq,
            size: options.pattern.len() as u32,
            bytes: options.pattern.clone(),
            rw: item.rw,
        })
        .collect();
    Ok(MemorySearchResult {
        matches,
        total: page.total,
        offset: options.offset,
        limit: options.limit,
        has_more: page.has_more,
    })
}

fn paginate_occurrences(
    page: CachePage,
    options: &MemorySearchOptions,
    content_identity: String,
) -> Result<MemorySearchOccurrenceResult> {
    let size = u32::try_from(options.pattern.len())
        .map_err(|_| TraceError::InvalidArgument("pattern is too large".to_string()))?;
    let matches = page
        .matches
        .iter()
        .map(|item| MemorySearchOccurrence {
            address: item.address,
            seq: item.seq,
            size,
            rw: item.rw,
        })
        .collect();
    Ok(MemorySearchOccurrenceResult {
        content_identity,
        matches,
        total: page.total,
        offset: options.offset,
        limit: options.limit,
        has_more: page.has_more,
    })
}

fn validate_public_response_budget(options: &MemorySearchOptions) -> Result<()> {
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

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn trace_content_hash(data: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    TRACE_HASH_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    sha256(data)
}

pub(crate) fn compute_trace_content_hash(data: &[u8]) -> [u8; 32] {
    trace_content_hash(data)
}

fn ensure_trace_unchanged(data: &[u8], expected_hash: &[u8; 32]) -> Result<()> {
    let actual_hash = trace_content_hash(data);
    if &actual_hash != expected_hash {
        return Err(TraceError::CacheError(
            "trace changed during memory search; cache was not published".to_string(),
        ));
    }
    Ok(())
}

// ── fd fingerprint：helper 的受验证内容身份复用 ──

/// 同一 fd 的元数据签名。dev/ino/len/mtime/ctime 任一变化都意味着内容可能
/// 已变，此时持久化 fingerprint 一律失效。
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FdSignature {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(unix)]
fn fd_signature(file: &File) -> Result<FdSignature> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(TraceError::Io)?;
    Ok(FdSignature {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn fingerprint_path(signature: &FdSignature) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(signature.dev.to_le_bytes());
    hasher.update(signature.ino.to_le_bytes());
    hasher.update(signature.len.to_le_bytes());
    hasher.update(signature.mtime.to_le_bytes());
    hasher.update(signature.mtime_nsec.to_le_bytes());
    hasher.update(signature.ctime.to_le_bytes());
    hasher.update(signature.ctime_nsec.to_le_bytes());
    let name = format!("{:x}", hasher.finalize());
    Some(crate::cache::cache_dir()?.join("fingerprints").join(name))
}

#[cfg(unix)]
fn load_fd_fingerprint(signature: &FdSignature) -> Option<[u8; 32]> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = fingerprint_path(signature)?;
    // no-follow + fstat + 精确长度：FIFO 会阻塞读、符号链接可指向任意目标、
    // 超大文件会导致不受控分配，全部在读取前拒绝。
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    let expected_len = (FINGERPRINT_MAGIC.len() + 32) as u64;
    if !metadata.is_file() || metadata.len() != expected_len {
        return None;
    }
    let mut bytes = [0u8; 40];
    file.read_exact(&mut bytes).ok()?;
    if bytes[..8] != FINGERPRINT_MAGIC[..] {
        return None;
    }
    bytes[8..40].try_into().ok()
}

/// 持久化 fingerprint 只是加速手段：写入失败只影响后续性能，不影响正确性，
/// 因此尽力而为。读取侧只接受完整、带 magic 的内容。
#[cfg(unix)]
fn store_fd_fingerprint(signature: &FdSignature, trace_hash: &[u8; 32]) {
    let Some(path) = fingerprint_path(signature) else {
        return;
    };
    let Some(parent) = path.parent() else { return };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let temp = parent.join(format!(
        ".tmp.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut bytes = Vec::with_capacity(FINGERPRINT_MAGIC.len() + 32);
    bytes.extend_from_slice(FINGERPRINT_MAGIC);
    bytes.extend_from_slice(trace_hash);
    if fs::write(&temp, bytes).is_ok() {
        let _ = fs::rename(&temp, &path);
    } else {
        let _ = fs::remove_file(&temp);
    }
}

/// fingerprint 的来源。测试与诊断用它验证"第二页没有重新完整 hash"；
/// 生产路径不传 probe，零开销。
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintSource {
    /// trace 内容被完整 SHA-256（fingerprint 未命中或已失效）。
    Computed,
    /// fstat 签名与持久化 fingerprint 完全一致，复用了已验证的 hash。
    Reused,
}

/// fd helper 的搜索入口。trace 内容身份只通过 trace-ui 自己验证过的机制获得：
/// 首次对 mmap 做完整 SHA-256 并把 hash 与 fd 元数据签名绑定持久化；后续
/// 只有在 fstat 签名完全一致时才复用。搜索完成后再次 fstat，任何中途的
/// 原地修改都会使整个结果作废，而不是返回旧缓存。
///
/// `probe` 只用于测试观察 fingerprint 决策，生产调用传 None。
#[cfg(unix)]
pub fn search_memory_fd_verified(
    file: &File,
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
    probe: Option<&mut dyn FnMut(FingerprintSource)>,
) -> Result<MemorySearchOccurrenceResult> {
    validate_options(&options)?;
    let before = fd_signature(file)?;
    let trace_hash = match load_fd_fingerprint(&before) {
        Some(hash) => {
            // 复用前复验：读取 fingerprint 文件期间 fd 可能已被改写。
            if fd_signature(file)? != before {
                return Err(TraceError::CacheError(
                    "trace fd changed while loading its fingerprint".to_string(),
                ));
            }
            if let Some(probe) = probe {
                probe(FingerprintSource::Reused);
            }
            hash
        }
        None => {
            let hash = trace_content_hash(data);
            if fd_signature(file)? != before {
                return Err(TraceError::CacheError(
                    "trace fd changed while computing its content hash".to_string(),
                ));
            }
            store_fd_fingerprint(&before, &hash);
            if let Some(probe) = probe {
                probe(FingerprintSource::Computed);
            }
            hash
        }
    };
    let pattern_hash = sha256(&options.pattern);
    let content_identity =
        memory_search_content_identity(&trace_hash, &pattern_hash, format, &options);
    let page = complete_cached_page(data, format, &options, &trace_hash, &pattern_hash)?;
    if fd_signature(file)? != before {
        return Err(TraceError::CacheError(
            "trace fd changed while the memory search was running".to_string(),
        ));
    }
    paginate_occurrences(page, &options, content_identity)
}

fn write_filter_key(hasher: &mut Sha256, options: &MemorySearchOptions) {
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

/// 每条 record 的完整性 tag：绑定内容身份、记录序号与 record 字节。
/// 合法外观的篡改（改 seq/address/rw）或跨页复制都会使 tag 失配。
fn record_tag(identity: &str, index: u64, record: &[u8; CACHE_RECORD_LEN]) -> [u8; CACHE_TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(identity.as_bytes());
    hasher.update(index.to_le_bytes());
    hasher.update(record);
    hasher.finalize()[..CACHE_TAG_LEN]
        .try_into()
        .expect("tag length")
}

fn load_cache_page(
    path: &PathBuf,
    trace_len: u64,
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
    format: TraceFormat,
    options: &MemorySearchOptions,
    content_identity: &str,
) -> Option<CachePage> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() < CACHE_HEADER_LEN as u64 {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; CACHE_HEADER_LEN];
    file.read_exact(&mut header).ok()?;
    if &header[0..8] != CACHE_MAGIC
        || u64::from_le_bytes(header[8..16].try_into().ok()?) != trace_len
        || &header[16..48] != trace_hash
        || &header[48..80] != pattern_hash
        || header[80]
            != match format {
                TraceFormat::Unidbg => 0,
                TraceFormat::Gumtrace => 1,
            }
    {
        return None;
    }
    let flags = header[81];
    if flags & !0b11 != 0 {
        return None;
    }
    if header[106..112] != [0, 0, 0, 0, 0, 0] {
        return None;
    }
    let seq_range = decode_seq_range(&header[82..90], flags & 1 != 0)?;
    let memory_range = decode_memory_range(&header[90..106], flags & 2 != 0)?;
    if seq_range != options.seq_range || memory_range != options.memory_range {
        return None;
    }
    let count = u64::from_le_bytes(header[112..120].try_into().ok()?);
    let records_bytes = count.checked_mul(CACHE_RECORD_LEN as u64)?;
    let tags_bytes = count.checked_mul(CACHE_TAG_LEN as u64)?;
    let expected_len = (CACHE_HEADER_LEN as u64)
        .checked_add(records_bytes)?
        .checked_add(tags_bytes)?;
    if metadata.len() != expected_len {
        return None;
    }
    let total = u32::try_from(count).ok()?;
    let page_start = u64::from(options.offset);
    let page_end = page_start.saturating_add(u64::from(options.limit));
    let page_end = page_end.min(count);
    // 请求页完全越过结果末尾：直接返回空页，不能继续做减法。
    if page_start >= count {
        return Some(CachePage {
            total,
            matches: Vec::new(),
            has_more: false,
        });
    }
    let tags_offset = (CACHE_HEADER_LEN as u64).checked_add(records_bytes)?;
    // 除请求页外回读前一条边界 record：跨页的重复/逆序只能靠它发现。
    // 读取量仍是 O(page size + 1)，不会退化成从头扫描。
    let read_start = if page_start > 0 {
        page_start - 1
    } else {
        page_start
    };
    let read_len = page_end - read_start;
    let record_offset = read_start.checked_mul(CACHE_RECORD_LEN as u64)?;
    let record_offset = (CACHE_HEADER_LEN as u64).checked_add(record_offset)?;
    file.seek(std::io::SeekFrom::Start(record_offset)).ok()?;
    let record_bytes = (read_len as usize).checked_mul(CACHE_RECORD_LEN)?;
    let mut records = vec![0u8; record_bytes];
    file.read_exact(&mut records).ok()?;
    let tag_pos = tags_offset.checked_add(read_start.checked_mul(CACHE_TAG_LEN as u64)?)?;
    file.seek(std::io::SeekFrom::Start(tag_pos)).ok()?;
    let tag_bytes = (read_len as usize).checked_mul(CACHE_TAG_LEN)?;
    let mut tags = vec![0u8; tag_bytes];
    file.read_exact(&mut tags).ok()?;

    let mut matches = Vec::new();
    let mut previous_key: Option<(u32, u64)> = None;
    for index in read_start..page_end {
        let slot = (index - read_start) as usize;
        let record: &[u8; CACHE_RECORD_LEN] = records
            [slot * CACHE_RECORD_LEN..(slot + 1) * CACHE_RECORD_LEN]
            .try_into()
            .ok()?;
        let tag: &[u8; CACHE_TAG_LEN] = tags[slot * CACHE_TAG_LEN..(slot + 1) * CACHE_TAG_LEN]
            .try_into()
            .ok()?;
        if &record_tag(content_identity, index, record) != tag {
            return None;
        }
        if record[5..8] != [0, 0, 0] {
            return None;
        }
        let seq = u32::from_le_bytes(record[0..4].try_into().ok()?);
        let rw = match record[4] {
            0 => MemorySearchRw::Read,
            1 => MemorySearchRw::Write,
            _ => return None,
        };
        let address = u64::from_le_bytes(record[8..16].try_into().ok()?);
        if previous_key.is_some_and(|previous| (seq, address) <= previous) {
            return None;
        }
        previous_key = Some((seq, address));
        if index < page_start {
            continue; // 边界 record：只参与顺序校验，不进入响应页
        }
        #[cfg(test)]
        CACHE_RECORD_READ_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if options
            .seq_range
            .is_some_and(|(start, end)| seq < start || seq > end)
            || options.memory_range.is_some_and(|(start, end)| {
                address < start
                    || address
                        .checked_add(options.pattern.len() as u64)
                        .is_none_or(|match_end| match_end > end)
            })
        {
            return None;
        }
        matches.push(MemoryOccurrence { address, seq, rw });
    }
    Some(CachePage {
        total,
        matches,
        has_more: page_end < count,
    })
}

/// Flush the parent directory after publishing a cache file.  A cache whose
/// directory entry was not flushed cannot be considered published, so open
/// and sync failures are errors, not best-effort hints.
fn sync_parent_dir(parent: &Path) -> Result<()> {
    let parent_file = File::open(parent).map_err(TraceError::Io)?;
    parent_file.sync_all().map_err(TraceError::Io)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn stream_cache(
    path: &PathBuf,
    trace_bytes: &[u8],
    trace_len: u64,
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
    format: TraceFormat,
    options: &MemorySearchOptions,
    content_identity: &str,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        TraceError::CacheError("memory search cache has no parent directory".to_string())
    })?;
    fs::create_dir_all(parent).map_err(TraceError::Io)?;
    cleanup_stale_staging_files(parent)?;
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("memory-search"),
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(TraceError::Io)?;
        let header = make_cache_header(trace_len, trace_hash, pattern_hash, format, options, 0);
        file.write_all(&header).map_err(TraceError::Io)?;

        let mut count = 0u64;
        let mut previous_key: Option<(u32, u64)> = None;
        scan_memory_with_sink(trace_bytes, format, options, |item| {
            let key = (item.seq, item.address);
            if previous_key.is_some_and(|previous| key <= previous) {
                return Err(TraceError::CacheError(
                    "memory search produced non-increasing occurrence keys".to_string(),
                ));
            }
            previous_key = Some(key);
            count = count.checked_add(1).ok_or_else(|| {
                TraceError::InvalidArgument("too many memory search matches".to_string())
            })?;
            if count > u64::from(u32::MAX) {
                return Err(TraceError::InvalidArgument(
                    "too many memory search matches".to_string(),
                ));
            }
            let mut record = [0u8; CACHE_RECORD_LEN];
            record[0..4].copy_from_slice(&item.seq.to_le_bytes());
            record[4] = match item.rw {
                MemorySearchRw::Read => 0,
                MemorySearchRw::Write => 1,
            };
            record[8..16].copy_from_slice(&item.address.to_le_bytes());
            file.write_all(&record).map_err(TraceError::Io)?;
            Ok(())
        })?;
        ensure_trace_unchanged(trace_bytes, trace_hash)?;
        // 第二遍：顺序读回 record 并追加每条 record 的完整性 tag。
        // 只在构建时付出这次 O(N) 顺序 I/O；后续命中仍是 O(page)。
        let mut index = 0u64;
        let mut record_buf = [0u8; CACHE_RECORD_LEN];
        file.seek(std::io::SeekFrom::Start(CACHE_HEADER_LEN as u64))
            .map_err(TraceError::Io)?;
        let mut tag_buf = Vec::with_capacity(4096 * CACHE_TAG_LEN);
        while index < count {
            file.read_exact(&mut record_buf).map_err(TraceError::Io)?;
            tag_buf.extend_from_slice(&record_tag(content_identity, index, &record_buf));
            index += 1;
            if tag_buf.len() == 4096 * CACHE_TAG_LEN {
                let tag_pos = CACHE_HEADER_LEN as u64
                    + count * CACHE_RECORD_LEN as u64
                    + (index - 4096) * CACHE_TAG_LEN as u64;
                write_all_at(&file, &tag_buf, tag_pos).map_err(TraceError::Io)?;
                tag_buf.clear();
            }
        }
        if !tag_buf.is_empty() {
            let written = index - (tag_buf.len() / CACHE_TAG_LEN) as u64;
            let tag_pos = CACHE_HEADER_LEN as u64
                + count * CACHE_RECORD_LEN as u64
                + written * CACHE_TAG_LEN as u64;
            write_all_at(&file, &tag_buf, tag_pos).map_err(TraceError::Io)?;
        }
        file.seek(std::io::SeekFrom::Start(0))
            .map_err(TraceError::Io)?;
        let header = make_cache_header(trace_len, trace_hash, pattern_hash, format, options, count);
        file.write_all(&header).map_err(TraceError::Io)?;
        file.sync_all().map_err(TraceError::Io)?;
        fs::rename(&temp_path, path).map_err(TraceError::Io)?;
        sync_parent_dir(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_all_at(file: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(not(unix))]
    {
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(offset))?;
        file.write_all(buf)
    }
}

/// 检查指定进程是否实际持有（打开着）某个文件。
/// 用于区分“真实的长扫描 writer”与“复用了旧 PID 的无关进程”：
/// 前者任何年龄都不得回收，后者按年龄兑底。
#[cfg(target_os = "linux")]
fn staging_file_held_by(pid: u32, path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    for entry in entries.flatten() {
        if let Ok(link) = fs::read_link(entry.path()) {
            let link = fs::canonicalize(&link).unwrap_or(link);
            if link == target {
                return true;
            }
        }
    }
    false
}

#[cfg(all(unix, not(target_os = "linux")))]
fn staging_file_held_by(_pid: u32, _path: &Path) -> bool {
    // 无 /proc 可查时保守保留活着 PID 的 staging（年龄规则不介入）。
    true
}

/// Remove abandoned cache staging files left by a process that was killed
/// while scanning.  A live writer keeps its staging file; a subsequent build
/// reclaims files whose recorded writer PID no longer exists, so repeated
/// failed helpers cannot accumulate unbounded disk usage.
fn cleanup_stale_staging_files(parent: &Path) -> Result<()> {
    let entries = fs::read_dir(parent).map_err(TraceError::Io)?;
    let current_pid = std::process::id();
    for entry in entries {
        let entry = entry.map_err(TraceError::Io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(rest) = name.strip_prefix('.') else {
            continue;
        };
        let Some((cache_name, pid_and_uuid)) = rest.rsplit_once(".tmp.") else {
            continue;
        };
        if !cache_name.ends_with(".memory-search.cache") {
            continue;
        }
        let Some(pid_text) = pid_and_uuid.split('.').next() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        // 活着的 PID 仍可能是复用的：只有该进程实际持有这个文件时才一定是
        // 真实 writer，任何年龄都保留；不持有但较新的 staging 可能是即将被
        // 持有的并发构建，也保留；其余活着但过期的 staging 一律回收。
        let pid_alive = pid == current_pid || staging_process_is_alive(pid);
        if pid_alive {
            if staging_file_held_by(pid, &entry.path()) {
                continue;
            }
            let aged_out = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|modified| {
                    modified
                        .elapsed()
                        .map(|age| age > STAGING_MAX_AGE)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if !aged_out {
                continue;
            }
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(TraceError::Io(error)),
        }
    }
    Ok(())
}

fn staging_process_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if pid > i32::MAX as u32 {
            return false;
        }
        // SAFETY: kill(pid, 0) performs no signal delivery; it only probes
        // whether the process exists (EPERM still means it is alive).
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn make_cache_header(
    trace_len: u64,
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
    format: TraceFormat,
    options: &MemorySearchOptions,
    count: u64,
) -> [u8; CACHE_HEADER_LEN] {
    let mut header = [0u8; CACHE_HEADER_LEN];
    header[0..8].copy_from_slice(CACHE_MAGIC);
    header[8..16].copy_from_slice(&trace_len.to_le_bytes());
    header[16..48].copy_from_slice(trace_hash);
    header[48..80].copy_from_slice(pattern_hash);
    header[80] = match format {
        TraceFormat::Unidbg => 0,
        TraceFormat::Gumtrace => 1,
    };
    encode_ranges(&mut header, options);
    header[112..120].copy_from_slice(&count.to_le_bytes());
    header
}

fn encode_ranges(header: &mut [u8; CACHE_HEADER_LEN], options: &MemorySearchOptions) {
    let mut flags = 0u8;
    if let Some((seq_start, seq_end)) = options.seq_range {
        flags |= 1;
        header[82..86].copy_from_slice(&seq_start.to_le_bytes());
        header[86..90].copy_from_slice(&seq_end.to_le_bytes());
    }
    if let Some((memory_start, memory_end)) = options.memory_range {
        flags |= 2;
        header[90..98].copy_from_slice(&memory_start.to_le_bytes());
        header[98..106].copy_from_slice(&memory_end.to_le_bytes());
    }
    header[81] = flags;
}

fn decode_seq_range(bytes: &[u8], present: bool) -> Option<Option<(u32, u32)>> {
    if !present {
        return Some(None);
    }
    let start = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let end = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if start > end {
        return None;
    }
    Some(Some((start, end)))
}

fn decode_memory_range(bytes: &[u8], present: bool) -> Option<Option<(u64, u64)>> {
    if !present {
        return Some(None);
    }
    let start = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let end = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    if start >= end {
        return None;
    }
    Some(Some((start, end)))
}

fn validate_options(options: &MemorySearchOptions) -> Result<()> {
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

fn expand_mem_op(mem: &MemOp) -> Vec<ByteValue> {
    match mem.layout {
        // atomic/RMW 的最终字节是旧值与寄存器的运算结果，trace 注解不足以精确
        // 恢复：write 使整个访问范围失效，read 不覆盖已有已知值（两者都表现
        // 为全部 unknown）。
        MemLayout::Atomic => {
            let mut result = Vec::new();
            append_unknown(&mut result, mem.elem_width);
            result
        }
        // exclusive store 是否真正写入由状态寄存器决定：失败（非 0）对内存
        // 没有任何影响（不写字节也不失效）；状态未知时保守失效整个范围。
        MemLayout::ExclusiveScalar | MemLayout::ExclusivePair => match mem.exclusive_status {
            Some(0) => expand_scalar_or_pair(mem),
            Some(_) => Vec::new(),
            None => {
                let mut result = Vec::new();
                for _ in 0..mem.value_count.max(1) {
                    append_unknown(&mut result, mem.elem_width);
                }
                result
            }
        },
        // 单 lane structure / replicate load：每个寄存器只贡献一个元素。
        // replicate 的注解值在所有 lane 相同，lane 0 即内存字节。
        MemLayout::SimdLane => {
            let mut result = Vec::new();
            let elem = usize::from(mem.simd_elem_bytes);
            if elem == 0 {
                // 元素宽度不可得时不得猜：整个访问范围 unknown。
                for _ in 0..mem.value_count.max(1) {
                    append_unknown(&mut result, mem.elem_width);
                }
                return result;
            }
            for slot in 0..usize::from(mem.value_count) {
                append_simd_lane(
                    &mut result,
                    mem.simd_values[slot],
                    usize::from(mem.simd_lane) * elem,
                    elem,
                );
            }
            result
        }
        // 多寄存器 st1/ld1：每个寄存器的内容连续摆放。
        MemLayout::SimdContiguous => {
            let mut result = Vec::new();
            for slot in 0..usize::from(mem.value_count) {
                append_simd_reg(&mut result, mem.simd_values[slot], mem.simd_reg_bytes);
            }
            result
        }
        // st2-st4/ld2-ld4：同一 lane 的各寄存器元素相邻，按 lane 交错。
        MemLayout::SimdInterleaved => {
            let mut result = Vec::new();
            let reg_bytes = usize::from(mem.simd_reg_bytes);
            let elem = usize::from(mem.simd_elem_bytes);
            if reg_bytes == 0 || elem == 0 || elem > reg_bytes {
                // 排列信息不完整时不得猜布局：整个访问范围 unknown。
                append_unknown(&mut result, mem.elem_width);
                for _ in 1..mem.value_count {
                    append_unknown(&mut result, mem.elem_width);
                }
                return result;
            }
            let count = usize::from(mem.value_count);
            for lane in 0..(reg_bytes / elem) {
                for slot in 0..count {
                    append_simd_lane(&mut result, mem.simd_values[slot], lane * elem, elem);
                }
            }
            result
        }
        _ => expand_scalar_or_pair(mem),
    }
}

fn expand_scalar_or_pair(mem: &MemOp) -> Vec<ByteValue> {
    let mut result = Vec::new();
    if mem.elem_width <= 8 {
        append_scalar(&mut result, mem.elem_width, mem.value);
    } else {
        // 128-bit values use lo/hi instead of value.  Missing lanes stay
        // unknown; they must not be replaced with zero or omitted.
        append_wide(&mut result, mem.value_lo, mem.value_hi);
    }

    for slot in 1..mem.value_count {
        if slot == 1 {
            if mem.elem_width <= 8 {
                append_scalar(&mut result, mem.elem_width, mem.value2);
            } else {
                append_wide(&mut result, mem.value2_lo, mem.value2_hi);
            }
        } else {
            // Parser currently extracts at most two register values.  Any
            // remaining register slots are still part of the real access;
            // preserve their width as unknown rather than dropping them.
            append_unknown(&mut result, mem.elem_width);
        }
    }
    // A known scalar with a missing pair must still occupy the pair's byte
    // range when parser metadata says this is a pair.  The parser exposes no
    // separate pair width; callers only receive bytes it could actually read.
    result
}

/// 追加一个 SIMD 寄存器的低 reg_bytes 字节；缺失的寄存器值保持 unknown。
fn append_simd_reg(output: &mut Vec<ByteValue>, value: Option<u128>, reg_bytes: u8) {
    let bytes = value.map(u128::to_le_bytes);
    output.extend((0..usize::from(reg_bytes)).map(|i| match bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

/// 追加一个 SIMD 寄存器在某个 lane 上的元素字节；缺失的值保持 unknown。
fn append_simd_lane(output: &mut Vec<ByteValue>, value: Option<u128>, offset: usize, width: usize) {
    let bytes = value.map(u128::to_le_bytes);
    output.extend((offset..offset + width).map(|i| match bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

fn append_scalar(output: &mut Vec<ByteValue>, width: u8, value: Option<u64>) {
    let width = usize::from(width.min(8));
    if width == 0 {
        return;
    }
    let bytes = value.map(u64::to_le_bytes);
    output.extend((0..width).map(|i| match bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

fn append_wide(output: &mut Vec<ByteValue>, low: Option<u64>, high: Option<u64>) {
    let low_bytes = low.map(u64::to_le_bytes);
    let high_bytes = high.map(u64::to_le_bytes);
    output.extend((0..8).map(|i| match low_bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
    output.extend((0..8).map(|i| match high_bytes {
        Some(ref bytes) => ByteValue {
            value: bytes[i],
            known: true,
        },
        None => ByteValue::unknown(),
    }));
}

fn append_unknown(output: &mut Vec<ByteValue>, width: u8) {
    let bytes = if width <= 8 { usize::from(width) } else { 16 };
    output.extend((0..bytes).map(|_| ByteValue::unknown()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 测试 panic 会 poison 全局锁；缓存测试需要互相隔离的状态，
    /// 必须用 poison 容忍的方式取锁，否则一个失败会连带全部缓存测试。
    fn cache_test_guard() -> std::sync::MutexGuard<'static, ()> {
        CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
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
    fn cache_contains_all_occurrences_and_default_ranges_hit_without_rescanning() {
        let _guard = cache_test_guard();
        let mut trace = String::new();
        for index in 0..201u32 {
            trace.push_str(&format!(
                "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n",
                seq = index * 2,
            ));
            if index != 200 {
                trace.push_str(&format!(
                    "[00:00:00 {seq:03}][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n",
                    seq = index * 2 + 1,
                ));
            }
        }
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);

        let first = search_memory_cached(
            "/tmp/target-discovery.trace",
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                pattern: vec![1, 2, 3, 4],
                seq_range: None,
                memory_range: None,
                offset: 0,
                limit: 1,
            },
        )
        .expect("first cached search");
        assert_eq!(first.total, 201);
        CACHE_RECORD_READ_COUNT.store(0, Ordering::SeqCst);

        let second = search_memory_cached(
            "/tmp/renamed-target-discovery.trace",
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                pattern: vec![1, 2, 3, 4],
                seq_range: None,
                memory_range: None,
                offset: 200,
                limit: 1,
            },
        )
        .expect("cached second page");
        assert_eq!(second.total, 201);
        assert_eq!(second.matches.len(), 1);
        assert_eq!(second.matches[0].seq, 400);
        assert_eq!(CACHE_RECORD_READ_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);

        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn cache_identity_uses_trace_content_not_pathname() {
        let data = b"trace";
        let trace_hash = sha256(data);
        let pattern_hash = sha256(&[1, 2, 3]);
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        };
        assert_eq!(
            memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options),
            memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options),
        );
    }

    #[test]
    fn cache_with_nonzero_reserved_record_bytes_is_rejected_and_rebuilt() {
        let _guard = cache_test_guard();
        let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-corrupt-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        };
        let path = "/tmp/corrupt-memory-search.trace";
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("write cache");
        let trace_hash = sha256(trace.as_bytes());
        let pattern_hash = sha256(&options.pattern);
        let cache_path =
            memory_cache_path(&trace_hash, &pattern_hash, TraceFormat::Unidbg, &options)
                .expect("cache path");
        let mut bytes = std::fs::read(&cache_path).expect("read cache");
        bytes[CACHE_HEADER_LEN + 5] = 1;
        std::fs::write(&cache_path, bytes).expect("corrupt cache");
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
            .expect("rebuild cache");
        assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn cache_with_duplicate_occurrence_key_is_rejected_and_rebuilt() {
        let _guard = cache_test_guard();
        let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-duplicate-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 10,
        };
        let path = "/tmp/duplicate-memory-search.trace";
        let first =
            search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
                .expect("write cache");
        assert_eq!(first.total, 2);
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let mut bytes = std::fs::read(&cache_path).expect("read cache");
        let first_record = bytes[CACHE_HEADER_LEN..CACHE_HEADER_LEN + CACHE_RECORD_LEN].to_vec();
        bytes[CACHE_HEADER_LEN + CACHE_RECORD_LEN..CACHE_HEADER_LEN + 2 * CACHE_RECORD_LEN]
            .copy_from_slice(&first_record);
        std::fs::write(&cache_path, bytes).expect("corrupt cache");
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
        let rebuilt = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
            .expect("rebuild cache");
        assert_eq!(rebuilt.total, 2);
        assert_eq!(rebuilt.matches.len(), 2);
        assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn session_fingerprint_reuses_trace_hash_across_pages() {
        let _guard = cache_test_guard();
        let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-hash-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        };
        let path = "/tmp/hash-count-memory-search.trace";
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("write cache");
        let trace_hash = trace_content_hash(trace.as_bytes());
        TRACE_HASH_COUNT.store(0, Ordering::SeqCst);
        search_memory_cached_with_trace_hash(
            trace.as_bytes(),
            TraceFormat::Unidbg,
            options.clone(),
            trace_hash,
        )
        .expect("first page");
        search_memory_cached_with_trace_hash(
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                offset: 1,
                ..options
            },
            trace_hash,
        )
        .expect("second page");
        assert_eq!(TRACE_HASH_COUNT.load(Ordering::SeqCst), 0);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn stale_memory_cache_staging_is_removed_before_a_new_build() {
        let _guard = cache_test_guard();
        let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-staging-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        };
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let stale_path = cache_path.parent().expect("cache parent").join(format!(
            ".{}.tmp.4294967295.stale",
            cache_path
                .file_name()
                .expect("cache filename")
                .to_string_lossy()
        ));
        std::fs::write(&stale_path, vec![0u8; CACHE_HEADER_LEN]).expect("stale staging");
        search_memory_cached(
            "/tmp/staging-memory-search.trace",
            trace.as_bytes(),
            TraceFormat::Unidbg,
            options,
        )
        .expect("build cache");
        assert!(!stale_path.exists());
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn malformed_memory_event_fails_scan_and_does_not_publish_cache() {
        let _guard = cache_test_guard();
        let trace = "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=not-an-address w0=0x04030201 x1=0x3000 => w0=0x04030201\n";
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-malformed-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        };
        let result = search_memory_cached(
            "/tmp/malformed-memory-search.trace",
            trace.as_bytes(),
            TraceFormat::Unidbg,
            options.clone(),
        );
        assert!(result.is_err());
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        assert!(!cache_path.exists());
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn cache_scan_failure_does_not_publish_partial_cache() {
        let _guard = cache_test_guard();
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-failure-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        let trace = b"\xff\n";
        let options = MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 1,
        };
        let result = search_memory_cached(
            "/tmp/invalid-memory-search.trace",
            trace,
            TraceFormat::Unidbg,
            options.clone(),
        );
        assert!(result.is_err());
        let cache_path = memory_cache_path(
            &sha256(trace),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        assert!(!cache_path.exists());
        let temporary_files = std::fs::read_dir(&cache_dir)
            .expect("cache directory")
            .filter_map(|entry| entry.ok())
            .count();
        assert_eq!(temporary_files, 0);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    /// 三条 occurrence 的 trace，供 cache 篡改测试复用。
    fn three_occurrence_trace() -> &'static str {
        "[00:00:00 000][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 001][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 002][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n[00:00:00 003][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x08070605 x1=0x3000 => w0=0x08070605\n[00:00:00 004][lib.so 0x100] [00000000] 0x40000100: \"str w0, [x1]\" ; mem[WRITE] abs=0x2000 w0=0x04030201 x1=0x3000 => w0=0x04030201\n"
    }

    fn tamper_cache_dir(label: &str) -> PathBuf {
        let cache_dir = std::env::temp_dir().join(format!(
            "trace-ui-memory-cache-{label}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("cache dir");
        crate::cache::set_cache_dir_override(Some(cache_dir.clone()));
        cache_dir
    }

    fn default_options() -> MemorySearchOptions {
        MemorySearchOptions {
            pattern: vec![1, 2, 3, 4],
            seq_range: None,
            memory_range: None,
            offset: 0,
            limit: 10,
        }
    }

    #[test]
    fn cache_valid_looking_record_tamper_is_detected_and_rebuilt() {
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("tamper");
        let options = default_options();
        let path = "/tmp/tamper-memory-search.trace";
        let fresh =
            search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
                .expect("write cache");
        assert_eq!(fresh.total, 3);
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let mut bytes = std::fs::read(&cache_path).expect("read cache");
        // 把第一条 record 的 seq 从 0 改成 1：格式完全合法、顺序仍然递增，
        // 但内容是假的（seq 1 的写入值其实是 0x08070605）。
        bytes[CACHE_HEADER_LEN..CACHE_HEADER_LEN + 4].copy_from_slice(&1u32.to_le_bytes());
        std::fs::write(&cache_path, bytes).expect("tamper cache");
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
        let served = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
            .expect("rebuilt search");
        assert_eq!(
            served, fresh,
            "valid-looking tampered record must never be served"
        );
        assert_eq!(
            SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
            1,
            "tampered cache must trigger a rebuild"
        );
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn cache_cross_page_duplicate_is_detected_via_boundary_record() {
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("cross-page");
        let options = default_options();
        let path = "/tmp/cross-page-memory-search.trace";
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("write cache");
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let mut bytes = std::fs::read(&cache_path).expect("read cache");
        // 第二页只有 record[1]；把它改成 record[0] 的副本。只读当前页时
        // 页内顺序校验发现不了跨页重复，必须回读边界 record 或校验完整性。
        let first_record = bytes[CACHE_HEADER_LEN..CACHE_HEADER_LEN + CACHE_RECORD_LEN].to_vec();
        bytes[CACHE_HEADER_LEN + CACHE_RECORD_LEN..CACHE_HEADER_LEN + 2 * CACHE_RECORD_LEN]
            .copy_from_slice(&first_record);
        std::fs::write(&cache_path, bytes).expect("tamper cache");
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
        let second_page = search_memory_cached(
            path,
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                offset: 1,
                limit: 1,
                ..default_options()
            },
        )
        .expect("rebuilt second page");
        assert_eq!(second_page.matches.len(), 1);
        assert_eq!(second_page.matches[0].seq, 2);
        assert_eq!(
            SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
            1,
            "cross-page duplicate must trigger a rebuild"
        );
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn cache_tamper_on_a_later_page_is_detected_when_that_page_is_served() {
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("later-page");
        let options = default_options();
        let path = "/tmp/later-page-memory-search.trace";
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("write cache");
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let mut bytes = std::fs::read(&cache_path).expect("read cache");
        // 篡改第三页（record[2]）的 address，先请求第 0 页再请求第 2 页。
        bytes[CACHE_HEADER_LEN + 2 * CACHE_RECORD_LEN + 8
            ..CACHE_HEADER_LEN + 2 * CACHE_RECORD_LEN + 16]
            .copy_from_slice(&0x9999u64.to_le_bytes());
        std::fs::write(&cache_path, bytes).expect("tamper cache");
        let page0 = search_memory_cached(
            path,
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                offset: 0,
                limit: 1,
                ..default_options()
            },
        )
        .expect("page 0");
        assert_eq!(page0.matches[0].seq, 0);
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
        let page2 = search_memory_cached(
            path,
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                offset: 2,
                limit: 1,
                ..default_options()
            },
        )
        .expect("page 2");
        assert_eq!(
            page2.matches[0].seq, 4,
            "tampered page must be rebuilt, not served"
        );
        assert_eq!(page2.matches[0].address, 0x2000);
        assert_eq!(SEARCH_SCAN_COUNT.load(Ordering::SeqCst), 1);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn stale_staging_is_also_removed_on_a_cache_hit() {
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("hit-cleanup");
        let options = default_options();
        let path = "/tmp/hit-cleanup-memory-search.trace";
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("write cache");
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let stale_path = cache_path.parent().expect("cache parent").join(format!(
            ".{}.tmp.4294967295.stale",
            cache_path
                .file_name()
                .expect("cache filename")
                .to_string_lossy()
        ));
        std::fs::write(&stale_path, vec![0u8; CACHE_HEADER_LEN]).expect("stale staging");
        SEARCH_SCAN_COUNT.store(0, Ordering::SeqCst);
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
            .expect("cache hit");
        assert_eq!(
            SEARCH_SCAN_COUNT.load(Ordering::SeqCst),
            0,
            "must be a cache hit"
        );
        assert!(
            !stale_path.exists(),
            "hit path must also reclaim stale staging"
        );
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn stale_staging_with_a_recycled_live_pid_is_removed_by_age() {
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("pid-reuse");
        let options = default_options();
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        // 当前进程 PID 一定活着：模拟 PID 被复用后遗留的 staging。
        let stale_path = cache_path.parent().expect("cache parent").join(format!(
            ".{}.tmp.{}.stale",
            cache_path
                .file_name()
                .expect("cache filename")
                .to_string_lossy(),
            std::process::id()
        ));
        std::fs::write(&stale_path, vec![0u8; CACHE_HEADER_LEN]).expect("stale staging");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&stale_path)
            .expect("open stale")
            .set_modified(old)
            .expect("age stale staging");
        search_memory_cached(
            "/tmp/pid-reuse-memory-search.trace",
            trace.as_bytes(),
            TraceFormat::Unidbg,
            options,
        )
        .expect("build cache");
        assert!(
            !stale_path.exists(),
            "aged staging must be reclaimed even when its PID is alive"
        );
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn cache_page_beyond_the_result_end_returns_empty() {
        // offset 越过缓存结果末尾：不得下溢 panic，返回空页。
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("page-beyond-end");
        let path = "/tmp/page-beyond-end-memory-search.trace";
        search_memory_cached(
            path,
            trace.as_bytes(),
            TraceFormat::Unidbg,
            default_options(),
        )
        .expect("initial search");
        let paged = search_memory_cached(
            path,
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                offset: 2,
                limit: 1,
                ..default_options()
            },
        )
        .expect("page beyond the result end must be empty, not a panic");
        assert_eq!(paged.matches.len(), 1);
        let past = search_memory_cached(
            path,
            trace.as_bytes(),
            TraceFormat::Unidbg,
            MemorySearchOptions {
                offset: 5,
                limit: 1,
                ..default_options()
            },
        )
        .expect("offset past the end must be an empty page");
        assert!(past.matches.is_empty());
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn corrupt_huge_record_count_is_rejected_and_rebuilt() {
        // 篡改 header 的 count 为巨大值：长度校验必须安全拒绝并重建，不能溢出。
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("huge-record-count");
        let path = "/tmp/huge-record-count-memory-search.trace";
        let options = default_options();
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("initial search");
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let mut bytes = std::fs::read(&cache_path).expect("cache file");
        bytes[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&cache_path, &bytes).expect("corrupt cache");
        let result = search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
            .expect("huge count must be rejected and the cache rebuilt");
        assert_eq!(result.total, 3);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn aged_staging_still_open_by_a_live_pid_is_kept() {
        // PID 被复用时靠 mtime 年龄兜底回收；但文件仍被活着的进程实际持有
        // 时（真实长扫描的 writer），年龄规则不得误删。
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("staging-held");
        let path = "/tmp/staging-held-memory-search.trace";
        let options = default_options();
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("initial search");
        let cache_path = memory_cache_path(
            &sha256(trace.as_bytes()),
            &sha256(&options.pattern),
            TraceFormat::Unidbg,
            &options,
        )
        .expect("cache path");
        let cache_name = cache_path
            .file_name()
            .expect("cache name")
            .to_string_lossy()
            .into_owned();
        let stale_path = cache_dir.join(format!(".{cache_name}.tmp.{}.stale", std::process::id()));
        let held = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&stale_path)
            .expect("held staging");
        held.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600))
            .expect("age the staging file");
        // 文件仍被本进程（活 PID）实际持有：不得被年龄规则回收。
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options.clone())
            .expect("cached search keeps the held staging");
        assert!(
            stale_path.exists(),
            "staging still open by a live pid must not be reclaimed by age alone"
        );
        // 释放后：年龄规则正常回收。
        drop(held);
        search_memory_cached(path, trace.as_bytes(), TraceFormat::Unidbg, options)
            .expect("cached search reclaims the released staging");
        assert!(
            !stale_path.exists(),
            "released aged staging must be reclaimed"
        );
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[cfg(unix)]
    #[test]
    fn oversized_or_symlinked_fingerprint_is_rejected_and_recomputed() {
        // fingerprint 只是加速：读取必须 bounded、no-follow、精确长度预检；
        // 超大文件或符号链接一律拒绝并重新完整 hash，不能阻塞或失控分配。
        let _guard = cache_test_guard();
        let trace = three_occurrence_trace();
        let cache_dir = tamper_cache_dir("fingerprint-bounded");
        let trace_dir = std::env::temp_dir().join(format!(
            "trace-ui-fp-trace-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&trace_dir).expect("trace dir");
        let trace_path = trace_dir.join("trace.log");
        std::fs::write(&trace_path, trace).expect("trace");
        let file = File::open(&trace_path).expect("open trace");
        let data = std::fs::read(&trace_path).expect("read trace");
        let options = default_options();
        let mut decisions = Vec::new();
        let run = |decisions: &mut Vec<FingerprintSource>| {
            search_memory_fd_verified(
                &file,
                &data,
                TraceFormat::Unidbg,
                options.clone(),
                Some(&mut |source| decisions.push(source)),
            )
            .expect("fd verified search")
        };
        run(&mut decisions);
        assert_eq!(decisions, [FingerprintSource::Computed]);
        decisions.clear();
        run(&mut decisions);
        assert_eq!(decisions, [FingerprintSource::Reused]);

        let signature = fd_signature(&file).expect("signature");
        let fingerprint = fingerprint_path(&signature).expect("fingerprint path");
        // 超大文件：必须被拒绝并重新计算。
        std::fs::write(&fingerprint, vec![0u8; 1 << 20]).expect("oversized fingerprint");
        decisions.clear();
        run(&mut decisions);
        assert_eq!(decisions, [FingerprintSource::Computed]);
        // 符号链接：必须被拒绝并重新计算。
        let _ = std::fs::remove_file(&fingerprint);
        let real = cache_dir.join("real-fingerprint-target");
        std::fs::write(&real, b"not-a-fingerprint").expect("target");
        std::os::unix::fs::symlink(&real, &fingerprint).expect("symlink");
        decisions.clear();
        run(&mut decisions);
        assert_eq!(decisions, [FingerprintSource::Computed]);
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(cache_dir);
        let _ = std::fs::remove_dir_all(trace_dir);
    }

    #[test]
    fn parent_directory_sync_failure_is_propagated() {
        let result = sync_parent_dir(Path::new("/proc/self/definitely-not-a-cache-dir"));
        assert!(
            result.is_err(),
            "parent directory open failure must propagate"
        );
    }
}
