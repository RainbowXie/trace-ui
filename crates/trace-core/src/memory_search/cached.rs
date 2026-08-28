//! 完整结果磁盘缓存的入口与分页：缓存不含分页状态，每页从校验过的
//! 完整结果集精确切出。

use trace_parser::types::TraceFormat;

use super::cache::{load_cache_page, stream_cache};
use super::scan::scan_memory_page;
use super::{
    ensure_trace_unchanged, memory_cache_path, memory_search_content_identity, trace_content_hash,
    validate_options, validate_public_response_budget, CachePage, MemorySearchMatch,
    MemorySearchOccurrence, MemorySearchOccurrenceResult, MemorySearchOptions, MemorySearchResult,
};
use crate::error::{Result, TraceError};

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
    let pattern_hash = super::sha256(&options.pattern);
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
    let pattern_hash = super::sha256(&options.pattern);
    let content_identity =
        memory_search_content_identity(&trace_hash, &pattern_hash, format, &options);
    let page = complete_cached_page(data, format, &options, &trace_hash, &pattern_hash)?;
    paginate_occurrences(page, &options, content_identity)
}

pub(crate) fn complete_cached_page(
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
        super::cache::cleanup_stale_staging_files(parent)?;
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
    super::SEARCH_SCAN_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

pub(crate) fn paginate_page(
    page: CachePage,
    options: &MemorySearchOptions,
) -> Result<MemorySearchResult> {
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

pub(crate) fn paginate_occurrences(
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
