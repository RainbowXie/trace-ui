use memchr::memchr_iter;
use rayon::prelude::*;

use crate::chunk_scan;
use crate::merge;
use crate::scan_unified::{self as taint, ProgressFn, ScanResult};

/// Parallel version of scan_unified.
/// Falls back to single-threaded for small files.
pub fn scan_unified_parallel(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_fn: Option<ProgressFn>,
    num_chunks: usize,
) -> anyhow::Result<ScanResult> {
    // Small files or single chunk: fall back to single-threaded
    if data.len() < 10 * 1024 * 1024 || num_chunks <= 1 {
        return taint::scan_unified(data, data_only, no_prune, skip_strings, progress_fn);
    }

    let scan_start = std::time::Instant::now();

    let format = trace_parser::gumtrace::detect_format(data);

    // Phase 0: Split and count lines
    let chunks_meta = split_into_chunks(data, num_chunks);
    eprintln!(
        "[perf] Phase 0 (split+count): {:?}, {} chunks, {} lines",
        scan_start.elapsed(),
        chunks_meta.len(),
        chunks_meta.iter().map(|c| c.line_count).sum::<u32>()
    );

    // LINE_MASK safety check: 29-bit line number limit (bits 29-31 reserved for flags)
    let total_lines: u32 = chunks_meta.iter().map(|c| c.line_count).sum();
    if total_lines > crate::scanner::LINE_MASK {
        anyhow::bail!(
            "文件行数 {} 超过当前支持的最大值 {}（约 5.36 亿行）。",
            total_lines,
            crate::scanner::LINE_MASK,
        );
    }

    if let Some(ref cb) = progress_fn {
        cb(0, data.len());
    }

    // Phase 0 complete — report 2% so user sees progress after line counting
    if let Some(ref cb) = progress_fn {
        cb(data.len() / 50, data.len());
    }

    // Phase 1: Parallel chunk scanning with progress reporting
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let global_bytes_done = Arc::new(AtomicUsize::new(0));
    let data_len = data.len();
    let progress_fn_arc: Option<Arc<dyn Fn(usize, usize) + Send + Sync>> =
        progress_fn.map(|f| Arc::new(f) as Arc<dyn Fn(usize, usize) + Send + Sync>);

    let chunk_results: Vec<_> = chunks_meta
        .par_iter()
        .map(|meta| {
            // Build a per-chunk progress callback that reports byte deltas
            let chunk_cb: Option<Arc<dyn Fn(usize) + Send + Sync>> =
                progress_fn_arc.as_ref().map(|pfn| {
                    let gbd = global_bytes_done.clone();
                    let pfn = pfn.clone();
                    let dl = data_len;
                    Arc::new(move |bytes_delta: usize| {
                        let total = gbd.fetch_add(bytes_delta, Ordering::Relaxed) + bytes_delta;
                        let progress = total * 2 / 3; // Phase 1 = first 67%
                        pfn(progress, dl);
                    }) as Arc<dyn Fn(usize) + Send + Sync>
                });

            chunk_scan::scan_chunk(
                data,
                chunk_scan::ScanChunkConfig {
                    start_byte: meta.start_byte,
                    end_byte: meta.end_byte,
                    start_line: meta.start_line,
                    format,
                    data_only,
                    no_prune,
                    skip_strings: true, // 并行扫描始终跳过字符串：跨 chunk 边界会断裂，改由 MemAccessIndex 构建后用路径 1 精确构建
                    progress_cb: chunk_cb,
                },
            )
        })
        .collect();

    eprintln!("[perf] Phase 1 (parallel scan): {:?}", scan_start.elapsed());

    // Phase 1 complete — progress is at 67%
    if let Some(ref cb) = progress_fn_arc {
        cb(data_len * 2 / 3, data_len);
    }

    let phase2_start = std::time::Instant::now();
    // Phase 2: Sequential merge with progress reporting
    let merge_cb = |phase2_frac: f64| {
        if let Some(ref pfn) = progress_fn_arc {
            let global = (2.0 / 3.0 + phase2_frac / 3.0) * data_len as f64;
            pfn(global as usize, data_len);
        }
    };

    let result = merge::merge_all_chunks(
        chunk_results,
        format,
        data_only,
        skip_strings,
        Some(&merge_cb),
        None,
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    eprintln!("[perf] Phase 2 (merge): {:?}", phase2_start.elapsed());
    eprintln!("[perf] Total scan: {:?}", scan_start.elapsed());

    if let Some(ref cb) = progress_fn_arc {
        cb(data.len(), data.len());
    }

    Ok(result)
}

/// Metadata for a chunk of the file.
pub struct ChunkMeta {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u32,
    pub line_count: u32,
}

/// Split data into N chunks at newline boundaries.
/// Phase 0: uses parallel memchr to count lines per chunk.
pub fn split_into_chunks(data: &[u8], n: usize) -> Vec<ChunkMeta> {
    let n = n.max(1);
    let len = data.len();
    if len == 0 {
        return vec![ChunkMeta {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            line_count: 0,
        }];
    }

    // 1. Determine raw byte boundaries, adjusting to nearest newline
    let chunk_size = len / n;
    let mut boundaries = Vec::with_capacity(n + 1);
    boundaries.push(0usize);

    for i in 1..n {
        let raw = i * chunk_size;
        // Find next newline after raw boundary
        let adjusted = match memchr::memchr(b'\n', &data[raw..]) {
            Some(pos) => raw + pos + 1, // start of next line
            None => len,
        };
        if adjusted < len && adjusted != *boundaries.last().unwrap() {
            boundaries.push(adjusted);
        }
    }
    boundaries.push(len);
    boundaries.dedup();

    // 2. Count lines per chunk (parallel using rayon)
    use rayon::prelude::*;
    let line_counts: Vec<u32> = boundaries
        .windows(2)
        .collect::<Vec<_>>()
        .par_iter()
        .map(|window| {
            let start = window[0];
            let end = window[1];
            let chunk_data = &data[start..end];
            let newline_count = memchr_iter(b'\n', chunk_data).count() as u32;
            // If this is the LAST chunk and doesn't end with newline, there's one more line
            if end == len && !chunk_data.is_empty() && *chunk_data.last().unwrap() != b'\n' {
                newline_count + 1
            } else {
                newline_count
            }
        })
        .collect();

    // 3. Compute prefix sums for global line offsets
    let mut chunks = Vec::with_capacity(line_counts.len());
    let mut cumulative_lines = 0u32;
    for (i, window) in boundaries.windows(2).enumerate() {
        chunks.push(ChunkMeta {
            start_byte: window[0],
            end_byte: window[1],
            start_line: cumulative_lines,
            line_count: line_counts[i],
        });
        cumulative_lines += line_counts[i];
    }

    chunks
}

#[cfg(test)]
mod tests;
