//! 缓存文件格式：header 字段区 + 摘要、固定长 record、逐条完整性 tag、
//! staging 原子发布与遗留回收。

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use trace_parser::types::TraceFormat;

use super::scan::scan_memory_with_sink;
#[cfg(test)]
use super::CACHE_RECORD_READ_COUNT;
use super::{
    cache_header_total_len, ensure_trace_unchanged, CachePage, MemoryOccurrence,
    MemorySearchOptions, MemorySearchRw, CACHE_HEADER_DIGEST_LEN, CACHE_HEADER_LEN, CACHE_MAGIC,
    CACHE_RECORD_LEN, CACHE_TAG_LEN,
};
use crate::error::{Result, TraceError};
use crate::staging;

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

pub(crate) fn load_cache_page(
    path: &PathBuf,
    trace_len: u64,
    trace_hash: &[u8; 32],
    pattern_hash: &[u8; 32],
    format: TraceFormat,
    options: &MemorySearchOptions,
    content_identity: &str,
) -> Option<CachePage> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() < cache_header_total_len() {
        return None;
    }
    let mut file = File::open(path).ok()?;
    // 字段区 + 摘要一起读入；摘要不一致即整体作废走重建。
    let mut header_full = vec![0u8; CACHE_HEADER_LEN + CACHE_HEADER_DIGEST_LEN];
    file.read_exact(&mut header_full).ok()?;
    let header: &[u8; CACHE_HEADER_LEN] = header_full[..CACHE_HEADER_LEN].try_into().ok()?;
    if &header[0..8] != CACHE_MAGIC
        || cache_header_digest(header) != header_full[CACHE_HEADER_LEN..]
    {
        return None;
    }
    if u64::from_le_bytes(header[8..16].try_into().ok()?) != trace_len
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
    let expected_len = cache_header_total_len()
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
    let tags_offset = cache_header_total_len().checked_add(records_bytes)?;
    // 除请求页外回读前一条边界 record：跨页的重复/逆序只能靠它发现。
    // 读取量仍是 O(page size + 1)，不会退化成从头扫描。
    let read_start = if page_start > 0 {
        page_start - 1
    } else {
        page_start
    };
    let read_len = page_end - read_start;
    let record_offset = read_start.checked_mul(CACHE_RECORD_LEN as u64)?;
    let record_offset = cache_header_total_len().checked_add(record_offset)?;
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

pub(crate) use crate::staging::cleanup_stale_staging_files;

#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_cache(
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
    staging::cleanup_stale_staging_files(parent)?;
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
        write_cache_header(&mut file, &header).map_err(TraceError::Io)?;

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
        file.seek(std::io::SeekFrom::Start(cache_header_total_len()))
            .map_err(TraceError::Io)?;
        let mut tag_buf = Vec::with_capacity(4096 * CACHE_TAG_LEN);
        while index < count {
            file.read_exact(&mut record_buf).map_err(TraceError::Io)?;
            tag_buf.extend_from_slice(&record_tag(content_identity, index, &record_buf));
            index += 1;
            if tag_buf.len() == 4096 * CACHE_TAG_LEN {
                let tag_pos = cache_header_total_len()
                    + count * CACHE_RECORD_LEN as u64
                    + (index - 4096) * CACHE_TAG_LEN as u64;
                write_all_at(&file, &tag_buf, tag_pos).map_err(TraceError::Io)?;
                tag_buf.clear();
            }
        }
        if !tag_buf.is_empty() {
            let written = index - (tag_buf.len() / CACHE_TAG_LEN) as u64;
            let tag_pos = cache_header_total_len()
                + count * CACHE_RECORD_LEN as u64
                + written * CACHE_TAG_LEN as u64;
            write_all_at(&file, &tag_buf, tag_pos).map_err(TraceError::Io)?;
        }
        // 最终 header（带真实 count）连同摘要一起覆写发布。
        let header = make_cache_header(trace_len, trace_hash, pattern_hash, format, options, count);
        write_cache_header(&mut file, &header).map_err(TraceError::Io)?;
        file.sync_all().map_err(TraceError::Io)?;
        fs::rename(&temp_path, path).map_err(TraceError::Io)?;
        // rename 已把新文件挂到最终名；父目录 fsync 失败不得把这次搜索写成错误。
        let _ = staging::published_after_rename(path, parent);
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

/// 字段区的完整性摘要：篡改 count、格式位或过滤器而不同步重算摘要即被拒绝。
/// 这不是安全 MAC（key 是公开的 compat 版本串），只防损坏与静默截断。
fn cache_header_digest(fields: &[u8; CACHE_HEADER_LEN]) -> [u8; CACHE_HEADER_DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(super::CACHE_COMPAT_VERSION);
    hasher.update(fields);
    hasher.finalize().into()
}

/// 完整头部（字段区 + 摘要）一次性写出。
fn write_cache_header(file: &mut File, fields: &[u8; CACHE_HEADER_LEN]) -> std::io::Result<()> {
    let mut full = [0u8; CACHE_HEADER_LEN + CACHE_HEADER_DIGEST_LEN];
    full[..CACHE_HEADER_LEN].copy_from_slice(fields);
    full[CACHE_HEADER_LEN..].copy_from_slice(&cache_header_digest(fields));
    file.seek(std::io::SeekFrom::Start(0))?;
    file.write_all(&full)
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
