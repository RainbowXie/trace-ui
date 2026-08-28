//! fd fingerprint：helper 的受验证内容身份复用。

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use trace_parser::types::TraceFormat;

use super::cached::{complete_cached_page, paginate_occurrences};
use super::{
    memory_search_content_identity, sha256, trace_content_hash, validate_options,
    MemorySearchOccurrenceResult, MemorySearchOptions, FINGERPRINT_MAGIC,
};
use crate::error::{Result, TraceError};

/// 同一 fd 的文件身份签名（dev/ino/len/mtime/ctime）。任一变化都意味着内容
/// 可能已变，此时持久化 fingerprint 一律失效。
///
/// 调用方（fd helper）必须在 mmap trace **之前**取得基线签名并传入
/// `search_memory_fd_verified_with_signature`，否则 mmap 与首次 fstat 之间的
/// 文件增长会把旧内容绑定到新长度的身份上。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdSignature {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

pub fn fd_signature(file: &File) -> Result<FdSignature> {
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

pub(crate) fn fingerprint_path(signature: &FdSignature) -> Option<PathBuf> {
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

fn load_fd_fingerprint(signature: &FdSignature) -> Option<[u8; 32]> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = fingerprint_path(signature)?;
    // no-follow + non-block + fstat + 精确长度：符号链接可指向任意目标，
    // FIFO/设备文件会在 open() 或 read() 上永久阻塞，超大文件会导致不受控
    // 分配。O_NONBLOCK 让恶意 FIFO 立即返回打开成功、随后被 fstat 的
    // regular-file 检查拒绝；对普通文件该标志没有任何副作用。
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
pub fn search_memory_fd_verified(
    file: &File,
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
    probe: Option<&mut dyn FnMut(FingerprintSource)>,
) -> Result<MemorySearchOccurrenceResult> {
    let baseline = fd_signature(file)?;
    search_memory_fd_verified_with_signature(file, data, format, options, &baseline, probe)
}

/// 同 `search_memory_fd_verified`，但签名基线由调用方在 mmap **之前**取得：
/// 若 fd 在 mmap 与本调用之间发生变化（如文件增长），立即报错而不是把旧
/// 内容的 hash 绑定到新长度签名上。
pub fn search_memory_fd_verified_with_signature(
    file: &File,
    data: &[u8],
    format: TraceFormat,
    options: MemorySearchOptions,
    baseline: &FdSignature,
    probe: Option<&mut dyn FnMut(FingerprintSource)>,
) -> Result<MemorySearchOccurrenceResult> {
    validate_options(&options)?;
    let before = *baseline;
    if fd_signature(file)? != before {
        return Err(TraceError::CacheError(
            "trace fd changed between mmap and the start of the search".to_string(),
        ));
    }
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
