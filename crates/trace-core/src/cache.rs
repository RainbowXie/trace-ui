use crate::query::strings::StringIndex;
use crate::staging;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

// MAGIC 版本即缓存布局版本：布局变更（如 .p2.cache 增加 ActivationTree section）
// 时必须递增，否则旧布局缓存仍判有效——升级后老 session 会静默缺失新能力
// （ActivationTree 永远 IndexNotReady 且 CacheHit 不触发重扫）。
// V6：ActivationTree 增加 all_by_call/resolved_by_resume 两个序列化字段，
// 与 V5 的 bincode 布局不兼容；旧 V5/更早缓存 magic 不匹配自动 miss →
// 触发重扫 → 写新缓存。
// MAGIC（无后缀常量）服务于 48 字节旧 bincode 路径，与 section 缓存互不影响。
// MAGIC_V6：section 缓存当前布局版本号（TCACHE06）。
const MAGIC_V6: &[u8; 8] = b"TCACHE06";
const MAGIC: &[u8; 8] = b"TCACHE03";
const HEAD_SIZE: usize = 1024 * 1024; // 1MB
const HEADER_LEN_V6: usize = 64;

static CACHE_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

#[cfg(test)]
static CACHE_DIR_OVERRIDE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 测试中使用 `set_cache_dir_override` 时必须持有此锁，防止并行测试覆盖全局 override。
/// pub：trace-mcp 集成测试同样需要隔离 cache 目录。
pub fn cache_dir_override_test_lock() -> std::sync::MutexGuard<'static, ()> {
    #[cfg(test)]
    {
        CACHE_DIR_OVERRIDE_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
    #[cfg(not(test))]
    {
        // 非 test 构建（外部集成测试编译 trace-core 时不带 cfg(test)）：
        // 用独立的进程级锁，语义一致
        static EXTERNAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        EXTERNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub fn set_cache_dir_override(path: Option<PathBuf>) {
    *CACHE_DIR_OVERRIDE.write().unwrap() = path;
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(guard) = CACHE_DIR_OVERRIDE.read() {
        if let Some(ref p) = *guard {
            return Some(p.clone());
        }
    }
    dirs::data_dir().map(|d| d.join("trace-ui").join("cache"))
}

/// 测试辅助：trace 路径对应的缓存哈希前缀。
pub fn path_hash_for_test(file_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn cache_path(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}.bin", hash, suffix)))
}

/// Cache path with explicit extension (no automatic `.bin` suffix).
fn cache_path_ext(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}", hash, suffix)))
}

fn head_hash(data: &[u8]) -> [u8; 32] {
    let end = data.len().min(HEAD_SIZE);
    let mut hasher = Sha256::new();
    hasher.update(&data[..end]);
    hasher.finalize().into()
}

fn validate_header(buf: &[u8], data: &[u8]) -> bool {
    if buf.len() < 48 || &buf[0..8] != MAGIC {
        return false;
    }
    let stored_size = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
    if stored_size != data.len() as u64 {
        return false;
    }
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    cached_hash == head_hash(data)
}

fn validate_header_from_reader(reader: &mut impl Read, data: &[u8]) -> bool {
    let mut header = [0u8; 48];
    if reader.read_exact(&mut header).is_err() {
        return false;
    }
    validate_header(&header, data)
}

fn write_header(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&head_hash(data));
}

// ── 通用加载/保存 (bincode, legacy) ──

fn load_cached<T: serde::de::DeserializeOwned>(
    file_path: &str,
    data: &[u8],
    suffix: &str,
) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) {
        return None;
    }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // 序列化先进内存：bincode 失败不得留下半截临时文件（也避免
    // 写入闭包里吞掉序列化错误后仍 rename 半截文件）。
    let Ok(payload) = bincode::serialize(value) else {
        return;
    };
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    let _ = staging::atomic_publish(&path, move |w| {
        w.write_all(&header).is_ok() && w.write_all(&payload).is_ok()
    });
}

/// 将预序列化的 bincode 字节写入缓存文件（TCACHE03 header + raw bytes），不依赖 session。
pub fn save_bincode_raw(file_path: &str, data: &[u8], suffix: &str, payload: &[u8]) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    let _ = staging::atomic_publish(&path, move |w| {
        w.write_all(&header).is_ok() && w.write_all(payload).is_ok()
    });
}

// ── Section-based cache save/load ──

/// 将预序列化的 section 字节写入缓存文件（header + raw bytes），不依赖 session。
pub fn save_sections_raw(file_path: &str, data: &[u8], suffix: &str, section_bytes: &[u8]) {
    let Some(path) = cache_path_ext(file_path, suffix) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut header = Vec::with_capacity(HEADER_LEN_V6);
    header.extend_from_slice(MAGIC_V6);
    header.extend_from_slice(&(data.len() as u64).to_le_bytes());
    header.extend_from_slice(&head_hash(data));
    header.resize(HEADER_LEN_V6, 0); // pad to 64 bytes

    let payload_len = section_bytes.len();
    if staging::atomic_publish(&path, move |w| {
        w.write_all(&header).is_ok() && w.write_all(section_bytes).is_ok()
    }) {
        eprintln!(
            "[cache] saved {} ({} + {} bytes)",
            suffix, HEADER_LEN_V6, payload_len
        );
    }
}

fn load_cache_mmap(file_path: &str, data: &[u8], suffix: &str) -> Option<Arc<Mmap>> {
    let path = cache_path_ext(file_path, suffix)?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[cache] {} not found: {:?}", suffix, path);
            return None;
        }
    };
    let mmap = unsafe { Mmap::map(&file) }.ok()?;

    // Validate V6 header
    if mmap.len() < HEADER_LEN_V6 {
        eprintln!("[cache] {} too small: {} bytes", suffix, mmap.len());
        return None;
    }
    if &mmap[0..8] != MAGIC_V6 {
        eprintln!("[cache] {} magic mismatch: {:?}", suffix, &mmap[0..8]);
        return None;
    }
    let stored_size = u64::from_le_bytes(mmap[8..16].try_into().ok()?);
    if stored_size != data.len() as u64 {
        eprintln!(
            "[cache] {} size mismatch: stored={} actual={}",
            suffix,
            stored_size,
            data.len()
        );
        return None;
    }
    let cached_hash: [u8; 32] = mmap[16..48].try_into().ok()?;
    if cached_hash != head_hash(data) {
        eprintln!("[cache] {} hash mismatch", suffix);
        return None;
    }

    // 布局预检：三个核心缓存（p2/scan/lidx）的 section 布局在加载时统一
    // 验证，任一失败 = 损坏/截断，整体判 miss 触发重扫——不得 mmap 命中
    // 后在 view getter 里 unwrap panic（archives.rs 的 views_from_sections
    // 返回 None 时调用方 unwrap），也不得留下半新半旧的 session。
    let layout_ok = match suffix {
        ".p2.cache" => {
            crate::flat::archives::Phase2Archive::views_from_sections(&mmap[HEADER_LEN_V6..])
                .is_some()
        }
        ".scan.cache" => {
            crate::flat::archives::ScanArchive::views_from_sections(&mmap[HEADER_LEN_V6..])
                .is_some()
        }
        ".lidx.cache" => {
            crate::flat::line_index::LineIndexArchive::views_from_sections(&mmap[HEADER_LEN_V6..])
                .is_some()
        }
        // 其他后缀（string/gumtrace-extra 等 bincode 缓存）布局由反序列化兜底
        _ => true,
    };
    if !layout_ok {
        eprintln!("[cache] {} section layout invalid (corrupted)", suffix);
        return None;
    }

    eprintln!("[cache] {} loaded: {} bytes", suffix, mmap.len());
    Some(Arc::new(mmap))
}

// ── Section-based cache load ──

pub fn load_phase2_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, data, ".p2.cache")
}

pub fn load_scan_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, data, ".scan.cache")
}

pub fn load_lidx_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, data, ".lidx.cache")
}

// ── StringIndex bincode 缓存 ──

pub fn save_string_cache(file_path: &str, data: &[u8], index: &StringIndex) {
    save_cached(file_path, data, ".strings", index);
}

pub fn load_string_cache(file_path: &str, data: &[u8]) -> Option<StringIndex> {
    load_cached(file_path, data, ".strings")
}

// ── Crypto scan bincode 缓存 ──

use crate::query::crypto::CryptoScanResult;

pub fn save_crypto_cache(file_path: &str, data: &[u8], result: &CryptoScanResult) {
    save_cached(file_path, data, ".crypto", result);
}

pub fn load_crypto_cache(file_path: &str, data: &[u8]) -> Option<CryptoScanResult> {
    load_cached(file_path, data, ".crypto")
}

// ── Gumtrace extra (call_annotations + consumed_seqs) bincode 缓存 ──

use trace_parser::gumtrace::CallAnnotation;

pub fn save_gumtrace_extra(
    file_path: &str,
    data: &[u8],
    call_annotations: &std::collections::HashMap<u32, CallAnnotation>,
    consumed_seqs: &[u32],
) {
    save_cached(
        file_path,
        data,
        ".gum-extra",
        &(call_annotations, consumed_seqs),
    );
}

pub fn load_gumtrace_extra(
    file_path: &str,
    data: &[u8],
) -> Option<(std::collections::HashMap<u32, CallAnnotation>, Vec<u32>)> {
    load_cached(file_path, data, ".gum-extra")
}

/// 删除指定文件的所有缓存
pub fn delete_cache(file_path: &str) {
    // New section-based cache suffixes
    for suffix in [
        ".p2.cache",
        ".scan.cache",
        ".lidx.cache",
        ".strings.bin",
        ".gum-extra.bin",
        ".crypto.bin",
    ] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old rkyv suffixes (cleanup)
    for suffix in [".p2.rkyv", ".scan.rkyv", ".lidx.rkyv"] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old bincode suffixes (cleanup)
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn get_cache_info() -> (String, u64) {
    let dir = cache_dir().unwrap_or_default();
    let path_str = dir.to_string_lossy().to_string();
    let size = dir_size(&dir);
    (path_str, size)
}

pub fn clear_all_cache() -> (u32, u64) {
    let Some(dir) = cache_dir() else {
        return (0, 0);
    };
    let mut count = 0u32;
    let mut total_size = 0u64;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_staging = name.starts_with('.') && name.contains(".tmp.");
            let ext = path.extension().and_then(|e| e.to_str());
            if is_staging || ext == Some("bin") || ext == Some("rkyv") || ext == Some("cache") {
                if let Ok(meta) = path.metadata() {
                    total_size += meta.len();
                }
                if std::fs::remove_file(&path).is_ok() {
                    count += 1;
                }
            }
        }
    }
    (count, total_size)
}

fn dir_size(path: &PathBuf) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod magic_version_tests {
    use super::*;

    /// p2 缓存携带序列化的 ActivationTree，布局变更必须升 magic 否则旧
    /// V5（无新字段）误命中且反序列化失败 → 永久 IndexNotReady。
    /// 此断言锁定当前 magic；下次改 ActivationTree 序列化时递增并更新此处。
    #[test]
    fn p2_magic_tracks_activation_tree_layout() {
        assert_eq!(MAGIC_V6, b"TCACHE06");
    }
}
