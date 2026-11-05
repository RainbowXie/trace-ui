#[cfg(unix)]
use crate::memory_search::{fd_signature, FdSignature};
use crate::query::strings::StringIndex;
use crate::staging;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

// MAGIC 版本即缓存布局版本：布局变更（如 .p2.cache 增加 ActivationTree section）
// 时必须递增，否则旧布局缓存仍判有效——升级后老 session 会静默缺失新能力
// （ActivationTree 永远 IndexNotReady 且 CacheHit 不触发重扫）。
// V6：ActivationTree 增加 all_by_call/resolved_by_resume 两个序列化字段。
// V7：利用 64 字节 header 的尾部 16 字节绑定 section payload 摘要；此前
// 只校验 trace 身份，payload 内位损坏若保持长度/结构关系会静默命中。
// MAGIC（无后缀常量）服务于 48 字节旧 bincode 路径，与 section 缓存互不影响。
// MAGIC_V7：section 缓存当前布局版本号（TCACHE08：检查点快照开始包含
// ret: 特殊行的 X0 效应；旧 TCACHE07 缓存因内容不同自动失效）。
const MAGIC_V7: &[u8; 8] = b"TCACHE08";
const MAGIC: &[u8; 8] = b"TCACHE03";
const HEADER_LEN_V7: usize = 64;
const SECTION_DIGEST_LEN: usize = 16;

// 大型 section 缓存的 payload 摘要（.scan.cache 931 MiB）每次 helper 子进程
// 都要重算一遍 SHA-256，这是纯重复劳动：文件内容只可能通过写入改变，而
// Linux 上任何写入都会推进 ctime。把「上次完整校验时的文件指纹 + 摘要」记在
// 旁路记录里，fstat 签名不变即可免算；小文件仍走全量摘要，保证损坏检测
// 测试与同纳秒篡改的判定不受影响。
const VERIFIED_MAGIC: &[u8; 8] = b"TCVERIFY";
const VERIFIED_LEN: usize = 8 + 56 + SECTION_DIGEST_LEN;
const SMALL_CACHE_FULL_DIGEST_LIMIT: u64 = 16 * 1024 * 1024;
const VERIFIED_SUFFIX: &str = ".verified";

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

fn verified_path(cache_path: &Path) -> PathBuf {
    let mut name = cache_path.as_os_str().to_os_string();
    name.push(VERIFIED_SUFFIX);
    PathBuf::from(name)
}

/// 旁路记录只在「文件指纹 + 头部摘要」都被证明一致时才算数；任何读取失败
/// 都退化为重算全量摘要，正确性不依赖它。
#[cfg(unix)]
fn verified_digest_matches(file: &File, path: &Path, digest: &[u8; SECTION_DIGEST_LEN]) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(signature) = fd_signature(file) else {
        return false;
    };
    // 旁路记录住在缓存目录里，同样是不可信输入：符号链接可指向任意目标，
    // FIFO/设备文件会在 open()/read() 上永久阻塞，超大文件会导致不受控
    // 分配。no-follow + non-block + fstat + 精确长度让这些情形立即判 miss，
    // 回退到全量摘要校验。
    let Ok(mut record) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(verified_path(path))
    else {
        return false;
    };
    let Ok(metadata) = record.metadata() else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != VERIFIED_LEN as u64 {
        return false;
    }
    let mut bytes = [0u8; VERIFIED_LEN];
    if record.read_exact(&mut bytes).is_err() {
        return false;
    }
    if &bytes[..8] != VERIFIED_MAGIC {
        return false;
    }
    if FdSignature::decode(&bytes[8..64]) != Some(signature) {
        return false;
    }
    bytes[64..].try_into().ok() == Some(*digest)
}

#[cfg(unix)]
fn store_verified_digest(file: &File, path: &Path, digest: &[u8; SECTION_DIGEST_LEN]) {
    let Ok(signature) = fd_signature(file) else {
        return;
    };
    let mut record = Vec::with_capacity(VERIFIED_LEN);
    record.extend_from_slice(VERIFIED_MAGIC);
    record.extend_from_slice(&signature.encode());
    record.extend_from_slice(digest);
    let _ = staging::atomic_publish(&verified_path(path), move |writer| {
        writer.write_all(&record).is_ok()
    });
}

// 非 Unix 平台无法从 fstat 得到 (dev, ino, ctime) 这项绑定证据，旁路记录
// 一律不成立：加载时照旧对整份 payload 重算 SHA-256。
#[cfg(not(unix))]
fn verified_digest_matches(_: &File, _: &Path, _: &[u8; SECTION_DIGEST_LEN]) -> bool {
    false
}

#[cfg(not(unix))]
fn store_verified_digest(_: &File, _: &Path, _: &[u8; SECTION_DIGEST_LEN]) {}

fn section_digest(data: &[u8]) -> [u8; SECTION_DIGEST_LEN] {
    Sha256::digest(data)[..SECTION_DIGEST_LEN]
        .try_into()
        .expect("section digest length")
}

fn validate_header(buf: &[u8], trace_len: u64, trace_hash: &[u8; 32]) -> bool {
    if buf.len() < 48 || &buf[0..8] != MAGIC {
        return false;
    }
    let stored_size = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
    if stored_size != trace_len {
        return false;
    }
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    &cached_hash == trace_hash
}

fn validate_header_from_reader(
    reader: &mut impl Read,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> bool {
    let mut header = [0u8; 48];
    if reader.read_exact(&mut header).is_err() {
        return false;
    }
    validate_header(&header, trace_len, trace_hash)
}

fn write_header(buf: &mut Vec<u8>, trace_len: u64, trace_hash: &[u8; 32]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&trace_len.to_le_bytes());
    buf.extend_from_slice(trace_hash);
}

// ── 通用加载/保存 (bincode, legacy) ──

fn load_cached<T: serde::de::DeserializeOwned>(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    suffix: &str,
) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, trace_len, trace_hash) {
        return None;
    }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    suffix: &str,
    value: &T,
) {
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
    write_header(&mut header, trace_len, trace_hash);
    let _ = staging::atomic_publish(&path, move |w| {
        w.write_all(&header).is_ok() && w.write_all(&payload).is_ok()
    });
}

/// 将预序列化的 bincode 字节写入缓存文件（TCACHE03 header + raw bytes），不依赖 session。
pub fn save_bincode_raw(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    suffix: &str,
    payload: &[u8],
) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, trace_len, trace_hash);
    let _ = staging::atomic_publish(&path, move |w| {
        w.write_all(&header).is_ok() && w.write_all(payload).is_ok()
    });
}

// ── Section-based cache save/load ──

/// 将预序列化的 section 字节写入缓存文件（header + raw bytes），不依赖 session。
pub fn save_sections_raw(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    suffix: &str,
    section_bytes: &[u8],
) {
    let Some(path) = cache_path_ext(file_path, suffix) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut header = Vec::with_capacity(HEADER_LEN_V7);
    header.extend_from_slice(MAGIC_V7);
    header.extend_from_slice(&trace_len.to_le_bytes());
    header.extend_from_slice(trace_hash);
    let digest = section_digest(section_bytes);
    header.extend_from_slice(&digest);
    debug_assert_eq!(header.len(), HEADER_LEN_V7);

    let payload_len = section_bytes.len();
    if staging::atomic_publish(&path, move |w| {
        w.write_all(&header).is_ok() && w.write_all(section_bytes).is_ok()
    }) {
        // 刚写入的字节就是下一次进程要校验的字节：立即记录文件指纹，
        // 下次加载无需再对整份 payload 重算 SHA-256。小文件仍按全量摘要校验，
        // 不为它们留无用的旁路记录。
        if payload_len as u64 > SMALL_CACHE_FULL_DIGEST_LIMIT {
            if let Ok(published) = File::open(&path) {
                store_verified_digest(&published, &path, &digest);
            }
        }
        eprintln!(
            "[cache] saved {} ({} + {} bytes)",
            suffix, HEADER_LEN_V7, payload_len
        );
    }
}

fn load_cache_mmap(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    suffix: &str,
) -> Option<Arc<Mmap>> {
    let path = cache_path_ext(file_path, suffix)?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[cache] {} not found: {:?}", suffix, path);
            return None;
        }
    };
    let mmap = unsafe { Mmap::map(&file) }.ok()?;

    // Validate V7 header
    if mmap.len() < HEADER_LEN_V7 {
        eprintln!("[cache] {} too small: {} bytes", suffix, mmap.len());
        return None;
    }
    if &mmap[0..8] != MAGIC_V7 {
        eprintln!("[cache] {} magic mismatch: {:?}", suffix, &mmap[0..8]);
        return None;
    }
    let stored_size = u64::from_le_bytes(mmap[8..16].try_into().ok()?);
    if stored_size != trace_len {
        eprintln!(
            "[cache] {} size mismatch: stored={} actual={}",
            suffix, stored_size, trace_len
        );
        return None;
    }
    let cached_hash: [u8; 32] = mmap[16..48].try_into().ok()?;
    if &cached_hash != trace_hash {
        eprintln!("[cache] {} trace hash mismatch", suffix);
        return None;
    }
    let cached_payload_digest: [u8; SECTION_DIGEST_LEN] =
        mmap[48..HEADER_LEN_V7].try_into().ok()?;
    let verified = mmap.len() as u64 > SMALL_CACHE_FULL_DIGEST_LIMIT
        && verified_digest_matches(&file, &path, &cached_payload_digest);
    if !verified {
        if cached_payload_digest != section_digest(&mmap[HEADER_LEN_V7..]) {
            eprintln!("[cache] {} payload digest mismatch", suffix);
            return None;
        }
        if mmap.len() as u64 > SMALL_CACHE_FULL_DIGEST_LIMIT {
            store_verified_digest(&file, &path, &cached_payload_digest);
        }
    }

    // 布局预检：三个核心缓存（p2/scan/lidx）的 section 布局在加载时统一
    // 验证，任一失败 = 损坏/截断，整体判 miss 触发重扫——不得 mmap 命中
    // 后在 view getter 里 unwrap panic（archives.rs 的 views_from_sections
    // 返回 None 时调用方 unwrap），也不得留下半新半旧的 session。
    let layout_ok = match suffix {
        ".p2.cache" => {
            crate::flat::archives::Phase2Archive::views_from_sections(&mmap[HEADER_LEN_V7..])
                .is_some()
        }
        ".scan.cache" => {
            crate::flat::archives::ScanArchive::views_from_sections(&mmap[HEADER_LEN_V7..])
                .is_some()
        }
        ".lidx.cache" => {
            crate::flat::line_index::LineIndexArchive::views_from_sections(&mmap[HEADER_LEN_V7..])
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

pub fn load_phase2_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, trace_len, trace_hash, ".p2.cache")
}

pub fn load_scan_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, trace_len, trace_hash, ".scan.cache")
}

pub fn load_lidx_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, trace_len, trace_hash, ".lidx.cache")
}

// ── 通用 raw payload 旁路缓存（TCACHE03 header + 调用方自定义字节）──

/// 读取 `save_bincode_raw` 写入的 payload（不含头部）。载荷自己的布局标识
/// 必须由调用方校验：TCACHE03 头部只绑定 trace 身份，不描述载荷形状，
/// 直接 bincode 反序列化旧字节会读到垃圾长度。
pub(crate) fn load_bincode_raw(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    suffix: &str,
) -> Option<Vec<u8>> {
    let path = cache_path(file_path, suffix)?;
    let mut reader = BufReader::new(std::fs::File::open(&path).ok()?);
    if !validate_header_from_reader(&mut reader, trace_len, trace_hash) {
        return None;
    }
    let mut payload = Vec::new();
    reader.read_to_end(&mut payload).ok()?;
    Some(payload)
}

// ── StringIndex bincode 缓存 ──

pub fn save_string_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    index: &StringIndex,
) {
    save_cached(file_path, trace_len, trace_hash, ".strings", index);
}

pub fn load_string_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> Option<StringIndex> {
    load_cached(file_path, trace_len, trace_hash, ".strings")
}

// ── Crypto scan bincode 缓存 ──

use crate::query::crypto::CryptoScanResult;

pub fn save_crypto_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    result: &CryptoScanResult,
) {
    save_cached(file_path, trace_len, trace_hash, ".crypto", result);
}

pub fn load_crypto_cache(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> Option<CryptoScanResult> {
    load_cached(file_path, trace_len, trace_hash, ".crypto")
}

// ── Gumtrace extra (call_annotations + consumed_seqs) bincode 缓存 ──

use trace_parser::gumtrace::CallAnnotation;

pub fn save_gumtrace_extra(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
    call_annotations: &std::collections::HashMap<u32, CallAnnotation>,
    consumed_seqs: &[u32],
) {
    save_cached(
        file_path,
        trace_len,
        trace_hash,
        ".gum-extra",
        &(call_annotations, consumed_seqs),
    );
}

pub fn load_gumtrace_extra(
    file_path: &str,
    trace_len: u64,
    trace_hash: &[u8; 32],
) -> Option<(std::collections::HashMap<u32, CallAnnotation>, Vec<u32>)> {
    load_cached(file_path, trace_len, trace_hash, ".gum-extra")
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
        ".modules.bin",
    ] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(&p);
            let _ = std::fs::remove_file(verified_path(&p));
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
            // `.verified` 是缓存文件的旁路校验记录：清缓存时一并回收，
            // 否则每次重建都会留下无人引用的陈旧记录。
            if is_staging
                || ext == Some("bin")
                || ext == Some("rkyv")
                || ext == Some("cache")
                || ext == Some("verified")
            {
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

    /// section 缓存同时绑定布局版本与 payload 摘要；任一合同改变都必须升 magic。
    /// 此断言锁定当前版本，避免下次格式变更漏改。
    #[test]
    fn section_magic_tracks_payload_integrity_contract() {
        assert_eq!(MAGIC_V7, b"TCACHE08");
    }

    #[test]
    fn section_cache_identity_includes_trace_tail() {
        let _guard = cache_dir_override_test_lock();
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-cache-tail-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        set_cache_dir_override(Some(dir.clone()));

        let path = "/tmp/trace-ui-cache-tail.trace";
        let mut original = vec![0u8; 1024 * 1024 + 1];
        original[1024 * 1024] = 1;
        let archive = crate::flat::line_index::LineIndexArchive {
            sampled_offsets: vec![0],
            total: 1,
        };
        let original_hash: [u8; 32] = Sha256::digest(&original).into();
        save_sections_raw(
            path,
            original.len() as u64,
            &original_hash,
            ".lidx.cache",
            &archive.to_sections(),
        );
        assert!(load_lidx_cache(path, original.len() as u64, &original_hash).is_some());

        let mut changed = original;
        changed[1024 * 1024] = 2;
        let changed_hash: [u8; 32] = Sha256::digest(&changed).into();
        assert!(
            load_lidx_cache(path, changed.len() as u64, &changed_hash).is_none(),
            "same-size trace changes after the first MiB must invalidate caches"
        );

        set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod verified_digest_tests {
    use super::*;

    /// 大型 section 缓存的完整摘要被绑定到缓存文件自身的 fstat 签名：
    /// 命中时不必重算 931 MiB SHA-256，但任何改写都会让旁路记录失配并
    /// 重新完整校验（fail-closed）。
    #[test]
    fn large_section_cache_digest_binds_to_the_cache_file_signature() {
        let _guard = cache_dir_override_test_lock();
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-verified-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        set_cache_dir_override(Some(dir.clone()));

        let path = "/tmp/trace-ui-verified-large.trace";
        // 2.2M 采样点 = 17.6 MiB payload，超过小文件阈值才会走旁路记录。
        let samples = 2_200_000u64;
        let archive = crate::flat::line_index::LineIndexArchive {
            sampled_offsets: (0..samples).collect(),
            total: u32::try_from(samples * 256).unwrap(),
        };
        let bytes = archive.to_sections();
        assert!(bytes.len() as u64 > SMALL_CACHE_FULL_DIGEST_LIMIT);
        let trace_hash = [9u8; 32];
        save_sections_raw(path, 4242, &trace_hash, ".lidx.cache", &bytes);

        let cache_file = cache_path_ext(path, ".lidx.cache").expect("cache path");
        let file = File::open(&cache_file).expect("open cache file");
        let digest = section_digest(&bytes);
        assert!(
            verified_digest_matches(&file, &cache_file, &digest),
            "保存后必须立即写入与文件指纹绑定的摘要记录"
        );
        assert!(load_lidx_cache(path, 4242, &trace_hash).is_some());
        // 旁路记录缺失时回退全量摘要，仍然命中。
        std::fs::remove_file(verified_path(&cache_file)).unwrap();
        assert!(load_lidx_cache(path, 4242, &trace_hash).is_some());

        // 改写 payload：文件指纹失效，必须重新全量校验并拒绝。
        let mut corrupted = std::fs::read(&cache_file).unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        std::fs::write(&cache_file, &corrupted).unwrap();
        assert!(
            load_lidx_cache(path, 4242, &trace_hash).is_none(),
            "文件指纹变化后不得凭借旁路记录跳过完整摘要校验"
        );

        set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 旁路记录住在缓存目录里，同样是不可信输入：它必须像 fingerprint 一样
    /// no-follow 打开。否则一个符号链接就能把「摘要正确」这句话绕开，让损坏
    /// 的 payload 直接命中。
    #[cfg(unix)]
    #[test]
    fn symlinked_verified_record_cannot_bypass_the_payload_digest() {
        let _guard = cache_dir_override_test_lock();
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-verified-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        set_cache_dir_override(Some(dir.clone()));

        let path = "/tmp/trace-ui-verified-link.trace";
        // 偶数步长让 sampled_offsets 留出间隙：改动一个值仍保持严格递增，
        // 因此被拒只能是因为摘要校验，而不是 section 布局预检。
        let samples = 2_200_000u64;
        let archive = crate::flat::line_index::LineIndexArchive {
            sampled_offsets: (0..samples).map(|index| index * 2).collect(),
            total: u32::try_from(samples * 256).unwrap(),
        };
        let bytes = archive.to_sections();
        assert!(bytes.len() as u64 > SMALL_CACHE_FULL_DIGEST_LIMIT);
        let trace_hash = [7u8; 32];
        save_sections_raw(path, 4242, &trace_hash, ".lidx.cache", &bytes);

        let cache_file = cache_path_ext(path, ".lidx.cache").expect("cache path");
        let digest = section_digest(&bytes);
        let mut corrupted = std::fs::read(&cache_file).unwrap();
        corrupted[HEADER_LEN_V7 + 1000 * 8] ^= 1;
        std::fs::write(&cache_file, &corrupted).unwrap();
        assert!(
            crate::flat::line_index::LineIndexArchive::views_from_sections(
                &corrupted[HEADER_LEN_V7..]
            )
            .is_some(),
            "损坏后的布局仍然合法，拒绝只能来自摘要校验"
        );

        // 伪造一条「摘要 + 当前文件指纹」都正确的旁路记录，只通过符号链接
        // 暴露：跟随链接就会跳过整份 payload 的摘要校验。
        let signature = fd_signature(&File::open(&cache_file).unwrap()).unwrap();
        let mut record = Vec::with_capacity(VERIFIED_LEN);
        record.extend_from_slice(VERIFIED_MAGIC);
        record.extend_from_slice(&signature.encode());
        record.extend_from_slice(&digest);
        let real = dir.join("real.verified");
        std::fs::write(&real, record).unwrap();
        let _ = std::fs::remove_file(verified_path(&cache_file));
        std::os::unix::fs::symlink(&real, verified_path(&cache_file)).unwrap();

        assert!(
            load_lidx_cache(path, 4242, &trace_hash).is_none(),
            "符号链接的旁路记录不得被采信"
        );

        set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
