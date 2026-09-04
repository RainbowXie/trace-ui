//! 缓存 staging 生命周期：崩溃留下的临时文件必须能被后续读写回收。
//!
//! 命名合同：`.{cache_name}.tmp.{pid}.{unique}`。
//! unique 用 UUID，避免同进程并发写撞名；pid 用于判断 writer 是否还活着。

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Duration;

use crate::error::{Result, TraceError};

/// PID 被复用后靠年龄兑底回收：活着但不持有 fd 的 staging 超过这个时间才删。
pub(crate) const STAGING_MAX_AGE: Duration = Duration::from_secs(24 * 3600);

#[cfg(test)]
thread_local! {
    static FORCE_PARENT_FSYNC_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 测试注入限定在当前测试线程，避免 `cargo test` 并行执行时让无关发布
/// 路径也收到 fsync 失败，产生同源假证据。
#[cfg(test)]
pub(crate) struct ForceParentFsyncFailGuard;

#[cfg(test)]
impl ForceParentFsyncFailGuard {
    pub(crate) fn arm() -> Self {
        FORCE_PARENT_FSYNC_FAIL.with(|flag| {
            assert!(!flag.replace(true), "parent fsync failure already armed");
        });
        Self
    }
}

#[cfg(test)]
impl Drop for ForceParentFsyncFailGuard {
    fn drop(&mut self) {
        FORCE_PARENT_FSYNC_FAIL.with(|flag| flag.set(false));
    }
}

/// rename 之后必须 fsync 父目录，否则崩溃会让目录项回滚到旧名字。
pub(crate) fn sync_parent_dir(parent: &Path) -> Result<()> {
    #[cfg(test)]
    if FORCE_PARENT_FSYNC_FAIL.with(|flag| flag.get()) {
        return Err(TraceError::Io(io::Error::other(
            "injected parent dir fsync failure",
        )));
    }
    let parent_file = File::open(parent).map_err(TraceError::Io)?;
    parent_file.sync_all().map_err(TraceError::Io)?;
    Ok(())
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

#[cfg(not(unix))]
fn staging_file_held_by(_pid: u32, _path: &Path) -> bool {
    // Windows 无 fd 持有检测；按死 PID 处理，交由年龄/PID 规则回收。
    false
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

/// 解析 `.{name}.tmp.{pid}.{unique}`。不符合合同的文件不是本模块的 staging。
fn parse_staging_name(name: &str) -> Option<(&str, u32)> {
    let rest = name.strip_prefix('.')?;
    let (cache_name, pid_and_unique) = rest.rsplit_once(".tmp.")?;
    let pid_text = pid_and_unique.split('.').next()?;
    let pid = pid_text.parse::<u32>().ok()?;
    Some((cache_name, pid))
}

/// 杀进程留下的 staging 必须被后续读写回收，否则会无限堆积。
/// 活 writer 持有 fd 时任何年龄都保留；活 PID 但不持有且未过期也保留
///（并发构建刚 create_new、尚未 open 完的窗口）。
pub(crate) fn cleanup_stale_staging_files(parent: &Path) -> Result<()> {
    let entries = fs::read_dir(parent).map_err(TraceError::Io)?;
    let current_pid = std::process::id();
    for entry in entries {
        let entry = entry.map_err(TraceError::Io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((_cache_name, pid)) = parse_staging_name(&name) else {
            continue;
        };
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
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(TraceError::Io(error)),
        }
    }
    Ok(())
}

/// 原子发布：create_new staging → 写入 → flush + fsync → rename → 父目录 fsync。
/// 失败删本次 tmp；开始写之前先回收同目录遗留 staging。
/// `write_fn` 返回 false 表示调用方主动放弃（不发布）。
/// rename 成功即已发布；父目录 fsync 失败只记日志，不得把已可见的新文件写成失败。
pub(crate) fn atomic_publish(
    path: &Path,
    write_fn: impl FnOnce(&mut BufWriter<File>) -> bool,
) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if fs::create_dir_all(parent).is_err() {
        return false;
    }
    if cleanup_stale_staging_files(parent).is_err() {
        return false;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("cache");
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        name,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let file = match OpenOptions::new().write(true).create_new(true).open(&tmp) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut writer = BufWriter::new(file);
    let ok = (|| {
        if !write_fn(&mut writer) {
            return false;
        }
        if writer.flush().is_err() {
            return false;
        }
        let file = match writer.into_inner() {
            Ok(f) => f,
            Err(_) => return false,
        };
        if file.sync_all().is_err() {
            return false;
        }
        drop(file);
        if fs::rename(&tmp, path).is_err() {
            return false;
        }
        published_after_rename(path, parent)
    })();
    if !ok {
        let _ = fs::remove_file(&tmp);
    }
    ok
}

/// rename 已成功：读者能看到新文件。父目录 fsync 失败只记日志，
/// 不得返回 false——否则调用方会当成没写上（第一次搜索报错，盘上却已有文件）。
/// `atomic_publish` 与 `stream_cache` 共用：两条写路径不得各写一套失败语义。
pub(crate) fn published_after_rename(path: &Path, parent: &Path) -> bool {
    if let Err(error) = sync_parent_dir(parent) {
        eprintln!(
            "[cache] parent dir fsync failed after rename {}: {error}",
            path.display()
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use memmap2::Mmap;
    use std::io::Write;

    fn unique_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-staging-{}-{}-{}",
            label,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn publish_keeps_old_mmap_bytes() {
        let dir = unique_dir("mmap");
        let path = dir.join("target.cache");
        fs::write(&path, b"old-bytes").unwrap();
        let file = File::open(&path).unwrap();
        let mmap = unsafe { Mmap::map(&file) }.unwrap();
        assert_eq!(&mmap[..], b"old-bytes");

        assert!(atomic_publish(&path, |w| w.write_all(b"new-bytes").is_ok()));
        assert_eq!(&mmap[..], b"old-bytes");
        assert_eq!(fs::read(&path).unwrap(), b"new-bytes");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_write_leaves_no_tmp() {
        let dir = unique_dir("fail");
        let path = dir.join("target.cache");
        fs::write(&path, b"keep").unwrap();
        assert!(!atomic_publish(&path, |_w| false));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "失败写不得留下 staging");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dead_pid_staging_is_reclaimed_on_next_publish() {
        let dir = unique_dir("reclaim");
        let path = dir.join("target.cache");
        let stale = dir.join(".target.cache.tmp.4294967295.stale");
        fs::write(&stale, b"abandoned").unwrap();
        assert!(atomic_publish(&path, |w| w.write_all(b"fresh").is_ok()));
        assert!(!stale.exists());
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parent_fsync_failure_after_rename_still_counts_as_published() {
        // 注入点在 sync_parent_dir：必须走 atomic_publish，否则改回
        // `sync_parent_dir(parent).is_err() { return false }` 测试仍绿。
        let dir = unique_dir("parent-fsync");
        let path = dir.join("target.cache");
        let _fail = ForceParentFsyncFailGuard::arm();
        assert!(atomic_publish(&path, |w| w.write_all(b"visible").is_ok()));
        assert_eq!(fs::read(&path).unwrap(), b"visible");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "已发布不得误删最终文件或留下 staging");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_rejects_plain_cache_files() {
        assert!(parse_staging_name("target.cache").is_none());
        assert!(parse_staging_name(".target.cache").is_none());
        assert_eq!(
            parse_staging_name(".target.cache.tmp.12.abcd"),
            Some(("target.cache", 12))
        );
    }
}
