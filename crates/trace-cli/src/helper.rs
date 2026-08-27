//! The fd-based byte-search helper used by the Analysis Case adapter.
//!
//! The adapter has already validated the trace and pattern files.  It passes
//! their open descriptors to this process so this helper never has to reopen
//! a pathname (and therefore cannot observe a replacement file).

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{FromRawFd, RawFd};

use serde::Deserialize;
#[cfg(all(unix, debug_assertions))]
use trace_core::memory_search::FingerprintSource;
use trace_core::memory_search::{
    search_memory_fd_verified, MemorySearchOccurrenceResult, MemorySearchOptions,
};
use trace_parser::gumtrace;

const MAX_PATTERN_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperRequest {
    #[serde(default)]
    seq_range: Option<SeqRange>,
    #[serde(default)]
    memory_range: Option<MemoryRange>,
    #[serde(default)]
    offset: u32,
    limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeqRange {
    start: u32,
    end: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryRange {
    address: String,
    size: u64,
}

/// Return whether argv requests the fd-based helper mode.
pub(crate) fn requested() -> bool {
    std::env::args().any(|arg| arg == "--search-memory-helper")
}

/// Run the fd-based helper and write one JSON response to stdout.
pub(crate) fn run() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let trace_fd = parse_fd_arg(&args, "--trace-fd")?;
    let pattern_fd = parse_fd_arg(&args, "--pattern-fd")?;
    validate_inherited_fds(trace_fd, pattern_fd)?;

    #[cfg(unix)]
    let trace = unsafe { File::from_raw_fd(trace_fd) };
    #[cfg(unix)]
    let mut pattern = unsafe { File::from_raw_fd(pattern_fd) };
    #[cfg(not(unix))]
    return Err(anyhow::anyhow!("fd helper is only supported on Unix"));

    ensure_regular(&trace, "trace fd")?;
    ensure_regular(&pattern, "pattern fd")?;
    let pattern_bytes = read_from_start(&mut pattern, Some(MAX_PATTERN_BYTES), "pattern fd")?;
    if pattern_bytes.is_empty() {
        return Err(anyhow::anyhow!("pattern fd contains an empty pattern"));
    }

    let request_bytes = read_stdin_bounded()?;
    let request: HelperRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| anyhow::anyhow!("invalid helper request: {error}"))?;
    let seq_range = request.seq_range.map(|range| (range.start, range.end));
    let memory_range = request
        .memory_range
        .map(|range| {
            let start = trace_core::parse_hex_addr(&range.address)
                .map_err(|error| anyhow::anyhow!("invalid memory range address: {error}"))?;
            let end = start
                .checked_add(range.size)
                .ok_or_else(|| anyhow::anyhow!("memory range address + size overflows u64"))?;
            Ok::<_, anyhow::Error>((start, end))
        })
        .transpose()?;
    let trace_map = unsafe {
        memmap2::MmapOptions::new()
            .map(&trace)
            .map_err(|error| anyhow::anyhow!("trace fd mmap failed: {error}"))?
    };
    let format = gumtrace::detect_format(&trace_map);
    // --fingerprint-log 是测试专用的观察口：只在 debug 构建中存在，
    // 生产（release）构建不接受这个参数，也不产生任何额外文件写入。
    #[cfg(all(unix, debug_assertions))]
    let mut fingerprint_probe = parse_fingerprint_log_arg(&args)?;
    #[cfg(not(all(unix, debug_assertions)))]
    reject_fingerprint_log_arg(&args)?;
    let result = search_memory_fd_verified(
        &trace,
        &trace_map,
        format,
        MemorySearchOptions {
            pattern: pattern_bytes,
            seq_range,
            memory_range,
            offset: request.offset,
            limit: request.limit,
        },
        #[cfg(all(unix, debug_assertions))]
        fingerprint_probe
            .as_mut()
            .map(|probe| probe.as_mut() as &mut dyn FnMut(FingerprintSource)),
        #[cfg(not(all(unix, debug_assertions)))]
        None,
    )?;
    write_response(&result)?;
    Ok(())
}

/// fingerprint 决策观察口的类型（仅测试使用）
#[cfg(all(unix, debug_assertions))]
type FingerprintProbe = Box<dyn FnMut(FingerprintSource)>;

/// 测试专用：把 fingerprint 决策追加写入 --fingerprint-log 指定的路径。
#[cfg(all(unix, debug_assertions))]
fn parse_fingerprint_log_arg(args: &[String]) -> anyhow::Result<Option<FingerprintProbe>> {
    let Some(path) = args
        .windows(2)
        .find(|pair| pair[0] == "--fingerprint-log")
        .map(|pair| std::path::PathBuf::from(&pair[1]))
    else {
        return Ok(None);
    };
    Ok(Some(Box::new(move |source| {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            use std::io::Write as _;
            let decision = match source {
                FingerprintSource::Computed => "computed",
                FingerprintSource::Reused => "reused",
            };
            let _ = writeln!(file, "{decision}");
        }
    })))
}

#[cfg(not(all(unix, debug_assertions)))]
fn reject_fingerprint_log_arg(args: &[String]) -> anyhow::Result<()> {
    if args.iter().any(|arg| arg == "--fingerprint-log") {
        return Err(anyhow::anyhow!(
            "--fingerprint-log is only available in debug builds"
        ));
    }
    Ok(())
}

fn parse_fd_arg(args: &[String], name: &str) -> anyhow::Result<RawFd> {
    let value = args
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| anyhow::anyhow!("missing {name} argument"))?;
    let fd = value
        .parse::<i32>()
        .map_err(|error| anyhow::anyhow!("invalid {name} value: {error}"))?;
    if fd < 0 {
        return Err(anyhow::anyhow!("{name} must be non-negative"));
    }
    Ok(fd)
}

fn validate_inherited_fds(trace_fd: RawFd, pattern_fd: RawFd) -> anyhow::Result<()> {
    if trace_fd < 3 || pattern_fd < 3 {
        return Err(anyhow::anyhow!(
            "trace and pattern fds must not use reserved standard descriptors 0, 1, or 2"
        ));
    }
    if trace_fd == pattern_fd {
        return Err(anyhow::anyhow!(
            "trace and pattern fds must be different descriptors"
        ));
    }
    Ok(())
}

fn ensure_regular(file: &File, label: &str) -> anyhow::Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("{label} metadata failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow::anyhow!("{label} is not a regular file"));
    }
    Ok(())
}

fn read_from_start(file: &mut File, max: Option<usize>, label: &str) -> anyhow::Result<Vec<u8>> {
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| anyhow::anyhow!("{label} seek failed: {error}"))?;
    let mut bytes = Vec::new();
    match max {
        Some(max) => {
            let mut bounded = file.take((max as u64).saturating_add(1));
            bounded
                .read_to_end(&mut bytes)
                .map_err(|error| anyhow::anyhow!("{label} read failed: {error}"))?;
            if bytes.len() > max {
                return Err(anyhow::anyhow!("{label} exceeds {} byte limit", max));
            }
        }
        None => {
            file.read_to_end(&mut bytes)
                .map_err(|error| anyhow::anyhow!("{label} read failed: {error}"))?;
        }
    }
    Ok(bytes)
}

fn read_stdin_bounded() -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut stdin = io::stdin()
        .lock()
        .take((MAX_CONTROL_BYTES as u64).saturating_add(1));
    stdin
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("control request read failed: {error}"))?;
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(anyhow::anyhow!(
            "control request exceeds {} byte limit",
            MAX_CONTROL_BYTES
        ));
    }
    Ok(bytes)
}

fn encode_response(result: &MemorySearchOccurrenceResult) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(result).map_err(|error| anyhow::anyhow!("response encoding failed: {error}"))
}

fn write_response(result: &MemorySearchOccurrenceResult) -> anyhow::Result<()> {
    let encoded = encode_response(result)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&encoded)
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|error| anyhow::anyhow!("response write failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trace_core::memory_search::{
        MemorySearchOccurrence, MemorySearchOccurrenceResult, MemorySearchRw,
    };

    #[test]
    fn helper_response_is_bounded_for_maximum_pattern_size() {
        let result = MemorySearchOccurrenceResult {
            content_identity: "test-content-identity".to_string(),
            matches: vec![MemorySearchOccurrence {
                address: 0x2000,
                seq: 1,
                size: MAX_PATTERN_BYTES as u32,
                rw: MemorySearchRw::Write,
            }],
            total: 1,
            offset: 0,
            limit: 1,
            has_more: false,
        };
        let encoded = encode_response(&result).expect("encode response");
        assert!(
            encoded.len() < 1024,
            "helper response unexpectedly large: {}",
            encoded.len()
        );
        assert!(!encoded.windows(8).any(|window| window == b"bytes\""));
    }
}
