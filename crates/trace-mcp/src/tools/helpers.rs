//! TraceToolHandler 的内部自由函数：JSON 序列化、阻塞执行、行裁剪、
//! 搜索选项解析与范围解析。独立成模块避免 tools 路由实现超出文件规模上限。

use crate::types::SearchMemoryRequest;
use trace_core::memory_search::{
    parse_pattern_hex, MemorySearchOptions, MemorySearchResult, MemorySearchRw,
};
use trace_core::{api_types::TraceLine, parse_hex_addr};

pub(crate) fn json(val: &impl serde::Serialize) -> String {
    serde_json::to_string(val)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
}

/// Run a blocking closure on the tokio blocking thread pool to avoid starving
/// the async runtime. Used for heavy TraceEngine operations.
pub(crate) async fn blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("Task panicked: {}", e))?
}

/// Compact 模式下裁剪 TraceLine 为精简 JSON
pub(crate) fn compact_line(line: &TraceLine) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "seq": line.seq,
        "address": line.address,
    });
    if !line.so_offset.is_empty() {
        obj["so_offset"] = serde_json::json!(line.so_offset);
    }
    obj["disasm"] = serde_json::json!(line.disasm);
    if !line.changes.is_empty() {
        obj["changes"] = serde_json::json!(line.changes);
    }
    if let Some(ref rw) = line.mem_rw {
        obj["mem_rw"] = serde_json::json!(rw);
    }
    if let Some(ref addr) = line.mem_addr {
        obj["mem_addr"] = serde_json::json!(addr);
    }
    if let Some(ref name) = line.so_name {
        obj["so_name"] = serde_json::json!(name);
    }
    if let Some(ref info) = line.call_info {
        if !info.func_name.is_empty() {
            obj["func_name"] = serde_json::json!(info.func_name);
        }
    }
    obj
}

pub(crate) fn format_lines(lines: &[TraceLine], full: bool) -> Vec<serde_json::Value> {
    if full {
        lines
            .iter()
            .map(|l| {
                serde_json::to_value(l)
                    .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
            })
            .collect()
    } else {
        lines.iter().map(compact_line).collect()
    }
}

pub(crate) fn parse_memory_search_options(
    req: &SearchMemoryRequest,
) -> Result<MemorySearchOptions, String> {
    let pattern = parse_pattern_hex(&req.pattern).map_err(|e| e.to_string())?;
    let seq_range = req
        .seq_range
        .as_ref()
        .map(|range| {
            if range.start > range.end {
                Err("seq_range.start must not exceed seq_range.end".to_string())
            } else {
                Ok((range.start, range.end))
            }
        })
        .transpose()?;
    let memory_range = req
        .memory_range
        .as_ref()
        .map(|range| {
            if range.size == 0 {
                return Err("memory_range.size must be positive".to_string());
            }
            let start = parse_hex_addr(&range.address)?;
            let end = start
                .checked_add(range.size)
                .ok_or_else(|| "memory_range address + size overflows u64".to_string())?;
            Ok((start, end))
        })
        .transpose()?;
    Ok(MemorySearchOptions {
        pattern,
        seq_range,
        memory_range,
        offset: req.offset,
        limit: req.limit,
    })
}

pub(crate) fn format_memory_search_result(result: MemorySearchResult) -> String {
    let matches: Vec<serde_json::Value> = result
        .matches
        .into_iter()
        .map(|item| {
            let rw = match item.rw {
                MemorySearchRw::Read => "read",
                MemorySearchRw::Write => "write",
            };
            serde_json::json!({
                "address": format!("0x{:x}", item.address),
                "seq": item.seq,
                "size": item.size,
                "bytes": item.bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "rw": rw,
            })
        })
        .collect();
    json(&serde_json::json!({
        "matches": matches,
        "total": result.total,
        "offset": result.offset,
        "limit": result.limit,
        "has_more": result.has_more,
    }))
}

/// 检查 changes 字段是否仅包含栈/帧指针寄存器变化
pub(crate) fn is_stack_only_change(changes: &str) -> bool {
    if changes.is_empty() {
        return false;
    }
    let mut has_any = false;
    for token in changes.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any = true;
            match reg {
                "sp" | "x29" | "fp" | "wsp" | "w29" => {}
                _ => return false,
            }
        }
    }
    has_any
}

/// Parse address range string like "0x246F00-0x249800"
pub(crate) fn parse_addr_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid addr_range format '{}'. Expected: '0x246F00-0x249800'",
            range
        ));
    }
    let start = parse_hex_addr(parts[0].trim())?;
    let end = parse_hex_addr(parts[1].trim())?;
    if start > end {
        return Err(format!(
            "Invalid addr_range: start (0x{:x}) > end (0x{:x})",
            start, end
        ));
    }
    Ok((start, end))
}

/// Parse seq range string like "3000-6000"
pub(crate) fn parse_seq_range(range: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid seq_range format '{}'. Expected: '3000-6000'",
            range
        ));
    }
    let start: u32 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid start seq: '{}'", parts[0].trim()))?;
    let end: u32 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid end seq: '{}'", parts[1].trim()))?;
    if start > end {
        return Err(format!(
            "Invalid seq_range: start ({}) > end ({})",
            start, end
        ));
    }
    Ok((start, end))
}

/// Check if TraceLine's SO offset falls within an address range
pub(crate) fn line_in_addr_range(line: &TraceLine, start: u64, end: u64) -> bool {
    parse_hex_addr(&line.so_offset)
        .map(|offset| offset >= start && offset <= end)
        .unwrap_or(false)
}
