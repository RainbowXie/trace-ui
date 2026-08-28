//! Memory 与寄存器查询方法：get_memory_at / get_mem_history_* / get_registers_at。

use std::collections::HashMap;

use crate::api_types::*;
use crate::browse::{parse_trace_line, parse_trace_line_gumtrace};
use crate::error::{Result, TraceError};
use crate::flat::line_index::LineIndexView;
use crate::phase2::extract_insn_offset;
use trace_parser::types::{RegId, TraceFormat};
use trace_parser::{def_use, insn_class, parser};

/// 从 trace 行提取偏移地址，回退到绝对地址
fn resolve_offset(
    seq: u32,
    abs_addr: u64,
    line_index: Option<&LineIndexView<'_>>,
    data: &[u8],
) -> String {
    if let Some(li) = line_index {
        if let Some(line_bytes) = li.get_line(data, seq) {
            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                let offset = extract_insn_offset(line_str);
                if offset != 0 {
                    return format!("0x{:x}", offset);
                }
            }
        }
    }
    format!("0x{:x}", abs_addr)
}

// ── Registers helpers ──

const REG_NAMES: &[(&str, u8)] = &[
    ("X0", 0),
    ("X1", 1),
    ("X2", 2),
    ("X3", 3),
    ("X4", 4),
    ("X5", 5),
    ("X6", 6),
    ("X7", 7),
    ("X8", 8),
    ("X9", 9),
    ("X10", 10),
    ("X11", 11),
    ("X12", 12),
    ("X13", 13),
    ("X14", 14),
    ("X15", 15),
    ("X16", 16),
    ("X17", 17),
    ("X18", 18),
    ("X19", 19),
    ("X20", 20),
    ("X21", 21),
    ("X22", 22),
    ("X23", 23),
    ("X24", 24),
    ("X25", 25),
    ("X26", 26),
    ("X27", 27),
    ("X28", 28),
    ("X29", 29),
    ("X30", 30),
    ("SP", 31),
    ("NZCV", 65),
];

fn reg_id_to_name(r: RegId) -> Option<&'static str> {
    match r.0 {
        0 => Some("X0"),
        1 => Some("X1"),
        2 => Some("X2"),
        3 => Some("X3"),
        4 => Some("X4"),
        5 => Some("X5"),
        6 => Some("X6"),
        7 => Some("X7"),
        8 => Some("X8"),
        9 => Some("X9"),
        10 => Some("X10"),
        11 => Some("X11"),
        12 => Some("X12"),
        13 => Some("X13"),
        14 => Some("X14"),
        15 => Some("X15"),
        16 => Some("X16"),
        17 => Some("X17"),
        18 => Some("X18"),
        19 => Some("X19"),
        20 => Some("X20"),
        21 => Some("X21"),
        22 => Some("X22"),
        23 => Some("X23"),
        24 => Some("X24"),
        25 => Some("X25"),
        26 => Some("X26"),
        27 => Some("X27"),
        28 => Some("X28"),
        29 => Some("X29"),
        30 => Some("X30"),
        31 => Some("SP"),
        65 => Some("NZCV"),
        _ => None,
    }
}

impl crate::engine::TraceEngine {
    pub fn get_memory_at(
        &self,
        session_id: &str,
        addr: u64,
        seq: u32,
        length: u32,
    ) -> Result<MemorySnapshot> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        // 对齐到 16 字节边界
        let base = addr & !0xF;
        let len = length.max(16) as usize;

        let mut bytes = vec![0u8; len];
        let mut known = vec![false; len];

        for offset in 0..len {
            let byte_addr = base + offset as u64;

            // 检查 byte_addr-7 .. byte_addr 共 8 个可能的基地址
            let mut best_seq: Option<u32> = None;
            let mut best_byte: u8 = 0;

            for check_offset in 0u64..=7 {
                if byte_addr < check_offset {
                    continue;
                }
                let check_addr = byte_addr - check_offset;

                if let Some(records) = mem_view.query(check_addr) {
                    let pos = records.partition_point(|r| r.seq <= seq);
                    if pos > 0 {
                        let rec = &records[pos - 1];
                        let candidate_seq = rec.seq;
                        let candidate_data = rec.data;
                        let candidate_size = rec.size;

                        if check_offset < candidate_size as u64
                            && (best_seq.is_none() || candidate_seq > best_seq.unwrap())
                        {
                            best_seq = Some(candidate_seq);
                            best_byte = ((candidate_data >> (check_offset * 8)) & 0xFF) as u8;
                        }
                    }
                }
            }

            if best_seq.is_some() {
                bytes[offset] = best_byte;
                known[offset] = true;
            }
        }

        Ok(MemorySnapshot {
            base_addr: format!("0x{:x}", base),
            bytes,
            known,
            length: len as u32,
        })
    }

    pub fn get_mem_history_meta(
        &self,
        session_id: &str,
        addr: u64,
        center_seq: u32,
    ) -> Result<MemHistoryMeta> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => {
                return Ok(MemHistoryMeta {
                    total: 0,
                    center_index: 0,
                    samples: Vec::new(),
                })
            }
        };

        let center_index = records.partition_point(|r| r.seq < center_seq);
        let center_index = center_index.min(records.len().saturating_sub(1));

        // Minimap 采样：等间距取 ~300 条记录
        const SAMPLE_COUNT: usize = 300;
        let samples = if records.len() <= SAMPLE_COUNT {
            Vec::new()
        } else {
            let line_index = state.line_index_view();
            let data: &[u8] = &state.mmap;
            let format = state.trace_format;
            (0..SAMPLE_COUNT)
                .map(|i| {
                    let idx = i * records.len() / SAMPLE_COUNT;
                    let rec = &records[idx];
                    let disasm = line_index
                        .as_ref()
                        .and_then(|li| li.get_line(data, rec.seq))
                        .and_then(|raw| match format {
                            TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                            TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                        })
                        .map(|parsed| parsed.disasm)
                        .unwrap_or_default();
                    MemHistoryRecord {
                        seq: rec.seq,
                        rw: if rec.is_read() {
                            "R".to_string()
                        } else {
                            "W".to_string()
                        },
                        data: format!("0x{:x}", rec.data),
                        size: rec.size,
                        insn_addr: resolve_offset(
                            rec.seq,
                            rec.insn_addr,
                            line_index.as_ref(),
                            data,
                        ),
                        disasm,
                    }
                })
                .collect()
        };

        Ok(MemHistoryMeta {
            total: records.len(),
            center_index,
            samples,
        })
    }

    pub fn get_mem_history_range(
        &self,
        session_id: &str,
        addr: u64,
        start_index: usize,
        limit: usize,
    ) -> Result<Vec<MemHistoryRecord>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let start = start_index.min(records.len());
        let end = (start + limit).min(records.len());
        let slice = &records[start..end];

        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let format = state.trace_format;

        let result: Vec<MemHistoryRecord> = slice
            .iter()
            .map(|rec| {
                let disasm = line_index
                    .get_line(data, rec.seq)
                    .and_then(|raw| match format {
                        TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                        TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                    })
                    .map(|parsed| parsed.disasm)
                    .unwrap_or_default();
                MemHistoryRecord {
                    seq: rec.seq,
                    rw: if rec.is_read() {
                        "R".to_string()
                    } else {
                        "W".to_string()
                    },
                    data: format!("0x{:x}", rec.data),
                    size: rec.size,
                    insn_addr: resolve_offset(rec.seq, rec.insn_addr, Some(&line_index), data),
                    disasm,
                }
            })
            .collect();

        Ok(result)
    }

    pub fn get_registers_at(&self, session_id: &str, seq: u32) -> Result<HashMap<String, String>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let reg_view = state
            .reg_checkpoints_view()
            .ok_or(TraceError::IndexNotReady)?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        // 找最近检查点
        let (ckpt_seq, snapshot) = reg_view
            .nearest_before(seq)
            .ok_or_else(|| TraceError::Internal("无可用检查点".to_string()))?;

        let mut values = *snapshot;

        // 从检查点重放到目标 seq
        for replay_seq in ckpt_seq..=seq {
            if let Some(raw) = line_index.get_line(&state.mmap, replay_seq) {
                if let Ok(line_str) = std::str::from_utf8(raw) {
                    crate::phase2::update_reg_values(&mut values, line_str);
                }
            }
        }

        // 构建返回结果
        let mut result = HashMap::new();
        for &(name, idx) in REG_NAMES {
            let val = values[idx as usize];
            if val != u64::MAX {
                result.insert(name.to_string(), format!("0x{:016x}", val));
            } else {
                result.insert(name.to_string(), "?".to_string());
            }
        }

        // PC = 当前行的指令地址 + 提取当前行被修改的寄存器名
        let format = state.trace_format;
        if let Some(raw) = line_index.get_line(&state.mmap, seq) {
            let parsed = match format {
                TraceFormat::Unidbg => parse_trace_line(seq, raw),
                TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
            };
            if let Some(parsed) = parsed {
                let pc_display = if let Some(hex_str) = parsed
                    .address
                    .strip_prefix("0x")
                    .or_else(|| parsed.address.strip_prefix("0X"))
                {
                    if let Ok(addr_val) = u64::from_str_radix(hex_str, 16) {
                        format!("0x{:016x}", addr_val)
                    } else {
                        parsed.address
                    }
                } else {
                    parsed.address
                };
                result.insert("PC".to_string(), pc_display);
            }
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let mut changed = Vec::new();
                if let Some(arrow_pos) = line_str.find(" => ").or_else(|| line_str.find(" -> ")) {
                    let changes = &line_str[arrow_pos + 4..];
                    for part in changes.split_whitespace() {
                        if let Some(eq_pos) = part.find('=') {
                            let reg_name = &part[..eq_pos];
                            changed.push(reg_name.to_uppercase());
                        }
                    }
                }
                if !changed.is_empty() {
                    result.insert("__changed".to_string(), changed.join(","));
                }

                // 提取 USE（读取）寄存器
                if let Some(parsed) = parser::parse_line(line_str) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (_, uses) = def_use::determine_def_use(cls, &parsed);
                    let read_names: Vec<&str> =
                        uses.iter().filter_map(|r| reg_id_to_name(*r)).collect();
                    if !read_names.is_empty() {
                        result.insert("__read".to_string(), read_names.join(","));
                    }
                }
            }
        }

        Ok(result)
    }
}
