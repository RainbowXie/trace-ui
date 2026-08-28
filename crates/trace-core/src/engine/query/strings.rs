//! 字符串查询与扫描方法：get_strings / get_string_xrefs / scan_strings / cancel_scan_strings。

use std::sync::atomic::Ordering;

use crate::api_types::*;
use crate::browse::{parse_trace_line, parse_trace_line_gumtrace};
use crate::error::{Result, TraceError};
use crate::phase2::extract_insn_offset;
use crate::query::strings::{StringBuilder, StringEncoding, StringRw};
use trace_parser::types::TraceFormat;

impl crate::engine::TraceEngine {
    pub fn get_strings(
        &self,
        session_id: &str,
        options: StringQueryOptions,
    ) -> Result<StringsResult> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let string_index = state
            .string_index
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;

        let search_lower = options.search.as_ref().map(|s| s.to_lowercase());

        let filtered: Vec<(usize, &crate::query::strings::StringRecord)> = string_index
            .strings
            .iter()
            .enumerate()
            .filter(|(_, r)| r.byte_len >= options.min_len)
            .filter(|(_, r)| match &search_lower {
                Some(q) => r.content.to_lowercase().contains(q.as_str()),
                None => true,
            })
            .collect();

        let total = filtered.len() as u32;
        let page: Vec<StringRecordDto> = filtered
            .into_iter()
            .skip(options.offset as usize)
            .take(options.limit as usize)
            .map(|(idx, r)| StringRecordDto {
                idx: idx as u32,
                addr: format!("0x{:x}", r.addr),
                content: r.content.clone(),
                encoding: match r.encoding {
                    StringEncoding::Ascii => "ASCII".to_string(),
                    StringEncoding::Utf8 => "UTF-8".to_string(),
                },
                byte_len: r.byte_len,
                seq: r.seq,
                xref_count: r.xref_count,
                rw: match r.rw {
                    StringRw::Read => "R".to_string(),
                    StringRw::Write => "W".to_string(),
                },
            })
            .collect();

        Ok(StringsResult {
            strings: page,
            total,
        })
    }

    pub fn get_string_xrefs(
        &self,
        session_id: &str,
        addr: u64,
        byte_len: u32,
    ) -> Result<Vec<StringXRef>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let mmap = &state.mmap;
        let format = state.trace_format;

        let mut xrefs: Vec<StringXRef> = Vec::new();
        let mut seen_seqs = std::collections::HashSet::new();

        for offset in 0..byte_len as u64 {
            let target = addr + offset;
            if let Some(records) = mem_view.query(target) {
                for rec in records {
                    if seen_seqs.insert(rec.seq) {
                        let rw_str = if rec.is_read() { "R" } else { "W" };
                        let disasm = line_index
                            .get_line(mmap, rec.seq)
                            .and_then(|raw| match format {
                                TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                                TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                            })
                            .map(|t| t.disasm)
                            .unwrap_or_default();
                        let insn_addr_str = line_index
                            .get_line(mmap, rec.seq)
                            .and_then(|raw| std::str::from_utf8(raw).ok())
                            .map(|line_str| {
                                let off = extract_insn_offset(line_str);
                                if off != 0 {
                                    format!("0x{:x}", off)
                                } else {
                                    format!("0x{:x}", rec.insn_addr)
                                }
                            })
                            .unwrap_or_else(|| format!("0x{:x}", rec.insn_addr));
                        xrefs.push(StringXRef {
                            seq: rec.seq,
                            rw: rw_str.to_string(),
                            insn_addr: insn_addr_str,
                            disasm,
                        });
                    }
                }
            }
        }

        xrefs.sort_by_key(|x| x.seq);
        Ok(xrefs)
    }

    pub fn scan_strings(&self, session_id: &str) -> Result<()> {
        let handle = self.get_handle(session_id)?;

        // 使用 compare_exchange 防止并发扫描
        if handle
            .scanning_strings
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(TraceError::OperationInProgress(
                "scan_strings already running".to_string(),
            ));
        }

        // 确保无论成功与否都重置 scanning_strings
        let result = (|| -> Result<()> {
            // 1. Collect READ+WRITE records and reset cancel flag
            let mut accesses: Vec<(u64, u64, u8, u32, StringRw)>;
            {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

                accesses = Vec::new();
                for (addr, rec) in mem_view.iter_all() {
                    if rec.size <= 8 {
                        let rw = if rec.is_write() {
                            StringRw::Write
                        } else {
                            StringRw::Read
                        };
                        accesses.push((addr, rec.data, rec.size, rec.seq, rw));
                    }
                }
            }

            // 2. Sort by seq
            accesses.sort_unstable_by_key(|a| a.3);

            // 3. Reset cancellation flag
            handle.scan_strings_cancel.store(false, Ordering::SeqCst);

            // 4. Run StringBuilder
            let estimated_pages = (accesses.len() / 500).max(1024);
            let mut sb = StringBuilder::with_capacity(estimated_pages);
            for (i, &(addr, data, size, seq, rw)) in accesses.iter().enumerate() {
                if i % 10000 == 0 && handle.scan_strings_cancel.load(Ordering::SeqCst) {
                    return Err(TraceError::Cancelled);
                }
                sb.process_access(addr, data, size, seq, rw);
            }

            // 5. finish + fill_xref_counts
            let mut string_index = sb.finish();
            {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
                StringBuilder::fill_xref_counts_view(&mut string_index, &mem_view);
            }

            // 6. Write results and update cache
            {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                crate::cache::save_string_cache(&state.file_path, &state.mmap, &string_index);
                state.string_index = Some(string_index);
            }

            Ok(())
        })();

        // Always reset scanning_strings
        handle.scanning_strings.store(false, Ordering::SeqCst);

        result
    }

    pub fn cancel_scan_strings(&self, session_id: &str) {
        // Fire-and-forget, silently ignore if session not found
        if let Ok(handle) = self.get_handle(session_id) {
            handle.scan_strings_cancel.store(true, Ordering::SeqCst);
        }
    }
}
