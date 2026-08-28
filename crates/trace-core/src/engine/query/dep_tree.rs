//! 依赖树与 DEF/USE 查询方法：build_dep_tree / build_dep_tree_from_slice /
//! get_line_def_registers / get_def_use_chain。

use crate::api_types::*;
use crate::error::{Result, TraceError};
use trace_parser::types::{parse_reg, RegId, TraceFormat};
use trace_parser::{def_use, gumtrace as gumtrace_parser, insn_class, parser};

// ── DEF/USE helpers ──

const MAX_SCAN_RANGE: u32 = 50000;

// ── Dep tree constants ──

const DEFAULT_MAX_NODES: u32 = 10_000;

fn parse_line_for_format(
    line: &str,
    format: TraceFormat,
) -> Option<trace_parser::types::ParsedLine> {
    match format {
        TraceFormat::Unidbg => parser::parse_line(line),
        TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line),
    }
}

impl crate::engine::TraceEngine {
    pub fn build_dep_tree(
        &self,
        session_id: &str,
        seq: u32,
        target: &str,
        options: DepTreeOptions,
    ) -> Result<crate::query::dep_tree::DependencyGraph> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let format = state.trace_format;
        let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        let spec = if target.starts_with("mem:") {
            format!("{}@{}", target, seq + 1)
        } else {
            let reg_name = target.strip_prefix("reg:").unwrap_or(target);
            format!("reg:{}@{}", reg_name, seq + 1)
        };

        let reg_last_def = state
            .reg_last_def
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let mem_last_def = state.mem_last_def_view().ok_or(TraceError::IndexNotReady)?;

        let max_nodes = options.max_nodes.unwrap_or(DEFAULT_MAX_NODES);
        let start_idx = crate::engine::slice::resolve_start_index(
            &spec,
            reg_last_def,
            &mem_last_def,
            &state.mmap,
            &lidx_view,
            format,
        )
        .map_err(TraceError::InvalidArgument)?;

        let scan_view = state.scan_view().ok_or(TraceError::IndexNotReady)?;

        let mut graph = crate::query::dep_tree::build_graph(
            &scan_view,
            start_idx,
            options.data_only,
            max_nodes,
        );
        crate::query::dep_tree::populate_graph_info(&mut graph, &state.mmap, &lidx_view, format);
        Ok(graph)
    }

    pub fn build_dep_tree_from_slice(
        &self,
        session_id: &str,
        options: DepTreeOptions,
    ) -> Result<crate::query::dep_tree::DependencyGraph> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let origin = state.slice_origin.as_ref().ok_or_else(|| {
            TraceError::InvalidArgument(
                "No active taint analysis result, please run taint tracking first".to_string(),
            )
        })?;
        let spec = origin.from_specs.first().ok_or_else(|| {
            TraceError::InvalidArgument("No from_specs in SliceOrigin".to_string())
        })?;
        let data_only = options.data_only || origin.data_only;
        let max_nodes = options.max_nodes.unwrap_or(DEFAULT_MAX_NODES);

        let reg_last_def = state
            .reg_last_def
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let mem_last_def = state.mem_last_def_view().ok_or(TraceError::IndexNotReady)?;
        let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        let start_idx = crate::engine::slice::resolve_start_index(
            spec,
            reg_last_def,
            &mem_last_def,
            &state.mmap,
            &lidx_view,
            format,
        )
        .map_err(TraceError::InvalidArgument)?;

        let scan_view = state.scan_view().ok_or(TraceError::IndexNotReady)?;

        let mut graph =
            crate::query::dep_tree::build_graph(&scan_view, start_idx, data_only, max_nodes);
        crate::query::dep_tree::populate_graph_info(&mut graph, &state.mmap, &lidx_view, format);
        Ok(graph)
    }

    pub fn get_line_def_registers(&self, session_id: &str, seq: u32) -> Result<Vec<String>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        if let Some(raw) = lidx_view.get_line(&state.mmap, seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(ref p) = parsed {
                    let cls = insn_class::classify_and_refine(p);
                    let (defs, _) = def_use::determine_def_use(cls, p);
                    return Ok(defs.iter().map(|r| format!("{:?}", r)).collect());
                }
            }
        }
        Ok(vec![])
    }

    pub fn get_def_use_chain(&self, session_id: &str, seq: u32, reg: &str) -> Result<DefUseChain> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let target_reg = parse_reg(reg)
            .ok_or_else(|| TraceError::InvalidArgument(format!("未知寄存器: {}", reg)))?;

        let total = state.total_lines;
        let format = state.trace_format;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        // === 分析 anchor 行：判断 target_reg 在当前行是 DEF 还是 USE ===
        let mut anchor_is_use = false;
        let mut anchor_is_def = false;
        if let Some(raw) = line_index.get_line(&state.mmap, seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                if let Some(parsed) = parse_line_for_format(line_str, format) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (defs, uses) = def_use::determine_def_use(cls, &parsed);
                    anchor_is_def = defs.contains(&target_reg);
                    anchor_is_use = uses.contains(&target_reg);
                }
            }
        }

        // === 向上扫描：仅当 anchor 行 USE 了该寄存器时才查找上游 DEF ===
        let mut def_seq: Option<u32> = None;
        if anchor_is_use && seq > 0 {
            let scan_start = seq.saturating_sub(MAX_SCAN_RANGE);
            for s in (scan_start..seq).rev() {
                if let Some(raw) = line_index.get_line(&state.mmap, s) {
                    if let Ok(line_str) = std::str::from_utf8(raw) {
                        if let Some(parsed) = parse_line_for_format(line_str, format) {
                            let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                            let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                            let (defs, _) = def_use::determine_def_use(cls, &parsed);
                            if defs.contains(&target_reg) {
                                def_seq = Some(s);
                                break;
                            }
                        } else if format == TraceFormat::Gumtrace
                            && target_reg == RegId::X0
                            && matches!(
                                gumtrace_parser::parse_special_line(line_str),
                                Some(gumtrace_parser::SpecialLine::Ret { .. })
                            )
                        {
                            def_seq = Some(s);
                            break;
                        }
                    }
                }
            }
        }

        // === 向下扫描：仅当 anchor 行 DEF 了该寄存器时才收集下游 USE ===
        let mut use_seqs: Vec<u32> = Vec::new();
        let mut redefined_seq: Option<u32> = None;
        if anchor_is_def {
            let scan_end = total.min(seq + MAX_SCAN_RANGE);
            for s in (seq + 1)..scan_end {
                if let Some(raw) = line_index.get_line(&state.mmap, s) {
                    if let Ok(line_str) = std::str::from_utf8(raw) {
                        if let Some(parsed) = parse_line_for_format(line_str, format) {
                            let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                            let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                            let (defs, uses) = def_use::determine_def_use(cls, &parsed);

                            // 先检查 USE（同一行可能既 USE 又 DEF，如 add x0, x0, #1）
                            if uses.contains(&target_reg) {
                                use_seqs.push(s);
                            }

                            // 再检查 DEF（重新定义 = 扫描终点）
                            if defs.contains(&target_reg) {
                                redefined_seq = Some(s);
                                break;
                            }
                        } else if format == TraceFormat::Gumtrace
                            && target_reg == RegId::X0
                            && matches!(
                                gumtrace_parser::parse_special_line(line_str),
                                Some(gumtrace_parser::SpecialLine::Ret { .. })
                            )
                        {
                            redefined_seq = Some(s);
                            break;
                        }
                    }
                }
            }
        }

        Ok(DefUseChain {
            def_seq,
            use_seqs,
            redefined_seq,
        })
    }
}
