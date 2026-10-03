//! Bounded production fact generation; legacy graph/provenance collectors remain independent.
use super::super::activation::stable_site;
use super::{
    block_stream::{scan_owned, stream_executed_blocks},
    budget::{Budget, FunctionFactContext},
    collector, lines, memory_stream,
};
use crate::api_types::*;
use crate::error::{Result, TraceError};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

fn validate(context: FunctionFactContext<'_>) -> Result<()> {
    let source = context.trace;
    if source != context.activation.trace
        || source.artifact.is_empty()
        || source.artifact.starts_with('/')
        || source.artifact.contains('\\')
        || !source.artifact.ends_with(".json")
        || source
            .artifact
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || source.artifact.chars().any(char::is_control)
        || (!source.pointer.is_empty() && !source.pointer.starts_with('/'))
    {
        return Err(TraceError::InvalidArgument(
            "invalid function fact context source".into(),
        ));
    }
    let mut pointer = source.pointer.bytes();
    while let Some(byte) = pointer.next() {
        if byte == b'~' && !matches!(pointer.next(), Some(b'0' | b'1')) {
            return Err(TraceError::InvalidArgument(
                "invalid function fact JSON pointer".into(),
            ));
        }
    }
    Ok(())
}

impl crate::engine::TraceEngine {
    /// Generate a complete legacy wire DTO while reserving its formal temporary
    /// bundle projection (trace, activation, anchors; no top-level function).
    /// Source/FD binding must be verified by the caller. No caller-selected quota.
    /// Three independent fixed-layout working areas are capped at 8 MiB each;
    /// exhaustion is an Internal resource error, not logical bundle overflow.
    /// Raw lines entering this path have a separate 1 MiB parser resource bound
    /// (after CR/LF stripping). The retained trace must remain immutable.
    /// This does not bound the session's existing full dependency index build.
    pub fn get_function_facts_bounded(
        &self,
        session_id: &str,
        context: FunctionFactContext<'_>,
        target_modules: &[String],
        cancel: &AtomicBool,
    ) -> Result<FunctionFactBundleDto> {
        self.build_function_facts_bounded(
            session_id,
            context,
            target_modules,
            cancel,
            super::budget::FACT_BUNDLE_LIMIT,
        )
    }

    pub(super) fn build_function_facts_bounded(
        &self,
        session_id: &str,
        context: FunctionFactContext<'_>,
        target_modules: &[String],
        cancel: &AtomicBool,
        logical_limit: u64,
    ) -> Result<FunctionFactBundleDto> {
        validate(context)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let selector = context.activation;
        let root = tree
            .activations
            .iter()
            .find(|a| a.call_seq == selector.call_seq && a.entry_seq == selector.entry_seq)
            .ok_or_else(|| {
                TraceError::InvalidArgument("function fact selector not found".into())
            })?;
        if root.id == 0
            || root.unresolved_reason.is_some()
            || !(root.call_seq < root.entry_seq
                && root.entry_seq <= root.exit_seq
                && root.exit_seq < root.resume_seq
                && root.resume_seq < state.total_lines)
        {
            return Err(TraceError::InvalidArgument(
                "function facts require closed Confirmed Activation".into(),
            ));
        }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let site = |seq| -> Result<String> {
            let raw = index
                .get_line(&state.mmap, seq)
                .ok_or_else(|| TraceError::InvalidArgument("fact boundary missing".into()))?;
            super::block_stream::check_raw(raw)?;
            let line =
                std::str::from_utf8(raw).map_err(|e| TraceError::InvalidArgument(e.to_string()))?;
            if trace_parser::strict_memory::instruction_parts(line).is_none() {
                return Err(TraceError::InvalidArgument(
                    "fact boundary lacks instruction".into(),
                ));
            }
            stable_site(line).ok_or_else(|| {
                TraceError::InvalidArgument("fact boundary lacks stable site".into())
            })
        };
        let function = site(root.entry_seq)?;
        if function != selector.function {
            return Err(TraceError::InvalidArgument("fact function mismatch".into()));
        }
        // Context strings remain borrowed even when oversized: count before cloning.
        let mut entry = super::replay::registers_at(&state, root.entry_seq, cancel)?;
        let resume = super::replay::registers_at(&state, root.resume_seq, cancel)?;
        if entry[31] == u64::MAX {
            if let Some(sp) = index
                .get_line(&state.mmap, root.entry_seq)
                .and_then(|r| std::str::from_utf8(r).ok())
                .and_then(|line| lines::prestate_register_value(line, "sp"))
            {
                entry[31] = sp;
            }
        }
        let mut dto = FunctionFactBundleDto {
            function,
            trace_anchors: FunctionTraceAnchorsDto {
                call: FunctionAnchorDto {
                    seq: root.call_seq,
                    offset: site(root.call_seq)?,
                },
                entry: FunctionAnchorDto {
                    seq: root.entry_seq,
                    offset: selector.function.into(),
                },
                exit: FunctionAnchorDto {
                    seq: root.exit_seq,
                    offset: site(root.exit_seq)?,
                },
                resume: FunctionAnchorDto {
                    seq: root.resume_seq,
                    offset: site(root.resume_seq)?,
                },
            },
            abi: FunctionAbiDto {
                entry_sp: super::known_register(&entry, 31),
                arguments: (0..8)
                    .map(|r| (format!("X{r}"), super::known_register(&entry, r)))
                    .collect(),
                stack_arguments: Vec::new(),
                returns: BTreeMap::from([("X0".into(), super::known_register(&resume, 0))]),
            },
            executed_block_sequence: Vec::new(),
            memory_reads: Vec::new(),
            global_reads: Vec::new(),
            memory_writes: Vec::new(),
            global_writes: Vec::new(),
            external_call_events: Vec::new(),
            unresolved: Vec::new(),
        };
        let mut budget = Budget::with_limit(context, &dto, logical_limit)?;
        super::global_stream::validate_mappings(&state, target_modules, cancel)?;
        stream_executed_blocks(&state, tree, root, cancel, |block, entry_seq| {
            #[derive(serde::Serialize)]
            struct Preview<'a> {
                block: &'a str,
                entry_seq: u32,
            }
            budget.item(
                &Preview { block, entry_seq },
                2,
                dto.executed_block_sequence.is_empty(),
            )?;
            collector::reserve_vec(&mut dto.executed_block_sequence)?;
            dto.executed_block_sequence.push(ExecutedBlockEntryDto {
                block: block.into(),
                entry_seq,
            });
            Ok(())
        })?;
        if entry[31] != u64::MAX {
            dto.abi.stack_arguments =
                super::stack_stream::collect(&state, tree, root, entry[31], cancel, &mut budget)?;
        }
        let cells = memory_stream::final_bytes(&state, tree, root, cancel)?;
        let relevant = memory_stream::relevant(&state, tree, root, cancel)?;
        let is_relevant = |seq| {
            relevant
                .as_ref()
                .is_none_or(|r| r.values.binary_search_by_key(&seq, |d| d.seq).is_ok())
        };
        // Only proved static immediate sources with complete dependency coverage
        // and an owned block occurrence can omit their source gap. Other gaps
        // remain unchanged; the retained block list was budgeted above.
        scan_owned(&state, tree, root, cancel, |insn| {
            let annotated = ["mem_w=", "mem_r=", "mem[WRITE]", "mem[READ]"]
                .iter()
                .any(|m| insn.line.contains(m));
            if annotated && trace_parser::strict_memory::memory_marker(insn.line).is_none() {
                collector::unresolved(
                    &mut dto.unresolved,
                    &mut budget,
                    "unsupported_instruction",
                    std::iter::once(insn.seq),
                    None,
                    "访存地址或读写注记畸形/冲突，拒绝该访存事实",
                )?;
            }
            if let Some((m, _op)) = trace_parser::strict_memory::instruction_parts(insn.line) {
                if super::immediate::candidate(insn.line)
                    && super::immediate_gap(
                        tree,
                        root,
                        &dto.executed_block_sequence,
                        relevant.as_ref(),
                        state.pair_split_view().is_some(),
                        insn.seq,
                        insn.line,
                    )
                {
                    collector::unresolved(
                        &mut dto.unresolved,
                        &mut budget,
                        "unsupported_instruction",
                        std::iter::once(insn.seq),
                        None,
                        "immediate source grammar, ownership, block or dependency coverage incomplete",
                    )?;
                }
                if let Some(effect) = memory_stream::effect(insn.line) {
                    match effect {
                        memory_stream::Effect::Block { address, .. } => collector::unresolved(
                            &mut dto.unresolved,
                            &mut budget,
                            "unsupported_instruction",
                            std::iter::once(insn.seq),
                            Some(&format!("0x{address:x}")),
                            &format_args!("{m} 写入访存宽度未覆盖，已保守阻断后续读取并记录缺口"),
                        )?,
                        memory_stream::Effect::Applied { address, size, .. }
                            if address.checked_add(size as u64 - 1).is_none() =>
                        {
                            collector::unresolved(
                                &mut dto.unresolved,
                                &mut budget,
                                "unsupported_instruction",
                                std::iter::once(insn.seq),
                                Some(&format!("0x{address:x}")),
                                &format_args!("{m} 写入访存地址加宽度溢出，拒绝该写入事实"),
                            )?
                        }
                        _ => {}
                    }
                }
            }
            Ok(true)
        })?;
        // The closure above releases mutable access before read materialization.
        scan_owned(&state, tree, root, cancel, |insn| {
            let Some((m, op)) = trace_parser::strict_memory::instruction_parts(insn.line) else {
                return Ok(true);
            };
            let Some(address) = lines::line_mem_annotation(insn.line, "mem_r") else {
                return Ok(true);
            };
            let Some(size) = lines::access_width(m, op) else {
                if is_relevant(insn.seq) {
                    collector::unresolved(
                        &mut dto.unresolved,
                        &mut budget,
                        "unsupported_instruction",
                        std::iter::once(insn.seq),
                        Some(&format!("0x{address:x}")),
                        &format_args!("{m} 访存宽度未覆盖，无法产出读取事实"),
                    )?;
                }
                return Ok(true);
            };
            if trace_parser::strict_memory::memory_op(insn.line).is_none() {
                if is_relevant(insn.seq) {
                    collector::unresolved(
                        &mut dto.unresolved,
                        &mut budget,
                        "unsupported_instruction",
                        std::iter::once(insn.seq),
                        Some(&format!("0x{address:x}")),
                        "访存操作数或读写方向未能严格确定，拒绝该读取事实",
                    )?;
                }
                return Ok(true);
            }
            if is_relevant(insn.seq) && address.checked_add(size as u64 - 1).is_none() {
                collector::unresolved(
                    &mut dto.unresolved,
                    &mut budget,
                    "unsupported_instruction",
                    std::iter::once(insn.seq),
                    Some(&format!("0x{address:x}")),
                    "访存地址加宽度溢出，拒绝该读取事实",
                )?;
            }
            Ok(true)
        })?;
        super::read_stream::collect(
            &state,
            tree,
            root,
            cancel,
            &relevant,
            entry[31],
            target_modules,
            &mut dto,
            &mut budget,
        )?;
        collector::writes(
            &state,
            tree,
            root,
            cancel,
            target_modules,
            &mut dto,
            &mut budget,
            &cells.values,
        )?;
        drop(cells);
        drop(relevant);
        super::event_stream::collect(
            &state,
            tree,
            root,
            cancel,
            &mut dto.external_call_events,
            &mut budget,
        )?;
        dto.unresolved.sort_unstable_by(|a, b| {
            a.seqs
                .cmp(&b.seqs)
                .then(a.kind.cmp(&b.kind))
                .then(a.detail.cmp(&b.detail))
        });
        budget.verify(context, &dto)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        Ok(dto)
    }
}
