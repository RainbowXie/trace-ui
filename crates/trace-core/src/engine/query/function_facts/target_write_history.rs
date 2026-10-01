//! Raw 普通写历史，既不使用最终 FunctionCallRecord，也不使用零填充索引。
use super::super::activation::{stable_runtime_site, stable_site};
use crate::{
    api_types::*,
    error::{Result, TraceError},
};
use std::collections::BTreeSet;

fn invalid(s: &str) -> TraceError {
    TraceError::InvalidArgument(s.into())
}
fn gap(gaps: &mut Vec<AddressGapDto>, seq: u32, kind: &str) {
    gaps.push(AddressGapDto {
        seq,
        kind: kind.into(),
        detail: "raw observation cannot prove complete target history".into(),
    });
}
#[derive(Clone, Default)]
struct ByteDefinition {
    value: Option<u8>,
    seq: Option<u32>,
    owner: Option<TargetHistoryOwnerDto>,
}
fn snapshot(
    seq: u32,
    phase: &'static str,
    state: &[ByteDefinition],
) -> Result<TargetHistorySnapshotDto> {
    let mut definitions: Vec<TargetHistoryDefinitionRunDto> = Vec::new();
    for (offset, b) in state.iter().enumerate() {
        if let Some(last) = definitions
            .last_mut()
            .filter(|last| last.last_writer_seq == b.seq && last.owner == b.owner)
        {
            last.size += 1;
        } else {
            if definitions.len() >= 32_768 {
                return Err(invalid("snapshot definition capacity"));
            }
            definitions.push(TargetHistoryDefinitionRunDto {
                target_offset: offset as u32,
                size: 1,
                last_writer_seq: b.seq,
                owner: b.owner.clone(),
            });
        }
    }
    Ok(TargetHistorySnapshotDto {
        seq,
        phase,
        bytes: state.iter().map(|b| b.value).collect(),
        definitions,
    })
}
fn formed(s: &TargetHistorySnapshotDto) -> bool {
    s.bytes.iter().all(Option::is_some)
        && s.definitions.iter().all(|d| {
            d.last_writer_seq.is_some() && d.owner.as_ref().is_some_and(|o| o.in_root_closure)
        })
}

impl crate::engine::TraceEngine {
    pub fn get_target_write_history(
        &self,
        sid: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        target_modules: &[String],
        selected: &TargetHistorySelectionDto,
        capture_seq: u32,
    ) -> Result<TargetWriteHistoryDto> {
        let start = selected
            .address
            .strip_prefix("0x")
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| invalid("invalid target address"))?;
        if selected.address != format!("0x{start:x}")
            || selected.size == 0
            || selected.size > 1024 * 1024
        {
            return Err(invalid(
                "target requires canonical address and size 1..1048576",
            ));
        }
        let end = start
            .checked_add(u64::from(selected.size))
            .ok_or_else(|| invalid("target range overflow"))?;
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.len() != target_modules.len() || modules.len() > 500 {
            return Err(invalid("invalid target modules capacity/duplicates"));
        }
        // Existing mapping query validates canonical modules and all observed bases.
        let runtime_mapping = if modules.is_empty() {
            None
        } else {
            Some(self.get_runtime_mapping(sid, call_seq, entry_seq, function, target_modules)?)
        };
        let handle = self.get_handle(sid)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let root = tree
            .activations
            .iter()
            .find(|a| a.id != 0 && a.call_seq == call_seq && a.entry_seq == entry_seq)
            .ok_or_else(|| invalid("root selector not found"))?;
        if root.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= root.exit_seq
                && root.exit_seq < root.resume_seq
                && root.resume_seq < state.total_lines)
        {
            return Err(invalid("root requires closed confirmed boundaries"));
        }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let raw = |seq| -> Result<&str> {
            std::str::from_utf8(
                index
                    .get_line(&state.mmap, seq)
                    .ok_or_else(|| invalid("missing raw line"))?,
            )
            .map_err(|_| invalid("invalid raw UTF8"))
        };
        if stable_site(raw(entry_seq)?).as_deref() != Some(function) {
            return Err(invalid("root function mismatch"));
        }
        for seq in [call_seq, entry_seq, root.exit_seq, root.resume_seq] {
            if stable_runtime_site(raw(seq)?).is_none()
                || trace_parser::strict_memory::instruction_parts(raw(seq)?).is_none()
            {
                return Err(invalid("boundary lacks real instruction site"));
            }
        }
        for seq in [selected.seq, capture_seq] {
            if seq >= state.total_lines
                || stable_runtime_site(raw(seq)?).is_none()
                || trace_parser::strict_memory::instruction_parts(raw(seq)?).is_none()
            {
                return Err(invalid("observation must anchor a real instruction"));
            }
        }
        let mut closure = BTreeSet::from([root.id]);
        let mut pending = vec![root.id];
        let mut gaps = Vec::new();
        while let Some(id) = pending.pop() {
            let a = tree
                .activations
                .iter()
                .find(|a| a.id == id)
                .ok_or_else(|| invalid("closure child missing"))?;
            for child in &a.children_ids {
                if !closure.insert(*child) {
                    return Err(invalid("closure is not a tree"));
                }
                let c = tree
                    .activations
                    .iter()
                    .find(|c| c.id == *child)
                    .ok_or_else(|| invalid("closure child missing"))?;
                if c.parent_id != Some(id)
                    || c.unresolved_reason.is_some()
                    || !(a.entry_seq <= c.call_seq
                        && c.call_seq < c.entry_seq
                        && c.entry_seq <= c.exit_seq
                        && c.exit_seq < c.resume_seq
                        && c.resume_seq <= a.exit_seq)
                {
                    gap(&mut gaps, c.entry_seq, "unconfirmed_closure");
                }
                pending.push(*child);
                if closure.len() > 8192 {
                    return Err(invalid("closure capacity"));
                }
            }
        }
        let caller = tree
            .activations
            .iter()
            .find(|a| Some(a.id) == root.parent_id)
            .filter(|a| {
                a.id != 0
                    && a.unresolved_reason.is_none()
                    && a.entry_seq <= call_seq
                    && root.resume_seq <= a.exit_seq
                    && a.exit_seq < a.resume_seq
                    && a.resume_seq < state.total_lines
            });
        let last = selected.seq.max(capture_seq);
        if selected.seq < entry_seq || capture_seq < entry_seq || last >= state.total_lines {
            return Err(invalid("observation outside trace/root start"));
        }
        if last
            .checked_sub(entry_seq)
            .and_then(|v| v.checked_add(1))
            .is_none_or(|n| n > 50_000)
        {
            return Err(invalid("history line capacity"));
        }
        if last > root.exit_seq {
            if last != root.resume_seq && caller.is_none_or(|a| last > a.exit_seq) {
                gap(&mut gaps, last, "caller_or_time_window_unknown");
            }
            if caller.is_none() {
                gap(&mut gaps, root.resume_seq, "caller_not_closed");
            }
        }
        if selected.rw.is_none() && selected.seq != root.resume_seq {
            gap(&mut gaps, selected.seq, "observation_phase_unknown");
        }
        if capture_seq < selected.seq
            || (capture_seq == selected.seq && selected.rw == Some(TargetObservationRw::Write))
        {
            gap(&mut gaps, capture_seq, "capture_before_formation");
        }
        let mut bytes = vec![ByteDefinition::default(); selected.size as usize];
        let mut writes = Vec::new();
        let mut selected_snapshot = None;
        let mut capture_snapshot = None;
        let mut raw_bytes = 0usize;
        let mut payload_bytes = 0usize;
        let mut access_count = 0usize;
        for seq in entry_seq..=last {
            if seq == capture_seq {
                capture_snapshot = Some(snapshot(seq, "before_instruction", &bytes)?);
            }
            if seq == selected.seq && selected.rw != Some(TargetObservationRw::Write) {
                selected_snapshot = Some(snapshot(seq, "before_instruction", &bytes)?);
            }
            let line = raw(seq)?;
            raw_bytes = raw_bytes
                .checked_add(line.len())
                .ok_or_else(|| invalid("raw capacity overflow"))?;
            if raw_bytes > 32 * 1024 * 1024 || line.len() > 4096 {
                return Err(invalid("history raw capacity"));
            }
            let gaps_before = gaps.len();
            let owner = tree.activation_for_seq(seq);
            let owner_dto = owner.map(|a| TargetHistoryOwnerDto {
                call_seq: a.call_seq,
                entry_seq: a.entry_seq,
                in_root_closure: closure.contains(&a.id),
            });
            if seq == selected.seq
                && selected.rw.is_some()
                && !owner.is_some_and(|a| closure.contains(&a.id) && a.unresolved_reason.is_none())
            {
                gap(&mut gaps, seq, "selected_owner_outside_closure");
            }
            let owner_allowed = owner.is_some_and(|a| {
                a.unresolved_reason.is_none()
                    && (closure.contains(&a.id)
                        || (seq >= root.resume_seq && caller.is_some_and(|c| c.id == a.id)))
            });
            // A boundary instruction is needed to validate a before-state, but its
            // effects are irrelevant unless either requested snapshot is after it.
            let affects = seq < last
                || (seq == selected.seq && selected.rw == Some(TargetObservationRw::Write));
            if !owner_allowed && affects {
                gap(&mut gaps, seq, "raw_owner_unknown");
            }
            let parts = trace_parser::strict_memory::instruction_parts(line);
            let parsed = if line.contains("!0x") {
                trace_parser::gumtrace::parse_line_gumtrace_full(line)
            } else {
                trace_parser::parser::parse_line_full(line)
            };
            let (Some((mnemonic, operand)), Some(parsed)) = (parts, parsed) else {
                if affects {
                    gap(&mut gaps, seq, "raw_instruction_unknown");
                    bytes.fill(ByteDefinition::default());
                }
                continue;
            };
            if stable_runtime_site(line).is_none() && affects {
                gap(&mut gaps, seq, "raw_site_unknown");
            }
            let class = trace_parser::insn_class::classify_and_refine(&parsed);
            use trace_parser::insn_class::InsnClass;
            let memory_class = matches!(
                class,
                InsnClass::LoadReg
                    | InsnClass::LoadPair
                    | InsnClass::StoreReg
                    | InsnClass::StorePair
                    | InsnClass::StoreExcl
                    | InsnClass::AtomicLoadOp
                    | InsnClass::CompareAndSwap
            );
            let mem = trace_parser::strict_memory::memory_op(line);
            let has_marker =
                line.contains("mem_w=") || line.contains("mem_r=") || line.contains("abs=");
            if affects && (memory_class || has_marker || operand.contains('[')) && mem.is_none() {
                gap(&mut gaps, seq, "memory_effect_unobserved");
            }
            if affects
                && (matches!(
                    class,
                    InsnClass::Svc
                        | InsnClass::SysRegWrite
                        | InsnClass::BranchReg
                        | InsnClass::Branch
                ) || (matches!(class, InsnClass::Nop) && mnemonic != "nop"))
            {
                gap(&mut gaps, seq, "unsupported_instruction_effect");
            }
            if affects
                && (matches!(mnemonic, "bl" | "blr")
                    && !tree
                        .activations
                        .iter()
                        .any(|a| a.id != 0 && a.call_seq == seq && a.unresolved_reason.is_none()))
            {
                gap(&mut gaps, seq, "external_effect_unobserved");
            }
            if affects
                && state.call_annotations.contains_key(&seq)
                && !tree
                    .activations
                    .iter()
                    .any(|a| a.id != 0 && a.call_seq == seq && a.unresolved_reason.is_none())
            {
                gap(&mut gaps, seq, "external_effect_unobserved");
            }
            // Unobserved effects may overwrite any target byte: no stale value
            // survives a gap merely because no mem marker was printed.
            if affects && gaps.len() != gaps_before {
                bytes.fill(ByteDefinition::default());
            }
            if let Some(mem) = mem {
                access_count += 1;
                let size = u32::from(mem.elem_width)
                    .checked_mul(u32::from(mem.value_count))
                    .ok_or_else(|| invalid("write width overflow"))?;
                let limit = mem
                    .abs
                    .checked_add(u64::from(size))
                    .ok_or_else(|| invalid("write address overflow"))?;
                if seq == selected.seq && selected.rw.is_some() {
                    let write = selected.rw == Some(TargetObservationRw::Write);
                    if mem.is_write != write || mem.abs > start || limit < end {
                        gap(&mut gaps, seq, "selected_occurrence_mismatch");
                    }
                    if !write && mem.abs <= start && end <= limit {
                        let observed = crate::memory_search::expand_mem_op(&mem);
                        if (start..end).any(|a| {
                            observed.get((a - mem.abs) as usize).is_some_and(|v| {
                                v.known
                                    && bytes[(a - start) as usize]
                                        .value
                                        .is_some_and(|b| b != v.value)
                            })
                        }) {
                            gap(&mut gaps, seq, "selected_read_conflicts_with_history");
                            bytes.fill(ByteDefinition::default());
                        }
                    }
                }
                if mem.is_write && affects && mem.abs < end && start < limit {
                    let values = crate::memory_search::expand_mem_op(&mem);
                    if values.is_empty()
                        && seq == selected.seq
                        && selected.rw == Some(TargetObservationRw::Write)
                    {
                        gap(&mut gaps, seq, "selected_write_has_no_effect");
                    }
                    if !values.is_empty() {
                        if values.len() != size as usize {
                            gap(&mut gaps, seq, "write_width_unknown");
                        }
                        let lo = start.max(mem.abs);
                        let hi = end.min(limit);
                        let count = (hi - lo) as usize;
                        payload_bytes = payload_bytes
                            .checked_add(count)
                            .ok_or_else(|| invalid("write payload overflow"))?;
                        if writes.len() >= 8192 || payload_bytes > 4 * 1024 * 1024 {
                            return Err(invalid("history write capacity"));
                        }
                        let clipped = (lo..hi)
                            .map(|a| {
                                values
                                    .get((a - mem.abs) as usize)
                                    .and_then(|v| v.known.then_some(v.value))
                            })
                            .collect::<Vec<_>>();
                        for (i, value) in clipped.iter().enumerate() {
                            bytes[(lo - start) as usize + i] = ByteDefinition {
                                value: *value,
                                seq: Some(seq),
                                owner: owner_dto.clone(),
                            };
                        }
                        writes.push(TargetHistoryWriteDto {
                            seq,
                            owner: owner_dto.clone(),
                            address: format!("0x{:x}", mem.abs),
                            size,
                            target_offset: (lo - start) as u32,
                            write_offset: (lo - mem.abs) as u32,
                            bytes: clipped,
                            effect: TargetHistoryEffectDto {
                                seq,
                                phase: "after_instruction",
                            },
                        });
                    }
                }
            } else if seq == selected.seq && selected.rw.is_some() {
                gap(&mut gaps, seq, "selected_occurrence_unobserved");
            }
            if seq == selected.seq && selected.rw == Some(TargetObservationRw::Write) {
                selected_snapshot = Some(snapshot(seq, "after_instruction", &bytes)?);
            }
        }
        let selected_snapshot =
            selected_snapshot.ok_or_else(|| invalid("selected snapshot unavailable"))?;
        let capture_snapshot =
            capture_snapshot.ok_or_else(|| invalid("capture snapshot unavailable"))?;
        if !formed(&selected_snapshot) {
            gap(&mut gaps, selected.seq, "selected_definition_incomplete");
        }
        if !formed(&capture_snapshot) {
            gap(&mut gaps, capture_seq, "capture_definition_incomplete");
        }
        // Keep memory bounded before serialization: a pathological alternating
        // writer per byte must fail, not allocate an unbounded JSON producer map.
        if selected_snapshot.definitions.len() + capture_snapshot.definitions.len() > 65_536 {
            return Err(invalid("snapshot definition capacity"));
        }
        Ok(TargetWriteHistoryDto {
            trace_session: sid.into(),
            call_seq,
            entry_seq,
            function: function.into(),
            exit_seq: root.exit_seq,
            resume_seq: root.resume_seq,
            selected: selected.clone(),
            capture_seq,
            runtime_mapping,
            writes,
            selected_snapshot,
            capture_snapshot,
            coverage: AddressCoverageDto {
                first_seq: entry_seq,
                last_seq: last,
                scanned_lines: last - entry_seq + 1,
                access_count,
                complete: gaps.is_empty(),
            },
            gaps,
        })
    }
}
