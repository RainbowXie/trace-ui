//! Root execution-before entry through execution-after exit, including callees.
//! Only concrete operand-labelled copy/fixed arithmetic is propagated.
use super::super::activation::{stable_runtime_site, stable_site};
use super::{
    abi::collect_stack_arguments, blocks::OwnedInsn, global_map::StableGlobalMap, lines,
    registers_at,
};
use crate::api_types::*;
use crate::error::{Result, TraceError};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use trace_parser::types::{ParsedLine, RegId};

const MAX_LINES: u32 = 50_000;
const MAX_RAW: usize = 32 * 1024 * 1024;
const MAX_ACCESSES: usize = 8192;
// Together with operand/line/access bounds these cap candidate DTO allocation;
// the helper independently encodes the entire response under its 64 MiB limit.
const MAX_STEPS: usize = 8192;
const MAX_CHAIN: usize = 128;
fn invalid(text: &str) -> TraceError {
    TraceError::InvalidArgument(text.into())
}
fn hex(value: u64) -> String {
    format!("0x{value:x}")
}
#[derive(Clone)]
struct Proof {
    value: u64,
    delta: i64,
    anchor: AddressOriginDto,
    steps: Vec<AddressDefinitionStepDto>,
}
fn values(parsed: &ParsedLine, reg: RegId, post: bool) -> Option<u64> {
    let list = if post {
        &parsed.post_arrow_regs
    } else {
        &parsed.pre_arrow_regs
    };
    let mut matches = list
        .as_ref()?
        .iter()
        .filter(|(id, _)| *id == reg)
        .map(|(_, v)| *v);
    let value = matches.next()?;
    matches.all(|other| other == value).then_some(value)
}
fn immediate(text: &str) -> Option<i64> {
    let text = text.strip_prefix('#')?;
    let (negative, number) = text.strip_prefix('-').map_or((false, text), |s| (true, s));
    let value = if let Some(s) = number.strip_prefix("0x") {
        i64::from_str_radix(s, 16).ok()?
    } else {
        number.parse().ok()?
    };
    if negative {
        value.checked_neg()
    } else {
        Some(value)
    }
}
fn offset_operand(text: &str) -> Option<(&str, i64)> {
    let start = text.find('[')?;
    let end = text[start..].find(']')? + start;
    if !text[end + 1..].trim().is_empty() {
        return None;
    } // writeback stays a gap
    let parts = text[start + 1..end]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [base] => Some((base, 0)),
        [base, off] => Some((base, immediate(off)?)),
        _ => None,
    }
}
fn reg64(text: &str) -> Option<RegId> {
    if text.starts_with('w') {
        return None;
    }
    let reg = trace_parser::types::parse_reg(text)?;
    (reg.0 <= 31 && !reg.is_zero()).then_some(reg)
}
fn add(value: u64, delta: i64) -> Option<u64> {
    value.checked_add_signed(delta)
}
fn gap(gaps: &mut Vec<AddressGapDto>, seq: u32, kind: &str, detail: &str) {
    gaps.push(AddressGapDto {
        seq,
        kind: kind.into(),
        detail: detail.into(),
    });
}
impl crate::engine::TraceEngine {
    pub fn get_address_provenance(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        target_modules: &[String],
    ) -> Result<AddressProvenanceDto> {
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.len() != target_modules.len()
            || modules.len() > 500
            || modules.iter().any(|m| {
                stable_site(&format!("[{m}] 0x0!0x0 nop")).as_deref() != Some(&format!("{m}+0x0"))
            })
        {
            return Err(invalid("invalid or duplicate target_modules"));
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
        let root = tree
            .activations
            .iter()
            .find(|a| a.call_seq == call_seq && a.entry_seq == entry_seq)
            .ok_or_else(|| invalid("address provenance selector not found"))?;
        if root.id == 0
            || root.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= root.exit_seq
                && root.exit_seq < root.resume_seq
                && root.resume_seq < state.total_lines)
        {
            return Err(invalid(
                "address provenance requires closed Confirmed Activation",
            ));
        }
        let count = root
            .exit_seq
            .checked_sub(entry_seq)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| invalid("window overflow"))?;
        if count > MAX_LINES {
            return Err(invalid(
                "address provenance line capacity exceeded; no partial coverage",
            ));
        }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let raw_line = |seq| -> Result<&str> {
            std::str::from_utf8(
                index
                    .get_line(&state.mmap, seq)
                    .ok_or_else(|| invalid("missing raw line"))?,
            )
            .map_err(|_| invalid("invalid raw UTF8"))
        };
        for seq in [call_seq, entry_seq, root.exit_seq, root.resume_seq] {
            let raw = raw_line(seq)?;
            if trace_parser::strict_memory::instruction_parts(raw).is_none()
                || stable_runtime_site(raw).is_none()
            {
                return Err(invalid("boundary lacks real instruction site"));
            }
            if seq == entry_seq && stable_site(raw).as_deref() != Some(function) {
                return Err(invalid("function site mismatch"));
            }
        }
        let global_map = StableGlobalMap::collect(&state, target_modules)?;
        let mut owned = Vec::new();
        let mut raw_bytes = 0usize;
        for seq in entry_seq..=root.exit_seq {
            let raw = raw_line(seq)?;
            if raw.len() > 4096 {
                return Err(invalid("address provenance per-line capacity exceeded"));
            }
            raw_bytes = raw_bytes
                .checked_add(raw.len())
                .ok_or_else(|| invalid("raw capacity overflow"))?;
            if raw_bytes > MAX_RAW {
                return Err(invalid("address provenance raw capacity exceeded"));
            }
            if let Some((mnemonic, operand)) = trace_parser::strict_memory::instruction_parts(raw) {
                if operand.len() > 512 {
                    return Err(invalid("address provenance operand capacity exceeded"));
                }
                owned.push(OwnedInsn {
                    seq,
                    site: stable_site(raw).unwrap_or_default(),
                    transfer: false,
                    line: raw.into(),
                    mnemonic: Some(mnemonic.into()),
                    first_operand: Some(operand.into()),
                });
            }
        }
        let entry = registers_at(&state, entry_seq)?;
        let entry_sp = (entry[31] != u64::MAX)
            .then_some(entry[31])
            .or_else(|| lines::prestate_register_value(raw_line(entry_seq).ok()?, "sp"));
        let root_owned = owned
            .iter()
            .filter(|i| {
                tree.activation_for_seq(i.seq)
                    .is_some_and(|a| a.id == root.id)
            })
            .map(|i| OwnedInsn {
                seq: i.seq,
                site: i.site.clone(),
                transfer: i.transfer,
                line: i.line.clone(),
                mnemonic: i.mnemonic.clone(),
                first_operand: i.first_operand.clone(),
            })
            .collect::<Vec<_>>();
        let slots = entry_sp
            .map(|sp| collect_stack_arguments(&root_owned, sp))
            .unwrap_or_default();
        let mut proofs = HashMap::<RegId, Proof>::new();
        for reg in 0..8 {
            if entry[reg] != u64::MAX {
                proofs.insert(
                    RegId(reg as u8),
                    Proof {
                        value: entry[reg],
                        delta: 0,
                        anchor: AddressOriginDto::AbiRegister {
                            seq: entry_seq,
                            register: format!("x{reg}"),
                            value: hex(entry[reg]),
                        },
                        steps: vec![],
                    },
                );
            }
        }
        if let Some(sp) = entry_sp {
            proofs.insert(
                RegId::SP,
                Proof {
                    value: sp,
                    delta: 0,
                    anchor: AddressOriginDto::EntrySp {
                        seq: entry_seq,
                        value: hex(sp),
                    },
                    steps: vec![],
                },
            );
        }
        // Lookup sets avoid rescanning every call boundary for each raw line.
        let unresolved_calls = tree
            .activations
            .iter()
            .filter(|a| a.id != root.id && a.unresolved_reason.is_some())
            .map(|a| a.call_seq)
            .collect::<BTreeSet<_>>();
        let external_calls = tree
            .bypassed_calls
            .iter()
            .map(|c| c.call_seq)
            .collect::<BTreeSet<_>>();
        let mut accesses = Vec::new();
        let mut gaps = Vec::new();
        let mut steps_total = 0usize;
        let mut prior_writes = Vec::<(u64, u32)>::new();
        let mut unknown_effect = false;
        let positions = owned
            .iter()
            .enumerate()
            .map(|(n, i)| (i.seq, n))
            .collect::<BTreeMap<_, _>>();
        for seq in entry_seq..=root.exit_seq {
            let raw = raw_line(seq)?;
            if unresolved_calls.contains(&seq) {
                gap(
                    &mut gaps,
                    seq,
                    "unconfirmed_callee",
                    "nested call has unresolved ownership or boundary",
                );
                proofs.clear();
                unknown_effect = true;
            }
            let Some(&position) = positions.get(&seq) else {
                gap(
                    &mut gaps,
                    seq,
                    "unsupported_line",
                    "special or unparsed line may hide effects",
                );
                proofs.clear();
                unknown_effect = true;
                continue;
            };
            let insn = &owned[position];
            let mnemonic = insn.mnemonic.as_deref().unwrap();
            let operand = insn.first_operand.as_deref().unwrap();
            let owner = tree.activation_for_seq(seq);
            if owner.is_none_or(|a| a.entry_seq < entry_seq || a.exit_seq > root.exit_seq) {
                gap(
                    &mut gaps,
                    seq,
                    "ownership",
                    "instruction lacks confirmed root-closure owner",
                );
                proofs.clear();
                unknown_effect = true;
            }
            let parsed = if raw.contains("!0x") {
                trace_parser::gumtrace::parse_line_gumtrace_full(raw)
            } else {
                trace_parser::parser::parse_line_full(raw)
            };
            let Some(parsed) = parsed else {
                gap(
                    &mut gaps,
                    seq,
                    "unsupported_parse",
                    "strict instruction lacks ParsedLine",
                );
                proofs.clear();
                unknown_effect = true;
                continue;
            };
            let marker = trace_parser::strict_memory::memory_marker(raw);
            let mem = trace_parser::strict_memory::memory_op(raw);
            let class = trace_parser::insn_class::classify_and_refine(&parsed);
            let (defs, _) = trace_parser::def_use::determine_def_use(class, &parsed);
            let parts = operand.split(',').map(str::trim).collect::<Vec<_>>();
            let mut loaded_stack = None;
            if let Some((write, address)) = marker {
                if accesses.len() >= MAX_ACCESSES {
                    return Err(invalid("address provenance access capacity exceeded"));
                }
                let size = mem
                    .as_ref()
                    .map(|m| u32::from(m.elem_width) * u32::from(m.value_count));
                let mut proof = None;
                if mem
                    .as_ref()
                    .is_some_and(|m| m.exclusive_status.is_some_and(|s| s != 0))
                {
                    gap(
                        &mut gaps,
                        seq,
                        "exclusive_no_effect",
                        "printed store marker does not prove a successful access",
                    );
                }
                if let Some((base, offset)) = offset_operand(operand) {
                    if let Some(reg) = reg64(base) {
                        if parsed.base_reg == Some(reg) {
                            if let Some(p) = proofs.get(&reg) {
                                if values(&parsed, reg, false) == Some(p.value)
                                    && add(p.value, offset) == Some(address)
                                    && p.delta.checked_add(offset).is_some()
                                {
                                    let mut p = p.clone();
                                    p.delta = p.delta.checked_add(offset).unwrap();
                                    p.steps.push(AddressDefinitionStepDto {
                                        seq,
                                        operation: "address".into(),
                                        source_operand: base.into(),
                                        target_operand: operand[operand.find('[').unwrap()..]
                                            .into(),
                                        pre_value: hex(p.value),
                                        post_value: hex(address),
                                    });
                                    proof = Some(p);
                                }
                            }
                        }
                    }
                }
                if mem.is_none()
                    || size.is_none_or(|s| s == 0 || address.checked_add(u64::from(s)).is_none())
                {
                    gap(
                        &mut gaps,
                        seq,
                        "memory_parse",
                        "unknown width or inconsistent strict annotation",
                    );
                    proof = None;
                }
                if let Some(p) = &proof {
                    if matches!(p.anchor, AddressOriginDto::GlobalAdrp { .. })
                        && global_map
                            .stable_global_for_access(&owned, position, address, size.unwrap_or(0))
                            .is_none()
                    {
                        proof = None;
                    }
                }
                if proof.is_none() {
                    gap(
                        &mut gaps,
                        seq,
                        "address_definition",
                        "address operand lacks supported root entry or strict ADRP chain",
                    );
                }
                if let Some(p) = &proof {
                    steps_total = steps_total
                        .checked_add(p.steps.len())
                        .ok_or_else(|| invalid("step overflow"))?;
                    if steps_total > MAX_STEPS {
                        return Err(invalid("address provenance step capacity exceeded"));
                    }
                }
                accesses.push(AddressAccessDto {
                    seq,
                    address: hex(address),
                    size,
                    rw: if write { "write" } else { "read" }.into(),
                    address_operand: operand
                        .find('[')
                        .map(|s| operand[s..].to_owned())
                        .unwrap_or_else(|| operand.into()),
                    origin_anchor: proof.as_ref().map(|p| p.anchor.clone()),
                    definition_steps: proof.as_ref().map(|p| p.steps.clone()).unwrap_or_default(),
                    integer_delta: proof.as_ref().map(|p| p.delta),
                });
                if write {
                    if let Some(size) = size {
                        prior_writes.push((address, size));
                    } else {
                        unknown_effect = true;
                    }
                } else if mnemonic == "ldr"
                    && size == Some(8)
                    && !unknown_effect
                    && accesses.last().is_some_and(|a| {
                        matches!(a.origin_anchor, Some(AddressOriginDto::EntrySp { .. }))
                    })
                    && owner.is_some_and(|a| a.id == root.id)
                {
                    if let Some(sp) = entry_sp {
                        if let Some(slot) = slots.iter().find(|s| {
                            s.size == 8
                                && s.read_seqs.contains(&seq)
                                && sp.checked_add_signed(s.offset) == Some(address)
                        }) {
                            let intact = prior_writes.iter().all(|(a, s)| {
                                a.checked_add(u64::from(*s)).is_some_and(|end| {
                                    end <= address
                                        || address.checked_add(8).is_some_and(|e| e <= *a)
                                })
                            });
                            if intact {
                                if let (Some(reg), Some(value)) = (
                                    parts.first().and_then(|r| reg64(r)),
                                    slot.value.as_ref().and_then(|v| {
                                        u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()
                                    }),
                                ) {
                                    if values(&parsed, reg, true) == Some(value) {
                                        loaded_stack = Some((
                                            reg,
                                            Proof {
                                                value,
                                                delta: 0,
                                                anchor: AddressOriginDto::StackArgument {
                                                    seq: entry_seq,
                                                    stack_offset: slot.offset,
                                                    size: 8,
                                                    value: hex(value),
                                                },
                                                steps: vec![AddressDefinitionStepDto {
                                                    seq,
                                                    operation: "stack_load".into(),
                                                    source_operand: accesses
                                                        .last()
                                                        .unwrap()
                                                        .address_operand
                                                        .clone(),
                                                    target_operand: parts[0].into(),
                                                    pre_value: hex(address),
                                                    post_value: hex(value),
                                                }],
                                            },
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            } else if parsed.mem_op.is_some()
                || mnemonic.starts_with("ld")
                || mnemonic.starts_with("st")
                || raw.contains("mem_r=")
                || raw.contains("mem_w=")
                || raw.contains("abs=")
            {
                gap(
                    &mut gaps,
                    seq,
                    "missing_memory_annotation",
                    "possible access has no unambiguous address/direction",
                );
                unknown_effect = true;
            }
            let mut next = None;
            if matches!(mnemonic, "mov" | "add" | "sub")
                && ((mnemonic == "mov" && parts.len() == 2)
                    || (mnemonic != "mov" && parts.len() == 3))
            {
                if let (Some(dst), Some(src)) = (reg64(parts[0]), reg64(parts[1])) {
                    if let Some(p) = proofs.get(&src) {
                        let delta = if mnemonic == "mov" {
                            Some(0)
                        } else {
                            immediate(parts[2]).and_then(|v| {
                                if mnemonic == "sub" {
                                    v.checked_neg()
                                } else {
                                    Some(v)
                                }
                            })
                        };
                        if let Some(delta) = delta {
                            if let (Some(value), Some(total)) =
                                (add(p.value, delta), p.delta.checked_add(delta))
                            {
                                if values(&parsed, src, false) == Some(p.value)
                                    && values(&parsed, dst, true) == Some(value)
                                    && p.steps.len() < MAX_CHAIN
                                {
                                    let mut p = p.clone();
                                    p.steps.push(AddressDefinitionStepDto {
                                        seq,
                                        operation: mnemonic.into(),
                                        source_operand: parts[1..].join(", "),
                                        target_operand: parts[0].into(),
                                        pre_value: hex(p.value),
                                        post_value: hex(value),
                                    });
                                    p.value = value;
                                    p.delta = total;
                                    next = Some((dst, p));
                                }
                            }
                        }
                    }
                }
            } else if mnemonic == "adrp" && parts.len() == 2 {
                if let (Some(dst), Some(page), Some((module, runtime, offset))) = (
                    reg64(parts[0]),
                    immediate(parts[1]).and_then(|v| u64::try_from(v).ok()),
                    stable_runtime_site(raw),
                ) {
                    if global_map
                        .bases
                        .get(&module)
                        .is_some_and(|base| runtime.checked_sub(offset) == Some(*base))
                        && values(&parsed, dst, true) == Some(page)
                    {
                        if let Some(stable) = page.checked_sub(global_map.bases[&module]) {
                            next = Some((
                                dst,
                                Proof {
                                    value: page,
                                    delta: 0,
                                    anchor: AddressOriginDto::GlobalAdrp {
                                        seq,
                                        register: parts[0].into(),
                                        value: hex(page),
                                        global: format!("{module}+0x{stable:x}"),
                                    },
                                    steps: vec![],
                                },
                            ));
                        }
                    }
                }
            }
            for reg in defs {
                proofs.remove(&reg);
            }
            // Unknown classes default to Nop in the slicer: never preserve a pointer through them.
            if matches!(class, trace_parser::insn_class::InsnClass::Nop) && mnemonic != "nop" {
                proofs.clear();
                unknown_effect = true;
                gap(
                    &mut gaps,
                    seq,
                    "unsupported_instruction",
                    "unknown class cannot preserve definitions",
                );
            }
            if let Some((reg, p)) = next.or(loaded_stack) {
                proofs.insert(reg, p);
            }
            if external_calls.contains(&seq) {
                gap(
                    &mut gaps,
                    seq,
                    "external_boundary",
                    "unrecorded callee effects and returns cannot be relocated",
                );
                proofs.clear();
                unknown_effect = true;
            }
            // Raw post writes not represented by the classifier must break aliases too.
            if let Some(post) = &parsed.post_arrow_regs {
                for (reg, value) in post.iter() {
                    if proofs.get(reg).is_some_and(|p| p.value != *value) {
                        proofs.remove(reg);
                    }
                }
            }
        }
        Ok(AddressProvenanceDto {
            trace_session: session_id.into(),
            call_seq,
            entry_seq,
            function: function.into(),
            exit_seq: root.exit_seq,
            resume_seq: root.resume_seq,
            target_modules: modules.into_iter().collect(),
            coverage: AddressCoverageDto {
                first_seq: entry_seq,
                last_seq: root.exit_seq,
                scanned_lines: count,
                access_count: accesses.len(),
                complete: gaps.is_empty(),
            },
            accesses,
            gaps,
        })
    }
}
