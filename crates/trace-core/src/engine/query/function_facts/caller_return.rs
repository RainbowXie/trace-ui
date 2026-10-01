//! Bounded concrete X0 return-to-caller address-use query. No symbolic inference.
use super::super::activation::{stable_runtime_site, stable_site};
use super::registers_at;
use crate::{
    api_types::*,
    error::{Result, TraceError},
};
use std::collections::{BTreeSet, HashMap};
use trace_parser::types::{ParsedLine, RegId};
const MAX_LINES: u32 = 50_000;
const MAX_RAW: usize = 32 * 1024 * 1024;
const MAX_STEPS: usize = 8192;
const MAX_CHAIN: usize = 128;
fn invalid(s: &str) -> TraceError {
    TraceError::InvalidArgument(s.into())
}
fn hex(v: u64) -> String {
    format!("0x{v:x}")
}
fn parse(raw: &str) -> Option<ParsedLine> {
    if raw.contains("!0x") {
        trace_parser::gumtrace::parse_line_gumtrace_full(raw)
    } else {
        trace_parser::parser::parse_line_full(raw)
    }
}
fn value(p: &ParsedLine, reg: RegId, post: bool) -> Option<u64> {
    let list = if post {
        &p.post_arrow_regs
    } else {
        &p.pre_arrow_regs
    };
    let mut iter = list
        .as_ref()?
        .iter()
        .filter(|(r, _)| *r == reg)
        .map(|(_, v)| *v);
    let v = iter.next()?;
    iter.all(|other| other == v).then_some(v)
}
fn reg64(s: &str) -> Option<RegId> {
    if s.starts_with('w') {
        return None;
    }
    let r = trace_parser::types::parse_reg(s)?;
    (r.0 < 31 && !r.is_zero()).then_some(r)
}
fn immediate(s: &str) -> Option<i64> {
    let s = s.strip_prefix('#')?;
    let (neg, n) = s.strip_prefix('-').map_or((false, s), |n| (true, n));
    let n: i64 = if let Some(h) = n.strip_prefix("0x") {
        i64::from_str_radix(h, 16).ok()?
    } else {
        n.parse().ok()?
    };
    if neg {
        n.checked_neg()
    } else {
        Some(n)
    }
}
fn address_operand(s: &str) -> Option<(&str, &str, i64)> {
    let start = s.find('[')?;
    let tail = &s[start..];
    let inside = tail.strip_prefix('[')?.strip_suffix(']')?;
    let parts = inside.split(',').map(str::trim).collect::<Vec<_>>();
    match parts.as_slice() {
        [base] => Some((tail, base, 0)),
        [base, off] => Some((tail, base, immediate(off)?)),
        _ => None,
    }
}
fn gap(gaps: &mut Vec<AddressGapDto>, seq: u32, kind: &str, detail: &str) {
    gaps.push(AddressGapDto {
        seq,
        kind: kind.into(),
        detail: detail.into(),
    });
}
#[derive(Clone)]
struct Chain {
    value: u64,
    delta: i64,
    steps: Vec<AddressDefinitionStepDto>,
}
impl crate::engine::TraceEngine {
    pub fn get_caller_return_uses(
        &self,
        sid: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        target_modules: &[String],
    ) -> Result<CallerReturnUsesDto> {
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.len() != target_modules.len()
            || modules.len() > 500
            || modules.iter().any(|m| {
                stable_site(&format!("[{m}] 0x0!0x0 nop")).as_deref() != Some(&format!("{m}+0x0"))
            })
        {
            return Err(invalid("invalid or duplicate target_modules"));
        }
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
            .find(|a| a.call_seq == call_seq && a.entry_seq == entry_seq && a.id != 0)
            .ok_or_else(|| invalid("return selector not found"))?;
        if root.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= root.exit_seq
                && root.exit_seq < root.resume_seq
                && root.resume_seq < state.total_lines)
        {
            return Err(invalid("return requires closed confirmed root"));
        }
        let caller = tree
            .activations
            .iter()
            .find(|a| Some(a.id) == root.parent_id)
            .ok_or_else(|| invalid("missing caller owner"))?;
        let closed = caller.id != 0
            && caller.unresolved_reason.is_none()
            && caller.entry_seq <= call_seq
            && root.resume_seq <= caller.exit_seq
            && caller.exit_seq < caller.resume_seq
            && caller.resume_seq < state.total_lines;
        let wanted_last = if closed {
            caller.exit_seq
        } else {
            state.total_lines - 1
        };
        let last = wanted_last.min(root.resume_seq.saturating_add(MAX_LINES - 1));
        if root.exit_seq - entry_seq + 1 > MAX_LINES {
            return Err(invalid("return definition window capacity exceeded"));
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
            return Err(invalid("return function site mismatch"));
        }
        for seq in [call_seq, entry_seq, root.exit_seq, root.resume_seq] {
            if stable_runtime_site(raw(seq)?).is_none()
                || trace_parser::strict_memory::instruction_parts(raw(seq)?).is_none()
            {
                return Err(invalid("return boundary lacks real site"));
            }
        }
        let mut gaps = Vec::new();
        if !closed {
            gap(
                &mut gaps,
                root.resume_seq,
                "caller_not_closed",
                "trace_root or unresolved caller cannot establish negative coverage",
            );
        }
        if last != wanted_last {
            gap(
                &mut gaps,
                last,
                "line_capacity",
                "caller window truncated; no negative coverage",
            );
        }
        let mut bytes = 0usize;
        let mut definition = None;
        // Scan actual root-owned definitions only. Unknown instructions invalidate the candidate.
        for seq in entry_seq..=root.exit_seq {
            let line = raw(seq)?;
            bytes = bytes
                .checked_add(line.len())
                .ok_or_else(|| invalid("raw capacity overflow"))?;
            if bytes > MAX_RAW || line.len() > 4096 {
                return Err(invalid("return raw capacity exceeded"));
            }
            let Some((mnemonic, operand)) = trace_parser::strict_memory::instruction_parts(line)
            else {
                definition = None;
                continue;
            };
            if operand.len() > 512 {
                return Err(invalid("return operand capacity exceeded"));
            }
            let Some(p) = parse(line) else {
                definition = None;
                continue;
            };
            let class = trace_parser::insn_class::classify_and_refine(&p);
            let (defs, _) = trace_parser::def_use::determine_def_use(class, &p);
            if mnemonic == "ret" {
                continue;
            } // Synthetic X0 return DEF is not a numeric producer.
            if matches!(class, trace_parser::insn_class::InsnClass::Nop) && mnemonic != "nop" {
                definition = None;
            }
            if defs.contains(&RegId(0)) || matches!(mnemonic, "bl" | "blr" | "svc") {
                definition = None;
                if !matches!(mnemonic, "bl" | "blr" | "svc")
                    && tree
                        .activation_for_seq(seq)
                        .is_some_and(|a| a.id == root.id)
                {
                    definition = value(&p, RegId(0), true).map(|v| (seq, v));
                }
            }
        }
        let exit = parse(raw(root.exit_seq)?);
        let resume = parse(raw(root.resume_seq)?);
        let replay = registers_at(&state, root.resume_seq)?;
        let anchor = definition.filter(|(_, v)| {
            exit.as_ref().and_then(|p| value(p, RegId(0), false)) == Some(*v)
                && resume.as_ref().and_then(|p| value(p, RegId(0), false)) == Some(*v)
                && replay[0] == *v
                && tree
                    .activation_for_seq(root.exit_seq)
                    .is_some_and(|a| a.id == root.id)
                && tree
                    .activation_for_seq(root.resume_seq)
                    .is_some_and(|a| a.id == caller.id)
                && trace_parser::strict_memory::instruction_parts(raw(root.exit_seq).unwrap_or(""))
                    .is_some_and(|(m, _)| m == "ret")
        });
        let mut chains = HashMap::<RegId, Chain>::new();
        let mut anchors = Vec::new();
        if let Some((seq, v)) = anchor {
            anchors.push(ReturnAnchorDto {
                register: "x0".into(),
                value: hex(v),
                definition_seq: seq,
                exit_seq: root.exit_seq,
                resume_seq: root.resume_seq,
            });
            chains.insert(
                RegId(0),
                Chain {
                    value: v,
                    delta: 0,
                    steps: vec![],
                },
            );
        } else {
            gap(
                &mut gaps,
                root.resume_seq,
                "return_anchor",
                "missing real X0 definition or exit/pre-resume/replay/owner mismatch",
            );
        }
        let mut uses = Vec::new();
        let mut steps = 0usize;
        let mut access_count = 0usize;
        let mut scanned = 0u32;
        for seq in root.resume_seq..=last {
            let line = raw(seq)?;
            bytes = bytes
                .checked_add(line.len())
                .ok_or_else(|| invalid("raw capacity overflow"))?;
            if bytes > MAX_RAW || line.len() > 4096 {
                gap(
                    &mut gaps,
                    seq,
                    "raw_capacity",
                    "scan stopped before this line",
                );
                break;
            }
            scanned += 1;
            let Some((m, operand)) = trace_parser::strict_memory::instruction_parts(line) else {
                chains.clear();
                gap(
                    &mut gaps,
                    seq,
                    "unsupported_parse",
                    "special/unparsed line breaks source coverage",
                );
                continue;
            };
            if operand.len() > 512 {
                return Err(invalid("return operand capacity exceeded"));
            }
            if !tree
                .activation_for_seq(seq)
                .is_some_and(|a| a.id == caller.id)
            {
                chains.clear();
                gap(
                    &mut gaps,
                    seq,
                    "ownership",
                    "instruction is not caller-owned",
                );
                continue;
            }
            let Some(p) = parse(line) else {
                chains.clear();
                gap(&mut gaps, seq, "unsupported_parse", "missing ParsedLine");
                continue;
            };
            if matches!(m, "bl" | "blr" | "svc") {
                chains.clear();
                gap(
                    &mut gaps,
                    seq,
                    "call_boundary",
                    "return propagation stops at calls/external effects",
                );
                continue;
            }
            let class = trace_parser::insn_class::classify_and_refine(&p);
            let (defs, _) = trace_parser::def_use::determine_def_use(class, &p);
            if matches!(class, trace_parser::insn_class::InsnClass::Nop) && m != "nop" {
                chains.clear();
                gap(
                    &mut gaps,
                    seq,
                    "unsupported_instruction",
                    "unknown class cannot preserve return chains",
                );
                continue;
            }
            let marker = trace_parser::strict_memory::memory_marker(line);
            let mem = trace_parser::strict_memory::memory_op(line);
            if let Some((write, address)) = marker {
                access_count += 1;
                if access_count > 8192 {
                    return Err(invalid("return access capacity exceeded"));
                }
                let size = mem
                    .as_ref()
                    .map(|op| u32::from(op.elem_width) * u32::from(op.value_count));
                let valid = size
                    .is_some_and(|s| s > 0 && address.checked_add(u64::from(s)).is_some())
                    && mem
                        .as_ref()
                        .is_some_and(|op| op.exclusive_status.is_none_or(|s| s == 0));
                if !valid {
                    chains.clear();
                    gap(
                        &mut gaps,
                        seq,
                        "memory_parse",
                        "unknown width, conflicting annotation or unsuccessful exclusive effect",
                    );
                } else if let Some((label, base, off)) = address_operand(operand) {
                    if let Some(reg) = reg64(base) {
                        if let Some(c) = chains.get(&reg) {
                            if p.base_reg == Some(reg)
                                && value(&p, reg, false) == Some(c.value)
                                && c.value.checked_add_signed(off) == Some(address)
                                && c.delta.checked_add(off).is_some()
                            {
                                let count = c.steps.len() + 1;
                                if count > MAX_CHAIN
                                    || steps.checked_add(count).is_none_or(|n| n > MAX_STEPS)
                                {
                                    return Err(invalid("return step capacity exceeded"));
                                }
                                steps += count;
                                let mut definition_steps = c.steps.clone();
                                definition_steps.push(AddressDefinitionStepDto {
                                    seq,
                                    operation: "address".into(),
                                    source_operand: base.into(),
                                    target_operand: label.into(),
                                    pre_value: hex(c.value),
                                    post_value: hex(address),
                                });
                                uses.push(CallerReturnUseDto {
                                    register: "x0".into(),
                                    value: anchors[0].value.clone(),
                                    use_seq: seq,
                                    address: hex(address),
                                    size: size.unwrap(),
                                    rw: if write { "write" } else { "read" }.into(),
                                    address_operand: label.into(),
                                    definition_steps,
                                    integer_delta: c.delta.checked_add(off).unwrap(),
                                    chain_complete: true,
                                });
                            } else {
                                chains.clear();
                                gap(
                                    &mut gaps,
                                    seq,
                                    "address_mismatch",
                                    "return chain disagrees with real address operand",
                                );
                            }
                        }
                    }
                } else {
                    chains.clear();
                    gap(
                        &mut gaps,
                        seq,
                        "unsupported_address",
                        "indexed/writeback address not covered",
                    );
                }
            } else if mem.is_some()
                || m.starts_with("ld")
                || m.starts_with("st")
                || line.contains("mem_r=")
                || line.contains("mem_w=")
                || line.contains("abs=")
            {
                chains.clear();
                gap(
                    &mut gaps,
                    seq,
                    "missing_memory_annotation",
                    "possible memory use lacks strict marker",
                );
            }
            let parts = operand.split(',').map(str::trim).collect::<Vec<_>>();
            let mut next = None;
            if (m == "mov" && parts.len() == 2) || (matches!(m, "add" | "sub") && parts.len() == 3)
            {
                if let (Some(dst), Some(src)) = (reg64(parts[0]), reg64(parts[1])) {
                    if let Some(c) = chains.get(&src) {
                        let delta = if m == "mov" {
                            Some(0)
                        } else {
                            immediate(parts[2]).and_then(|d| {
                                if m == "sub" {
                                    d.checked_neg()
                                } else {
                                    Some(d)
                                }
                            })
                        };
                        if let Some(d) = delta {
                            if let (Some(v), Some(total)) =
                                (c.value.checked_add_signed(d), c.delta.checked_add(d))
                            {
                                if value(&p, src, false) == Some(c.value)
                                    && value(&p, dst, true) == Some(v)
                                {
                                    if c.steps.len() + 1 >= MAX_CHAIN || steps >= MAX_STEPS {
                                        return Err(invalid("return chain capacity exceeded"));
                                    }
                                    steps += 1;
                                    let mut c = c.clone();
                                    c.steps.push(AddressDefinitionStepDto {
                                        seq,
                                        operation: m.into(),
                                        source_operand: parts[1..].join(", "),
                                        target_operand: parts[0].into(),
                                        pre_value: hex(c.value),
                                        post_value: hex(v),
                                    });
                                    c.value = v;
                                    c.delta = total;
                                    next = Some((dst, c));
                                } else {
                                    gap(
                                        &mut gaps,
                                        seq,
                                        "copy_mismatch",
                                        "copy/arithmetic values disagree",
                                    );
                                    chains.clear();
                                }
                            }
                        }
                    }
                }
            }
            // All real DEFs, including W aliases, kill old identities. Other reads of
            // a tracked value are not covered negative evidence (store-data included).
            let (_, read_regs) = trace_parser::def_use::determine_def_use(class, &p);
            if marker.is_some_and(|(write, _)| write) {
                // Data operands are separate from the bracketed address operand.
                // Report their use, but never certify address use by equal numbers.
                let data = operand.split('[').next().unwrap_or("");
                if data
                    .split(',')
                    .map(str::trim)
                    .filter_map(trace_parser::types::parse_reg)
                    .any(|r| chains.contains_key(&r))
                {
                    gap(
                        &mut gaps,
                        seq,
                        "store_data_escape",
                        "returned value stored as data; later memory propagation is not covered",
                    );
                    chains.clear();
                }
            }
            if next.is_none()
                && marker.is_none()
                && m != "ret"
                && read_regs.iter().any(|r| chains.contains_key(r))
            {
                gap(
                    &mut gaps,
                    seq,
                    "unsupported_return_use",
                    "return read is outside supported copy/address subset",
                );
                chains.clear();
            }
            for reg in defs {
                chains.remove(&reg);
            }
            if let Some((r, c)) = next {
                chains.insert(r, c);
            }
        }
        let complete = closed && gaps.is_empty() && scanned == last - root.resume_seq + 1;
        Ok(CallerReturnUsesDto {
            trace_session: sid.into(),
            call_seq,
            entry_seq,
            function: function.into(),
            exit_seq: root.exit_seq,
            resume_seq: root.resume_seq,
            target_modules: modules.into_iter().collect(),
            caller: ReturnCallerDto {
                call_seq: caller.call_seq,
                entry_seq: caller.entry_seq,
                exit_seq: caller.exit_seq,
                resume_seq: caller.resume_seq,
                closed,
            },
            anchors,
            uses,
            coverage: AddressCoverageDto {
                first_seq: root.resume_seq,
                last_seq: root.resume_seq + scanned.saturating_sub(1),
                scanned_lines: scanned,
                access_count,
                complete,
            },
            gaps,
        })
    }
}
