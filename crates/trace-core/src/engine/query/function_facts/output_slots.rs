//! Exact observed store -> last-definition load -> operand-labelled address use.
//! Deliberately does not infer pointers from numeric ranges or store-data reads.
use super::super::activation::{stable_runtime_site, stable_site};
use crate::{api_types::*, error::{Result, TraceError}};
use std::collections::{BTreeSet, HashMap, HashSet};
use trace_parser::types::{ParsedLine, RegId};
fn invalid(s: &str) -> TraceError { TraceError::InvalidArgument(s.into()) }
fn hex(v: u64) -> String { format!("0x{v:x}") }
fn reg64(s: &str) -> Option<RegId> {
    if s.starts_with('w') { return None; }
    let r = trace_parser::types::parse_reg(s)?;
    (r.0 < 31 && !r.is_zero()).then_some(r)
}
fn value(p: &ParsedLine, r: RegId, post: bool) -> Option<u64> {
    let values = if post { &p.post_arrow_regs } else { &p.pre_arrow_regs };
    let mut it = values.as_ref()?.iter().filter(|(id,_)| *id == r).map(|(_,v)| *v);
    let v = it.next()?; it.all(|n| n == v).then_some(v)
}
fn immediate(s: &str) -> Option<i64> { trace_parser::strict_memory::integer_immediate(s) }
fn address_base(s: &str) -> Option<RegId> {
    if s == "sp" { trace_parser::types::parse_reg(s) } else { reg64(s) }
}
fn address_operand(s: &str) -> Option<(&str, RegId, i64)> {
    trace_parser::strict_memory::simple_address_operand(s)
}
fn gap(g: &mut Vec<AddressGapDto>, seq: u32, kind: &str) {
    g.push(AddressGapDto {seq,kind:kind.into(),detail:"coverage/identity interrupted; never negative pointer evidence".into()});
}
#[derive(Clone)]
struct Store { seq: u32, owner: u32, operand: String, value: u64 }
#[derive(Clone)]
struct Chain { slot: u64, store: Store, load: u32, owner: u32, dst: String, value: u64, delta: i64, steps: Vec<AddressDefinitionStepDto> }
impl crate::engine::TraceEngine {
    pub fn get_output_slot_uses(&self, sid: &str, call_seq: u32, entry_seq: u32, function: &str, target_modules: &[String], slot_ranges: &[OutputSlotRangeDto]) -> Result<OutputSlotUsesDto> {
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.len() != target_modules.len() || modules.len() > 500 || modules.iter().any(|m| stable_site(&format!("[{m}] 0x0!0x0 nop")).as_deref() != Some(&format!("{m}+0x0"))) { return Err(invalid("invalid target_modules")); }
        if slot_ranges.is_empty() || slot_ranges.len() > 128 { return Err(invalid("slot range count must be 1..128")); }
        let mut ranges = Vec::new(); let mut total = 0u64;
        for r in slot_ranges {
            let a = r.address.strip_prefix("0x").and_then(|s| u64::from_str_radix(s,16).ok()).ok_or_else(|| invalid("invalid slot address"))?;
            if hex(a) != r.address || r.size == 0 { return Err(invalid("slot address must be canonical and size positive")); }
            let end = a.checked_add(u64::from(r.size)).ok_or_else(|| invalid("slot range overflow"))?;
            total = total.checked_add(u64::from(r.size)).ok_or_else(|| invalid("slot total overflow"))?;
            if total > 1024*1024 || ranges.iter().any(|&(b,e)| a < e && b < end) { return Err(invalid("slot ranges overlap or exceed capacity")); }
            ranges.push((a,end));
        }
        let handle = self.get_handle(sid)?;
        let state = handle.state.read().map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state.activation_tree.as_ref().ok_or(TraceError::IndexNotReady)?;
        let root = tree.activations.iter().find(|a| a.id != 0 && a.call_seq == call_seq && a.entry_seq == entry_seq).ok_or_else(|| invalid("root selector not found"))?;
        if root.unresolved_reason.is_some() || !(call_seq < entry_seq && entry_seq <= root.exit_seq && root.exit_seq < root.resume_seq && root.resume_seq < state.total_lines) { return Err(invalid("root requires closed confirmed ownership")); }
        let caller = tree.activations.iter().find(|a| Some(a.id) == root.parent_id).ok_or_else(|| invalid("missing caller"))?;
        let closed = caller.id != 0 && caller.unresolved_reason.is_none() && caller.entry_seq <= call_seq && root.resume_seq <= caller.exit_seq && caller.exit_seq < caller.resume_seq && caller.resume_seq < state.total_lines;
        let wanted = if closed { caller.exit_seq } else { root.exit_seq };
        let last = wanted.min(entry_seq.saturating_add(49_999));
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let raw = |seq| -> Result<&str> { std::str::from_utf8(index.get_line(&state.mmap,seq).ok_or_else(|| invalid("missing line"))?).map_err(|_| invalid("invalid UTF8")) };
        if stable_site(raw(entry_seq)?).as_deref() != Some(function) { return Err(invalid("function site mismatch")); }
        for seq in [call_seq,entry_seq,root.exit_seq,root.resume_seq] { if stable_runtime_site(raw(seq)?).is_none() || trace_parser::strict_memory::instruction_parts(raw(seq)?).is_none() { return Err(invalid("boundary lacks real site")); } }
        let mut gaps = Vec::new();
        if !closed { gap(&mut gaps,root.resume_seq,"caller_not_closed"); }
        if last != wanted { gap(&mut gaps,last,"line_capacity"); }
        let mut stores = HashMap::<u64,Store>::new();
        let mut final_stores = HashMap::<u64,u32>::new();
        let mut byte_definitions = HashMap::<u64,(u32,Option<u8>)>::new();
        let mut final_bytes = HashMap::<u64,(u32,Option<u8>)>::new();
        let mut loaded_values = HashMap::<RegId,(u64,u64)>::new();
        let mut chains = HashMap::<RegId,Chain>::new();
        // Negative-only store-source obligations. Reads need propagation we do
        // not implement here; an actual supported overwrite can discharge one.
        let mut store_sources = HashSet::<RegId>::new();
        let mut uses = Vec::new(); let mut bytes = 0usize; let mut scanned = 0u32; let mut access_count = 0; let mut steps = 0usize;
        for seq in entry_seq..=last {
            if seq == root.resume_seq {
                final_stores = stores.iter().map(|(a,s)| (*a,s.seq)).collect();
                final_bytes = byte_definitions.clone();
            }
            let line = raw(seq)?;
            bytes = bytes.checked_add(line.len()).ok_or_else(|| invalid("raw overflow"))?;
            if bytes > 32*1024*1024 || line.len() > 4096 { gap(&mut gaps,seq,"raw_capacity"); break; }
            scanned += 1;
            let expected = if seq < root.resume_seq { root.id } else { caller.id };
            let Some(owner) = tree.activation_for_seq(seq).filter(|a| a.id == expected) else { stores.clear(); chains.clear(); gap(&mut gaps,seq,"ownership"); continue; };
            let parts = trace_parser::strict_memory::instruction_parts(line);
            let parsed = if line.contains("!0x") { trace_parser::gumtrace::parse_line_gumtrace_full(line) } else { trace_parser::parser::parse_line_full(line) };
            let (Some((m,operand)),Some(p)) = (parts,parsed) else { stores.clear(); chains.clear(); gap(&mut gaps,seq,"unsupported_parse"); continue; };
            if operand.len() > 512 { return Err(invalid("operand capacity")); }
            let class = trace_parser::insn_class::classify_and_refine(&p);
            let (defs,reads) = trace_parser::def_use::determine_def_use(class,&p);
            if reads.iter().any(|r| store_sources.contains(r))
                || address_operand(operand).is_some_and(|(_,r,_)| store_sources.contains(&r)) {
                gap(&mut gaps,seq,"untracked_store_source_use");
            }
            let elements = trace_parser::strict_memory::integer_memory_elements(line);
            let data_reads = elements.as_ref().is_some_and(|es| m.starts_with("st") && es.iter().any(|e| store_sources.contains(&e.register)));
            if data_reads { gap(&mut gaps,seq,"untracked_store_source_use"); }
            if matches!(m,"mov"|"add"|"sub") && operand.split(',').skip(1).map(str::trim)
                .filter_map(trace_parser::strict_memory::integer_register)
                .any(|r| store_sources.contains(&r) || (loaded_values.contains_key(&r) && !chains.contains_key(&r))) {
                gap(&mut gaps,seq,"untracked_register_source_use");
            }
            if reads.iter().any(|r| loaded_values.contains_key(r) && !chains.contains_key(r))
                || address_operand(operand).is_some_and(|(_,r,_)| loaded_values.contains_key(&r) && !chains.contains_key(&r)) {
                gap(&mut gaps,seq,"untracked_loaded_value_use");
            }
            if m == "ret" && !store_sources.is_empty() {
                gap(&mut gaps,seq,"untracked_store_source_return");
            }
            if matches!(m,"bl"|"blr"|"svc") || (matches!(class,trace_parser::insn_class::InsnClass::Nop) && m != "nop") { stores.clear(); chains.clear(); gap(&mut gaps,seq,"call_external_or_unknown"); continue; }
            // Negative coverage is an instruction-by-instruction mechanical
            // observation, not a language-level scalar/pointer classification.
            let args = operand.split(',').map(str::trim).collect::<Vec<_>>();
            let supported_data = match (m, args.as_slice()) {
                ("mov", [dst, src]) => trace_parser::strict_memory::integer_register(dst).is_some_and(|_| {
                    let expected = trace_parser::strict_memory::observed_register_value(line,src,false)
                        .or_else(|| immediate(src).and_then(|v| u64::try_from(v).ok()));
                    expected.is_some() && expected == trace_parser::strict_memory::observed_register_value(line,dst,true)
                }),
                ("add" | "sub", [dst, src, imm]) => {
                    match (address_base(dst), address_base(src), immediate(imm)) {
                        (Some(d),Some(s),Some(n)) => {
                            let delta = if m == "sub" { n.checked_neg() } else { Some(n) };
                            let expected = value(&p,s,false).zip(delta).and_then(|(v,n)| v.checked_add_signed(n));
                            expected.is_some() && expected == value(&p,d,true)
                        },
                        _ => false,
                    }
                },
                ("nop", [""]) => true,
                ("ret", [""]) => seq == if owner.id == root.id { root.exit_seq } else { caller.exit_seq },
                ("ldr" | "ldur" | "str" | "stur" | "ldrb" | "ldurb" | "strb" | "sturb" |
                    "ldrh" | "ldurh" | "strh" | "sturh" | "ldp" | "stp", _) => elements.is_some(),
                _ => false,
            };
            if !supported_data { gap(&mut gaps,seq,"unsupported_instruction_effect"); }
            if m == "ret" && (!chains.is_empty() || !loaded_values.is_empty() || value(&p,RegId(0),false).is_none()) {
                gap(&mut gaps,seq,"untracked_return_escape");
            }
            let marker = trace_parser::strict_memory::memory_marker(line);
            let mem = trace_parser::strict_memory::memory_op(line);
            let mut loaded = None;
            let mut stored_sources = Vec::new();
            let mut new_loaded = Vec::new();
            if let Some((write,a)) = marker {
                access_count += 1; if access_count > 8192 { return Err(invalid("access capacity")); }
                let concrete_address = address_operand(operand).is_some_and(|(_,base,off)|
                    p.base_reg == Some(base) && value(&p,base,false).and_then(|v| v.checked_add_signed(off)) == Some(a));
                let valid = mem.as_ref().and_then(|op| {
                    let size = u32::from(op.elem_width)*u32::from(op.value_count);
                    (concrete_address && size > 0 && op.exclusive_status.is_none_or(|v| v == 0)).then_some(size).and_then(|n| a.checked_add(u64::from(n)).map(|e| (n,e)))
                });
                if let Some((size,end)) = valid {
                    // Address-use certification happens before destination DEFs. Data
                    // operands are never consulted here, even if numerically equal.
                    if let Some((label,base,off)) = address_operand(operand) {
                        if let Some(c) = chains.get(&base) {
                            if p.base_reg == Some(base) && value(&p,base,false) == Some(c.value) && c.value.checked_add_signed(off) == Some(a) {
                                let delta = c.delta.checked_add(off).ok_or_else(|| invalid("delta overflow"))?;
                                if c.steps.len()+1 > 128 || steps.checked_add(c.steps.len()+1).is_none_or(|n| n > 8192) { return Err(invalid("step capacity")); }
                                steps += c.steps.len()+1;
                                let mut ds = c.steps.clone(); ds.push(AddressDefinitionStepDto {seq,operation:"address".into(),source_operand:format!("x{}",base.0),target_operand:label.into(),pre_value:hex(c.value),post_value:hex(a)});
                                if uses.len() >= 8192 { return Err(invalid("use capacity")); }
                                uses.push(OutputSlotUseDto {slot_address:hex(c.slot),slot_size:8,store_seq:c.store.seq,store_owner_entry_seq:c.store.owner,store_operand:c.store.operand.clone(),store_value:hex(c.store.value),store_bytes:c.store.value.to_le_bytes().to_vec(),load_seq:c.load,load_owner_entry_seq:c.owner,load_destination:c.dst.clone(),load_value:hex(c.store.value),use_seq:seq,use_owner_entry_seq:owner.entry_seq,address:hex(a),size,rw:if write {"write"} else {"read"}.into(),address_operand:label.into(),integer_delta:delta,definition_steps:ds,chain_complete:true,final_output_definition:false});
                            } else { chains.clear(); gap(&mut gaps,seq,"address_mismatch"); }
                        }
                    } else { chains.clear(); gap(&mut gaps,seq,"unsupported_address"); }
                    let data = operand.split(',').next().unwrap_or("").trim();
                    let data_reg = reg64(data);
                    if elements.as_ref().is_none_or(|es| es.iter().any(|e| e.value.is_none())) {
                        gap(&mut gaps,seq,"unsupported_memory_data_effect");
                    }
                    if let Some(es) = &elements {
                        if !write && (es.iter().any(|e| Some(e.register) == p.base_reg)
                            || (es.len() == 2 && es[0].register == es[1].register)) {
                            gap(&mut gaps,seq,"ambiguous_load_identity");
                        }
                        if !write && es.iter().any(|e| store_sources.contains(&e.register) || loaded_values.contains_key(&e.register)) {
                            gap(&mut gaps,seq,"load_overwrites_live_identity");
                        }
                        let mut offset = 0u64;
                        for e in es {
                            let start = a + offset;
                            let stop = start + u64::from(e.width);
                            let overlaps = ranges.iter().any(|&(b,end)| start < end && b < stop);
                            if write {
                                if loaded_values.values().any(|&(b,end)| start < end && b < stop) {
                                    gap(&mut gaps,seq,"loaded_identity_overwrite");
                                }
                                if loaded_values.contains_key(&e.register) { gap(&mut gaps,seq,"untracked_store_data_escape"); }
                                if overlaps {
                                    let known = e.value.map(u64::to_le_bytes);
                                    for i in 0..e.width {
                                        let at = start + u64::from(i);
                                        if ranges.iter().any(|&(b,end)| b <= at && at < end) {
                                            byte_definitions.insert(at,(seq,known.map(|v| v[usize::from(i)])));
                                        }
                                    }
                                    if !e.register.is_zero() { stored_sources.push(e.register); }
                                    if e.value.is_none() { gap(&mut gaps,seq,"unknown_store_value"); }
                                }
                            } else if overlaps {
                                let observed = e.value.map(u64::to_le_bytes);
                                let matches = (0..e.width).all(|i| {
                                    byte_definitions.get(&(start + u64::from(i))).is_some_and(|(_,v)|
                                        v.is_some() && *v == observed.map(|v| v[usize::from(i)]))
                                });
                                if !matches { gap(&mut gaps,seq,"load_without_slot_definition"); }
                                else if store_sources.contains(&e.register) || loaded_values.contains_key(&e.register) {
                                    gap(&mut gaps,seq,"load_overwrites_live_identity");
                                }
                                else { new_loaded.push((e.register,(start,stop))); }
                            }
                            offset += u64::from(e.width);
                        }
                    }
                    if write {
                        if data_reg.is_some_and(|r| chains.contains_key(&r)) {
                            gap(&mut gaps,seq,"untracked_store_data_escape");
                        }
                        if chains.values().any(|c| a < c.slot.saturating_add(8) && c.slot < end) {
                            gap(&mut gaps,seq,"loaded_identity_overwrite");
                        }
                        stores.retain(|b,_| !(a < b.saturating_add(8) && *b < end));
                        // Partial or any alias overwrite kills even already loaded
                        // identities: conservative, not invented alias independence.
                        chains.retain(|_,c| !(a < c.slot.saturating_add(8) && c.slot < end));
                        let op = mem.as_ref().unwrap();
                        let data = operand.split(',').next().unwrap_or("").trim();
                        if seq < root.resume_seq && size == 8 && op.value_count == 1 && reg64(data).is_some() && ranges.iter().any(|&(b,e)| b <= a && end <= e) {
                            if let Some(v) = op.value.filter(|v| value(&p,reg64(data).unwrap(),false) == Some(*v)) {
                                if stores.len() >= 8192 { return Err(invalid("store capacity")); }
                                stores.insert(a,Store {seq,owner:owner.entry_seq,operand:data.into(),value:v});
                                // Source obligations are registered independently per element.
                            } else { gap(&mut gaps,seq,"unknown_store_value"); }
                        }
                    } else {
                        let op = mem.as_ref().unwrap();
                        let dst = operand.split(',').next().unwrap_or("").trim();
                        if size == 8 && op.value_count == 1 {
                            if ranges.iter().any(|&(b,e)| a < e && b < end) && !stores.contains_key(&a) {
                                gap(&mut gaps,seq,"load_without_single_x_slot_definition");
                            }
                            if let (Some(s),Some(r)) = (stores.get(&a),reg64(dst)) {
                                if op.value == Some(s.value) && value(&p,r,true) == Some(s.value) && defs.contains(&r) {
                                    loaded = Some((r,Chain {slot:a,store:s.clone(),load:seq,owner:owner.entry_seq,dst:dst.into(),value:s.value,delta:0,steps:vec![AddressDefinitionStepDto {seq,operation:"load".into(),source_operand:hex(a),target_operand:dst.into(),pre_value:hex(s.value),post_value:hex(s.value)}]}));
                                } else { gap(&mut gaps,seq,"load_mismatch"); }
                            }
                        }
                    }
                } else { stores.clear(); chains.clear(); gap(&mut gaps,seq,"unknown_memory_effect"); }
            } else if mem.is_some() || m.starts_with("ld") || m.starts_with("st") || line.contains("mem_r=") || line.contains("mem_w=") || line.contains("abs=") { stores.clear(); chains.clear(); gap(&mut gaps,seq,"unknown_memory_alias"); }
            let operands = operand.split(',').map(str::trim).collect::<Vec<_>>();
            let mut copied = None;
            if (m == "mov" && operands.len() == 2) || (matches!(m,"add"|"sub") && operands.len() == 3) {
                if let (Some(dst),Some(src)) = (reg64(operands[0]),reg64(operands[1])) {
                    if let Some(c) = chains.get(&src) {
                        let d = if m == "mov" { Some(0) } else { immediate(operands[2]).and_then(|d| if m == "sub" { d.checked_neg() } else {Some(d)}) };
                        if let Some(d) = d {
                            if let (Some(v),Some(delta)) = (c.value.checked_add_signed(d),c.delta.checked_add(d)) {
                                if value(&p,src,false) == Some(c.value) && value(&p,dst,true) == Some(v) {
                                    if c.steps.len()+1 >= 128 || steps >= 8192 { return Err(invalid("chain capacity")); } steps += 1;
                                    let mut c = c.clone(); c.steps.push(AddressDefinitionStepDto {seq,operation:m.into(),source_operand:operands[1..].join(", "),target_operand:operands[0].into(),pre_value:hex(c.value),post_value:hex(v)}); c.value=v; c.delta=delta; copied=Some((dst,c));
                                } else { chains.clear(); gap(&mut gaps,seq,"copy_mismatch"); }
                            }
                        }
                    }
                }
            }
            if matches!(m,"mov"|"add"|"sub") && operands.get(1).and_then(|s| trace_parser::strict_memory::integer_register(s)).is_some_and(|r| chains.contains_key(&r)) && copied.is_none() {
                gap(&mut gaps,seq,"untracked_register_use");
            }
            if m != "ret" {
                for r in defs { chains.remove(&r); }
                // Explicit operand identities also cover W aliases and both pair destinations.
                if !m.starts_with("st") {
                    if let Some(es) = &elements { for e in es { chains.remove(&e.register); } }
                }
                if matches!(m,"mov"|"add"|"sub") {
                    if let Some(r) = operands.first().and_then(|s| trace_parser::strict_memory::integer_register(s)) { chains.remove(&r); }
                }
            }
            if supported_data && matches!(m,"mov"|"add"|"sub") {
                if let Some(dst) = operands.first().and_then(|s| trace_parser::strict_memory::integer_register(s)) {
                    store_sources.remove(&dst);
                    loaded_values.remove(&dst);
                }
            }
            for r in stored_sources { store_sources.insert(r); }
            for (r,range) in new_loaded { loaded_values.insert(r,range); }
            if let Some((r,c)) = loaded.or(copied) { chains.insert(r,c); }
        }
        // Observation is execution-before resume, not after the resume instruction.
        if last < root.resume_seq { gap(&mut gaps,root.resume_seq,"final_observation_uncovered"); }
        // Every requested byte needs a known real last write. This is separate
        // from source/load use obligations and never a scalar type inference.
        for &(start,end) in &ranges {
            if (start..end).any(|at| final_bytes.get(&at).is_none_or(|(_,v)| v.is_none())) {
                gap(&mut gaps,root.resume_seq,"final_range_definition_uncovered");
            }
        }
        for u in &mut uses {
            let a = u64::from_str_radix(&u.slot_address[2..],16).unwrap();
            u.final_output_definition = final_stores.get(&a) == Some(&u.store_seq)
                && (a..a+8).all(|at| final_bytes.get(&at).is_some_and(|(seq,v)| *seq == u.store_seq && v.is_some()));
        }
        if uses.iter().any(|u| !u.final_output_definition) {
            gap(&mut gaps,root.resume_seq,"transient_store_not_final_output");
        }
        // Only this fixed kind is a non-blocking time-point diagnostic. Every
        // other gap is missing coverage; an empty uses list alone is no proof.
        // Complete means no unaccounted use in this finite executed window,
        // never that a value cannot be a pointer in any future language context.
        let complete = closed && last == wanted && scanned == wanted - entry_seq + 1
            && gaps.iter().all(|g| g.kind == "transient_store_not_final_output");
        Ok(OutputSlotUsesDto {trace_session:sid.into(),call_seq,entry_seq,function:function.into(),target_modules:modules.into_iter().collect(),exit_seq:root.exit_seq,resume_seq:root.resume_seq,slot_ranges:slot_ranges.to_vec(),caller:ReturnCallerDto {call_seq:caller.call_seq,entry_seq:caller.entry_seq,exit_seq:caller.exit_seq,resume_seq:caller.resume_seq,closed},uses,coverage:AddressCoverageDto {first_seq:entry_seq,last_seq:entry_seq+scanned.saturating_sub(1),scanned_lines:scanned,access_count,complete},gaps})
    }
}
