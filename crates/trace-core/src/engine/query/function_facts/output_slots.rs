//! Exact observed store -> last-definition load -> operand-labelled address use.
//! Deliberately does not infer pointers from numeric ranges or store-data reads.
use super::super::activation::{stable_runtime_site, stable_site};
use crate::{api_types::*, error::{Result, TraceError}};
use std::collections::{BTreeSet, HashMap};
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
fn immediate(s: &str) -> Option<i64> {
    let s = s.strip_prefix('#')?;
    let (neg,n) = s.strip_prefix('-').map_or((false,s), |n| (true,n));
    let v = if let Some(h) = n.strip_prefix("0x") { i64::from_str_radix(h,16).ok()? } else { n.parse().ok()? };
    if neg { v.checked_neg() } else { Some(v) }
}
fn address_base(s: &str) -> Option<RegId> {
    if s == "sp" { trace_parser::types::parse_reg(s) } else { reg64(s) }
}
fn address_operand(s: &str) -> Option<(&str, RegId, i64)> {
    let label = &s[s.find('[')?..];
    let inside = label.strip_prefix('[')?.strip_suffix(']')?;
    let parts = inside.split(',').map(str::trim).collect::<Vec<_>>();
    match parts.as_slice() {
        [base] => Some((label, address_base(base)?, 0)),
        [base,off] => Some((label, address_base(base)?, immediate(off)?)),
        _ => None,
    }
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
        let mut chains = HashMap::<RegId,Chain>::new();
        let mut uses = Vec::new(); let mut bytes = 0usize; let mut scanned = 0u32; let mut access_count = 0; let mut steps = 0usize;
        for seq in entry_seq..=last {
            if seq == root.resume_seq { final_stores = stores.iter().map(|(a,s)| (*a,s.seq)).collect(); chains.clear(); }
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
            let (defs,_) = trace_parser::def_use::determine_def_use(class,&p);
            if matches!(m,"bl"|"blr"|"svc") || (matches!(class,trace_parser::insn_class::InsnClass::Nop) && m != "nop") { stores.clear(); chains.clear(); gap(&mut gaps,seq,"call_external_or_unknown"); continue; }
            let marker = trace_parser::strict_memory::memory_marker(line);
            let mem = trace_parser::strict_memory::memory_op(line);
            let mut loaded = None;
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
                    if write {
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
                            } else { gap(&mut gaps,seq,"unknown_store_value"); }
                        } else if ranges.iter().any(|&(b,e)| a < e && b < end) { gap(&mut gaps,seq,"partial_or_unsupported_store"); }
                    } else {
                        let op = mem.as_ref().unwrap();
                        let dst = operand.split(',').next().unwrap_or("").trim();
                        if size == 8 && op.value_count == 1 {
                            if let (Some(s),Some(r)) = (stores.get(&a),reg64(dst)) {
                                if op.value == Some(s.value) && value(&p,r,true) == Some(s.value) && defs.contains(&r) {
                                    loaded = Some((r,Chain {slot:a,store:s.clone(),load:seq,owner:owner.entry_seq,dst:dst.into(),value:s.value,delta:0,steps:vec![AddressDefinitionStepDto {seq,operation:"load".into(),source_operand:hex(a),target_operand:dst.into(),pre_value:hex(s.value),post_value:hex(s.value)}]}));
                                } else { gap(&mut gaps,seq,"load_mismatch"); }
                            }
                        } else if ranges.iter().any(|&(b,e)| a < e && b < end) { gap(&mut gaps,seq,"partial_or_pair_load"); }
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
            if m != "ret" { for r in defs { chains.remove(&r); } }
            if let Some((r,c)) = loaded.or(copied) { chains.insert(r,c); }
        }
        // Observation is execution-before resume, not after the resume instruction.
        if last < root.resume_seq { gap(&mut gaps,root.resume_seq,"final_observation_uncovered"); }
        for u in &mut uses { let a = u64::from_str_radix(&u.slot_address[2..],16).unwrap(); u.final_output_definition = final_stores.get(&a) == Some(&u.store_seq); }
        if uses.iter().any(|u| !u.final_output_definition) {
            gap(&mut gaps,root.resume_seq,"transient_store_not_final_output");
        }
        // This subset never claims a complete negative: unsupported non-address
        // reads/escapes and external effects are not exhaustively tracked.
        gap(&mut gaps,last,"negative_coverage_not_supported");
        Ok(OutputSlotUsesDto {trace_session:sid.into(),call_seq,entry_seq,function:function.into(),target_modules:modules.into_iter().collect(),exit_seq:root.exit_seq,resume_seq:root.resume_seq,slot_ranges:slot_ranges.to_vec(),caller:ReturnCallerDto {call_seq:caller.call_seq,entry_seq:caller.entry_seq,exit_seq:caller.exit_seq,resume_seq:caller.resume_seq,closed},uses,coverage:AddressCoverageDto {first_seq:entry_seq,last_seq:entry_seq+scanned.saturating_sub(1),scanned_lines:scanned,access_count,complete:false},gaps})
    }
}
