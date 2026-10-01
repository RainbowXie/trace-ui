//! Fixed leaf/frame subset raw ingredients, without provenance or private-object conclusions.
use super::super::activation::{stable_runtime_site, stable_site};
use crate::{api_types::*, error::{Result, TraceError}};
use std::collections::BTreeSet;
use trace_parser::types::{ParsedLine, RegId};
fn invalid(s: &str) -> TraceError { TraceError::InvalidArgument(s.into()) }
fn hex(v: u64) -> String { format!("0x{v:x}") }
fn reg(s: &str) -> Option<RegId> {
    let r = trace_parser::types::parse_reg(s)?;
    (matches!(s, "sp" | "fp" | "lr") || (s.starts_with('x') && r.0 < 31 && s == format!("x{}",r.0))).then_some(r)
}
fn value(p: &ParsedLine, r: RegId, post: bool) -> Option<u64> {
    let list = if post { &p.post_arrow_regs } else { &p.pre_arrow_regs };
    let mut it = list.as_ref()?.iter().filter(|(id,_)| *id == r).map(|(_,v)| *v);
    let v = it.next()?; it.all(|n| n == v).then_some(v)
}
fn immediate(s: &str) -> Option<i64> {
    let s = s.strip_prefix('#')?;
    let (neg,s) = s.strip_prefix('-').map_or((false,s), |s| (true,s));
    let n: i64 = if let Some(s) = s.strip_prefix("0x") { i64::from_str_radix(s,16).ok()? } else { s.parse().ok()? };
    if neg { n.checked_neg() } else { Some(n) }
}
fn role(p: &ParsedLine, name: &str, text: &str) -> Option<PrivateOperandRoleDto> {
    let r = reg(text)?;
    Some(PrivateOperandRoleDto { role:name.into(), operand:text.into(), register:if r.0 == 31 { "sp".into() } else { format!("x{}",r.0) }, width:64, pre_value:value(p,r,false).map(hex), post_value:value(p,r,true).map(hex) })
}
fn gap(g: &mut Vec<AddressGapDto>, seq: u32, kind: &str) {
    g.push(AddressGapDto {seq,kind:kind.into(),detail:"raw ingredient unsupported or missing; not private-object evidence".into()});
}
impl crate::engine::TraceEngine {
    pub fn get_private_frame_operands(&self, sid: &str, call_seq: u32, entry_seq: u32, function: &str, target_modules: &[String]) -> Result<PrivateFrameOperandsDto> {
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.len() != target_modules.len() || modules.len() > 500 || modules.iter().any(|m| stable_site(&format!("[{m}] 0x0!0x0 nop")).as_deref() != Some(&format!("{m}+0x0"))) { return Err(invalid("invalid target_modules")); }
        let handle = self.get_handle(sid)?;
        let state = handle.state.read().map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state.activation_tree.as_ref().ok_or(TraceError::IndexNotReady)?;
        let root = tree.activations.iter().find(|a| a.id != 0 && a.call_seq == call_seq && a.entry_seq == entry_seq).ok_or_else(|| invalid("root selector not found"))?;
        if root.unresolved_reason.is_some() || !(call_seq < entry_seq && entry_seq <= root.exit_seq && root.exit_seq < root.resume_seq && root.resume_seq < state.total_lines) { return Err(invalid("closed confirmed root required")); }
        let count = root.exit_seq.checked_sub(entry_seq).and_then(|n| n.checked_add(1)).ok_or_else(|| invalid("window overflow"))?;
        if count > 50_000 { return Err(invalid("line capacity exceeded")); }
        let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let raw = |seq| -> Result<&str> { std::str::from_utf8(index.get_line(&state.mmap,seq).ok_or_else(|| invalid("missing line"))?).map_err(|_| invalid("invalid UTF8")) };
        if stable_site(raw(entry_seq)?).as_deref() != Some(function) { return Err(invalid("function site mismatch")); }
        for seq in [call_seq,entry_seq,root.exit_seq,root.resume_seq] { if stable_runtime_site(raw(seq)?).is_none() || trace_parser::strict_memory::instruction_parts(raw(seq)?).is_none() { return Err(invalid("boundary lacks real site")); } }
        let mut instructions = Vec::new(); let mut gaps = Vec::new(); let mut bytes = 0usize; let mut accesses = 0usize;
        if tree.activations.iter().any(|a| a.parent_id == Some(root.id)) { gap(&mut gaps,entry_seq,"child_activation"); }
        // Only explicit printed SP observations are used; no entry replay fills gaps.
        let mut frame: Option<(u64,u64,i64)> = None;
        let mut restored = false;
        for seq in entry_seq..=root.exit_seq {
            let line = raw(seq)?;
            bytes = bytes.checked_add(line.len()).ok_or_else(|| invalid("raw overflow"))?;
            if bytes > 32*1024*1024 || line.len() > 4096 { return Err(invalid("raw capacity exceeded")); }
            let owner = tree.activation_for_seq(seq).filter(|a| a.id != 0 && a.unresolved_reason.is_none());
            if owner.is_none_or(|a| a.id != root.id) { gap(&mut gaps,seq,"ownership"); }
            let parts = trace_parser::strict_memory::instruction_parts(line);
            if parts.is_some_and(|(_,op)| op.len() > 512) { return Err(invalid("operand capacity exceeded")); }
            let mut row = PrivateInstructionDto {seq,raw_line:line.into(),site:stable_site(line),owner_entry_seq:owner.map(|a| a.entry_seq),mnemonic:parts.map(|(m,_)|m.into()),operand:parts.map(|(_,op)|op.into()),roles:Vec::new(),immediate:None,memory:None};
            let parsed = if line.contains("!0x") { trace_parser::gumtrace::parse_line_gumtrace_full(line) } else { trace_parser::parser::parse_line_full(line) };
            let (Some((m,op)),Some(p)) = (parts,parsed) else { gap(&mut gaps,seq,"unsupported_parse_or_special"); instructions.push(row); continue; };
            let args = op.split(',').map(str::trim).collect::<Vec<_>>();
            let mut supported = false;
            match (m,args.as_slice()) {
                ("mov",[dst,src]) => {
                    if let Some(d) = role(&p,"destination",dst) {
                        let source = role(&p,"copy_source",src);
                        row.immediate = immediate(src);
                        let expected = reg(src).and_then(|r|value(&p,r,false)).or_else(|| row.immediate.and_then(|n|u64::try_from(n).ok()));
                        supported = *dst != "sp" && expected.is_some() && reg(dst).and_then(|r|value(&p,r,true)) == expected;
                        row.roles.push(d); if let Some(s) = source { row.roles.push(s); }
                    }
                },
                ("add" | "sub",[dst,src,imm]) => {
                    row.immediate = immediate(imm);
                    if let (Some(d),Some(s)) = (role(&p,"destination",dst),role(&p,"arithmetic_source",src)) {
                        let delta = row.immediate.and_then(|n|if m == "sub" { n.checked_neg() } else { Some(n) });
                        let pre = reg(src).and_then(|r|value(&p,r,false));
                        let post = reg(dst).and_then(|r|value(&p,r,true));
                        supported = pre.zip(delta).and_then(|(v,n)|v.checked_add_signed(n)).is_some_and(|v|Some(v) == post);
                        row.roles.extend([d,s]);
                        if *dst == "sp" {
                            supported &= *src == "sp";
                            if supported && m == "sub" && seq == entry_seq && row.immediate.is_some_and(|n|n > 0) && frame.is_none() {
                                frame = Some((pre.unwrap(),post.unwrap(),row.immediate.unwrap()));
                            } else if supported && m == "add" && seq.checked_add(1) == Some(root.exit_seq) && !restored && frame.is_some_and(|(s,b,n)|pre == Some(b) && post == Some(s) && row.immediate == Some(n)) {
                                restored = true;
                            } else { gap(&mut gaps,seq,"unsupported_sp_change"); }
                        }
                    }
                },
                ("ldr" | "ldur" | "str" | "stur",_) => {
                    accesses += 1; if accesses > 8192 { return Err(invalid("memory capacity exceeded")); }
                    let write = m.starts_with("st");
                    if let Some((data,address)) = op.split_once(',') {
                        let label = address.trim();
                        let address_parts = label.strip_prefix('[').and_then(|s|s.strip_suffix(']')).map(|s|s.split(',').map(str::trim).collect::<Vec<_>>());
                        if let Some(parts) = address_parts {
                            let base = parts.first().copied().unwrap_or("");
                            let offset = match parts.as_slice() { [_] => Some(0),[_,off] => immediate(off),_ => None };
                            row.immediate = offset;
                            if let Some(r) = role(&p,"address_base",base) { row.roles.push(r); }
                            if let Some(r) = role(&p,if write {"store_data"} else {"load_destination"},data.trim()) { row.roles.push(r); }
                            if let Some(mem) = trace_parser::strict_memory::memory_op(line) {
                                let size = u32::from(mem.elem_width)*u32::from(mem.value_count);
                                if size == 8 && mem.value_count == 1 && reg(data.trim()).is_some_and(|r|r.0 < 31) {
                                    let observed = super::byte_effect::memory_bytes(line,size);
                                    supported = reg(base).and_then(|r|value(&p,r,false)).zip(offset).and_then(|(v,n)|v.checked_add_signed(n)) == Some(mem.abs)
                                        && mem.abs.checked_add(8).is_some() && mem.is_write == write && observed.iter().all(Option::is_some)
                                        && reg(data.trim()).and_then(|r|value(&p,r,!write)) == mem.value;
                                    row.memory = Some(PrivateMemoryDto {address:hex(mem.abs),size,rw:if write {"write"} else {"read"}.into(),bytes:observed});
                                }
                            }
                        }
                    }
                },
                ("nop",[""]) => { supported = true; },
                ("ret",[""]) => {
                    for (name,r) in [("return_value","x0"),("return_target","lr"),("stack_state","sp")] { row.roles.push(role(&p,name,r).unwrap()); }
                    supported = seq == root.exit_seq && [RegId(0),RegId(30),RegId(31)].iter().all(|r|value(&p,*r,false).is_some())
                        && value(&p,RegId(30),false) == stable_runtime_site(raw(root.resume_seq)?).map(|(_,pc,_)|pc);
                    if !frame.is_some_and(|(s,_,_)|restored && value(&p,RegId(31),false) == Some(s)) { gap(&mut gaps,seq,"sp_not_restored"); }
                },
                _ => {},
            }
            // Unexpected memory markers on non-memory instructions cannot vanish.
            if !matches!(m,"ldr"|"ldur"|"str"|"stur") && (trace_parser::strict_memory::memory_marker(line).is_some() || line.contains("mem_w=") || line.contains("mem_r=") || line.contains("abs=")) { supported = false; }
            // Explicit SP observations between allocation/restoration must agree.
            if let Some((s,b,_)) = frame {
                if !matches!(row.roles.first().map(|r|r.register.as_str()),Some("sp")) || !matches!(m,"add"|"sub") {
                    let expected = if restored {s} else {b};
                    if value(&p,RegId(31),false).is_some_and(|v|v != expected) || value(&p,RegId(31),true).is_some_and(|v|v != expected) { gap(&mut gaps,seq,"sp_observation_mismatch"); }
                }
            }
            if m != "ret" { row.roles.push(role(&p,"stack_state","sp").unwrap()); }
            if !supported { gap(&mut gaps,seq,"unsupported_instruction_operand_or_value"); }
            instructions.push(row);
        }
        if frame.is_none() || !restored { gap(&mut gaps,root.exit_seq,"fixed_frame_incomplete"); }
        Ok(PrivateFrameOperandsDto {trace_session:sid.into(),call_seq,entry_seq,function:function.into(),target_modules:modules.into_iter().collect(),exit_seq:root.exit_seq,resume_seq:root.resume_seq,coverage:AddressCoverageDto {first_seq:entry_seq,last_seq:root.exit_seq,scanned_lines:count,access_count:accesses,complete:gaps.is_empty()},instructions,gaps})
    }
}
