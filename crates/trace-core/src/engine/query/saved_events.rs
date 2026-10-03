//! Temporary saved-record observations. The caller authenticates capture roles;
//! this module only binds their existing event identity to this retained raw trace.
use serde::{Deserialize,Serialize};
use crate::{api_types::{GraphActivationSelectorDto},error::{Result,TraceError},session::SessionState};
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedEventMemory {pub address:String,pub size:u32,pub bytes:Option<String>}
#[derive(Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedEventObservation {
 pub owner:GraphActivationSelectorDto,pub event_index:u32,pub callsite:SavedEventAnchor,
 pub resume:SavedEventAnchor,pub target:SavedEventTarget,
 pub memory_reads:Vec<SavedEventMemory>,pub memory_writes:Vec<SavedEventMemory>,
}
#[derive(Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedEventAnchor {pub seq:u32,pub offset:String}
#[derive(Debug,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedEventTarget {pub module:Option<String>,pub entry:Option<String>,pub symbol:Option<String>}
fn invalid(s:&str)->TraceError{TraceError::InvalidArgument(format!("saved event observation: {s}"))}
pub(crate) fn memory_bytes(m:&SavedEventMemory)->Result<(u64,Vec<u8>)>{
 let address=m.address.strip_prefix("0x").and_then(|v|u64::from_str_radix(v,16).ok()).ok_or_else(||invalid("address"))?;
 if format!("0x{address:x}")!=m.address || m.size==0 || address.checked_add(u64::from(m.size)).is_none(){return Err(invalid("range"));}
 let hex=m.bytes.as_ref().ok_or_else(||invalid("unknown captured bytes"))?;
 if hex.len()!=m.size as usize*2 || !hex.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)){return Err(invalid("bytes"));}
 Ok((address,hex.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()))
}
/// Same branch classes as the existing annotation-backed Event collector.
/// Recorded calls keep their body effects visible; opaque effects cannot preserve winners.
pub(crate) fn opaque_boundary(state:&SessionState,tree:&crate::query::activation::ActivationTree,seq:u32,line:&str)->bool {
 let Some((m,_))=trace_parser::strict_memory::instruction_parts(line) else{return false};
 use trace_parser::insn_class::{classify,InsnClass};
 let class=classify(m,None);
 if m=="svc" {return true;}
 if tree.bypassed_calls.iter().any(|c|c.call_seq==seq){return true;}
 if matches!(class,InsnClass::BranchLink|InsnClass::BranchLinkReg) {
  return !tree.activations.iter().any(|a|a.id!=0 && a.call_seq==seq && a.unresolved_reason.is_none());
 }
 state.call_annotations.contains_key(&seq) && matches!(class,InsnClass::Branch|InsnClass::BranchReg)
}
/// An unknown instruction/effect is not evidence that captured memory survived.
pub(crate) fn possible_write(line:&str)->bool {
 let Some((m,_))=trace_parser::strict_memory::instruction_parts(line) else{return false};
 use trace_parser::insn_class::{classify,InsnClass};
 matches!(classify(m,None),InsnClass::StoreReg|InsnClass::StorePair|InsnClass::StoreExcl|InsnClass::SimdStore|InsnClass::AtomicLoadOp|InsnClass::CompareAndSwap)
  || m.starts_with("st") || (classify(m,None)==InsnClass::Nop && m!="nop")
}
/// Called after raw/event validation. Scope admission follows actual confirmed
/// ancestry, never an outer selector substituted for an event's real owner.
pub(crate) fn validate_scope(tree:&crate::query::activation::ActivationTree,root:&crate::query::activation::ConfirmedActivation,observations:&[SavedEventObservation])->Result<()> {
 for e in observations {
  let owner=tree.activation_for_seq(e.callsite.seq).ok_or_else(||invalid("scope owner"))?;
  if owner.call_seq!=e.owner.call_seq || owner.entry_seq!=e.owner.entry_seq || owner.exit_seq!=e.owner.exit_seq || owner.resume_seq!=e.owner.resume_seq {return Err(invalid("actual scope owner mismatch"));}
  let mut current=owner;let mut admitted=false;
  for _ in 0..128 {
   if current.unresolved_reason.is_some(){break;}
   if current.id==root.id{admitted=true;break;}
   if current.call_seq<root.entry_seq || current.resume_seq>root.exit_seq{break;}
   let Some(parent)=current.parent_id.and_then(|id|tree.activations.get(id as usize)) else{break;};current=parent;
  }
  if !admitted{return Err(invalid("event outside query closure"));}
 }Ok(())
}
pub(crate) fn validate(state:&SessionState,observations:&[SavedEventObservation])->Result<()> {
 if observations.len()>128{return Err(invalid("event capacity"));}
 let tree=state.activation_tree.as_ref().ok_or(TraceError::IndexNotReady)?;
 let index=state.line_index_view().ok_or(TraceError::IndexNotReady)?;
 let raw=|seq|->Result<&str>{std::str::from_utf8(index.get_line(&state.mmap,seq).ok_or_else(||invalid("raw seq"))?).map_err(|_|invalid("UTF8"))};
 let mut seen=std::collections::BTreeSet::new();let mut total=0usize;
 for e in observations {
  if !seen.insert(e.callsite.seq){return Err(invalid("duplicate call"));}
  let owner=tree.activations.iter().find(|a|a.id!=0 && a.call_seq==e.owner.call_seq && a.entry_seq==e.owner.entry_seq && a.exit_seq==e.owner.exit_seq && a.resume_seq==e.owner.resume_seq && a.unresolved_reason.is_none()).ok_or_else(||invalid("owner"))?;
  if super::activation::stable_site(raw(owner.entry_seq)?).as_deref()!=Some(&e.owner.function){return Err(invalid("owner function"));}
  let calls=tree.bypassed_calls.iter().filter(|c|c.parent_id==Some(owner.id)).collect::<Vec<_>>();
  let c=calls.get(e.event_index as usize).ok_or_else(||invalid("event index"))?;
  if c.call_seq!=e.callsite.seq || c.resume_seq!=e.resume.seq || c.call_seq<owner.entry_seq || c.resume_seq>owner.exit_seq{return Err(invalid("call/resume"));}
  if super::activation::stable_site(raw(c.call_seq)?).as_deref()!=Some(&e.callsite.offset) || super::activation::stable_site(raw(c.resume_seq)?).as_deref()!=Some(&e.resume.offset){return Err(invalid("anchors"));}
  if !trace_parser::strict_memory::instruction_parts(raw(c.call_seq)?).is_some_and(|(m,_)|matches!(m,"bl"|"blr")){return Err(invalid("call instruction"));}
  let call=super::activation::stable_runtime_site(raw(c.call_seq)?).ok_or_else(||invalid("call site"))?;
  let resume=super::activation::stable_runtime_site(raw(c.resume_seq)?).ok_or_else(||invalid("resume site"))?;
  if call.0!=resume.0 || call.1.checked_add(4)!=Some(resume.1){return Err(invalid("resume PC"));}
  for seq in c.call_seq+1..c.resume_seq {if trace_parser::strict_memory::instruction_parts(raw(seq)?).is_some() || trace_parser::gumtrace::parse_special_line(raw(seq)?).is_none(){return Err(invalid("recorded body or unknown intermediate row"));}}
  let symbol=state.call_annotations.get(&c.call_seq).map(|a|a.func_name.as_str());
  if e.target.module.is_some() || e.target.entry.is_some() || e.target.symbol.as_deref()!=symbol || symbol.is_none(){return Err(invalid("target identity"));}
  for list in [&e.memory_reads,&e.memory_writes] {
   if list.len()>8192{return Err(invalid("memory capacity"));}
   let mut ranges=Vec::new();
   for m in list {
    total=total.checked_add(m.size as usize).filter(|n|*n<=32*1024*1024).ok_or_else(||invalid("capture capacity"))?;
    let (a,bytes)=memory_bytes(m)?;let end=a+bytes.len() as u64;
    if ranges.iter().any(|&(b,e)|a<e && b<end){return Err(invalid("overlapping observations"));}ranges.push((a,end));
   }
  }
 }
 Ok(())
}
