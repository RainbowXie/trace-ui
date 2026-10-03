//! Strict recorded descendant scan for address definitions, not callee output
//! inference. Opaque boundaries stop identity; every raw DEF remains visible.
use crate::{error::{Result,TraceError},session::SessionState,query::activation::{ActivationTree,ConfirmedActivation}};
use std::sync::atomic::{AtomicBool,Ordering};
pub(super) fn scan(state:&SessionState,tree:&ActivationTree,root:&ConfirmedActivation,cancel:&AtomicBool,mut visit:impl FnMut(u32,&str)->Result<bool>)->Result<()> {
 let index=state.line_index_view().ok_or(TraceError::IndexNotReady)?;
 let raw=|seq|->Result<&str>{let bytes=index.get_line(&state.mmap,seq).ok_or_else(||TraceError::InvalidArgument("global closure raw missing".into()))?;super::block_stream::check_raw(bytes)?;std::str::from_utf8(bytes).map_err(|e|TraceError::InvalidArgument(e.to_string()))};
 for seq in root.entry_seq..=root.exit_seq {
  if cancel.load(Ordering::Relaxed){return Err(TraceError::Cancelled);}
  let line=raw(seq)?;
  if trace_parser::strict_memory::instruction_parts(line).is_none(){
   if trace_parser::gumtrace::parse_special_line(line).is_some(){continue;}return Err(TraceError::InvalidArgument("global closure unknown row".into()));
  }
  let Some(owner)=tree.activation_for_seq(seq) else{return Err(TraceError::InvalidArgument("global closure owner missing".into()))};
  let mut a=owner;let mut contained=false;
  for _ in 0..128 {
   if a.id==root.id{contained=true;break;}
   if a.unresolved_reason.is_some() || a.call_seq<root.entry_seq || a.resume_seq>root.exit_seq{return Err(TraceError::InvalidArgument("global closure unclosed child".into()));}
   let call=raw(a.call_seq)?;let (m,op)=trace_parser::strict_memory::instruction_parts(call).ok_or(TraceError::IndexNotReady)?;
   let target=if m=="bl"{trace_parser::strict_memory::integer_immediate(op).and_then(|v|u64::try_from(v).ok())}else if m=="blr"{trace_parser::strict_memory::observed_register_value(call,op,false)}else{None};
   let entry=super::super::activation::stable_runtime_site(raw(a.entry_seq)?).ok_or(TraceError::IndexNotReady)?;
   let site=super::super::activation::stable_runtime_site(call).ok_or(TraceError::IndexNotReady)?;
   let resume=super::super::activation::stable_runtime_site(raw(a.resume_seq)?).ok_or(TraceError::IndexNotReady)?;
   if target!=Some(entry.1) || site.0!=entry.0 || site.0!=resume.0 || site.1.checked_add(4)!=Some(resume.1)
    || !trace_parser::strict_memory::instruction_parts(raw(a.exit_seq)?).is_some_and(|(m,_)|m=="ret"){return Err(TraceError::InvalidArgument("global closure call boundary".into()));}
   a=tree.activations.get(a.parent_id.unwrap_or(0) as usize).ok_or(TraceError::IndexNotReady)?;
  }
  if !contained{return Err(TraceError::InvalidArgument("global closure depth".into()));}
  if !visit(seq,line)?{break;}
 }
 Ok(())
}
