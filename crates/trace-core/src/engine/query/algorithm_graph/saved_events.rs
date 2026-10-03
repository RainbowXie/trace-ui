//! Captured event-write winners to subsequent actual raw loads, never library
//! instructions or an invented top-level DynamicSource read index.
use std::collections::BTreeMap;
use crate::{engine::SavedEventObservation,error::{Result,TraceError},session::SessionState};
pub(super) fn load_edges(state:&SessionState,events:&[SavedEventObservation],target:u32,cancel:&std::sync::atomic::AtomicBool)->Result<Vec<(u32,u32)>> {
 if events.is_empty(){return Ok(Vec::new());}
 super::super::saved_events::validate(state,events)?;
 if target>=50_000{return Err(TraceError::InvalidArgument("saved event graph line capacity".into()));}
 let index=state.line_index_view().ok_or(TraceError::IndexNotReady)?;
 let tree=state.activation_tree.as_ref().ok_or(TraceError::IndexNotReady)?;
 let mut bytes=BTreeMap::<u64,(u8,u32)>::new();let mut edges=Vec::new();
 for seq in 0..=target {
  if cancel.load(std::sync::atomic::Ordering::Relaxed){return Err(TraceError::Cancelled);}
  if let Some(e)=events.iter().find(|e|e.resume.seq==seq) {
   for m in &e.memory_writes {let (address,values)=super::super::saved_events::memory_bytes(m)?;
    for (i,v) in values.into_iter().enumerate(){if bytes.len()>=1_048_576 && !bytes.contains_key(&(address+i as u64)){return Err(TraceError::InvalidArgument("event graph byte capacity".into()));}bytes.insert(address+i as u64,(v,e.callsite.seq));}
   }
  }
  let raw=index.get_line(&state.mmap,seq).ok_or_else(||TraceError::InvalidArgument("event graph raw missing".into()))?;
  let line=std::str::from_utf8(raw).map_err(|_|TraceError::InvalidArgument("event graph UTF8".into()))?;
  if super::super::saved_events::opaque_boundary(state,tree,seq,line) {
   // No unknown opaque call can preserve a preceding capture winner.
   bytes.clear();
  }
  let memory=trace_parser::strict_memory::memory_op(line);
  // A proved failed exclusive store has no write effect. Unknown success does.
  if memory.as_ref().is_some_and(|m|m.is_write && m.exclusive_status.is_some_and(|s|s!=0)){continue;}
  let Some((write,address))=trace_parser::strict_memory::memory_marker(line) else{
   if super::super::saved_events::possible_write(line) || line.contains("mem_w=") || line.contains("mem[WRITE]") {bytes.clear();}
   continue
  };
  if memory.is_none() || (super::super::saved_events::possible_write(line) && !write){bytes.clear();continue;}
  let Some(elements)=trace_parser::strict_memory::integer_memory_elements(line) else{bytes.clear();continue};
  let width=elements.iter().map(|e|u64::from(e.width)).sum::<u64>();
  let end=address.checked_add(width).ok_or_else(||TraceError::InvalidArgument("event graph address overflow".into()))?;
  if write {bytes.retain(|a,_|!(*a>=address && *a<end));continue;}
  let mut offset=0;let mut producers=std::collections::BTreeSet::new();let mut covered=true;
  for e in elements {
   let Some(value)=e.value else{covered=false;break};let observed=value.to_le_bytes();
   for i in 0..e.width {match bytes.get(&(address+offset+u64::from(i))) {
    Some((v,call)) if *v==observed[i as usize]=>{producers.insert(*call);},
    _=>covered=false,
   }}offset+=u64::from(e.width);
  }
  if !covered && bytes.range(address..end).next().is_some(){return Err(TraceError::InvalidArgument("event graph partial or mismatched read".into()));}
  if covered {for call in producers {edges.push((call,seq));}}
 }
 Ok(edges)
}
