//! Compact response accounting before retaining distinct output items. Internal
//! boundary workspace has a separate resource bound, not a Schema output claim.
use crate::error::{Result,TraceError};
use serde::Serialize;
pub(super) const LIMIT:usize=64*1024*1024;
fn overflow()->TraceError{TraceError::InvalidArgument("Graph fact response capacity exceeded".into())}
struct Counter(usize);
impl std::io::Write for Counter {
 fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0=self.0.checked_add(b.len()).ok_or_else(||std::io::Error::other("Graph size overflow"))?;Ok(b.len())}
 fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
pub(super) fn size(value:&impl Serialize)->Result<usize>{let mut c=Counter(0);serde_json::to_writer(&mut c,value).map_err(|e|TraceError::Internal(e.to_string()))?;Ok(c.0)}
pub(super) struct GraphBudget{used:usize,limit:usize}
impl GraphBudget {
 pub(super) fn new()->Self{Self{used:0,limit:LIMIT}}
 pub(super) fn envelope(&mut self,value:&impl Serialize)->Result<()> {self.reserve(value,false)}
 pub(super) fn reserve(&mut self,value:&impl Serialize,comma:bool)->Result<()> {
  let next=self.used.checked_add(size(value)?).and_then(|n|n.checked_add(usize::from(comma))).ok_or_else(overflow)?;
  if next>self.limit{return Err(overflow());}self.used=next;Ok(())
 }
 pub(super) fn push<T:Serialize+PartialEq>(&mut self,out:&mut Vec<T>,value:T)->Result<()> {
  if out.contains(&value){return Ok(());}self.reserve(&value,!out.is_empty())?;out.push(value);Ok(())
 }
 pub(super) fn verify(&self,value:&impl Serialize)->Result<()> {if size(value)?>self.limit{Err(overflow())}else{Ok(())}}
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn exact_boundary_dedupe_and_escaped_text_reserve_before_push(){
  let text="\"\n\\".repeat(8);let n=size(&text).unwrap();let mut b=GraphBudget{used:0,limit:n};let mut out=Vec::new();b.push(&mut out,text.clone()).unwrap();b.push(&mut out,text.clone()).unwrap();assert_eq!(out.len(),1);
  assert!(b.push(&mut out,"x".to_owned()).is_err());assert_eq!(out.len(),1);
  let mut b=GraphBudget{used:0,limit:n-1};assert!(b.push(&mut Vec::new(),text).is_err());
 }
}
