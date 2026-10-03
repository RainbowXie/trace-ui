//! Pure observed integer/control effects shared by independent raw consumers.
//! Numerical agreement is necessary, never a pointer or ownership classification.
use crate::{strict_memory as s,types::RegId};
pub struct IntegerDefinition { pub destination:RegId, pub sources:Vec<RegId>, pub value:u64 }
pub fn integer_definition(line:&str)->Option<IntegerDefinition> {
 let (m,op)=s::instruction_parts(line)?;let args=op.split(',').map(str::trim).collect::<Vec<_>>();
 let dst=*args.first()?;let destination=s::integer_register(dst)?;if destination.is_zero(){return None;}
 let width=if dst.starts_with('w'){32}else{64};let mask=if width==32{u32::MAX as u64}else{u64::MAX};
 let mut sources=Vec::new();
 let mut source=|operand:&str|->Option<u64>{
  if let Some(r)=s::integer_register(operand){if !r.is_zero(){sources.push(r);}s::observed_register_value(line,operand,false)}
  else{s::integer_immediate(operand).and_then(|v|u64::try_from(v).ok())}
 };
 let expected=match (m,args.as_slice()) {
  ("mov",[_,a])=>source(a)?,
  ("add",[_,a,b])=>source(a)?.checked_add(source(b)?)?,
  ("sub",[_,a,b])=>source(a)?.checked_sub(source(b)?)?,
  _=>return None,
 };
 if expected>mask || s::observed_register_value(line,dst,true)!=Some(expected){return None;}
 Some(IntegerDefinition{destination,sources,value:expected})
}
fn target(text:&str)->Option<u64>{s::integer_immediate(text).and_then(|v|u64::try_from(v).ok())}
/// Requires the actual next PC and current PC; target spelling alone is no proof.
pub fn branch_next(line:&str,pc:u64,next:u64)->bool {
 let Some((m,op))=s::instruction_parts(line) else{return false};
 let args=op.split(',').map(str::trim).collect::<Vec<_>>();
 let expected=match (m,args.as_slice()) {
  ("b",[to])=>target(to),
  ("cbz"|"cbnz",[reg,to])=>s::observed_register_value(line,reg,false).and_then(|v|{
   let taken=if m=="cbz"{v==0}else{v!=0};if taken{target(to)}else{pc.checked_add(4)}
  }),
  _=>None,
 };
 expected==Some(next)
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn observed_values_and_branch_targets_are_required(){
  assert!(integer_definition("[App] 0x100!0x100 add x9, x9, x5; x9=0x2 x5=0x1 -> x9=0x3").is_some());
  assert!(integer_definition("[App] 0x100!0x100 add x9, x9, x5; x9=0x2 -> x9=0x3").is_none());
  assert!(integer_definition("[App] 0x100!0x100 mov w9, #0; -> x9=0x100000000").is_none());
  assert!(branch_next("[App] 0x100!0x100 cbnz x8, #0x80; x8=0x1",0x100,0x80));
  assert!(!branch_next("[App] 0x100!0x100 cbnz x8, #0x80",0x100,0x80));
 }
}
