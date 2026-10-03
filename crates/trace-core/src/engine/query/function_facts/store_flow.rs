//! Current candidate-derived byte winners, not persistent write history.
//! A boolean is the union of all candidate origins: no first-source selection.
use super::fact_work::Fixed;
use crate::error::{Result,TraceError};
#[derive(Clone,Copy)]
struct Byte {address:u64,value:u8,seq:u32,owner:u32}
pub(super) struct StoreFlow {bytes:Fixed<Byte>}
impl StoreFlow {
 pub(super) fn new()->Result<Self>{Ok(Self{bytes:Fixed::new()?})}
 pub(super) fn write(&mut self,address:u64,width:u8,value:u64,candidate:bool,seq:u32,owner:u32)->Result<()> {
  if width==0 || width>8{return Err(TraceError::Internal("store flow width".into()));}
  let end=address.checked_add(u64::from(width)).ok_or_else(||TraceError::Internal("store flow range overflow".into()))?;
  self.bytes.values.retain(|b|b.address<address || b.address>=end);
  if candidate {for (i,value) in value.to_le_bytes().iter().take(width as usize).enumerate(){
   let address=address+i as u64;let pos=self.bytes.values.binary_search_by_key(&address,|b|b.address).unwrap_err();
   self.bytes.insert(pos,Byte{address,value:*value,seq,owner})?;
  }}Ok(())
 }
 pub(super) fn read(&self,address:u64,width:u8,value:u64)->Result<bool>{
  if width==0 || width>8{return Err(TraceError::Internal("store flow width".into()));}
  let mut candidate=false;
  for (i,value) in value.to_le_bytes().iter().take(width as usize).enumerate(){
   let address=address.checked_add(i as u64).ok_or_else(||TraceError::Internal("store flow read overflow".into()))?;
   if let Ok(pos)=self.bytes.values.binary_search_by_key(&address,|b|b.address){
    let b=&self.bytes.values[pos];let _writer=(b.seq,b.owner);
    if b.value!=*value{return Err(TraceError::InvalidArgument("candidate store/load bytes disagree".into()));}candidate=true;
   }
  }Ok(candidate)
 }
 pub(super) fn live(&self)->bool{!self.bytes.values.is_empty()}
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn bounded_bytes_preserve_partial_sources_and_refuse_capacity(){
  let mut flow=StoreFlow{bytes:Fixed::with_bytes(2*std::mem::size_of::<Byte>()).unwrap()};
  flow.write(10,2,0x0201,true,3,2).unwrap();assert!(flow.read(10,2,0x0201).unwrap());
  assert!(matches!(flow.write(12,1,3,true,4,2),Err(TraceError::Internal(_))));
  flow.write(10,1,0,false,5,2).unwrap();assert!(flow.read(10,2,0x0200).unwrap());
  assert!(flow.read(11,1,3).is_err());flow.write(11,1,0,false,6,2).unwrap();assert!(!flow.live());
 }
}
