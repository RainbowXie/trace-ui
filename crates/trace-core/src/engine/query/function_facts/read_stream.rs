//! Fixed-layout external read fragments, grouped before formal reservations.
//! Conflicting or unknown observations remain null; scratch exhaustion is explicit.
use super::{
    block_stream::scan_owned,
    budget::Budget,
    collector,
    fact_work::{Dependency, Fixed},
    lines,
};
use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;
use std::sync::atomic::AtomicBool;

struct Reads<'a> {
    state: &'a SessionState,
    tree: &'a ActivationTree,
    root: &'a ConfirmedActivation,
    cancel: &'a AtomicBool,
    relevant: &'a Option<Fixed<Dependency>>,
    stack: &'a [FunctionStackArgumentDto],
    sp: u64,
}
impl Reads<'_> {
    fn scan(&self, mut visit: impl FnMut(u64, u32, Option<&str>, u32) -> Result<()>) -> Result<()> {
        scan_owned(self.state, self.tree, self.root, self.cancel, |insn| {
            let Some((m, op)) = trace_parser::strict_memory::instruction_parts(insn.line) else {
                return Ok(true);
            };
            let Some(address) = lines::line_mem_annotation(insn.line, "mem_r") else {
                return Ok(true);
            };
            let Some(size) = lines::access_width(m, op) else {
                return Ok(true);
            };
            if trace_parser::strict_memory::memory_op(insn.line).is_none()
                || address.checked_add(size as u64 - 1).is_none()
            {
                return Ok(true);
            }
            let mut relevant = self
                .relevant
                .as_ref()
                .is_none_or(|r| r.values.binary_search_by_key(&insn.seq, |d| d.seq).is_ok());
            if !relevant && super::dataflow::literal_load_address(m, op) == Some(address) {
                let register = op.split(',').next().unwrap_or("").trim();
                scan_owned(self.state, self.tree, self.root, self.cancel, |consumer| {
                    if consumer.seq > insn.seq {
                        if let Some((_, operands)) =
                            trace_parser::strict_memory::instruction_parts(consumer.line)
                        {
                            if operands.split(',').skip(1).any(|p| p.trim() == register) {
                                relevant = true;
                                return Ok(false);
                            }
                        }
                    }
                    Ok(true)
                })?;
            }
            if !relevant
                || (self.sp != u64::MAX
                    && self.stack.iter().any(|s| {
                        self.sp.checked_add(s.offset as u64) == Some(address) && s.size == size
                    }))
            {
                return Ok(true);
            }
            let external = super::memory_stream::external_mask(
                self.state,
                self.tree,
                self.root,
                self.cancel,
                address,
                size,
                insn.seq,
            )?;
            let bytes = super::byte_effect::memory_bytes(insn.line, size);
            let mut offset = 0;
            while offset < size as usize {
                if !external[offset] {
                    offset += 1;
                    continue;
                }
                let start = offset;
                while offset < size as usize && external[offset] {
                    offset += 1;
                }
                let range = &bytes[start..offset];
                // Fixed ISA-width scratch, never a growing output string.
                let mut hex = [0u8; 128];
                let known = range.iter().all(Option::is_some);
                if known {
                    const DIGITS: &[u8] = b"0123456789abcdef";
                    for (pos, byte) in range.iter().enumerate() {
                        let byte = byte.expect("known");
                        hex[pos * 2] = DIGITS[(byte >> 4) as usize];
                        hex[pos * 2 + 1] = DIGITS[(byte & 15) as usize];
                    }
                }
                visit(
                    address + start as u64,
                    range.len() as u32,
                    known.then(|| std::str::from_utf8(&hex[..range.len() * 2]).expect("hex")),
                    insn.seq,
                )?;
            }
            Ok(true)
        })
    }
}
struct Fragment { address:u64, size:u32, seq:u32, hex:[u8;128], known:bool }
impl Fragment {
    fn new(address:u64,size:u32,hex:Option<&str>,seq:u32)->Result<Self> {
        if size==0 || size>64 || address.checked_add(u64::from(size)-1).is_none()
            || hex.is_some_and(|h|h.len()!=size as usize*2) {return Err(TraceError::Internal("invalid read fragment".into()));}
        let mut out=Self{address,size,seq,hex:[0;128],known:hex.is_some()};
        if let Some(hex)=hex {out.hex[..hex.len()].copy_from_slice(hex.as_bytes());}Ok(out)
    }
}
fn group_known(group:&[Fragment])->bool {
    let first=&group[0];group.iter().all(|f|f.known && f.hex==first.hex)
}
struct GroupSeqs<'a> { fragments: &'a [Fragment], cancel: &'a AtomicBool }
impl serde::Serialize for GroupSeqs<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut out = serializer.serialize_seq(None)?;
        let mut last = None;
        for fragment in self.fragments {
            if self.cancel.load(std::sync::atomic::Ordering::Relaxed) {return Err(S::Error::custom("operation cancelled"));}
            if last!=Some(fragment.seq) {out.serialize_element(&fragment.seq).map_err(S::Error::custom)?;last=Some(fragment.seq);}
        }
        out.end()
    }
}
#[derive(serde::Serialize)]
struct Plain<'a, 'b> {
    address: &'a str,
    size: u32,
    bytes: Option<&'a str>,
    read_seqs: GroupSeqs<'b>,
}
#[derive(serde::Serialize)]
struct Global<'a, 'b> {
    global: &'a str,
    size: u32,
    bytes: Option<&'a str>,
    read_seqs: GroupSeqs<'b>,
}

pub(super) fn collect(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
    relevant: &Option<Fixed<Dependency>>,
    sp: u64,
    modules: &[String],
    dto: &mut FunctionFactBundleDto,
    budget: &mut Budget,
) -> Result<()> {
    let reads = Reads {
        state,
        tree,
        root,
        cancel,
        relevant,
        stack: &dto.abi.stack_arguments,
        sp,
    };
    // Replay each real read once, not again for every group/reservation pass.
    // Fixed scratch fails at 8 MiB; it never silently truncates observations.
    let mut fragments=Fixed::<Fragment>::new()?;
    reads.scan(|address,size,hex,seq|fragments.push(Fragment::new(address,size,hex,seq)?))?;
    let check=|| if cancel.load(std::sync::atomic::Ordering::Relaxed) {Err(TraceError::Cancelled)}else{Ok(())};
    check()?;fragments.values.sort_unstable_by_key(|f|(f.address,f.size,f.seq));check()?;
    let mut start=0;
    while start<fragments.values.len() {
        check()?;let first=&fragments.values[start];let (address,size)=(first.address,first.size);
        let mut end=start+1;
        while end<fragments.values.len() && (fragments.values[end].address,fragments.values[end].size)==(address,size) {check()?;end+=1;}
        let group=&fragments.values[start..end];let known=group_known(group);
        let mut global = None;
        let mut all_global = !modules.is_empty();
        for fragment in group {
            check()?;let seq=fragment.seq;
            if all_global {
                match super::global_stream::identity(
                    state, tree, root, cancel, modules, seq, address, size,
                )? {
                    Some(identity) if global.as_ref().is_none_or(|old| old == &identity) => {
                        global = Some(identity)
                    }
                    _ => all_global = false,
                }
            }
        }
        let bytes = known.then(|| std::str::from_utf8(&group[0].hex[..size as usize * 2]).expect("hex"));
        let address = format!("0x{address:x}");
        let global = if all_global { global } else { None };
        if let Some(global) = &global {
            budget.item(
                &Global {
                    global,
                    size,
                    bytes,
                    read_seqs: GroupSeqs { fragments: group, cancel },
                },
                2,
                dto.global_reads.is_empty(),
            )?;
        } else {
            budget.item(
                &Plain {
                    address: &address,
                    size,
                    bytes,
                    read_seqs: GroupSeqs { fragments: group, cancel },
                },
                2,
                dto.memory_reads.is_empty(),
            )?;
        }
        let mut seqs = Vec::new();
        for fragment in group {check()?;if seqs.last()!=Some(&fragment.seq) {collector::reserve_vec(&mut seqs)?;seqs.push(fragment.seq);}}
        if bytes.is_none() {
            collector::unresolved(
                &mut dto.unresolved,
                budget,
                "missing_memory_definition",
                seqs.iter().copied(),
                Some(&address),
                &format!("内存读取 {address} 字节值未完全确定"),
            )?;
        }
        if let Some(global) = global {
            collector::reserve_vec(&mut dto.global_reads)?;
            dto.global_reads.push(FunctionGlobalReadDto {
                global,
                size,
                bytes: bytes.map(str::to_owned),
                read_seqs: seqs,
            });
        } else {
            collector::reserve_vec(&mut dto.memory_reads)?;
            dto.memory_reads.push(FunctionMemoryReadDto {
                address,
                size,
                bytes: bytes.map(str::to_owned),
                read_seqs: seqs,
            });
        }
        start=end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragments_bound_capacity_dedupe_seqs_and_preserve_unknown_conflicts() {
        let mut fragments=Fixed::<Fragment>::with_bytes(2*std::mem::size_of::<Fragment>()).unwrap();
        fragments.push(Fragment::new(0x7000,1,Some("11"),3).unwrap()).unwrap();
        fragments.push(Fragment::new(0x7000,1,Some("11"),3).unwrap()).unwrap();
        assert!(matches!(fragments.push(Fragment::new(0x7000,1,Some("22"),4).unwrap()),Err(TraceError::Internal(_))));
        assert!(group_known(&fragments.values));let cancel=AtomicBool::new(false);
        assert_eq!(serde_json::to_value(GroupSeqs{fragments:&fragments.values,cancel:&cancel}).unwrap(),serde_json::json!([3]));
        fragments.values[1]=Fragment::new(0x7000,1,Some("22"),4).unwrap();assert!(!group_known(&fragments.values));
        assert_eq!(serde_json::to_value(GroupSeqs{fragments:&fragments.values,cancel:&cancel}).unwrap(),serde_json::json!([3,4]));
        cancel.store(true,std::sync::atomic::Ordering::Relaxed);assert!(serde_json::to_value(GroupSeqs{fragments:&fragments.values,cancel:&cancel}).is_err());
        fragments.values[1]=Fragment::new(0x7000,1,None,4).unwrap();assert!(!group_known(&fragments.values));
        for (address,size,hex) in [(0,0,None),(0,65,None),(u64::MAX,2,None),(0,2,Some("11"))] {assert!(Fragment::new(address,size,hex,0).is_err());}
    }
}
