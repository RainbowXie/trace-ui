//! Two raw scans and bounded external joins. No ActivationTree or instruction
//! vector is reconstructed. All sort keys are BE; final cache integers are LE.
use super::{format::*, ownership::*, sort::{ExternalSort, SortBudget, read_record}, scratch::{Workspace, Stream}, OpenedTrace, ControlFlowStore};
use crate::{error::Result, query::activation::{InsnFact, UnresolvedReason}, engine::stable_runtime_site};
use std::{fs::File, path::Path, sync::atomic::AtomicBool};
use super::aggregate::finish_sections;
use memmap2::Mmap;
pub(super) const SITE: usize=264;
#[cfg(test)]
pub(super) static MERGE_PASSES: std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
/// Internal resource envelope, not an acceptance claim for any trace scale.
#[derive(Clone, Copy)]
pub struct BuildBudget {
    pub run_records: usize, pub merge_fan_in: usize, pub scratch_bytes: u64,
    pub max_depth: usize, pub max_line_bytes: usize, pub max_open_files: usize,
}
impl Default for BuildBudget {
    fn default()->Self { Self { run_records:65536, merge_fan_in:8, scratch_bytes:32*1024*1024*1024, max_depth:4096, max_line_bytes:1024*1024, max_open_files:256 } }
}
pub(super) fn be(r:&[u8],o:usize)->u32 { u32::from_be_bytes(r[o..o+4].try_into().unwrap()) }
pub(super) fn put(r:&mut [u8],o:usize,v:u32) { r[o..o+4].copy_from_slice(&v.to_be_bytes()); }
pub(super) fn le32(s:&mut Stream,v:u32,c:&AtomicBool)->Result<()> { s.write(&v.to_le_bytes(),c) }
pub(super) fn le64(s:&mut Stream,v:u64,c:&AtomicBool)->Result<()> { s.write(&v.to_le_bytes(),c) }
pub(super) fn sort<const W:usize>(w:&Workspace,b:BuildBudget)->Result<ExternalSort<W>> {
    ExternalSort::create_shared(&w.path,SortBudget{run_records:b.run_records,fan_in:b.merge_fan_in,scratch_bytes:b.scratch_bytes},w.quota.clone())
}
pub(super) fn sorted<const W:usize>(s:&mut ExternalSort<W>,w:&Workspace,c:&AtomicBool)->Result<Stream> {
    let mut f=s.finish(c)?;
    #[cfg(test)]
    MERGE_PASSES.fetch_add(s.merge_passes,std::sync::atomic::Ordering::Relaxed); let mut out=w.stream()?; out.copy(&mut f,c)?; Ok(out)
}
pub(super) fn data(m:&Option<Mmap>)->&[u8] { m.as_ref().map_or(&[], |m| &m[..]) }
fn visit(raw:&[u8],b:BuildBudget,c:&AtomicBool,mut f:impl FnMut(u32,u64,&str)->Result<()>)->Result<u32> {
    let mut seq=0u64; let mut offset=0u64;
    for line in raw.split_inclusive(|v|*v==b'\n') {
        cancel(c)?;
        if line.len()>b.max_line_bytes { return Err(bad("raw line byte capacity exceeded")); }
        if seq>=u32::MAX as u64 { return Err(bad("raw seq capacity exceeded")); }
        let text=std::str::from_utf8(line).map_err(|_|bad("raw UTF8"))?.trim_end_matches(['\r','\n']);
        f(u32::try_from(seq).map_err(|_|bad("seq capacity"))?,offset,text)?;
        seq=seq.checked_add(1).ok_or_else(||bad("seq overflow"))?;
        offset=offset.checked_add(line.len() as u64).ok_or_else(||bad("raw offset overflow"))?;
    }
    u32::try_from(seq).map_err(|_|bad("total line capacity"))
}
fn parsed(line:&str)->Result<Option<([u8;SITE],u64,u32)>> {
    if line.trim().is_empty() || trace_parser::gumtrace::parse_special_line(line).is_some() { return Ok(None); }
    let (module,pc,offset)=stable_runtime_site(line).ok_or_else(||bad("invalid stable/runtime instruction site"))?;
    if module.len()>255 { return Err(bad("module name exceeds builder fixed key capacity (255 bytes)")); }
    pc.checked_add(4).ok_or_else(||bad("expected resume PC capacity"))?;
    let (mnemonic,_)=trace_parser::strict_memory::instruction_parts(line).ok_or_else(||bad("invalid instruction"))?;
    let mut site=[0;SITE]; site[..module.len()].copy_from_slice(module.as_bytes()); site[256..].copy_from_slice(&offset.to_be_bytes());
    let kind=super::super::scan::kind(mnemonic) as u32;
    Ok(Some((site,pc,kind)))
}
pub(super) struct Lines<'a> { pub raw:&'a [u8], pub samples:&'a [u8], pub total:u32 }
impl Lines<'_> {
    pub fn line(&self,seq:u32)->Result<&str> {
        if seq>=self.total { return Err(bad("line outside trace")); }
        let mut p=usize::try_from(u64_at(self.samples,(seq as usize/256)*8)).map_err(|_|bad("line offset capacity"))?;
        for _ in 0..seq%256 { p+=memchr::memchr(b'\n',&self.raw[p..]).ok_or_else(||bad("line missing"))?+1; }
        let tail=&self.raw[p..]; let n=memchr::memchr(b'\n',tail).unwrap_or(tail.len());
        Ok(std::str::from_utf8(&tail[..n]).map_err(|_|bad("line UTF8"))?.trim_end_matches('\r'))
    }
    fn site(&self,seq:u32)->Result<[u8;SITE]> { Ok(parsed(self.line(seq)?)?.ok_or_else(||bad("boundary not instruction"))?.0) }
}
pub(super) fn lookup(keys:&[u8],width:usize,key:&[u8])->Result<u32> {
    let mut lo=0; let mut hi=keys.len()/width;
    while lo<hi { let m=lo+(hi-lo)/2; if &keys[m*width..m*width+key.len()]<key { lo=m+1; } else { hi=m; } }
    if lo>=keys.len()/width || &keys[lo*width..lo*width+key.len()]!=key { return Err(bad("external join key missing")); }
    u32::try_from(lo).ok().filter(|v|*v!=NONE).ok_or_else(||bad("ID capacity"))
}
struct Sink<'a> { records:&'a mut ExternalSort<80>, bypass:&'a mut Stream, cancel:&'a AtomicBool }
impl OwnershipSink for Sink<'_> {
    fn event(&mut self,e:OwnershipEvent)->Result<()> {
        match e {
            OwnershipEvent::Entry(_)=>Ok(()),
            OwnershipEvent::Closed(b)=>{
                let mut r=[0;80];
                for (i,v) in [b.id,b.parent,b.call.seq,b.entry.map_or(NONE,|f|f.seq),b.exit.map_or(NONE,|f|f.seq),b.resume.map_or(NONE,|f|f.seq),match b.unresolved {None=>0,Some(UnresolvedReason::TraceEndStillActive)=>1,Some(UnresolvedReason::DisplacedByAnotherCall)=>2,Some(UnresolvedReason::NoNextInsn)=>3}].iter().enumerate() { put(&mut r,i*4,*v); }
                for (i,v) in [b.call.pc,b.entry.map_or(0,|f|f.pc),b.exit.map_or(0,|f|f.pc),b.expected_resume].iter().enumerate() { r[32+i*8..40+i*8].copy_from_slice(&v.to_be_bytes()); }
                self.records.push(r,self.cancel)
            },
            OwnershipEvent::Bypassed{parent,call,resume}=>{
                for v in [parent,call.seq,resume.seq] { self.bypass.write(&v.to_be_bytes(),self.cancel)?; } Ok(())
            }
        }
    }
}
fn event(s:&mut ExternalSort<24>,seq:u32,aid:u32,kind:u32,addr:u32,related:u32,c:&AtomicBool)->Result<()> {
    let mut r=[0;24]; for (i,v) in [seq,aid,kind,addr,related,0].iter().enumerate() {put(&mut r,i*4,*v);} s.push(r,c)
}
pub(super) fn composite(w:&Workspace,parts:&mut [(&mut Stream,u64,u64)],c:&AtomicBool)->Result<Stream> {
    let mut out=w.stream()?; let mut offset=(parts.len()*16) as u64;
    for (_,width,count) in parts.iter() {
        offset=offset.checked_add(7).ok_or_else(||bad("subtable alignment"))?&!7;
        le64(&mut out,offset,c)?; le64(&mut out,*count,c)?;
        offset=offset.checked_add(bytes(*count,*width)?).ok_or_else(||bad("subtable size"))?;
    }
    for (part,width,count) in parts.iter_mut() {
        let aligned=out.len.checked_add(7).ok_or_else(||bad("subtable align"))?&!7;
        out.write(&[0;7][..(aligned-out.len) as usize],c)?;
        if part.len!=bytes(*count,*width)? { return Err(bad("subtable stream size")); }
        part.rewind()?; out.copy(&mut part.file,c)?;
    }
    Ok(out)
}
/// Builds and atomically publishes all 13 sections. Input FD must remain
/// immutable for mmap lifetime; metadata/hash checks do not prevent SIGBUS.
/// The target's parent is a trusted internal cache directory, never a Case path.
pub fn build_control_flow_store(trace:&OpenedTrace,target:&Path,c:&AtomicBool,b:BuildBudget)->Result<ControlFlowStore> {
    if b.max_line_bytes==0 || b.max_depth==0 || b.max_open_files<b.merge_fan_in.checked_add(128).ok_or_else(||bad("FD budget overflow"))? { return Err(bad("build resource budget")); }
    trace.verify_identity(c)?;
    let detected=match trace_parser::gumtrace::detect_format(trace.data()) { trace_parser::types::TraceFormat::Gumtrace=>TraceFormat::GumTrace, _=>TraceFormat::Unidbg };
    if detected!=trace.format { return Err(bad("parser detected format differs from retained trace format")); }
    let parent=target.parent().ok_or_else(||bad("cache target parent"))?;
    let w=Workspace::new(parent,b.scratch_bytes)?;
    // Quota covers simultaneously retained streams, runs and publish candidate;
    // FS metadata and an older published cache are not scratch payload bytes.
    let mut samples=w.stream()?; let mut bypass=w.stream()?;
    let mut sites=sort::<SITE>(&w,b)?; let mut starts=sort::<268>(&w,b)?; let mut closed=sort::<80>(&w,b)?;
    let mut resolver=OwnershipResolver::new(b.max_depth)?;
    let mut prev_owner=NONE; let mut prev_kind=0;
    // This implementation keeps fewer than 128 constant-schema stream/trace
    // handles plus one merging sort's fan-in. Reject smaller FD envelopes;
    // there are never per-activation files or simultaneously merging sorts.
    let total=visit(trace.data(),b,c,|seq,offset,line| {
        if seq%256==0 { le64(&mut samples,offset,c)?; }
        let Some((site,pc,kind))=parsed(line)? else { return Ok(()); };
        sites.push(site,c)?;
        let mut sink=Sink{records:&mut closed,bypass:&mut bypass,cancel:c};
        let owner=resolver.on_insn(InsnFact::new(seq,pc),&mut sink)?;
        if owner!=prev_owner || prev_kind!=0 { let mut r=[0;268]; put(&mut r,0,owner); r[4..].copy_from_slice(&site); starts.push(r,c)?; }
        prev_owner=owner; prev_kind=kind;
        if kind==4 { resolver.on_call(InsnFact::new(seq,pc),&mut sink)?; }
        Ok(())
    })?;
    if total==0 { return Err(bad("empty trace")); }
    let activation_count=resolver.finish(&mut Sink{records:&mut closed,bypass:&mut bypass,cancel:c})?;
    let closed_stream=sorted(&mut closed,&w,c)?; drop(closed);
    let cm=closed_stream.map()?; let cb=data(&cm);
    if cb.len()/80+1!=activation_count as usize { return Err(bad("activation creation count mismatch")); }
    let all_sites=sorted(&mut sites,&w,c)?; drop(sites);
    let mut unique_sites=w.stream()?; let mut input=File::open(&all_sites.path_for_build())?;
    let mut last=None;
    while let Some(r)=read_record::<SITE>(&mut input)? { cancel(c)?; if last.as_ref()!=Some(&r) { unique_sites.write(&r,c)?; last=Some(r); } }
    drop(input); drop(all_sites);
    let sm=unique_sites.map()?; let keys=data(&sm);
    let address_count=u32::try_from(keys.len()/SITE).ok().filter(|v|*v!=NONE).ok_or_else(||bad("address ID capacity"))?;
    let sample_map=samples.map()?; let lines=Lines{raw:trace.data(),samples:data(&sample_map),total};
    let mut modules_offsets=w.stream()?; let mut module_pool=w.stream()?; let mut addresses=w.stream()?;
    le64(&mut modules_offsets,0,c)?; let mut module_count=0u32; let mut previous_module=[255;256];
    for r in keys.chunks_exact(SITE) { cancel(c)?;
        if r[..256]!=previous_module { let len=r[..256].iter().position(|v|*v==0).unwrap_or(256); module_pool.write(&r[..len],c)?; le64(&mut modules_offsets,module_pool.len,c)?; previous_module.copy_from_slice(&r[..256]); module_count=module_count.checked_add(1).filter(|v|*v!=NONE).ok_or_else(||bad("module ID capacity"))?; }
        le32(&mut addresses,module_count-1,c)?; le32(&mut addresses,0,c)?; le64(&mut addresses,u64::from_be_bytes(r[256..264].try_into().unwrap()),c)?;
    }
    let mut modules=w.stream()?; modules_offsets.rewind()?; modules.copy(&mut modules_offsets.file,c)?; module_pool.rewind()?; modules.copy(&mut module_pool.file,c)?;
    drop(modules_offsets); drop(module_pool);
    let mut activations=w.stream()?;
    for v in [NONE,NONE,NONE,NONE,NONE,NONE,0,0] { le32(&mut activations,v,c)?; } for _ in 0..4 { le64(&mut activations,0,c)?; }
    let mut events=sort::<24>(&w,b)?; let mut function_sort=sort::<12>(&w,b)?;
    for (i,r) in cb.chunks_exact(80).enumerate() { cancel(c)?;
        let aid=be(r,0); if aid as usize!=i+1 { return Err(bad("activation ID join order")); }
        let entry=be(r,12); let reason=be(r,24);
        let function=if entry==NONE {NONE} else {lookup(keys,SITE,&lines.site(entry)?)?};
        for v in [function,be(r,4),be(r,8),entry,if reason==0 {be(r,16)} else {NONE},if reason==0 {be(r,20)} else {NONE},if reason==0 {1} else {2},reason] {le32(&mut activations,v,c)?;}
        for o in [32,40,48,56] { le64(&mut activations,u64::from_be_bytes(r[o..o+8].try_into().unwrap()),c)?; }
        event(&mut events,be(r,8),aid,0,lookup(keys,SITE,&lines.site(be(r,8))?)?,be(r,4),c)?;
        if entry!=NONE { event(&mut events,entry,aid,1,function,be(r,4),c)?; }
        if reason==0 {
            event(&mut events,be(r,16),aid,2,lookup(keys,SITE,&lines.site(be(r,16))?)?,be(r,4),c)?;
            event(&mut events,be(r,20),aid,3,lookup(keys,SITE,&lines.site(be(r,20))?)?,be(r,4),c)?;
            let mut f=[0;12]; put(&mut f,0,function);put(&mut f,4,be(r,8));put(&mut f,8,aid);function_sort.push(f,c)?;
        }
    }
    bypass.rewind()?; while let Some(r)=read_record::<12>(&mut bypass.file)? { event(&mut events,be(&r,8),be(&r,0),4,lookup(keys,SITE,&lines.site(be(&r,4))?)?,be(&r,4),c)?; }
    let boundary=sorted(&mut events,&w,c)?;drop(events);
    // Sort keys are BE; boundary section is explicitly converted to LE.
    let boundary_map=boundary.map()?; let mut boundary_le=w.stream()?;
    for r in data(&boundary_map).chunks_exact(24) { for o in (0..24).step_by(4) {le32(&mut boundary_le,be(r,o),c)?;} }
    let am=activations.map()?; let ab=data(&am);
    drop(boundary); drop(cm); drop(closed_stream); drop(bypass);
    let owner_starts=sorted(&mut starts,&w,c)?;drop(starts);
    let mut final_starts_sort=sort::<8>(&w,b)?; let osm=owner_starts.map()?;
    for r in data(&osm).chunks_exact(268) { cancel(c)?; let aid=be(r,0); let a=&ab[aid as usize*64..aid as usize*64+64]; if u32_at(a,24)==1 { let mut key=[0;8];put(&mut key,0,u32_at(a,0));put(&mut key,4,lookup(keys,SITE,&r[4..])?);final_starts_sort.push(key,c)?; } }
    drop(osm); drop(owner_starts);
    let fs=sorted(&mut final_starts_sort,&w,c)?;drop(final_starts_sort);
    let mut final_starts=w.stream()?; let fsm=fs.map()?; let mut last_key=None;
    for r in data(&fsm).chunks_exact(8) { if last_key.as_ref().map(|v:&[u8;8]|&v[..])!=Some(r) { final_starts.write(r,c)?;last_key=Some(r.try_into().unwrap()); } }
    drop(fsm); drop(fs);
    let fm=final_starts.map()?;
    let mut occurrences=sort::<24>(&w,b)?;
    let mut stack=Vec::<u32>::new(); let mut cursor=0usize; let eb=data(&boundary_map);
    let mut current:Option<[u8;24]>=None;
    let second_total=visit(trace.data(),b,c,|seq,_,line| {
        let Some((site,pc,kind))=parsed(line)? else { return Ok(()); };
        while cursor<eb.len() && be(eb,cursor)<seq { cursor+=24; }
        let mut at=cursor;
        while at<eb.len() && be(eb,at)==seq {
            let ev=&eb[at..at+24]; let aid=be(ev,4);
            match be(ev,8) {
                1=>{ if stack.len()>=b.max_depth {return Err(bad("replay stack budget"));} let a=&ab[aid as usize*64..aid as usize*64+64]; if u32_at(a,4)!=stack.last().copied().unwrap_or(0) || u64_at(a,40)!=pc {return Err(bad("entry replay mismatch"));} stack.push(aid); },
                3=>{ let a=&ab[aid as usize*64..aid as usize*64+64]; if u64_at(a,56)!=pc || stack.pop()!=Some(aid) {return Err(bad("resume replay mismatch"));} },
                4=>{
                    let call=be(ev,16); let (_,call_pc,call_kind)=parsed(lines.line(call)?)?.ok_or_else(||bad("bypassed call missing"))?;
                    if call_kind!=4 || call_pc.checked_add(4)!=Some(pc) || stack.last().copied().unwrap_or(0)!=aid {return Err(bad("bypassed parent/call replay mismatch"));}
                },
                0|2=>{}, // Checked after same-seq entry/resume changes owner.
                _=>return Err(bad("unknown replay boundary kind"))
            } at+=24;
        }
        for ev in eb[cursor..at].chunks_exact(24) {
            let aid=be(ev,4);let a=&ab[aid as usize*64..aid as usize*64+64];
            if be(ev,8)==0 && (kind!=4 || u64_at(a,32)!=pc || u32_at(a,4)!=stack.last().copied().unwrap_or(0)) {return Err(bad("call replay mismatch"));}
            if be(ev,8)==2 && (u64_at(a,48)!=pc || stack.last().copied().unwrap_or(0)!=aid) {return Err(bad("exit replay mismatch"));}
        }
        cursor=at;
        let owner=stack.last().copied().unwrap_or(0); let a=&ab[owner as usize*64..owner as usize*64+64];
        if u32_at(a,24)!=1 { if let Some(r)=current.take() {occurrences.push(r,c)?;} return Ok(()); }
        let function=u32_at(a,0); let addr=lookup(keys,SITE,&site)?;
        let mut target=[0;8];put(&mut target,0,function);put(&mut target,4,addr);
        let is_start=lookup(data(&fm),8,&target).is_ok();
        let new=current.as_ref().is_none_or(|r|be(r,0)!=owner || be(r,20)!=0) || is_start;
        if new { if let Some(r)=current.take() {occurrences.push(r,c)?;} let mut r=[0;24]; for (i,v) in [owner,seq,seq.checked_add(1).ok_or_else(||bad("end seq"))?,function,addr,kind].iter().enumerate(){put(&mut r,i*4,*v);} current=Some(r); }
        else {let r=current.as_mut().unwrap();put(r,8,seq.checked_add(1).ok_or_else(||bad("end seq"))?);put(r,20,kind);}
        Ok(())
    })?;
    if second_total!=total {return Err(bad("raw pass total mismatch"));}
    if let Some(r)=current {occurrences.push(r,c)?;}
    drop(boundary_map); drop(fm); drop(final_starts); drop(am);
    let occ=sorted(&mut occurrences,&w,c)?;drop(occurrences);
    let om=occ.map()?;
    let result=finish_sections(&w,b,c,trace,target,total,module_count,address_count,activation_count,&lines,modules,addresses,activations,boundary_le,&mut function_sort,data(&om));
    debug_assert!(w.quota.peak()<=b.scratch_bytes);
    result
}
