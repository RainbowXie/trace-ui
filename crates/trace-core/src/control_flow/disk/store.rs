use super::{format::*, trace::{hash, OpenedTrace}};
use crate::error::Result;
use memmap2::{Mmap, MmapOptions};
use std::{fs::{File, OpenOptions}, os::unix::fs::OpenOptionsExt, path::Path, sync::atomic::AtomicBool};

#[derive(Clone, Copy)]
pub struct FlatSection<'a> { pub data: &'a [u8], pub count: u64 }
impl<'a> FlatSection<'a> {
    pub fn record(self, id: u64, width: u64) -> Result<&'a [u8]> {
        if id >= self.count { return Err(bad("record ID")); }
        checked_slice(self.data, bytes(id, width)?, width)
    }
}
/// Validated mmap flat views; never reconstructs ActivationTree or occurrences.
pub struct ControlFlowStore { _file: File, mmap: Mmap }
impl ControlFlowStore {
    pub fn open(path: &Path, trace: &OpenedTrace, c: &AtomicBool) -> Result<Self> {
        trace.verify_identity(c)?;
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
        let before = file.metadata()?;
        if !before.is_file() || before.len() < PAYLOAD as u64 { return Err(bad("cache file type/size")); }
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        validate(&mmap, trace, c)?;
        use std::os::unix::fs::MetadataExt;
        let after = file.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len()
            || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec() {
            return Err(bad("cache changed during open"));
        }
        trace.verify_identity(c)?;
        Ok(Self { _file: file, mmap })
    }
    pub fn section(&self, section: Section) -> FlatSection<'_> { section_view(&self.mmap, section).unwrap() }
    pub fn total_lines(&self) -> u32 { u32_at(&self.mmap, 96) }
    /// Sample lookup scans at most 255 newlines, without allocating offsets.
    pub fn line<'a>(&self, trace: &'a OpenedTrace, seq_id: u32) -> Option<&'a [u8]> {
        if seq_id >= self.total_lines() { return None; }
        let l = self.section(Section::LineIndex).data;
        let mut pos = usize::try_from(u64_at(l, 8 + (seq_id as usize / 256) * 8)).ok()?;
        for _ in 0..seq_id % 256 { pos += memchr::memchr(b'\n', trace.data().get(pos..)?)? + 1; }
        let rest = trace.data().get(pos..)?;
        let end = memchr::memchr(b'\n', rest).unwrap_or(rest.len());
        Some(rest[..end].strip_suffix(b"\r").unwrap_or(&rest[..end]))
    }
}
fn section_view(b: &[u8], s: Section) -> Result<FlatSection<'_>> {
    let o = HEADER + s as usize * 24;
    Ok(FlatSection { data: checked_slice(b, u64_at(b,o), u64_at(b,o+8))?, count: u64_at(b,o+16) })
}
fn fixed(s: FlatSection<'_>, width: u64) -> Result<()> {
    if s.data.len() as u64 != bytes(s.count,width)? { return Err(bad("fixed section length")); }
    Ok(())
}
fn id(id: u32, count: u64) -> Result<()> { if u64::from(id) >= count { Err(bad("foreign ID")) } else { Ok(()) } }
fn optional_id(v: u32, n: u64) -> Result<()> { if v == NONE { Ok(()) } else { id(v,n) } }
fn range(start: u32, end: u32, total: u32) -> Result<()> {
    if start >= end || end > total { Err(bad("invalid seq range")) } else { Ok(()) }
}
// Pairs describe consecutive, non-overlapping subtables inside their section.
fn tables<'a>(s: FlatSection<'a>, widths: &[u64]) -> Result<Vec<FlatSection<'a>>> {
    let header = widths.len() * 16;
    if s.data.len() < header { return Err(bad("subtable header")); }
    let mut end = header as u64;
    let mut out = Vec::with_capacity(widths.len()); // constant schema size, never cache count
    for (i,w) in widths.iter().enumerate() {
        let off = u64_at(s.data,i*16); let count = u64_at(s.data,i*16+8);
        let aligned = end.checked_add(7).ok_or_else(|| bad("alignment overflow"))? & !7;
        if off != aligned { return Err(bad("subtable overlap/order")); }
        if checked_slice(s.data,end,off-end)?.iter().any(|v| *v != 0) { return Err(bad("nonzero padding")); }
        let len = bytes(count,*w)?;
        let data = checked_slice(s.data,off,len)?;
        end = off.checked_add(len).ok_or_else(|| bad("subtable end"))?;
        out.push(FlatSection{data,count});
    }
    if end != s.data.len() as u64 || out[0].count != s.count { return Err(bad("subtable length/count")); }
    Ok(out)
}
fn subrange(s: FlatSection<'_>, start: u64, count: u64, width: u64) -> Result<FlatSection<'_>> {
    if start.checked_add(count).ok_or_else(|| bad("subrange overflow"))? > s.count { return Err(bad("subrange outside table")); }
    Ok(FlatSection{data:checked_slice(s.data,bytes(start,width)?,bytes(count,width)?)?,count})
}
fn confirmed(a: FlatSection<'_>, activation: u32, function: u32) -> Result<()> {
    let r = a.record(u64::from(activation),64)?;
    if u32_at(r,24) != 1 || u32_at(r,0) != function { return Err(bad("source is not confirmed function activation")); }
    Ok(())
}
fn sources(s: FlatSection<'_>, a: FlatSection<'_>, function: u32, start: u64, count: u64, c: &AtomicBool) -> Result<()> {
    if count == 0 { return Err(bad("empty source set")); }
    let mut last = None;
    for r in subrange(s,start,count,4)?.data.chunks_exact(4) {
        cancel(c)?;
        let v = u32_at(r,0); confirmed(a,v,function)?;
        if last.is_some_and(|l| l >= v) { return Err(bad("sources not sorted unique")); } last = Some(v);
    }
    Ok(())
}
fn contains_id(s: FlatSection<'_>, wanted: u32) -> Result<bool> {
    let mut lo=0; let mut hi=s.count;
    while lo<hi { let mid=lo+(hi-lo)/2; let v=u32_at(s.record(mid,4)?,0);
        if v<wanted {lo=mid+1} else {hi=mid} }
    Ok(lo<s.count && u32_at(s.record(lo,4)?,0)==wanted)
}
pub(crate) fn validate(b: &[u8], trace: &OpenedTrace, c: &AtomicBool) -> Result<()> {
    cancel(c)?;
    if b.len() >= 12 && (&b[..8] != MAGIC || u32_at(b,8) != VERSION) {
        return Err(bad("incompatible control-flow cache version (requires v2)"));
    }
    if b.len() < PAYLOAD || &b[..8] != MAGIC || u32_at(b,8) != VERSION
        || u32_at(b,12) != trace.format as u32 || u64_at(b,16) != trace.len()
        || b[24..56] != trace.hash || u64_at(b,56) != b.len() as u64
        || b[100..128].iter().any(|v| *v != 0) { return Err(bad("header/identity/version")); }
    if hash(&b[HEADER..],c)? != b[64..96] { return Err(bad("payload hash")); }
    let total = u32_at(b,96);
    if total == 0 { return Err(bad("zero lines")); }
    let mut end = PAYLOAD as u64;
    for s in SECTIONS {
        cancel(c)?;
        let o = HEADER + s as usize * 24; let off = u64_at(b,o); let len = u64_at(b,o+8);
        let aligned = end.checked_add(7).ok_or_else(|| bad("alignment overflow"))? & !7;
        if off != aligned { return Err(bad("section alignment/order/overlap")); }
        if checked_slice(b,end,off-end)?.iter().any(|v| *v != 0) { return Err(bad("padding")); }
        checked_slice(b,off,len)?;
        end = off.checked_add(len).ok_or_else(|| bad("section end"))?;
    }
    if end != b.len() as u64 { return Err(bad("trailing bytes")); }
    let m = section_view(b,Section::Modules)?;
    let offsets_len = bytes(m.count.checked_add(1).ok_or_else(|| bad("modules overflow"))?,8)?;
    let offsets = checked_slice(m.data,0,offsets_len)?;
    let pool = checked_slice(m.data,offsets_len,m.data.len() as u64 - offsets_len)?;
    if u64_at(offsets,0) != 0 || u64_at(offsets,offsets.len()-8) != pool.len() as u64 { return Err(bad("module pool")); }
    for i in 0..m.count {
        cancel(c)?;
        let o = usize::try_from(bytes(i,8)?).map_err(|_| bad("offset capacity"))?;
        let start = u64_at(offsets,o); let end = u64_at(offsets,o+8);
        let len = end.checked_sub(start).ok_or_else(|| bad("module offsets"))?;
        if len == 0 || len > 4096 { return Err(bad("module name length")); }
        std::str::from_utf8(checked_slice(pool,start,len)?).map_err(|_| bad("module UTF8"))?;
    }
    let addresses = section_view(b,Section::StableAddresses)?; fixed(addresses,16)?;
    if m.count > NONE as u64 || addresses.count > NONE as u64 { return Err(bad("ID capacity")); }
    let mut last_address = None;
    for r in addresses.data.chunks_exact(16) {
        cancel(c)?; id(u32_at(r,0),m.count)?;
        let key = (u32_at(r,0),u64_at(r,8));
        if u32_at(r,4) != 0 || last_address.is_some_and(|k| k >= key) { return Err(bad("address ordering/reserved")); }
        last_address = Some(key);
    }
    let a = section_view(b,Section::Activations)?; fixed(a,64)?;
    if a.count == 0 || a.count > NONE as u64 { return Err(bad("activation capacity")); }
    for (i,r) in a.data.chunks_exact(64).enumerate() {
        cancel(c)?;
        let function=u32_at(r,0); let parent=u32_at(r,4); let call=u32_at(r,8); let entry=u32_at(r,12);
        let exit=u32_at(r,16); let resume=u32_at(r,20); let status=u32_at(r,24); let reason=u32_at(r,28);
        if i == 0 {
            if status != 0 || reason != 0 || [function,parent,call,exit,resume].iter().any(|v| *v != NONE) { return Err(bad("root record")); }
            if entry != NONE { seq(entry,total)?; }
            continue;
        }
        if u64::from(parent) >= i as u64 { return Err(bad("activation parent cycle")); }
        seq(call,total)?;
        if u64_at(r,32).checked_add(4) != Some(u64_at(r,56)) { return Err(bad("expected resume PC")); }
        match status {
            1 => {
                id(function,addresses.count)?; seq(entry,total)?; seq(exit,total)?; seq(resume,total)?;
                if reason != 0 || !(call < entry && entry <= exit && exit < resume) { return Err(bad("confirmed boundary")); }
                let pr=a.record(u64::from(parent),64)?;
                if parent!=0 && (call<u32_at(pr,12) || (u32_at(pr,24)==1 && resume>u32_at(pr,16))) { return Err(bad("child outside parent")); }
            }
            2 => {
                if !(1..=3).contains(&reason) || exit != NONE || resume != NONE { return Err(bad("unresolved boundary")); }
                if entry != NONE { seq(entry,total)?; id(function,addresses.count)?; if call >= entry || reason != 1 { return Err(bad("unresolved entry")); } }
                else if function != NONE || reason == 1 { return Err(bad("missing entry")); }
            }
            _ => return Err(bad("activation status")),
        }
    }
    let lines=section_view(b,Section::LineIndex)?;
    if lines.data.len() as u64 != 8u64.checked_add(bytes(lines.count,8)?).ok_or_else(||bad("line size"))?
        || u32_at(lines.data,0)!=total || u32_at(lines.data,4)!=0 || lines.count!=(u64::from(total)+255)/256 { return Err(bad("line index header")); }
    let raw_line=|seq_id:u32|->Result<&str> {
        seq(seq_id,total)?;
        let mut pos=usize::try_from(u64_at(lines.data,8+(seq_id as usize/256)*8)).map_err(|_|bad("line capacity"))?;
        for _ in 0..seq_id%256 {pos=pos.checked_add(memchr::memchr(b'\n',trace.data().get(pos..).ok_or_else(||bad("line offset"))?).ok_or_else(||bad("line missing"))?+1).ok_or_else(||bad("line offset overflow"))?;}
        let tail=trace.data().get(pos..).ok_or_else(||bad("line offset"))?;let end=memchr::memchr(b'\n',tail).unwrap_or(tail.len());
        Ok(std::str::from_utf8(&tail[..end]).map_err(|_|bad("line UTF8"))?.trim_end_matches('\r'))
    };
    let ev=section_view(b,Section::ActivationBoundaryEvents)?; fixed(ev,24)?;
    let mut last_seq=None;
    for r in ev.data.chunks_exact(24) {
        cancel(c)?; let s=u32_at(r,0); seq(s,total)?;
        optional_id(u32_at(r,4),a.count)?; optional_id(u32_at(r,12),addresses.count)?;
        if u32_at(r,8)==4 {
            let call=u32_at(r,16); seq(call,total)?;
            if call>=s || u32_at(r,4)==NONE || u32_at(r,12)==NONE { return Err(bad("bypassed boundary")); }
            let call_line=raw_line(call)?;let resume_line=raw_line(s)?;
            let (module,pc,offset)=crate::engine::stable_runtime_site(call_line).ok_or_else(||bad("bypassed call site"))?;
            let (_,resume_pc,_)=crate::engine::stable_runtime_site(resume_line).ok_or_else(||bad("bypassed resume site"))?;
            let (mnemonic,_)=trace_parser::strict_memory::instruction_parts(call_line).ok_or_else(||bad("bypassed call instruction"))?;
            if super::super::scan::kind(mnemonic)!=super::super::types::CfgEdgeKind::CallResume || pc.checked_add(4)!=Some(resume_pc) {return Err(bad("bypassed actual call/resume"));}
            let addr=addresses.record(u32_at(r,12) as u64,16)?;let mid=u32_at(addr,0) as usize;
            let module_start=u64_at(offsets,mid*8);let module_end=u64_at(offsets,(mid+1)*8);
            if checked_slice(pool,module_start,module_end-module_start)?!=module.as_bytes() || u64_at(addr,8)!=offset {return Err(bad("bypassed address mismatch"));}
            let parent=u32_at(r,4);
            if parent!=0 {let ar=a.record(parent as u64,64)?;let entry=u32_at(ar,12);if entry==NONE || call<entry || (u32_at(ar,24)==1 && s>u32_at(ar,16)){return Err(bad("bypassed outside parent"));}}
        } else { optional_id(u32_at(r,16),a.count)?; }
        let kind=u32_at(r,8); let aid=u32_at(r,4);
        if kind>4 || u32_at(r,20)!=0 || last_seq.is_some_and(|v| v>s) { return Err(bad("boundary event")); }
        if kind<4 {
            if aid==NONE || aid==0 { return Err(bad("boundary activation missing")); }
            let ar=a.record(u64::from(aid),64)?;
            let field=match kind {0=>8,1=>12,2=>16,_=>20};
            if u32_at(ar,field)!=s { return Err(bad("boundary event seq mismatch")); }
        }
        last_seq=Some(s);
    }
    let bt=tables(section_view(b,Section::Blocks)?,&[48,16,16,4])?;
    let blocks=bt[0]; if blocks.count > NONE as u64 { return Err(bad("block ID capacity")); }
    let mut last_block=None; let mut variant_end=0; let mut source_end=0;
    for (i,r) in blocks.data.chunks_exact(48).enumerate() {
        cancel(c)?; let f=u32_at(r,0); let addr=u32_at(r,4); id(f,addresses.count)?; id(addr,addresses.count)?;
        let key=(f,addr); if last_block.is_some_and(|v| v>=key) { return Err(bad("block order")); } last_block=Some(key);
        range(u32_at(r,8),u32_at(r,12),total)?;
        let vs=u64_at(r,16); let vc=u64_at(r,24); let ss=u64_at(r,32); let sc=u64_at(r,40);
        if vs != variant_end || ss != source_end || vc == 0 { return Err(bad("block subranges")); }
        let variants=subrange(bt[1],vs,vc,16)?;
        let block_sources=subrange(bt[3],ss,sc,4)?;
        let mut last_variant=None;
        for v in variants.data.chunks_exact(16) {
            cancel(c)?;
            if u32_at(v,0) as usize != i { return Err(bad("variant block")); }
            let aid=u32_at(v,4);
            confirmed(a,aid,f)?; range(u32_at(v,8),u32_at(v,12),total)?;
            let key=(aid,u32_at(v,8),u32_at(v,12));
            if last_variant.is_some_and(|k|k>=key) || !contains_id(block_sources,aid)? { return Err(bad("variant order/source")); }
            last_variant=Some(key);
            let ar=a.record(u64::from(u32_at(v,4)),64)?;
            if u32_at(v,8)<u32_at(ar,12) || u32_at(v,12)>u32_at(ar,16).checked_add(1).ok_or_else(||bad("exit overflow"))? { return Err(bad("variant activation range")); }
        }
        let v=variants.record(0,16)?;
        if u32_at(v,8)!=u32_at(r,8) || u32_at(v,12)!=u32_at(r,12) { return Err(bad("representative not first variant")); }
        sources(bt[3],a,f,ss,sc,c)?;
        variant_end=vs.checked_add(vc).ok_or_else(||bad("variants overflow"))?;
        source_end=ss.checked_add(sc).ok_or_else(||bad("sources overflow"))?;
    }
    if variant_end!=bt[1].count || source_end!=bt[3].count { return Err(bad("unreferenced block subtables")); }
    let mut last_ref=None;
    for r in bt[2].data.chunks_exact(16) {
        cancel(c)?; let f=u32_at(r,0); let bid=u32_at(r,4); let br=blocks.record(u64::from(bid),48)?;
        let key=(f,bid);
        if f!=u32_at(br,0) || u64_at(r,8)==0 || last_ref.is_some_and(|v|v>=key) { return Err(bad("function block reference")); } last_ref=Some(key);
    }
    if bt[2].count != blocks.count { return Err(bad("function block coverage")); }
    let starts=section_view(b,Section::OccurrenceStartSeqs)?;
    let ends=section_view(b,Section::OccurrenceEndSeqs)?;
    let bids=section_view(b,Section::OccurrenceBlockIds)?;
    let aids=section_view(b,Section::OccurrenceActivationIds)?;
    for s in [starts,ends,bids,aids] { fixed(s,4)?; if s.count!=starts.count { return Err(bad("parallel occurrence lengths")); } }
    let ranges=section_view(b,Section::ActivationOccurrenceRanges)?; fixed(ranges,16)?;
    if ranges.count!=a.count { return Err(bad("activation range count")); }
    let mut cursor=0;
    for (ai,r) in ranges.data.chunks_exact(16).enumerate() {
        cancel(c)?; let start=u64_at(r,0); let count=u64_at(r,8);
        if start!=cursor { return Err(bad("noncontiguous activation ranges")); }
        subrange(starts,start,count,4)?;
        let mut last_end=None;
        for j in start..start.checked_add(count).ok_or_else(||bad("range overflow"))? {
            cancel(c)?;
            let s=u32_at(starts.record(j,4)?,0); let e=u32_at(ends.record(j,4)?,0);
            let bid=u32_at(bids.record(j,4)?,0); let aid=u32_at(aids.record(j,4)?,0);
            if aid as usize!=ai || last_end.is_some_and(|v|v>s) { return Err(bad("occurrence owner/order")); }
            range(s,e,total)?; let br=blocks.record(u64::from(bid),48)?; confirmed(a,aid,u32_at(br,0))?;
            if !contains_id(subrange(bt[3],u64_at(br,32),u64_at(br,40),4)?,aid)? { return Err(bad("occurrence missing block source")); }
            let ar=a.record(u64::from(aid),64)?;
            if s<u32_at(ar,12) || e>u32_at(ar,16).checked_add(1).ok_or_else(||bad("exit overflow"))? { return Err(bad("occurrence outside activation")); }
            last_end=Some(e);
        }
        cursor=start.checked_add(count).ok_or_else(||bad("range overflow"))?;
    }
    if cursor!=starts.count { return Err(bad("occurrence coverage")); }
    let et=tables(section_view(b,Section::Edges)?,&[48,4])?;
    let mut last_edge=None; let mut edge_source_end=0;
    for r in et[0].data.chunks_exact(48) {
        cancel(c)?; let aid=u32_at(r,0); let from=u32_at(r,4); let to=u32_at(r,8); let kind=u32_at(r,12); let f=u32_at(r,16);
        let key=(f,aid,from,to,kind);
        if kind>5 || u32_at(r,20)!=0 || u64_at(r,24)==0 || last_edge.is_some_and(|v|v>=key) { return Err(bad("edge order/kind/count")); }
        for bid in [from,to] { if u32_at(blocks.record(u64::from(bid),48)?,0)!=f { return Err(bad("edge function mismatch")); } }
        let ss=u64_at(r,32); let sc=u64_at(r,40);
        if ss!=edge_source_end { return Err(bad("edge source layout")); }
        sources(et[1],a,f,ss,sc,c)?;
        if aid!=NONE { confirmed(a,aid,f)?; if sc!=1 || u32_at(subrange(et[1],ss,sc,4)?.data,0)!=aid { return Err(bad("local edge source")); } }
        edge_source_end=ss.checked_add(sc).ok_or_else(||bad("edge sources overflow"))?;
        last_edge=Some(key);
    }
    if edge_source_end!=et[1].count { return Err(bad("edge source coverage")); }
    let ft=tables(section_view(b,Section::FunctionActivationIndex)?,&[24,4])?;
    let mut last_function=None; let mut fc=0; let mut indexed=0;
    for r in ft[0].data.chunks_exact(24) {
        cancel(c)?; let f=u32_at(r,0); id(f,addresses.count)?;
        let start=u64_at(r,8); let count=u64_at(r,16);
        if u32_at(r,4)!=0 || start!=fc || count==0 || last_function.is_some_and(|v|v>=f) { return Err(bad("function index record")); }
        let mut last_call=None;
        for v in subrange(ft[1],start,count,4)?.data.chunks_exact(4) {
            cancel(c)?; let aid=u32_at(v,0); confirmed(a,aid,f)?; let ar=a.record(u64::from(aid),64)?; let key=(u32_at(ar,8),aid);
            if last_call.is_some_and(|v|v>=key) { return Err(bad("function activations order")); } last_call=Some(key);
            indexed+=1;
        }
        fc=start.checked_add(count).ok_or_else(||bad("function range overflow"))?; last_function=Some(f);
    }
    let mut confirmed_count=0u64;
    for r in a.data.chunks_exact(64) { cancel(c)?; if u32_at(r,24)==1 { confirmed_count+=1; } }
    if fc!=ft[1].count || indexed!=confirmed_count { return Err(bad("function activation coverage")); }
    let lines=section_view(b,Section::LineIndex)?;
    if lines.data.len() as u64 != 8u64.checked_add(bytes(lines.count,8)?).ok_or_else(||bad("line size"))?
        || u32_at(lines.data,0)!=total || u32_at(lines.data,4)!=0 || lines.count!=(u64::from(total)+255)/256 { return Err(bad("line index header")); }
    // Validate against actual raw lines, including special/blank and last no-newline.
    let mut n=0u64; let mut pos=0usize;
    while pos<trace.data().len() {
        cancel(c)?;
        if n%256==0 {
            let sample=usize::try_from(n/256).map_err(|_|bad("sample capacity"))?;
            if sample>=lines.count as usize || u64_at(lines.data,8+sample*8)!=pos as u64 { return Err(bad("line offset")); }
        }
        n=n.checked_add(1).ok_or_else(||bad("line overflow"))?;
        pos=match memchr::memchr(b'\n',&trace.data()[pos..]) { Some(rel)=>pos+rel+1, None=>trace.data().len() };
    }
    if n!=u64::from(total) { return Err(bad("line total")); }
    Ok(())
}
