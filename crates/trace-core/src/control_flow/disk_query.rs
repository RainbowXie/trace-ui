//! Bounded queries over validated CFG v3 flat sections. Raw instruction text is
//! read only for the selected page; no ActivationTree or occurrence Vec is rebuilt.
use super::{disk::{format::*, ControlFlowStore, FlatSection, OpenedTrace}, types::*};
use crate::error::{Result, TraceError};
use std::sync::atomic::AtomicBool;

const MAX_ITEMS: usize = 100_000;
const MAX_BLOCKS: usize = 10_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;
fn capacity() -> TraceError { TraceError::InvalidArgument("CFG complete response capacity exceeded".into()) }
struct Budget { bytes: usize, items: usize }
impl Budget {
    fn add(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(capacity)?;
        self.items = self.items.checked_add(1).ok_or_else(capacity)?;
        if self.bytes > MAX_BYTES || self.items > MAX_ITEMS { return Err(capacity()); }
        Ok(())
    }
}
fn table(s: FlatSection<'_>, pair: usize, width: u64) -> Result<FlatSection<'_>> {
    let start = u64_at(s.data, pair * 16); let count = u64_at(s.data, pair * 16 + 8);
    Ok(FlatSection { data: checked_slice(s.data, start, bytes(count, width)?)?, count })
}
fn lower(s: FlatSection<'_>, width: u64, key: impl Fn(&[u8]) -> bool) -> Result<u64> {
    let mut lo = 0; let mut hi = s.count;
    while lo < hi { let mid = lo + (hi-lo)/2; if key(s.record(mid,width)?) { lo=mid+1; } else { hi=mid; } }
    Ok(lo)
}
fn size(v: u64) -> Result<usize> { usize::try_from(v).map_err(|_| capacity()) }
fn inclusive(end: u32) -> Result<u32> { end.checked_sub(1).ok_or_else(|| bad("empty query range")) }

impl ControlFlowStore {
    fn address_text(&self, id: u32) -> Result<String> {
        let r = self.section(Section::StableAddresses).record(id.into(),16)?;
        let modules = self.section(Section::Modules);
        let mid = u32_at(r,0) as usize;
        let pool = bytes(modules.count.checked_add(1).ok_or_else(capacity)?,8)?;
        let start = u64_at(modules.data,mid*8); let end = u64_at(modules.data,(mid+1)*8);
        let name = std::str::from_utf8(checked_slice(modules.data,pool+start,end-start)?).map_err(|_| bad("module UTF8"))?;
        Ok(format!("{name}+0x{:x}",u64_at(r,8)))
    }
    fn function_record(&self, function: &str) -> Result<(u32, &[u8])> {
        let invalid=|| TraceError::InvalidArgument("no confirmed function in selected trace".into());
        let (name,offset)=function.split_once("+0x").ok_or_else(invalid)?;
        let offset=u64::from_str_radix(offset,16).map_err(|_|invalid())?;
        let modules=self.section(Section::Modules);
        let pool=bytes(modules.count+1,8)?;
        let mut module=None;
        for mid in 0..modules.count {
            let start=u64_at(modules.data,size(mid*8)?);let end=u64_at(modules.data,size((mid+1)*8)?);
            if checked_slice(modules.data,pool+start,end-start)?==name.as_bytes(){module=Some(u32::try_from(mid).map_err(|_|capacity())?);break;}
        }
        let mid=module.ok_or_else(invalid)?;
        let addresses=self.section(Section::StableAddresses);
        let aid=lower(addresses,16,|r|(u32_at(r,0),u64_at(r,8))<(mid,offset))?;
        if aid==addresses.count{return Err(invalid());}
        let address=addresses.record(aid,16)?;
        if (u32_at(address,0),u64_at(address,8))!=(mid,offset){return Err(invalid());}
        let fid=u32::try_from(aid).map_err(|_|capacity())?;
        // Reject noncanonical spellings just as the existing stable-site lookup.
        if self.address_text(fid)?!=function{return Err(invalid());}
        let functions=table(self.section(Section::FunctionActivationIndex),0,24)?;
        let pos=lower(functions,24,|r|u32_at(r,0)<fid)?;
        if pos<functions.count {let r=functions.record(pos,24)?;if u32_at(r,0)==fid{return Ok((fid,r));}}
        Err(invalid())
    }
    fn occurrence(&self, index: u64) -> Result<CfgOccurrence> {
        let get = |s| -> Result<u32> { Ok(u32_at(self.section(s).record(index,4)?,0)) };
        Ok(CfgOccurrence { activation_id:get(Section::OccurrenceActivationIds)?, block_id:get(Section::OccurrenceBlockIds)?,
            start_seq:get(Section::OccurrenceStartSeqs)?, end_seq:inclusive(get(Section::OccurrenceEndSeqs)?)? })
    }
    fn instructions(&self, trace: &OpenedTrace, start: u32, end: u32, budget: &mut Budget, c: &AtomicBool) -> Result<Vec<String>> {
        let mut result=Vec::new();
        for seq in start..end {
            cancel(c)?;
            let raw=self.line(trace,seq).ok_or_else(|| bad("representative seq"))?;
            let text=std::str::from_utf8(raw).map_err(|_| bad("trace UTF8"))?;
            if let Some((m,o))=trace_parser::strict_memory::instruction_parts(text) {
                let site=crate::engine::stable_site(text).ok_or_else(||bad("representative site"))?;
                budget.add(site.len().checked_add(m.len()).and_then(|n| n.checked_add(o.len()+32)).ok_or_else(capacity)?)?;
                result.push(format!("{}: {} {}",site,m,o).trim_end().to_owned());
            }
        }
        Ok(result)
    }
    pub(crate) fn disk_activation_cfg(&self, trace:&OpenedTrace, call:u32, entry:u32, function:&str, blocks:&CfgPage, occurrences:&CfgPage, c:&AtomicBool) -> Result<CfgView> {
        trace.verify_identity(c)?;
        let (fid,fr)=self.function_record(function)?;
        let ids=table(self.section(Section::FunctionActivationIndex),1,4)?;
        let start=u64_at(fr,8); let count=u64_at(fr,16);
        let activations=self.section(Section::Activations);
        // The function's IDs are ordered by (call_seq,id).
        let range=FlatSection {data:checked_slice(ids.data,bytes(start,4)?,bytes(count,4)?)?,count};
        let pos=lower(range,4,|r| u32_at(activations.record(u32_at(r,0).into(),64).unwrap(),8)<call)?;
        if pos<count { let aid=u32_at(range.record(pos,4)?,0); let a=activations.record(aid.into(),64)?;
            if u32_at(a,8)==call && u32_at(a,12)==entry { return self.disk_view(trace,fid,function,Some(aid),fr,blocks,occurrences,c); }
        }
        Err(TraceError::InvalidArgument("selector is not a confirmed activation of this function".into()))
    }
    pub(crate) fn disk_function_cfg(&self,trace:&OpenedTrace,function:&str,blocks:&CfgPage,occurrences:&CfgPage,c:&AtomicBool)->Result<CfgView> {
        trace.verify_identity(c)?;
        let (fid,fr)=self.function_record(function)?;
        self.disk_view(trace,fid,function,None,fr,blocks,occurrences,c)
    }
    fn disk_view(&self,trace:&OpenedTrace,fid:u32,function:&str,selected:Option<u32>,fr:&[u8],bp:&CfgPage,op:&CfgPage,c:&AtomicBool)->Result<CfgView> {
        if bp.limit>MAX_BLOCKS || op.limit>MAX_BLOCKS || bp.offset.checked_add(bp.limit).is_none() || op.offset.checked_add(op.limit).is_none() { return Err(capacity()); }
        let mut budget=Budget{bytes:0,items:0};
        let mut view=CfgView {function:function.into(),activations:Vec::new(),blocks:Vec::new(),edges:Vec::new(),occurrences:Vec::new(),total_blocks:0,total_occurrences:0,unresolved_boundaries:Vec::new()};
        budget.add(function.len()+std::mem::size_of::<CfgView>())?;
        let a=self.section(Section::Activations);
        let fi=table(self.section(Section::FunctionActivationIndex),1,4)?;
        let id_count=if selected.is_some(){1}else{u64_at(fr,16)};
        if id_count>MAX_ITEMS as u64 {return Err(capacity());}
        for n in 0..id_count {
            cancel(c)?;
            let aid=if let Some(id)=selected{id}else{u32_at(fi.record(u64_at(fr,8)+n,4)?,0)};
            let ar=a.record(aid.into(),64)?;
            budget.add(std::mem::size_of::<CfgActivation>())?;
            view.activations.push(CfgActivation{id:aid,call_seq:u32_at(ar,8),entry_seq:u32_at(ar,12)});
            let range=self.section(Section::ActivationOccurrenceRanges).record(aid.into(),16)?;
            let start=u64_at(range,0);let count=u64_at(range,8);
            let base=view.total_occurrences;view.total_occurrences=base.checked_add(size(count)?).ok_or_else(capacity)?;
            let from=op.offset.saturating_sub(base).min(size(count)?);
            let to=op.offset.checked_add(op.limit).ok_or_else(capacity)?.saturating_sub(base).min(size(count)?);
            for i in from..to {cancel(c)?;budget.add(std::mem::size_of::<CfgOccurrence>())?;view.occurrences.push(self.occurrence(start+i as u64)?);}
        }
        let block_section=self.section(Section::Blocks);
        let br=table(block_section,0,48)?;let variants=table(block_section,1,16)?;
        let refs=table(block_section,2,16)?;let sources=table(block_section,3,4)?;
        let ref_start=lower(refs,16,|r|u32_at(r,0)<fid)?;let ref_end=lower(refs,16,|r|u32_at(r,0)<=fid)?;
        let local=table(block_section,4,16)?;
        let (local_start,local_end)=if let Some(aid)=selected {
            (lower(local,16,|r|u32_at(r,0)<aid)?,lower(local,16,|r|u32_at(r,0)<=aid)?)
        }else{(0,0)};
        view.total_blocks=if selected.is_some(){size(local_end-local_start)?}else{size(ref_end-ref_start)?};
        let page_end=bp.offset.checked_add(bp.limit).ok_or_else(capacity)?.min(view.total_blocks);
        if selected.is_some() {
            for n in bp.offset.min(view.total_blocks)..page_end {cancel(c)?;let r=local.record(local_start+n as u64,16)?;
                view.blocks.push(self.disk_block(trace,u32_at(r,4),u64_at(r,8),selected,br,variants,sources,&mut budget,c)?);
            }
        } else {
            for n in bp.offset.min(view.total_blocks)..page_end {cancel(c)?;let r=refs.record(ref_start+n as u64,16)?;
                view.blocks.push(self.disk_block(trace,u32_at(r,4),u64_at(r,8),None,br,variants,sources,&mut budget,c)?);
            }
        }
        let edges=self.section(Section::Edges);let er=table(edges,0,48)?;let es=table(edges,1,4)?;
        let target=selected.unwrap_or(NONE);
        let from=lower(er,48,|r|(u32_at(r,16),u32_at(r,0))<(fid,target))?;
        let to=lower(er,48,|r|(u32_at(r,16),u32_at(r,0))<=(fid,target))?;
        if to-from>MAX_ITEMS as u64 {return Err(capacity());}
        for i in from..to {cancel(c)?;let r=er.record(i,48)?;budget.add(std::mem::size_of::<CfgEdge>())?;
            let kind=match u32_at(r,12){0=>CfgEdgeKind::Sequential,1=>CfgEdgeKind::Conditional,2=>CfgEdgeKind::Branch,3=>CfgEdgeKind::Indirect,4=>CfgEdgeKind::CallResume,5=>CfgEdgeKind::Return,_=>return Err(bad("edge kind"))};
            view.edges.push(CfgEdge{from:u32_at(r,4),to:u32_at(r,8),kind,count:u64_at(r,24),activation_ids:source_ids(es,u64_at(r,32),u64_at(r,40),&mut budget,c)?});
        }
        for r in a.data.chunks_exact(64).skip(1) {cancel(c)?;
            if u32_at(r,24)!=2 {continue;}
            let parent=u32_at(r,4);
            let parent_selected=if let Some(aid)=selected {parent==aid}else{parent!=NONE && u32_at(a.record(parent.into(),64)?,24)==1 && u32_at(a.record(parent.into(),64)?,0)==fid};
            let missing_entry_matches=u32_at(r,12)==NONE && self.line(trace,0)
                .and_then(|raw|std::str::from_utf8(raw).ok()).and_then(crate::engine::stable_site).as_deref()==Some(function);
            if parent_selected || u32_at(r,0)==fid || missing_entry_matches {
                budget.add(std::mem::size_of::<CfgBoundary>()+32)?;
                // Preserve the legacy DTO's zero entry sentinel; disk NONE is
                // never used as a raw seq or synthesized boundary fact.
                let entry=u32_at(r,12);let call=u32_at(r,8);
                let reason=match u32_at(r,28){1=>"TraceEndStillActive",2=>"DisplacedByAnotherCall",3=>"NoNextInsn",_=>return Err(bad("unresolved reason"))};
                view.unresolved_boundaries.push(CfgBoundary{call_seq:call,entry_seq:if entry==NONE{0}else{entry},reason:reason.into()});
            }
        }
        // Encoding itself is bounded as well; escaping may expand raw text.
        struct Counter(usize);
        impl std::io::Write for Counter {fn write(&mut self,b:&[u8])->std::io::Result<usize>{self.0=self.0.checked_add(b.len()).ok_or_else(||std::io::Error::other("CFG capacity"))?;if self.0>MAX_BYTES{return Err(std::io::Error::other("CFG capacity"));}Ok(b.len())}fn flush(&mut self)->std::io::Result<()>{Ok(())}}
        serde_json::to_writer(Counter(0),&view).map_err(|_|capacity())?;
        trace.verify_identity(c)?;
        Ok(view)
    }
    fn disk_block(&self,trace:&OpenedTrace,bid:u32,count:u64,selected:Option<u32>,br:FlatSection<'_>,variants:FlatSection<'_>,sources:FlatSection<'_>,budget:&mut Budget,c:&AtomicBool)->Result<CfgBlock> {
        let r=br.record(bid.into(),48)?;let site=self.address_text(u32_at(r,4))?;
        budget.add(std::mem::size_of::<CfgBlock>()+site.len())?;
        let ids=if let Some(id)=selected{budget.add(4)?;vec![id]}else{source_ids(sources,u64_at(r,32),u64_at(r,40),budget,c)?};
        let start=u64_at(r,16);let count_variants=u64_at(r,24);
        let all=FlatSection{data:checked_slice(variants.data,bytes(start,16)?,bytes(count_variants,16)?)?,count:count_variants};
        let (first,last)=if let Some(id)=selected {
            (lower(all,16,|v|u32_at(v,4)<id)?,lower(all,16,|v|u32_at(v,4)<=id)?)
        }else{(0,count_variants)};
        let mut representatives:Vec<CfgRepresentative>=Vec::new();
        for n in first..last {cancel(c)?;let v=all.record(n,16)?;
            let mut candidate_budget=Budget{bytes:budget.bytes,items:budget.items};
            let instructions=self.instructions(trace,u32_at(v,8),u32_at(v,12),&mut candidate_budget,c)?;
            if representatives.iter().any(|r|r.instructions==instructions){continue;}
            *budget=candidate_budget;budget.add(std::mem::size_of::<CfgRepresentative>())?;
            representatives.push(CfgRepresentative{start_seq:u32_at(v,8),end_seq:inclusive(u32_at(v,12))?,instructions});
        }
        if representatives.is_empty(){return Err(bad("missing selected block variants"));}
        Ok(CfgBlock{id:bid,site,count,activation_ids:ids,representatives})
    }
    pub(crate) fn disk_occurrence_for_seq(&self,trace:&OpenedTrace,seq:u32,c:&AtomicBool)->Result<Option<CfgOccurrence>> {
        trace.verify_identity(c)?;
        let result=(|| {
            let Some(raw)=self.line(trace,seq) else{return Ok(None)};
            let text=std::str::from_utf8(raw).map_err(|_|bad("trace UTF8"))?;
            if trace_parser::strict_memory::instruction_parts(text).is_none(){return Ok(None);}
            let events=self.section(Section::ActivationBoundaryEvents);
            let end=lower(events,24,|r|u32_at(r,0)<=seq)?;
            let mut owner=0;
            for i in (0..end).rev(){cancel(c)?;let e=events.record(i,24)?;if u32_at(e,8)==1{owner=u32_at(e,4);break;}}
            let a=self.section(Section::Activations);
            // The most recent entry may already have resumed. Unresolved children
            // must also be excluded when a confirmed ancestor has resumed.
            let mut p=owner;
            while p!=0 {cancel(c)?;let ar=a.record(p.into(),64)?;
                if u32_at(ar,24)==1 && seq>=u32_at(ar,20){owner=u32_at(ar,4);}
                p=u32_at(ar,4);
            }
            if owner==0 || u32_at(a.record(owner.into(),64)?,24)!=1{return Ok(None);}
            let r=self.section(Section::ActivationOccurrenceRanges).record(owner.into(),16)?;
            let start=u64_at(r,0);let count=u64_at(r,8);
            let starts=self.section(Section::OccurrenceStartSeqs);
            let range=FlatSection{data:checked_slice(starts.data,bytes(start,4)?,bytes(count,4)?)?,count};
            let pos=lower(range,4,|r|u32_at(r,0)<=seq)?;
            if pos==0{return Ok(None);}let o=self.occurrence(start+pos-1)?;
            Ok((seq<=o.end_seq).then_some(o))
        })();
        trace.verify_identity(c)?;
        result
    }
}
fn source_ids(s:FlatSection<'_>,start:u64,count:u64,budget:&mut Budget,c:&AtomicBool)->Result<Vec<u32>> {
    if count>MAX_ITEMS as u64{return Err(capacity());}
    let mut out=Vec::new();
    for n in start..start+count{cancel(c)?;budget.add(4)?;out.push(u32_at(s.record(n,4)?,0));}
    Ok(out)
}
