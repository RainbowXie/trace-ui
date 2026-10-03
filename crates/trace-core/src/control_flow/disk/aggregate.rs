use super::{build::*, format::*, scratch::{Workspace,Stream}, sort::{ExternalSort,read_record}, OpenedTrace,ControlFlowStore,CacheWriter};
use crate::error::Result;
use std::{fs::File,io::{Seek,SeekFrom},path::Path,sync::atomic::AtomicBool};
fn same_sequence(lines:&Lines<'_>,a:(u32,u32),b:(u32,u32),c:&AtomicBool)->Result<bool> {
    let mut x=a.0;let mut y=b.0;
    loop {
        cancel(c)?;
        let next=|pos:&mut u32,end:u32|->Result<Option<(String,String,String)>> {
            while *pos<end { let line=lines.line(*pos)?;*pos=pos.checked_add(1).ok_or_else(||bad("sequence seq overflow"))?;
                if let Some((m,o))=trace_parser::strict_memory::instruction_parts(line) {
                    let site=crate::engine::stable_site(line).ok_or_else(||bad("variant site"))?;
                    return Ok(Some((site,m.to_owned(),o.to_owned())));
                }
            } Ok(None)
        };
        let l=next(&mut x,a.1)?;let r=next(&mut y,b.1)?;
        if l!=r {return Ok(false);} if l.is_none(){return Ok(true);}
    }
}
pub(super) fn finish_sections(w:&Workspace,b:BuildBudget,c:&AtomicBool,trace:&OpenedTrace,target:&Path,total:u32,module_count:u32,address_count:u32,activation_count:u32,lines:&Lines<'_>,mut modules:Stream,mut addresses:Stream,mut activations:Stream,mut boundary:Stream,function_sort:&mut ExternalSort<12>,occ:&[u8])->Result<ControlFlowStore> {
    let mut block_sort=sort::<8>(w,b)?;
    for r in occ.chunks_exact(24) { let mut k=[0;8];put(&mut k,0,be(r,12));put(&mut k,4,be(r,16));block_sort.push(k,c)?; }
    let bs=sorted(&mut block_sort,w,c)?;drop(block_sort);let bm=bs.map()?;
    let mut block_keys=w.stream()?;let mut prev=None;
    for r in data(&bm).chunks_exact(8){if prev.as_ref().map(|v:&[u8;8]|&v[..])!=Some(r){block_keys.write(r,c)?;prev=Some(r.try_into().unwrap());}}
    drop(bm); drop(bs);
    let km=block_keys.map()?;let keys=data(&km);
    let block_count=u32::try_from(keys.len()/8).ok().filter(|v|*v!=NONE).ok_or_else(||bad("block ID capacity"))?;
    let mut starts=w.stream()?;let mut ends=w.stream()?;let mut bids=w.stream()?;let mut aids=w.stream()?;let mut ranges=w.stream()?;
    let mut byblock=sort::<24>(w,b)?;let mut edge_facts=sort::<20>(w,b)?;
    let mut index=0usize;let mut occurrence_cursor=0u64;
    for aid in 0..activation_count {
        le64(&mut ranges,occurrence_cursor,c)?;let initial=occurrence_cursor;let mut previous:Option<(u32,u32,u32)>=None;
        while index<occ.len() && be(occ,index)==aid {
            let r=&occ[index..index+24];let f=be(r,12);let mut key=[0;8];put(&mut key,0,f);put(&mut key,4,be(r,16));let bid=lookup(keys,8,&key)?;
            le32(&mut starts,be(r,4),c)?;le32(&mut ends,be(r,8),c)?;le32(&mut bids,bid,c)?;le32(&mut aids,aid,c)?;
            let mut br=[0;24];for(i,v)in [bid,aid,be(r,4),be(r,8),be(r,20),f].iter().enumerate(){put(&mut br,i*4,*v);}byblock.push(br,c)?;
            if let Some((from,kind,pf))=previous {if pf!=f{return Err(bad("activation function drift"));}let mut e=[0;20];for(i,v)in [f,aid,from,bid,kind].iter().enumerate(){put(&mut e,i*4,*v);}edge_facts.push(e,c)?;}
            previous=Some((bid,be(r,20),f));index+=24;occurrence_cursor=occurrence_cursor.checked_add(1).ok_or_else(||bad("occurrence count overflow"))?;
        }
        le64(&mut ranges,occurrence_cursor-initial,c)?;
    }
    if index!=occ.len(){return Err(bad("occurrence owner ID capacity"));}
    let grouped=sorted(&mut byblock,w,c)?;drop(byblock);let gm=grouped.map()?;let gb=data(&gm);
    let mut records=w.stream()?;let mut variants=w.stream()?;let mut references=w.stream()?;let mut sources=w.stream()?;
    let mut activation_blocks=sort::<16>(w,b)?;
    let mut cursor=0usize;let mut variant_count=0u64;let mut source_count=0u64;
    for bid in 0..block_count {
        let key=&keys[bid as usize*8..bid as usize*8+8];let f=be(key,0);let addr=be(key,4);
        let vs=variant_count;let ss=source_count;let mut executions=0u64;let mut local_executions=0u64;let mut last_aid=NONE;
        let flush_local=|aid:u32,count:u64,sorter:&mut ExternalSort<16>|->Result<()> {
            let mut key=[0;16];put(&mut key,0,aid);put(&mut key,4,bid);key[8..].copy_from_slice(&count.to_be_bytes());sorter.push(key,c)
        }; let mut activation_variant_start=vs;let mut representative=None;
        while cursor<gb.len() && be(gb,cursor)==bid {
            cancel(c)?;let r=&gb[cursor..cursor+24];let aid=be(r,4);let start=be(r,8);let end=be(r,12);
            if aid!=last_aid {if last_aid!=NONE {flush_local(last_aid,local_executions,&mut activation_blocks)?;}local_executions=0;le32(&mut sources,aid,c)?;source_count=source_count.checked_add(1).ok_or_else(||bad("source count"))?;last_aid=aid;activation_variant_start=variant_count;}
            // Only bounded per-line strings are allocated. Read existing reps
            // from scratch, comparing actual instruction sequences, not hashes.
            let mut reps=File::open(variants.path_for_build())?;
            reps.seek(SeekFrom::Start(bytes(activation_variant_start,16)?))?;
            let mut duplicate=false;
            for _ in activation_variant_start..variant_count {cancel(c)?;let v=read_record::<16>(&mut reps)?.ok_or_else(||bad("variant scratch truncated"))?;
                if same_sequence(lines,(start,end),(u32_at(&v,8),u32_at(&v,12)),c)? {duplicate=true;break;}}
            drop(reps);
            if !duplicate {for v in [bid,aid,start,end]{le32(&mut variants,v,c)?;}variant_count=variant_count.checked_add(1).ok_or_else(||bad("variant count"))?;representative.get_or_insert((start,end));}
            executions=executions.checked_add(1).ok_or_else(||bad("block execution count"))?;
            local_executions=local_executions.checked_add(1).ok_or_else(||bad("activation block execution count"))?;cursor+=24;
        }
        flush_local(last_aid,local_executions,&mut activation_blocks)?;
        let (rs,re)=representative.ok_or_else(||bad("block without occurrence"))?;
        for v in [f,addr,rs,re]{le32(&mut records,v,c)?;}for v in [vs,variant_count-vs,ss,source_count-ss]{le64(&mut records,v,c)?;}
        le32(&mut references,f,c)?;le32(&mut references,bid,c)?;le64(&mut references,executions,c)?;
    }
    drop(gm); drop(grouped); drop(km); drop(block_keys);
    let sorted_local=sorted(&mut activation_blocks,w,c)?;drop(activation_blocks);let local_map=sorted_local.map()?;
    let mut local_records=w.stream()?;
    for r in data(&local_map).chunks_exact(16) {le32(&mut local_records,be(r,0),c)?;le32(&mut local_records,be(r,4),c)?;le64(&mut local_records,u64::from_be_bytes(r[8..16].try_into().unwrap()),c)?;}
    let local_count=local_records.len/16;drop(local_map);drop(sorted_local);
    let mut blocks=composite(w,&mut[(&mut records,48,block_count as u64),(&mut variants,16,variant_count),(&mut references,16,block_count as u64),(&mut sources,4,source_count),(&mut local_records,16,local_count)],c)?;
    drop(local_records);
    drop(records);drop(variants);drop(references);drop(sources);
    let ef=sorted(&mut edge_facts,w,c)?;drop(edge_facts);let em=ef.map()?;
    let mut edge_sort=sort::<32>(w,b)?;
    let mut last:Option<[u8;20]>=None;let mut count=0u64;
    let flush=|key:[u8;20],count:u64,sorter:&mut ExternalSort<32>|->Result<()> {
        let mut local=[0;32];local[..20].copy_from_slice(&key);put(&mut local,20,be(&key,4));local[24..32].copy_from_slice(&count.to_be_bytes());sorter.push(local,c)?;
        let mut aggregate=local;put(&mut aggregate,4,NONE);sorter.push(aggregate,c)
    };
    for r in data(&em).chunks_exact(20){cancel(c)?;if last.as_ref().map(|v|&v[..])!=Some(r){if let Some(k)=last{flush(k,count,&mut edge_sort)?;}last=Some(r.try_into().unwrap());count=0;}count=count.checked_add(1).ok_or_else(||bad("edge count overflow"))?;}
    if let Some(k)=last {flush(k,count,&mut edge_sort)?;}
    drop(em); drop(ef);
    let es=sorted(&mut edge_sort,w,c)?;drop(edge_sort);let esm=es.map()?;
    let mut edge_records=w.stream()?;let mut edge_sources=w.stream()?;let mut edge_count=0u64;let mut source_cursor=0u64;
    let mut p=0usize;let e=data(&esm);
    while p<e.len(){cancel(c)?;let key=&e[p..p+20];let begin=source_cursor;let mut total_count=0u64;let mut last_source=None;
        while p<e.len() && &e[p..p+20]==key {let r=&e[p..p+32];let source=be(r,20);if last_source!=Some(source){le32(&mut edge_sources,source,c)?;source_cursor=source_cursor.checked_add(1).ok_or_else(||bad("edge source count"))?;last_source=Some(source);}total_count=total_count.checked_add(u64::from_be_bytes(r[24..32].try_into().unwrap())).ok_or_else(||bad("aggregate edge count"))?;p+=32;}
        for v in [be(key,4),be(key,8),be(key,12),be(key,16),be(key,0),0]{le32(&mut edge_records,v,c)?;}for v in [total_count,begin,source_cursor-begin]{le64(&mut edge_records,v,c)?;}edge_count=edge_count.checked_add(1).ok_or_else(||bad("edge records"))?;
    }
    drop(esm); drop(es);
    let mut edges=composite(w,&mut[(&mut edge_records,48,edge_count),(&mut edge_sources,4,source_cursor)],c)?;drop(edge_records);drop(edge_sources);
    let functions=sorted(function_sort,w,c)?;let function_map=functions.map()?;let fb=data(&function_map);
    let mut function_records=w.stream()?;let mut function_ids=w.stream()?;let mut fc=0u64;let mut ids=0u64;let mut p=0;
    while p<fb.len(){let f=be(fb,p);let start=ids;while p<fb.len() && be(fb,p)==f {le32(&mut function_ids,be(fb,p+8),c)?;ids=ids.checked_add(1).ok_or_else(||bad("function ID count"))?;p+=12;}
        le32(&mut function_records,f,c)?;le32(&mut function_records,0,c)?;le64(&mut function_records,start,c)?;le64(&mut function_records,ids-start,c)?;fc=fc.checked_add(1).ok_or_else(||bad("function count"))?;
    }
    drop(function_map); drop(functions);
    let mut function_index=composite(w,&mut[(&mut function_records,24,fc),(&mut function_ids,4,ids)],c)?;
    let mut line_index=w.stream()?;le32(&mut line_index,total,c)?;le32(&mut line_index,0,c)?;line_index.write(lines.samples,c)?;
    // Reserve the entire candidate (including section padding) against the same
    // build quota before CacheWriter writes any payload. Kept until publish.
    let mut candidate_bytes=PAYLOAD as u64;
    for s in [&modules,&addresses,&activations,&boundary,&blocks,&starts,&ends,&bids,&aids,&ranges,&edges,&function_index,&line_index]{candidate_bytes=candidate_bytes.checked_add(7).ok_or_else(||bad("candidate alignment"))?&!7;candidate_bytes=candidate_bytes.checked_add(s.len).ok_or_else(||bad("candidate size"))?;}
    w.quota.reserve(candidate_bytes)?;
    let mut writer=CacheWriter::create(target,trace,total,c)?;
    for (section,count,s) in [
        (Section::Modules,module_count as u64,&mut modules),(Section::StableAddresses,address_count as u64,&mut addresses),
        (Section::Activations,activation_count as u64,&mut activations),(Section::ActivationBoundaryEvents,boundary.len/24,&mut boundary),
        (Section::Blocks,block_count as u64,&mut blocks),(Section::OccurrenceStartSeqs,occurrence_cursor,&mut starts),
        (Section::OccurrenceEndSeqs,occurrence_cursor,&mut ends),(Section::OccurrenceBlockIds,occurrence_cursor,&mut bids),
        (Section::OccurrenceActivationIds,occurrence_cursor,&mut aids),(Section::ActivationOccurrenceRanges,activation_count as u64,&mut ranges),
        (Section::Edges,edge_count,&mut edges),(Section::FunctionActivationIndex,fc,&mut function_index),(Section::LineIndex,(total as u64+255)/256,&mut line_index)] {
        s.rewind()?;writer.write_section(section,count,s.len,&mut s.file,c)?;
    }
    let result=writer.publish(trace,c);w.quota.release(candidate_bytes);result
}
