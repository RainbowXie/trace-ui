use super::{*,format::*};
use std::{fs::File,sync::atomic::AtomicBool};
use crate::{control_flow::{ControlFlowIndex,types::CfgEdgeKind},engine::{stable_runtime_site,stable_site}};
fn pc(s:&str)->Option<u64>{stable_runtime_site(s).map(|v|v.1)}
fn run(text:&str){
    let dir=std::env::temp_dir().join(format!("cfg-real-build-{}",uuid::Uuid::new_v4()));std::fs::create_dir(&dir).unwrap();
    let raw=dir.join("raw");std::fs::write(&raw,text).unwrap();let c=AtomicBool::new(false);
    let trace=OpenedTrace::open(File::open(&raw).unwrap(),TraceFormat::GumTrace,&c).unwrap();
    let target=dir.join(trace.fd_cache_name());
    let budget=BuildBudget{run_records:2,merge_fan_in:2,scratch_bytes:4*1024*1024,max_depth:8,max_line_bytes:4096,max_open_files:256};
    let before=super::build::MERGE_PASSES.load(std::sync::atomic::Ordering::Relaxed);
    let store=build_control_flow_store(&trace,&target,&c,budget).unwrap();
    assert!(super::build::MERGE_PASSES.load(std::sync::atomic::Ordering::Relaxed)>=before+2);
    let reopened=ControlFlowStore::open(&target,&trace,&c).unwrap();
    for s in SECTIONS {assert_eq!(store.section(s).data,reopened.section(s).data);}
    let memory=ControlFlowIndex::build(text.as_bytes(),&c,stable_site,pc).unwrap();
    let a=store.section(Section::Activations);
    for old in &memory.tree.activations[1..] {let r=a.record(old.id as u64,64).unwrap();assert_eq!(u32_at(r,8),old.call_seq);assert_eq!(u32_at(r,12),if old.entry_pc==0 {NONE}else{old.entry_seq});assert_eq!(u32_at(r,24)==1,old.unresolved_reason.is_none());}
    let blocks=store.section(Section::Blocks).data;let off=u64_at(blocks,0) as usize;
    let address=store.section(Section::StableAddresses);
    let site=|bid:u32| {let r=&blocks[off+bid as usize*48..];let addr=address.record(u32_at(r,4) as u64,16).unwrap();format!("tiny.so+0x{:x}",u64_at(addr,8))};
    let starts=store.section(Section::OccurrenceStartSeqs);let ends=store.section(Section::OccurrenceEndSeqs);let bids=store.section(Section::OccurrenceBlockIds);let aids=store.section(Section::OccurrenceActivationIds);
    assert_eq!(starts.count,memory.occurrences.len() as u64);
    for (i,o) in memory.occurrences.iter().enumerate(){assert_eq!(u32_at(starts.data,i*4),o.start);assert_eq!(u32_at(ends.data,i*4).checked_sub(1),Some(o.end));assert_eq!(u32_at(aids.data,i*4),o.activation);assert_eq!(site(u32_at(bids.data,i*4)),memory.blocks[o.block as usize]);}
    let edge=store.section(Section::Edges).data;let eo=u64_at(edge,0) as usize;let ec=u64_at(edge,8) as usize;
    for aid in &memory.tree.confirmed_ids {
        let old=&memory.occurrences[memory.ranges[*aid as usize].clone()];
        for pair in old.windows(2){let from=&memory.blocks[pair[0].block as usize];let to=&memory.blocks[pair[1].block as usize];let kind=pair[0].outgoing as u32;
            let expected=old.windows(2).filter(|p|memory.blocks[p[0].block as usize]==*from && memory.blocks[p[1].block as usize]==*to && p[0].outgoing as u32==kind).count() as u64;
            assert!(edge[eo..eo+ec*48].chunks_exact(48).any(|r|u32_at(r,0)==*aid && site(u32_at(r,4))==*from && site(u32_at(r,8))==*to && u32_at(r,12)==kind && u64_at(r,24)==expected));
        }
    }
    // Per-activation exact sequence representatives, including specials.
    let vo=u64_at(blocks,16) as usize;let vc=u64_at(blocks,24) as usize;
    let instructions=|start:u32,end:u32|->Vec<String>{(start..end).filter_map(|seq|{
        let line=std::str::from_utf8(store.line(&trace,seq).unwrap()).unwrap();
        trace_parser::strict_memory::instruction_parts(line).map(|(m,o)|format!("{}: {} {}",stable_site(line).unwrap(),m,o).trim_end().to_owned())
    }).collect()};
    for o in &memory.occurrences {
        let seq=instructions(o.start,o.end+1);
        assert!(blocks[vo..vo+vc*16].chunks_exact(16).any(|v|u32_at(v,4)==o.activation && site(u32_at(v,0))==memory.blocks[o.block as usize] && instructions(u32_at(v,8),u32_at(v,12))==seq));
    }
    for (i,v) in blocks[vo..vo+vc*16].chunks_exact(16).enumerate(){
        assert!(!blocks[vo..vo+i*16].chunks_exact(16).any(|p|u32_at(p,0)==u32_at(v,0) && u32_at(p,4)==u32_at(v,4) && instructions(u32_at(p,8),u32_at(p,12))==instructions(u32_at(v,8),u32_at(v,12))));
    }
    // Failure must retain the complete previously published bytes.
    let old=std::fs::read(&target).unwrap();let mut too_small=budget;too_small.scratch_bytes=32;
    assert!(build_control_flow_store(&trace,&target,&c,too_small).is_err());assert_eq!(old,std::fs::read(&target).unwrap());
    let cancelled=AtomicBool::new(true);assert!(build_control_flow_store(&trace,&target,&cancelled,budget).is_err());assert_eq!(old,std::fs::read(&target).unwrap());
    let mut legacy=old.clone();legacy[..8].copy_from_slice(b"TCFG0001");legacy[8..12].copy_from_slice(&1u32.to_le_bytes());let legacy_path=dir.join("legacy");std::fs::write(&legacy_path,&legacy).unwrap();
    assert!(matches!(ControlFlowStore::open(&legacy_path,&trace,&c),Err(crate::error::TraceError::CacheError(s)) if s.contains("incompatible")));
    assert!(!std::fs::read_dir(&dir).unwrap().any(|e|e.unwrap().file_name().to_string_lossy().starts_with(".cfg-build")));
    drop(store);drop(reopened);drop(trace);std::fs::remove_dir_all(dir).unwrap();
}
fn text(ins:&[(u64,&str)])->String{ins.iter().map(|(p,s)|format!("[tiny.so] 0x{p:x}!0x{p:x} {s}\n")).collect()}
#[test]fn actual_two_pass_build_reopen_matches_memory(){
    let mut t=text(&[(0x100,"bl #0x200"),(0x200,"mov x0, x1"),(0x204,"bl #0x300"),(0x300,"add x0, x0, #1"),(0x304,"ret"),(0x208,"cbnz x0, #0x208"),(0x208,"cbnz x0, #0x208"),(0x20c,"bl #0x900"),(0x210,"retaa"),(0x104,"nop")]);
    t.insert_str(t.find("[tiny.so] 0x300").unwrap(),"\n");t.pop();run(&t);
}
#[test]fn late_target_variants_indirect_pac_recursive_and_unresolved(){
    run(&text(&[(0x100,"bl #0x200"),(0x200,"mov x0, x1"),(0x204,"add x0, x0, #1"),(0x208,"ret"),(0x104,"bl #0x200"),(0x200,"mov x0, x2"),(0x204,"br x16"),(0x204,"add x0, x0, #2"),(0x208,"ret"),(0x108,"blraa x16, x17"),(0x300,"bl #0x300"),(0x300,"bl #0x300"),(0x304,"ret"),(0x308,"ret"),(0x304,"ret"),(0x10c,"bl #0x400"),(0x400,"bl #0x500"),(0x500,"nop")]));
    assert_eq!(CfgEdgeKind::Indirect as u32,3);
    run(&text(&[(0x100,"bl #0x900"),(0x104,"bl #0x200"),(0x200,"b #0x208"),(0x208,"ret"),(0x108,"nop")]));
}
