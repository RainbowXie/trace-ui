use super::{disk::*,types::*,render_dot};
use crate::TraceEngine;
use std::{fs::File,sync::atomic::AtomicBool};
fn full()->CfgPage{CfgPage{offset:0,limit:10_000}}
fn tiny_budget()->BuildBudget{BuildBudget{run_records:2,merge_fan_in:2,scratch_bytes:8*1024*1024,max_depth:16,max_line_bytes:4096,max_open_files:256}}
fn text()->String {
    let ins=[(0x100,"bl #0x200"),(0x200,"mov x0, x1"),(0x204,"bl #0x300"),(0x300,"add x0, x0, #1"),(0x304,"ret"),(0x208,"cbnz x0, #0x208"),(0x208,"cbnz x0, #0x208"),(0x20c,"bl #0x900"),(0x210,"ret"),(0x104,"bl #0x200"),(0x200,"mov x0, x2"),(0x204,"bl #0x300"),(0x300,"add x0, x0, #2"),(0x304,"ret"),(0x208,"cbnz x0, #0x208"),(0x20c,"bl #0x900"),(0x210,"ret"),(0x108,"bl #0x400"),(0x400,"bl #0x500"),(0x500,"nop")];
    let mut t=ins.iter().map(|(p,s)|format!("[tiny.so] 0x{p:x}!0x{p:x} {s}\n")).collect::<String>();
    t.insert_str(t.find("[tiny.so] 0x300").unwrap(),"\n"); t.pop();t
}
fn normalized(v:&CfgView)->CfgView {
    let mut out:CfgView=serde_json::from_value(serde_json::to_value(v).unwrap()).unwrap();
    let map=out.blocks.iter().map(|b|((v.function.clone(),b.site.clone()),b.id)).collect::<std::collections::BTreeMap<_,_>>();
    let ids=map.values().enumerate().map(|(new,old)|(*old,new as u32)).collect::<std::collections::BTreeMap<_,_>>();
    for b in &mut out.blocks {b.id=ids[&b.id];}
    for e in &mut out.edges {e.from=ids[&e.from];e.to=ids[&e.to];}
    for o in &mut out.occurrences {o.block_id=ids[&o.block_id];}
    out.blocks.sort_by_key(|b|b.id);
    out.edges.sort_by_key(|e|(e.from,e.to,e.kind));
    out
}
fn compare(a:&CfgView,b:&CfgView) {
    let a=normalized(a);let b=normalized(b);
    assert_eq!(serde_json::to_value(&a).unwrap(),serde_json::to_value(&b).unwrap());
    assert_eq!(render_dot(&a).unwrap(),render_dot(&b).unwrap());
}
fn exact(a:&CfgView,b:&CfgView) {
    assert_eq!(serde_json::to_vec(a).unwrap(),serde_json::to_vec(b).unwrap());
    assert_eq!(render_dot(a).unwrap(),render_dot(b).unwrap());
}
#[test]
fn disk_sessions_cold_hot_force_pages_fd_identity_and_core_dot() {
    let _lock=crate::cache::cache_dir_override_test_lock();
    let dir=std::env::temp_dir().join(format!("cfg-query-{}",uuid::Uuid::new_v4()));std::fs::create_dir(&dir).unwrap();
    let cache=dir.join("cache");crate::cache::set_cache_dir_override(Some(cache.clone()));
    struct Reset;impl Drop for Reset{fn drop(&mut self){crate::cache::set_cache_dir_override(None);}}
    let _reset=Reset;
    let raw=dir.join("raw");std::fs::write(&raw,text()).unwrap();
    let engine=TraceEngine::new();
    let memory=engine.create_session_from_file(File::open(&raw).unwrap(),"same-label").unwrap().session_id;
    engine.build_control_flow_index(&memory).unwrap();
    let disk=engine.create_control_flow_session_from_file(File::open(&raw).unwrap(),"same-label").unwrap();
    engine.build_disk_control_flow_index(&disk,false,tiny_budget()).unwrap();
    let expected=engine.get_function_cfg(&memory,"tiny.so+0x200",full(),full()).unwrap();
    let cold=engine.get_function_cfg(&disk,"tiny.so+0x200",full(),full()).unwrap();compare(&expected,&cold);
    for a in &cold.activations {
        compare(&engine.get_activation_cfg(&memory,a.call_seq,a.entry_seq,"tiny.so+0x200",full(),full()).unwrap(),&engine.get_activation_cfg(&disk,a.call_seq,a.entry_seq,"tiny.so+0x200",full(),full()).unwrap());
    }
    for seq in 0..text().lines().count() as u32 {
        let d=engine.get_cfg_occurrence_for_seq(&disk,seq).unwrap();let m=engine.get_cfg_occurrence_for_seq(&memory,seq).unwrap();
        assert_eq!(d.as_ref().map(|o|(o.activation_id,o.start_seq,o.end_seq)),m.as_ref().map(|o|(o.activation_id,o.start_seq,o.end_seq)));
        if let (Some(d),Some(m))=(d,m) {
            let function=if [2,4].contains(&d.activation_id){"tiny.so+0x300"}else{"tiny.so+0x200"};
            let dv=engine.get_function_cfg(&disk,function,full(),full()).unwrap();let mv=engine.get_function_cfg(&memory,function,full(),full()).unwrap();
            assert_eq!(dv.blocks.iter().find(|b|b.id==d.block_id).unwrap().site,mv.blocks.iter().find(|b|b.id==m.block_id).unwrap().site);
        }
    }
    for offset in 0..cold.total_occurrences+2 {
        let page=engine.get_function_cfg(&disk,"tiny.so+0x200",CfgPage{offset:1,limit:1},CfgPage{offset,limit:2}).unwrap();
        assert_eq!(serde_json::to_value(&page.occurrences).unwrap(),serde_json::to_value(cold.occurrences.iter().skip(offset).take(2).collect::<Vec<_>>()).unwrap());
        assert_eq!(page.blocks[0].site,cold.blocks[1].site);
        assert!(render_dot(&page).is_err());
    }
    let target=std::fs::read_dir(&cache).unwrap().next().unwrap().unwrap().path();
    let old=std::fs::read(&target).unwrap();
    let hot=engine.create_control_flow_session_from_file(File::open(&raw).unwrap(),"same-label").unwrap();
    // Impossible builder quota proves hot does not rebuild.
    let mut no_build=tiny_budget();no_build.scratch_bytes=1;
    engine.build_disk_control_flow_index(&hot,false,no_build).unwrap();
    exact(&cold,&engine.get_function_cfg(&hot,"tiny.so+0x200",full(),full()).unwrap());
    assert!(engine.build_disk_control_flow_index(&hot,true,no_build).is_err());assert_eq!(old,std::fs::read(&target).unwrap());
    engine.build_disk_control_flow_index(&hot,true,tiny_budget()).unwrap();
    exact(&cold,&engine.get_function_cfg(&hot,"tiny.so+0x200",full(),full()).unwrap());
    assert_eq!(old,std::fs::read(&target).unwrap());
    let mut v1=old.clone();v1[..8].copy_from_slice(b"TCFG0001");v1[8..12].copy_from_slice(&1u32.to_le_bytes());std::fs::write(&target,&v1).unwrap();
    engine.build_disk_control_flow_index(&hot,false,tiny_budget()).unwrap();assert_eq!(old,std::fs::read(&target).unwrap());
    let mut v2=old.clone();v2[..8].copy_from_slice(b"TCFG0002");v2[8..12].copy_from_slice(&2u32.to_le_bytes());std::fs::write(&target,&v2).unwrap();
    assert!(engine.build_disk_control_flow_index(&hot,false,no_build).is_err());assert_eq!(v2,std::fs::read(&target).unwrap());
    engine.build_disk_control_flow_index(&hot,false,tiny_budget()).unwrap();assert_eq!(old,std::fs::read(&target).unwrap());
    let mut corrupt=old.clone();let last=corrupt.len()-1;corrupt[last]^=1;std::fs::write(&target,&corrupt).unwrap();
    assert!(engine.build_disk_control_flow_index(&hot,false,tiny_budget()).is_err());assert_eq!(corrupt,std::fs::read(&target).unwrap());
    for invalid in [old[..64].to_vec(),{let mut b=old.clone();b[..8].copy_from_slice(b"TCFG9999");b}] {
        std::fs::write(&target,&invalid).unwrap();assert!(engine.build_disk_control_flow_index(&hot,false,tiny_budget()).is_err());assert_eq!(invalid,std::fs::read(&target).unwrap());
    }
    std::fs::write(&target,&old).unwrap();
    let outside=dir.join("outside");std::fs::write(&outside,&old).unwrap();
    std::fs::remove_file(&target).unwrap();std::os::unix::fs::symlink(&outside,&target).unwrap();
    assert!(engine.build_disk_control_flow_index(&hot,false,tiny_budget()).is_err());
    assert!(engine.build_disk_control_flow_index(&hot,true,tiny_budget()).is_err());
    assert_eq!(old,std::fs::read(&outside).unwrap());
    std::fs::remove_file(&target).unwrap();std::fs::write(&target,&old).unwrap();
    let raw2=dir.join("raw2");std::fs::write(&raw2,text().replace("mov x0, x1","mov x0, x3")).unwrap();
    let second=engine.create_control_flow_session_from_file(File::open(&raw2).unwrap(),"same-label").unwrap();engine.build_disk_control_flow_index(&second,false,tiny_budget()).unwrap();
    // 只数本用例的 CFG 缓存文件：缓存目录同时存放内容指纹等其它旁路文件。
    assert_eq!(std::fs::read_dir(&cache).unwrap().flatten().filter(|e|e.file_name().to_string_lossy().starts_with("fd-")).count(),2);
    assert_ne!(serde_json::to_value(&cold.blocks).unwrap(),serde_json::to_value(engine.get_function_cfg(&second,"tiny.so+0x200",full(),full()).unwrap().blocks).unwrap());
    engine.close_session(&second).unwrap();assert!(engine.get_function_cfg(&second,"tiny.so+0x200",full(),full()).is_err());
    engine.cancel_build(&hot);assert!(engine.get_function_cfg(&hot,"tiny.so+0x200",full(),full()).is_err());
    std::fs::write(&raw,text().replace("mov x0, x1","mov x0, x4")).unwrap();assert!(engine.get_function_cfg(&disk,"tiny.so+0x200",full(),full()).is_err());assert!(engine.verify_control_flow_session_identity(&disk).is_err());
    drop(engine);std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn disk_activation_page_reads_more_than_ten_thousand_blocks() {
    let dir=std::env::temp_dir().join(format!("cfg-large-page-{}",uuid::Uuid::new_v4()));std::fs::create_dir(&dir).unwrap();
    let mut text=String::from("[tiny.so] 0x100!0x100 bl #0x200\n");
    // Repeat the entry block to distinguish execution counts from variants.
    text.push_str("[tiny.so] 0x200!0x200 b #0x200\n");
    for i in 0..10_000u64 {let p=0x200+i*4;text.push_str(&format!("[tiny.so] 0x{p:x}!0x{p:x} b #0x{:x}\n",p+4));}
    text.push_str("[tiny.so] 0x9e40!0x9e40 ret\n[tiny.so] 0x104!0x104 nop\n");
    let raw=dir.join("raw");std::fs::write(&raw,text).unwrap();let c=AtomicBool::new(false);
    let trace=OpenedTrace::open(File::open(&raw).unwrap(),format::TraceFormat::GumTrace,&c).unwrap();
    let mut budget=tiny_budget();budget.run_records=1024;budget.merge_fan_in=8;budget.scratch_bytes=32*1024*1024;
    let target=dir.join("cache");let store=build_control_flow_store(&trace,&target,&c,budget).unwrap();
    let empty=CfgPage{offset:0,limit:0};
    let page=store.disk_activation_cfg(&trace,0,1,"tiny.so+0x200",&CfgPage{offset:0,limit:1},&empty,&c).unwrap();
    assert_eq!(page.total_blocks,10_001);assert_eq!(page.total_occurrences,10_002);
    assert_eq!(page.blocks.len(),1);assert_eq!(page.blocks[0].site,"tiny.so+0x200");assert_eq!(page.blocks[0].count,2);
    assert_eq!(page.blocks[0].representatives.len(),2);assert!(render_dot(&page).is_err());
    let last=store.disk_activation_cfg(&trace,0,1,"tiny.so+0x200",&CfgPage{offset:10_000,limit:1},&empty,&c).unwrap();
    assert_eq!(last.total_blocks,10_001);assert_eq!(last.blocks[0].site,"tiny.so+0x9e40");assert_eq!(last.blocks[0].count,1);
    let beyond=store.disk_activation_cfg(&trace,0,1,"tiny.so+0x200",&CfgPage{offset:10_001,limit:1},&empty,&c).unwrap();assert!(beyond.blocks.is_empty());
    assert!(store.disk_activation_cfg(&trace,0,1,"tiny.so+0x200",&CfgPage{offset:0,limit:10_001},&empty,&c).is_err());
    let reopened=ControlFlowStore::open(&target,&trace,&c).unwrap();
    let hot=reopened.disk_activation_cfg(&trace,0,1,"tiny.so+0x200",&CfgPage{offset:0,limit:1},&empty,&c).unwrap();
    assert_eq!(serde_json::to_vec(&page).unwrap(),serde_json::to_vec(&hot).unwrap());
    drop(reopened);drop(store);drop(trace);std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn disk_query_recursive_owner_special_and_response_capacity() {
    let dir=std::env::temp_dir().join(format!("cfg-owner-{}",uuid::Uuid::new_v4()));std::fs::create_dir(&dir).unwrap();
    let raw=dir.join("raw");
    let text="[tiny.so] 0x100!0x100 bl #0x200\n[tiny.so] 0x200!0x200 bl #0x200\n\n[tiny.so] 0x200!0x200 bl #0x200\n[tiny.so] 0x204!0x204 ret\n[tiny.so] 0x208!0x208 ret\n[tiny.so] 0x204!0x204 ret\n[tiny.so] 0x104!0x104 nop";
    std::fs::write(&raw,text).unwrap();let c=AtomicBool::new(false);
    let trace=OpenedTrace::open(File::open(&raw).unwrap(),format::TraceFormat::GumTrace,&c).unwrap();
    let store=build_control_flow_store(&trace,&dir.join("cache"),&c,tiny_budget()).unwrap();
    let core=super::ControlFlowIndex::build(text.as_bytes(),&c,crate::engine::stable_site,|s|crate::engine::stable_runtime_site(s).map(|v|v.1)).unwrap();
    for seq in 0..8 {assert_eq!(serde_json::to_value(store.disk_occurrence_for_seq(&trace,seq,&c).unwrap()).unwrap(),serde_json::to_value(core.occurrence_for_seq(text.as_bytes(),seq).unwrap()).unwrap());}
    assert!(store.disk_function_cfg(&trace,"tiny.so+0x200",&CfgPage{offset:0,limit:10_001},&full(),&c).is_err());
    assert!(store.disk_activation_cfg(&trace,0,3,"tiny.so+0x200",&full(),&full(),&c).is_err());
    drop(store);drop(trace);std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn disk_query_repository_sample_unresolved_and_all_variants_match_core() {
    let samples=[include_str!("../../../../example-trace-gumtrace.txt").to_owned(),
        "[tiny.so] 0x100!0x100 bl #0x200\n[tiny.so] 0x200!0x200 nop\n[tiny.so] 0x204!0x204 ret\n[tiny.so] 0x104!0x104 bl #0x200\n[tiny.so] 0x200!0x200 bl #0x500\n[tiny.so] 0x500!0x500 nop".to_owned(),
        "[tiny.so] 0x100!0x100 bl #0x200\n[tiny.so] 0x200!0x200 nop\n[tiny.so] 0x204!0x204 ret\n[tiny.so] 0x104!0x104 bl #0x200".to_owned(),
        "[tiny.so] 0x100!0x100 bl #0x200\n[tiny.so] 0x200!0x200 br x16\n[tiny.so] 0x208!0x208 ret\n[tiny.so] 0x104!0x104 bl #0x300\n[tiny.so] 0x300!0x300 br x16\n[tiny.so] 0x208!0x208 ret\n[tiny.so] 0x108!0x108 nop".to_owned(),
        [(0x100,"bl #0x200"),(0x200,"bl #0x200"),(0x200,"bl #0x900"),(0x204,"ret"),(0x204,"ret"),(0x104,"nop")].iter().map(|(pc,insn)|format!("[00:00:00 000][tiny.so 0x{pc:x}] [00000000] 0x{pc:x}: \"{insn}\"\n")).collect()];
    for text in samples {
        let dir=std::env::temp_dir().join(format!("cfg-view-{}",uuid::Uuid::new_v4()));std::fs::create_dir(&dir).unwrap();
        let raw=dir.join("raw");std::fs::write(&raw,&text).unwrap();let c=AtomicBool::new(false);
        let format=match trace_parser::gumtrace::detect_format(text.as_bytes()){trace_parser::types::TraceFormat::Gumtrace=>format::TraceFormat::GumTrace,_=>format::TraceFormat::Unidbg};
        let trace=OpenedTrace::open(File::open(&raw).unwrap(),format,&c).unwrap();
        let store=build_control_flow_store(&trace,&dir.join("cache"),&c,tiny_budget()).unwrap();
        let core=super::ControlFlowIndex::build(text.as_bytes(),&c,crate::engine::stable_site,|s|crate::engine::stable_runtime_site(s).map(|v|v.1)).unwrap();
        for function in core.functions.keys() {
            compare(&core.function_cfg(text.as_bytes(),function,&full(),&full()).unwrap(),&store.disk_function_cfg(&trace,function,&full(),&full(),&c).unwrap());
        }
        drop(store);drop(trace);std::fs::remove_dir_all(dir).unwrap();
    }
}
