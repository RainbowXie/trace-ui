use trace_core::{TraceEngine,BuildOptions,engine::SavedEventObservation,api_types::OutputSlotRangeDto};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x0\n[App] 0x401000!0x1000 bl #0x402000; x0=0x0\n[App] 0x402000!0x2000 bl #0x499000; x0=0x6000 x1=0x5000 x2=0x8\ncall func: memcpy(0x6000, 0x5000, 0x8)\nret: 0x6000\n[App] 0x402004!0x2004 adrp x20, #0x404000; -> x20=0x404000\n[App] 0x402008!0x2008 mov x9, #4; -> x9=0x4\n[App] 0x40200c!0x200c str x9, [x20]; x20=0x404000 x9=0x4 mem_w=0x404000\n[App] 0x402010!0x2010 mov x9, #0; -> x9=0x0\n[App] 0x402014!0x2014 ret; x0=0x0\n[App] 0x401004!0x1004 ret; x0=0x0\n[App] 0x400004!0x4 nop\n";
fn event()->SavedEventObservation{serde_json::from_value(serde_json::json!({"owner":{"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x2000","call_seq":1,"entry_seq":2,"exit_seq":9,"resume_seq":10},"event_index":0,"callsite":{"seq":2,"offset":"App+0x2000"},"resume":{"seq":5,"offset":"App+0x2004"},"target":{"module":null,"entry":null,"symbol":"memcpy"},"memory_reads":[{"address":"0x5000","size":8,"bytes":"0100000000000000"}],"memory_writes":[{"address":"0x6000","size":8,"bytes":"0100000000000000"}]})).unwrap()}
fn address_query(raw:&str)->trace_core::api_types::AddressProvenanceDto {
 let path=std::env::temp_dir().join(format!("frame-demand-{}",uuid::Uuid::new_v4()));std::fs::write(&path,raw).unwrap();
 let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"frame-demand").unwrap().session_id;
 e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let p=e.get_address_provenance_with_saved_events(&sid,1,2,"App+0x2000",&["App".into()],&[event()]).unwrap();
 e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();p
}
fn observed_sp_raw()->String {
 RAW.replace("; x0=0x6000 x1=0x5000 x2=0x8", "; sp=0x9000 x0=0x6000 x1=0x5000 x2=0x8")
 .replace("; -> x20", "; sp=0x9000 -> x20")
 .replace("; x20=0x404000 x9", "; sp=0x9000 x20=0x404000 x9")
 .replace("ret; x0=0x0", "ret; sp=0x9000 x0=0x0")
}
#[test]fn descendant_event_matches_actual_child_owner_not_query_root(){
 let path=std::env::temp_dir().join(format!("descendant-event-{}",uuid::Uuid::new_v4()));std::fs::write(&path,RAW).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"descendant-event").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let p=e.get_address_provenance_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&[event()]).unwrap();assert!(p.coverage.complete,"{}",serde_json::to_string(&p).unwrap());assert!(p.frames.is_empty());
 let p=e.get_address_provenance(&sid,0,1,"App+0x1000",&["App".into()]).unwrap();assert!(p.gaps.iter().any(|g|g.seq==2 && g.kind=="external_boundary"));
 let mut wrong=event();wrong.owner.function="App+0x1000".into();wrong.owner.call_seq=0;wrong.owner.entry_seq=1;wrong.owner.exit_seq=10;wrong.owner.resume_seq=11;assert!(e.get_address_provenance_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&[wrong]).is_err());
 let mut wrong=event();wrong.resume.seq=6;assert!(e.get_address_provenance_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&[wrong]).is_err());
 e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();
}
#[test]fn incidental_pre_sp_does_not_demand_a_global_only_frame(){
 let p=address_query(&observed_sp_raw());assert!(p.frames.is_empty(),"{}",serde_json::to_string(&p).unwrap());
 assert!(p.coverage.complete);assert!(matches!(p.accesses[0].origin_anchor,Some(trace_core::api_types::AddressOriginDto::GlobalAdrp{seq:5,..})));
}
#[test]fn actual_sp_operands_and_unmodeled_post_changes_still_demand_frame(){
 for instruction in ["mov x9, sp; sp=0x9000 -> x9=0x9000", "ldr x9, [sp]; sp=0x9000 mem_r=0x9000 -> x9=0x4", "sub sp, sp, #0x10; sp=0x9000 -> sp=0x8ff0", "mystery x9, sp; sp=0x9000", "nop; sp=0x9000 -> sp=0x8ff0"] {
  let raw=observed_sp_raw().replace("mov x9, #4; -> x9=0x4",instruction);
  let p=address_query(&raw);assert_eq!(p.frames.len(),1,"{instruction}");assert!(!p.coverage.complete,"{instruction}");
  assert!(p.frames[0].gaps.iter().any(|g|g.seq==2 && g.kind=="frame_effect"),"{instruction}");
 }
}
#[test]fn explicit_event_then_independent_global_origin_and_complete_raw_output(){
 let path=std::env::temp_dir().join(format!("barrier-{}",uuid::Uuid::new_v4()));std::fs::write(&path,RAW).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"barrier").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let ranges=[OutputSlotRangeDto{address:"0x404000".into(),size:8}];
 let p=e.get_output_slot_uses_with_saved_events(&sid,1,2,"App+0x2000",&["App".into()],&ranges,&[event()]).unwrap();assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());assert_eq!(p.coverage.scanned_lines,9);
 let p=e.get_output_slot_uses(&sid,1,2,"App+0x2000",&["App".into()],&ranges).unwrap();assert!(!p.coverage.complete);
 let p=e.get_address_provenance_with_saved_events(&sid,1,2,"App+0x2000",&["App".into()],&[event()]).unwrap();assert!(p.coverage.complete,"{}",serde_json::to_string(&p).unwrap());assert_eq!(p.accesses.len(),1);
 e.close_session(&sid).unwrap();std::fs::remove_file(&path).unwrap();
 for change in [
  RAW.replace("str x9, [x20]; x20=0x404000 x9=0x4 mem_w=0x404000","str w9, [x20]; x20=0x404000 w9=0x4 mem_w=0x404000"),
  RAW.replace("adrp x20, #0x404000; -> x20=0x404000","ldr x20, [x3]; x3=0x404000 mem_r=0x404000 -> x20=0x404000"),
 ] {
  std::fs::write(&path,&change).unwrap();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"barrier-negative").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
  assert!(!e.get_output_slot_uses_with_saved_events(&sid,1,2,"App+0x2000",&["App".into()],&ranges,&[event()]).unwrap().coverage.complete);
  e.close_session(&sid).unwrap();
 }
 std::fs::remove_file(path).unwrap();
}
