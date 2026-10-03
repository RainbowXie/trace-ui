use trace_core::{TraceEngine,BuildOptions,engine::SavedEventObservation,api_types::OutputSlotRangeDto};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x0\n[App] 0x401000!0x1000 bl #0x402000; x0=0x0\n[App] 0x402000!0x2000 bl #0x499000; x0=0x6000 x1=0x5000 x2=0x8\ncall func: memcpy(0x6000, 0x5000, 0x8)\nret: 0x6000\n[App] 0x402004!0x2004 adrp x20, #0x404000; -> x20=0x404000\n[App] 0x402008!0x2008 mov x9, #4; -> x9=0x4\n[App] 0x40200c!0x200c str x9, [x20]; x20=0x404000 x9=0x4 mem_w=0x404000\n[App] 0x402010!0x2010 mov x9, #0; -> x9=0x0\n[App] 0x402014!0x2014 ret; x0=0x0\n[App] 0x401004!0x1004 ret; x0=0x0\n[App] 0x400004!0x4 nop\n";
fn event()->SavedEventObservation{serde_json::from_value(serde_json::json!({"owner":{"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x2000","call_seq":1,"entry_seq":2,"exit_seq":9,"resume_seq":10},"event_index":0,"callsite":{"seq":2,"offset":"App+0x2000"},"resume":{"seq":5,"offset":"App+0x2004"},"target":{"module":null,"entry":null,"symbol":"memcpy"},"memory_reads":[{"address":"0x5000","size":8,"bytes":"0100000000000000"}],"memory_writes":[{"address":"0x6000","size":8,"bytes":"0100000000000000"}]})).unwrap()}
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
