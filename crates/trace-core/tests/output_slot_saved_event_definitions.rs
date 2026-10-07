use trace_core::{TraceEngine, BuildOptions, engine::SavedEventObservation, api_types::{OutputSlotRangeDto, OutputSlotUsesDto}};
const RAW: &str = "[App] 0x400000!0x0 bl #0x401000; x0=0x0\n[App] 0x401000!0x1000 bl #0x402000; x0=0x0\n[App] 0x402000!0x2000 bl #0x499000; x0=0x404200 x1=0x5000 x2=0x8\ncall func: memcpy(0x404200, 0x5000, 0x8)\nret: 0x404200\n[App] 0x402004!0x2004 adrp x20, #0x404000; -> x20=0x404000\n[App] 0x402008!0x2008 ldr x9, [x20, #0x200]; x20=0x404000 mem_r=0x404200 -> x9=0x1\n[App] 0x40200c!0x200c add x10, x9, #1; x9=0x1 -> x10=0x2\n[App] 0x402010!0x2010 str x10, [x20, #0x300]; x20=0x404000 x10=0x2 mem_w=0x404300\n[App] 0x402014!0x2014 mov x9, #0; -> x9=0x0\n[App] 0x402018!0x2018 mov x10, #0; -> x10=0x0\n[App] 0x40201c!0x201c mov x20, #0; -> x20=0x0\n[App] 0x402020!0x2020 ret; x0=0x0\n[App] 0x401004!0x1004 ret; x0=0x0\n[App] 0x400004!0x4 nop\n";
fn event() -> SavedEventObservation {
 serde_json::from_value(serde_json::json!({"owner":{"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x2000","call_seq":1,"entry_seq":2,"exit_seq":12,"resume_seq":13},"event_index":0,"callsite":{"seq":2,"offset":"App+0x2000"},"resume":{"seq":5,"offset":"App+0x2004"},"target":{"module":null,"entry":null,"symbol":"memcpy"},"memory_reads":[],"memory_writes":[{"address":"0x404200","size":8,"bytes":"0100000000000000"}]})).unwrap()
}
fn query_result(raw: &str, events: &[SavedEventObservation]) -> trace_core::error::Result<OutputSlotUsesDto> {
 let path=std::env::temp_dir().join(format!("event-output-{}",uuid::Uuid::new_v4())); std::fs::write(&path,raw).unwrap();
 let e=TraceEngine::new(); let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"event-output").unwrap().session_id;
 e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let ranges=[OutputSlotRangeDto{address:"0x404200".into(),size:8},OutputSlotRangeDto{address:"0x404300".into(),size:8}];
 let p=e.get_output_slot_uses_with_saved_events(&sid,1,2,"App+0x2000",&["App".into()],&ranges,events);
 e.close_session(&sid).unwrap(); std::fs::remove_file(path).unwrap(); p
}
fn query(raw: &str, events: &[SavedEventObservation]) -> OutputSlotUsesDto { query_result(raw,events).unwrap() }
#[test] fn event_bytes_survive_scalar_load_alu_and_distinct_output_store() {
 let p=query(RAW,&[event()]); assert!(p.coverage.complete,"{}",serde_json::to_string(&p).unwrap()); assert!(p.uses.is_empty());
 assert!(!query(RAW,&[]).coverage.complete);
}
#[test] fn event_load_address_control_return_and_escape_remain_obligations() {
 for instruction in [
 "ldr x10, [x9]; x9=0x1 mem_r=0x1 -> x10=0x2",
 "add x10, x9, #1; x9=0x1 -> x10=0x2",
 "mov x10, x9; x9=0x1 -> x10=0x1",
 "br x9; x9=0x1",
 "bl #0x499100; x9=0x1",
 "mystery x10, x9; x9=0x1",
 ] {
 let mut raw=RAW.replace("add x10, x9, #1; x9=0x1 -> x10=0x2",instruction);
 // The ALU/copy cases use the propagated candidate as an address.
 if instruction.starts_with("add") || instruction.starts_with("mov") {
 raw=raw.replace("str x10, [x20, #0x300]; x20=0x404000 x10=0x2 mem_w=0x404300","ldr x11, [x10]; x10=0x2 mem_r=0x2 -> x11=0x0");
 }
 assert!(!query(&raw,&[event()]).coverage.complete,"{instruction}");
 }
 let raw=RAW.replace("mov x9, #0; -> x9=0x0","mov x0, x9; x9=0x1 -> x0=0x1").replace("ret; x0=0x0","ret; x0=0x1");
 assert!(!query(&raw,&[event()]).coverage.complete);
}
#[test] fn event_load_must_equal_captured_bytes() {
 let mut e=event(); e.memory_writes[0].bytes=Some("0200000000000000".into());
 let p=query(RAW,&[e]); assert!(!p.coverage.complete); assert!(p.gaps.iter().any(|g|g.kind=="load_without_slot_definition"));
}
#[test] fn partial_same_value_writer_cannot_merge_event_and_raw_load_origins() {
 let raw=RAW.replace("adrp x20, #0x404000; -> x20=0x404000","strb w8, [x20, #0x200]; x20=0x404000 w8=0x1 mem_w=0x404200");
 let p=query(&raw,&[event()]); assert!(!p.coverage.complete); assert!(p.gaps.iter().any(|g|g.kind=="mixed_event_load_definition")); assert!(p.uses.is_empty());
}
#[test] fn wrong_owner_resume_unknown_bytes_and_recorded_body_are_not_admitted() {
 let mut e=event(); e.owner.function="App+0x1000".into(); assert!(query_result(RAW,&[e]).is_err());
 let mut e=event(); e.resume.seq=6; assert!(query_result(RAW,&[e]).is_err());
 let mut e=event(); e.memory_writes[0].bytes=None; assert!(query_result(RAW,&[e]).is_err());
 let raw=RAW.replace("ret: 0x404200","[App] 0x499000!0x99000 nop"); assert!(query_result(&raw,&[event()]).is_err());
}
#[test] fn fresh_equal_event_does_not_discharge_live_loaded_candidate() {
 let raw=RAW.replace("[App] 0x402014!0x2014 mov x9, #0; -> x9=0x0", "[App] 0x402014!0x2014 bl #0x499000; x0=0x404200 x1=0x5000 x2=0x8\ncall func: memcpy(0x404200, 0x5000, 0x8)\nret: 0x404200");
 let mut first=event(); first.owner.exit_seq=14; first.owner.resume_seq=15;
 let mut second=event(); second.owner.exit_seq=14; second.owner.resume_seq=15; second.event_index=1; second.callsite.seq=9; second.callsite.offset="App+0x2014".into(); second.resume.seq=12; second.resume.offset="App+0x2018".into();
 let p=query(&raw,&[first,second]); assert!(!p.coverage.complete); assert!(p.gaps.iter().any(|g|g.seq==9 && g.kind=="untracked_store_data_escape")); assert!(p.uses.is_empty());
}
