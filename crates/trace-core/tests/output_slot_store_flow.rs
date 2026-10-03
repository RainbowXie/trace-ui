use trace_core::{TraceEngine,BuildOptions,api_types::OutputSlotRangeDto};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x7000\n[App] 0x401000!0x1000 bl #0x402000; x0=0x7000\n[App] 0x402000!0x2000 mov x9, #3; -> x9=0x3\n[App] 0x402004!0x2004 str x9, [x0]; x0=0x7000 x9=0x3 mem_w=0x7000\n[App] 0x402008!0x2008 mov x9, #0; -> x9=0x0\n[App] 0x40200c!0x200c ret; x0=0x7000\n[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x7000 mem_r=0x7000 -> x9=0x3\n[App] 0x401008!0x1008 add x9, x9, x5; x9=0x3 x5=0x1 -> x9=0x4\n[App] 0x40100c!0x100c str x9, [x3]; x3=0x8000 x9=0x4 mem_w=0x8000\n[App] 0x401010!0x1010 mov x9, #0; -> x9=0x0\n[App] 0x401014!0x1014 mov x0, #0; -> x0=0x0\n[App] 0x401018!0x1018 ret; x0=0x0\n[App] 0x400004!0x4 nop\n";
fn query(raw:&str)->trace_core::api_types::OutputSlotUsesDto{
 let path=std::env::temp_dir().join(format!("store-flow-{}",uuid::Uuid::new_v4()));std::fs::write(&path,raw).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"store-flow").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();let p=e.get_output_slot_uses(&sid,1,2,"App+0x2000",&["App".into()],&[OutputSlotRangeDto{address:"0x7000".into(),size:8}]).unwrap();e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();p
}
#[test]fn candidate_data_store_to_distinct_range_is_finite_coverage(){let p=query(RAW);assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());assert!(p.uses.is_empty());assert_eq!(p.coverage.scanned_lines,10);assert_eq!(p.coverage.access_count,3);}
#[test]fn partial_independent_overwrite_keeps_remaining_candidate_bytes(){
 let raw=RAW.replace("[App] 0x401014!", "[App] 0x401011!0x1011 strb w6, [x3]; x3=0x8000 w6=0x0 mem_w=0x8000\n[App] 0x401012!0x1012 ldrb w7, [x3, #1]; x3=0x8000 mem_r=0x8001 -> x7=0x0\n[App] 0x401013!0x1013 cbnz x7, #0x401014; x7=0x0\n[App] 0x401014!");assert!(!query(&raw).coverage.complete);
}
#[test]fn full_independent_overwrite_discharges_memory_candidate(){
 let raw=RAW.replace("[App] 0x401014!", "[App] 0x401011!0x1011 mov x6, #0; -> x6=0x0\n[App] 0x401012!0x1012 str x6, [x3]; x3=0x8000 x6=0x0 mem_w=0x8000\n[App] 0x401013!0x1013 ldr x7, [x3]; x3=0x8000 mem_r=0x8000 -> x7=0x0\n[App] 0x401014!");assert!(query(&raw).coverage.complete);
}
#[test]fn transferred_candidate_return_and_indirect_call_are_not_coverage(){
 for use_line in ["mov x0, x7; x7=0x4 -> x0=0x4", "blr x7; x7=0x4"] {
  let raw=RAW.replace("[App] 0x401014!", &format!("[App] 0x401011!0x1011 ldr x7, [x3]; x3=0x8000 mem_r=0x8000 -> x7=0x4\n[App] 0x401012!0x1012 {use_line}\n[App] 0x401014!"));assert!(!query(&raw).coverage.complete);
 }
}
#[test]fn unknown_overwrite_cannot_clean_candidate(){let raw=RAW.replace("[App] 0x401014!", "[App] 0x401011!0x1011 str x6, [x3]; x3=0x8000 mem_w=0x8000\n[App] 0x401014!");assert!(!query(&raw).coverage.complete);}
#[test]fn transferred_data_reloaded_as_address_stays_incomplete(){let raw=RAW.replace("[App] 0x401014!", "[App] 0x401011!0x1011 ldr x7, [x3]; x3=0x8000 mem_r=0x8000 -> x7=0x4\n[App] 0x401012!0x1012 ldr x8, [x7]; x7=0x4 mem_r=0x4 -> x8=0x1\n[App] 0x401013!0x1013 mov x7, #0; -> x7=0x0\n[App] 0x401014!");assert!(!query(&raw).coverage.complete);}
