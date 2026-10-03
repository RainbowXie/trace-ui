use std::fs::File;
use trace_core::{TraceEngine,BuildOptions};
use trace_core::api_types::OutputSlotRangeDto;
fn query(text:&str)->trace_core::api_types::OutputSlotUsesDto {
 let path=std::env::temp_dir().join(format!("output-control-{}",uuid::Uuid::new_v4()));std::fs::write(&path,text).unwrap();
 let e=TraceEngine::new();let sid=e.create_session_from_file(File::open(&path).unwrap(),"output-control-test").unwrap().session_id;
 e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let p=e.get_output_slot_uses(&sid,1,2,"App+0x2000",&["App".into()],&[OutputSlotRangeDto{address:"0x7000".into(),size:8}]).unwrap();
 e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();p
}
const LOOP:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x7000\n[App] 0x401000!0x1000 bl #0x402000; x0=0x7000\n[App] 0x402000!0x2000 mov x8, #2; -> x8=0x2\n[App] 0x402004!0x2004 mov x9, #1; -> x9=0x1\n[App] 0x402008!0x2008 str x9, [x0]; x9=0x1 x0=0x7000 mem_w=0x7000\n[App] 0x40200c!0x200c add x9, x9, #1; x9=0x1 -> x9=0x2\n[App] 0x402010!0x2010 sub x8, x8, #1; x8=0x2 -> x8=0x1\n[App] 0x402014!0x2014 cbnz x8, #0x402008; x8=0x1\n[App] 0x402008!0x2008 str x9, [x0]; x9=0x2 x0=0x7000 mem_w=0x7000\n[App] 0x40200c!0x200c mov x9, #0; -> x9=0x0\n[App] 0x402018!0x2018 ret; x0=0x7000\n[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x7000 mem_r=0x7000 -> x9=0x2\n[App] 0x401008!0x1008 add x9, x9, x5; x9=0x2 x5=0x1 -> x9=0x3\n[App] 0x40100c!0x100c mov x0, #0; -> x0=0x0\n[App] 0x401010!0x1010 ret; x0=0x0\n[App] 0x400004!0x4 nop\n";
#[test]fn observed_loop_and_derived_data_have_complete_finite_coverage(){let p=query(&LOOP.replace("[App] 0x40100c!0x100c mov x0", "[App] 0x401009!0x1009 mov x9, #0; -> x9=0x0\n[App] 0x40100c!0x100c mov x0"));assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());assert!(p.uses.is_empty());assert!(p.gaps.is_empty());assert_eq!(p.coverage.scanned_lines,14);}
#[test]fn closed_internal_child_is_scanned_and_external_or_cross_module_is_not_complete(){
 let text=LOOP.replace("[App] 0x402004!0x2004 mov x9, #1; -> x9=0x1", "[App] 0x402004!0x2004 bl #0x403000; x0=0x7000\n[App] 0x403000!0x3000 mov x9, #1; -> x9=0x1\n[App] 0x403004!0x3004 ret; x0=0x7000\n[App] 0x402008!0x2008 nop").replace("[App] 0x40100c!0x100c mov x0", "[App] 0x401009!0x1009 mov x9, #0; -> x9=0x0\n[App] 0x40100c!0x100c mov x0");
 let p=query(&text);assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());
 let p=query(&text.replace("[App] 0x403", "[Other] 0x403"));assert!(!p.coverage.complete);
 let p=query(&text.replace("bl #0x403000", "bl #0x999000"));assert!(!p.coverage.complete);
}
#[test]fn candidate_variable_add_address_and_live_return_are_not_negative(){
 let p=query(LOOP);assert!(!p.coverage.complete);assert!(p.gaps.iter().any(|g|g.kind=="untracked_return_escape"));
 let p=query(&LOOP.replace("[App] 0x40100c!0x100c mov x0", "[App] 0x401009!0x1009 ldr x7, [x9]; x9=0x3 mem_r=0x3 -> x7=0x0\n[App] 0x40100c!0x100c mov x0"));assert!(!p.coverage.complete);
}
#[test]fn repeated_slot_load_add_store_keeps_negative_obligations_until_real_kill(){
 let text=LOOP.replace("[App] 0x40200c!0x200c add x9, x9, #1; x9=0x1 -> x9=0x2", "[App] 0x402009!0x2009 ldr x9, [x0]; x0=0x7000 mem_r=0x7000 -> x9=0x1\n[App] 0x40200c!0x200c add x9, x9, #1; x9=0x1 -> x9=0x2")
 .replace("[App] 0x40100c!0x100c mov x0", "[App] 0x401009!0x1009 mov x9, #0; -> x9=0x0\n[App] 0x40100c!0x100c mov x0");
 let p=query(&text);assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());
}
#[test]fn initial_input_load_requires_tracked_use_and_real_final_definition(){
 let text=LOOP.replace("[App] 0x402004!0x2004 mov x9, #1; -> x9=0x1", "[App] 0x402004!0x2004 ldr x9, [x0]; x0=0x7000 mem_r=0x7000 -> x9=0x1")
 .replace("[App] 0x40100c!0x100c mov x0", "[App] 0x401009!0x1009 mov x9, #0; -> x9=0x0\n[App] 0x40100c!0x100c mov x0");
 let p=query(&text);assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());
 let bad=text.replace("[App] 0x402008!0x2008 str x9", "[App] 0x402006!0x2006 ldr x7, [x9]; x9=0x1 mem_r=0x1 -> x7=0x0\n[App] 0x402008!0x2008 str x9");assert!(!query(&bad).coverage.complete);
 let bad=text.replace("[App] 0x402004!0x2004 ldr x9", "[App] 0x402002!0x2002 strb w2, [x0]; x0=0x7000 w2=0xff mem_w=0x7000\n[App] 0x402004!0x2004 ldr x9");assert!(!query(&bad).coverage.complete);
 let bad=text.replace("[App] 0x402004!0x2004 ldr x9", "[App] 0x402002!0x2002 strb w2, [x0]; x0=0x7000 mem_w=0x7000\n[App] 0x402004!0x2004 ldr x9");assert!(!query(&bad).coverage.complete);
}
#[test]fn unknown_branch_observation_is_not_negative(){let p=query(&LOOP.replace("cbnz x8, #0x402008; x8=0x1","cbnz x8, #0x402008"));assert!(!p.coverage.complete);}
