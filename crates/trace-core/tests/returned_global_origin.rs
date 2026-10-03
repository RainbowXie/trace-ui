use trace_core::{TraceEngine,BuildOptions,api_types::AddressOriginDto};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x404300\n[App] 0x401000!0x1000 bl #0x402000; x0=0x404300\n[App] 0x402000!0x2000 adrp x20, #0x404000; -> x20=0x404000\n[App] 0x402004!0x2004 add x0, x20, #0x300; x20=0x404000 -> x0=0x404300\n[App] 0x402008!0x2008 mov x9, #3; -> x9=0x3\n[App] 0x40200c!0x200c str x9, [x0]; x0=0x404300 x9=0x3 mem_w=0x404300\n[App] 0x402010!0x2010 mov x9, #0; -> x9=0x0\n[App] 0x402014!0x2014 ret; x0=0x404300\n[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x404300 mem_r=0x404300 -> x9=0x3\n[App] 0x401008!0x1008 str x9, [x3]; x3=0x8000 x9=0x3 mem_w=0x8000\n[App] 0x40100c!0x100c ret; x0=0x404300\n[App] 0x400004!0x4 nop\n";
fn bounded(raw:&str)->trace_core::api_types::FunctionFactBundleDto {
 let path=std::env::temp_dir().join(format!("return-negative-{}",uuid::Uuid::new_v4()));std::fs::write(&path,raw).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"return-negative").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let source=trace_core::engine::FactSourceReference{artifact:"request.json",pointer:"/trace_files/0"};let context=trace_core::engine::FunctionFactContext{trace:source,activation:trace_core::engine::FactActivationSelector{trace:source,function:"App+0x1000",call_seq:0,entry_seq:1}};
 let p=e.get_function_facts_bounded(&sid,context,&["App".into()],&std::sync::atomic::AtomicBool::new(false)).unwrap();e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();p
}
#[test]fn same_numeric_scalar_or_w_alias_is_not_global_origin(){
 for definition in ["mov x0, #0x404300; -> x0=0x404300", "mov w0, #0x404300; -> x0=0x404300", "add x0, x20, #0x300; x20=0x404000 -> x0=0x404301"] {
  let raw=RAW.replace("add x0, x20, #0x300; x20=0x404000 -> x0=0x404300",definition);
  let p=bounded(&raw);assert!(!p.global_reads.iter().any(|r|r.read_seqs.contains(&8)));assert!(p.memory_reads.iter().any(|r|r.read_seqs.contains(&8)));
 }
}
#[test]fn opaque_effect_after_definition_does_not_preserve_global_identity(){
 let raw=RAW.replace("[App] 0x401004!0x1004 ldr", "[App] 0x401004!0x1004 bl #0x499000; x0=0x404300\ncall func: opaque(0x404300)\nret: 0x404300\n[App] 0x401008!0x1008 ldr").replace("[App] 0x401008!0x1008 str", "[App] 0x40100c!0x100c str").replace("[App] 0x40100c!0x100c ret", "[App] 0x401010!0x1010 ret");
 let p=bounded(&raw);assert!(!p.global_reads.iter().any(|r|r.read_seqs.contains(&11)));
}
#[test]fn recorded_callee_global_definition_survives_return_not_root_abi(){
 let path=std::env::temp_dir().join(format!("return-origin-{}",uuid::Uuid::new_v4()));std::fs::write(&path,RAW).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"return-origin").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let p=e.get_address_provenance(&sid,0,1,"App+0x1000",&["App".into()]).unwrap();let access=p.accesses.iter().find(|a|a.seq==8).unwrap();
 assert!(matches!(&access.origin_anchor,Some(AddressOriginDto::GlobalAdrp{seq:2,global,..}) if global=="App+0x4000"),"{}",serde_json::to_string(&p).unwrap());
 assert_eq!(access.integer_delta,Some(0x300));assert_eq!(access.definition_steps.iter().map(|s|s.seq).collect::<Vec<_>>(),vec![3,8]);
 let source=trace_core::engine::FactSourceReference{artifact:"request.json",pointer:"/trace_files/0"};
 let context=trace_core::engine::FunctionFactContext{trace:source,activation:trace_core::engine::FactActivationSelector{trace:source,function:"App+0x1000",call_seq:0,entry_seq:1}};
 let facts=e.get_function_facts_bounded(&sid,context,&["App".into()],&std::sync::atomic::AtomicBool::new(false)).unwrap();
 assert!(facts.global_reads.iter().any(|r|r.global=="App+0x4300" && r.read_seqs==vec![8] && r.bytes.as_deref()==Some("0300000000000000")),"{}",serde_json::to_string(&facts).unwrap());
 assert!(!facts.memory_reads.iter().any(|r|r.read_seqs.contains(&8)));
 e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();
}
