use trace_core::{TraceEngine,BuildOptions,api_types::{GraphActivationSelectorDto,GraphTraceReferenceDto,GraphMechanicalEndpointDto}};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x2\n[App] 0x401000!0x1000 adrp x20, #0x404000; x0=0x2 -> x20=0x404000\n[App] 0x401004!0x1004 ldr x5, [x20]; x20=0x404000 mem_r=0x404000 -> x5=0x4\n[App] 0x401008!0x1008 add x9, x0, x5; x0=0x2 x5=0x4 -> x9=0x6\n[App] 0x40100c!0x100c str x9, [x20, #8]; x9=0x6 x20=0x404000 mem_w=0x404008\n[App] 0x401010!0x1010 ret; x0=0x2\n[App] 0x400004!0x4 nop\n";
#[test]fn selected_global_write_is_instruction_with_preserved_global_access(){
 let path=std::env::temp_dir().join(format!("global-target-{}",uuid::Uuid::new_v4()));std::fs::write(&path,RAW).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"global-target").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let owner=GraphActivationSelectorDto{trace:GraphTraceReferenceDto{artifact:"request.json".into(),pointer:"/trace_files/0".into()},function:"App+0x1000".into(),call_seq:0,entry_seq:1,exit_seq:5,resume_seq:6};
 let p=e.get_algorithm_graph_facts_for_modules(&sid,4,0x404008,8,Some("write"),&[owner.clone()],&["App".into()]).unwrap();
 assert!(matches!(p.target,GraphMechanicalEndpointDto::Instruction{seq:4,..}));
 assert!(p.dependency_edges.iter().any(|edge|matches!(edge.producer,GraphMechanicalEndpointDto::Instruction{seq:3,..}) && edge.consumer==p.target));
 let access=p.dependency_edges.iter().filter(|edge|edge.producer==p.target && matches!(&edge.consumer,GraphMechanicalEndpointDto::GlobalReference{seq:4,access_index:1,access,global,size:8,bytes:Some(bytes),..} if access=="write" && global=="App+0x4008" && bytes=="0600000000000000")).count();assert_eq!(access,1);
 assert!(p.dependency_edges.iter().any(|edge|matches!(&edge.producer,GraphMechanicalEndpointDto::GlobalReference{seq:2,access,..} if access=="read")));
 let read=e.get_algorithm_graph_facts_for_modules(&sid,2,0x404000,8,Some("read"),&[owner.clone()],&["App".into()]).unwrap();
 assert!(matches!(read.target,GraphMechanicalEndpointDto::Instruction{seq:2,..}));
 assert_eq!(read.dependency_edges.iter().filter(|edge|edge.consumer==read.target && matches!(&edge.producer,GraphMechanicalEndpointDto::GlobalReference{seq:2,access_index:0,access,global,..} if access=="read" && global=="App+0x4000")).count(),1);
 for (seq,address,size,rw) in [(4,0x404000,8,"write"),(4,0x404008,9,"write"),(4,0x404008,8,"read"),(3,0x404008,8,"write")] {assert!(e.get_algorithm_graph_facts_for_modules(&sid,seq,address,size,Some(rw),&[owner.clone()],&["App".into()]).is_err());}
 e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();
}
