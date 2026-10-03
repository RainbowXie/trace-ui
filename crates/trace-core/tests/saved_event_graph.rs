use trace_core::{TraceEngine,BuildOptions,engine::SavedEventObservation};
use trace_core::api_types::{GraphActivationSelectorDto,GraphMechanicalEndpointDto};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x6000 sp=0x8000\n[App] 0x401000!0x1000 bl #0x499000; x0=0x6000 x1=0x5000 x2=0x8 sp=0x8000\ncall func: memcpy(0x6000, 0x5000, 0x8)\nret: 0x6000\n[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x6000 mem_r=0x6000 -> x9=0x1\n[App] 0x401008!0x1008 add x9, x9, #2; x9=0x1 -> x9=0x3\n[App] 0x40100c!0x100c str x9, [x3]; x9=0x3 x3=0x7000 mem_w=0x7000\n[App] 0x401010!0x1010 ret; x0=0x6000\n[App] 0x400004!0x4 nop\n";
fn event()->SavedEventObservation{serde_json::from_value(serde_json::json!({"owner":{"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x1000","call_seq":0,"entry_seq":1,"exit_seq":7,"resume_seq":8},"event_index":0,"callsite":{"seq":1,"offset":"App+0x1000"},"resume":{"seq":4,"offset":"App+0x1004"},"target":{"module":null,"entry":null,"symbol":"memcpy"},"memory_reads":[{"address":"0x5000","size":8,"bytes":"0100000000000000"}],"memory_writes":[{"address":"0x6000","size":8,"bytes":"0100000000000000"}]})).unwrap()}
#[test]fn event_capture_write_to_actual_load_edge_and_wrong_resume_refusal(){
 let path=std::env::temp_dir().join(format!("saved-event-{}",uuid::Uuid::new_v4()));std::fs::write(&path,RAW).unwrap();let engine=TraceEngine::new();
 let sid=engine.create_session_from_file(std::fs::File::open(&path).unwrap(),"saved-event-test").unwrap().session_id;
 engine.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let e=event();let owner:GraphActivationSelectorDto=e.owner.clone();
 let facts=engine.get_algorithm_graph_facts_with_saved_events(&sid,6,0x7000,8,Some("write"),&[owner.clone()],&["App".into()],&[e]).unwrap();
 assert!(facts.dependency_edges.iter().any(|edge|matches!(&edge.producer,GraphMechanicalEndpointDto::ExternalCallEvent{call_seq:1,resume_seq:4,event_index:0,..}) && matches!(&edge.consumer,GraphMechanicalEndpointDto::Instruction{seq:4,..})),"{}",serde_json::to_string(&facts).unwrap());
 let mut bad=event();bad.memory_writes[0].bytes=Some("0200000000000000".into());assert!(engine.get_algorithm_graph_facts_with_saved_events(&sid,6,0x7000,8,Some("write"),&[owner.clone()],&["App".into()],&[bad]).is_err());
 let mut bad=event();bad.memory_writes[0].size=4;bad.memory_writes[0].bytes=Some("01000000".into());assert!(engine.get_algorithm_graph_facts_with_saved_events(&sid,6,0x7000,8,Some("write"),&[owner.clone()],&["App".into()],&[bad]).is_err());
 let legacy=engine.get_algorithm_graph_facts_for_modules(&sid,6,0x7000,8,Some("write"),&[owner.clone()],&["App".into()]).unwrap();assert!(!legacy.dependency_edges.iter().any(|edge|matches!(&edge.producer,GraphMechanicalEndpointDto::ExternalCallEvent{call_seq:1,..}) && matches!(&edge.consumer,GraphMechanicalEndpointDto::Instruction{seq:4,..})));
 let mut e=event();e.resume.seq=5;assert!(engine.get_algorithm_graph_facts_with_saved_events(&sid,6,0x7000,8,Some("write"),&[owner],&["App".into()],&[e]).is_err());
 engine.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();
}
