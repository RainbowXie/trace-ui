use trace_core::{TraceEngine,BuildOptions,engine::SavedEventObservation,api_types::{GraphActivationSelectorDto,GraphMechanicalEndpointDto}};
fn run(barrier:&str,expected:bool){run_with(barrier,expected,false);}
fn run_with(barrier:&str,expected:bool,fresh:bool){
 let raw=format!("[App] 0x400000!0x0 bl #0x401000; x0=0x6000\n[App] 0x401000!0x1000 bl #0x499000; x0=0x6000 x1=0x5000 x2=0x8\ncall func: memcpy(0x6000, 0x5000, 0x8)\nret: 0x6000\n[App] 0x401004!0x1004 nop\n{barrier}[App] 0x401020!0x1020 ldr x9, [x0]; x0=0x6000 mem_r=0x6000 -> x9=0x1\n[App] 0x401024!0x1024 str x9, [x3]; x9=0x1 x3=0x7000 mem_w=0x7000\n[App] 0x401028!0x1028 ret; x0=0x6000\n[App] 0x400004!0x4 nop\n");
 let load=5+barrier.lines().count() as u32;let owner=GraphActivationSelectorDto{trace:trace_core::api_types::GraphTraceReferenceDto{artifact:"request.json".into(),pointer:"/trace_files/0".into()},function:"App+0x1000".into(),call_seq:0,entry_seq:1,exit_seq:load+2,resume_seq:load+3};
 let event:SavedEventObservation=serde_json::from_value(serde_json::json!({"owner":owner,"event_index":0,"callsite":{"seq":1,"offset":"App+0x1000"},"resume":{"seq":4,"offset":"App+0x1004"},"target":{"module":null,"entry":null,"symbol":"memcpy"},"memory_reads":[{"address":"0x5000","size":8,"bytes":"0100000000000000"}],"memory_writes":[{"address":"0x6000","size":8,"bytes":"0100000000000000"}]})).unwrap();
 let path=std::env::temp_dir().join(format!("event-barrier-{}",uuid::Uuid::new_v4()));std::fs::write(&path,&raw).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"event-barriers").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let mut observations=vec![event];
 if fresh {let mut second:SavedEventObservation=serde_json::from_value(serde_json::to_value(&observations[0]).unwrap()).unwrap();second.event_index=1;second.callsite.seq=5;second.callsite.offset="App+0x101c".into();second.resume.seq=load;second.resume.offset="App+0x1020".into();observations.push(second);}
 if barrier.contains("br x16") {
  let p=e.get_address_provenance_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&observations).unwrap();assert!(p.gaps.iter().any(|g|g.seq==5 && g.kind=="external_boundary"));
  let p=e.get_output_slot_uses_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&[trace_core::api_types::OutputSlotRangeDto{address:"0x7000".into(),size:8}],&observations).unwrap();assert!(p.gaps.iter().any(|g|g.seq==5 && g.kind=="call_external_or_unknown"));
 }
 let facts=e.get_algorithm_graph_facts_with_saved_events(&sid,load+1,0x7000,8,Some("write"),&[owner],&["App".into()],&observations).unwrap();
 let found=facts.dependency_edges.iter().any(|edge|matches!(edge.producer,GraphMechanicalEndpointDto::ExternalCallEvent{call_seq:1,..}) && matches!(edge.consumer,GraphMechanicalEndpointDto::Instruction{seq,..} if seq==load));
 if fresh {assert!(facts.dependency_edges.iter().any(|edge|matches!(edge.producer,GraphMechanicalEndpointDto::ExternalCallEvent{call_seq:5,..}) && matches!(edge.consumer,GraphMechanicalEndpointDto::Instruction{seq,..} if seq==load)));}
 assert_eq!(found,expected,"{}",serde_json::to_string(&facts).unwrap());e.close_session(&sid).unwrap();std::fs::remove_file(path).unwrap();
}
#[test]fn annotation_backed_br_kills_old_event_winner(){run("[App] 0x401008!0x1008 br x16; x16=0x499100\ncall func: opaque(0x6000)\nret: 0x6000\n",false);}
#[test]fn store_without_marker_kills_old_event_winner(){run("[App] 0x401008!0x1008 str x10, [x0]; x0=0x6000 x10=0x1\n",false);}
#[test]fn known_nonoverlap_write_keeps_event_winner(){run("[App] 0x401008!0x1008 str x10, [x4]; x4=0x8000 x10=0x1 mem_w=0x8000\n",true);}
#[test]fn fresh_second_capture_reestablishes_only_new_winner(){run_with("[App] 0x40101c!0x101c bl #0x499000; x0=0x6000 x1=0x5000 x2=0x8\ncall func: memcpy(0x6000, 0x5000, 0x8)\nret: 0x6000\n",false,true);}
#[test]fn unsupported_store_width_kills_old_event_winner(){run("[App] 0x401008!0x1008 st4 {v0.16b-v3.16b}, [x4]; x4=0x8000 mem_w=0x8000\n",false);}
