use trace_core::{TraceEngine,BuildOptions,engine::SavedEventObservation,api_types::{TargetHistorySelectionDto,TargetObservationRw}};
const RAW:&str="[App] 0x400000!0x0 bl #0x401000; x0=0x0\n[App] 0x401000!0x1000 bl #0x499000; x0=0x6000 x1=0x5000 x2=0x8\ncall func: memcpy(0x6000, 0x5000, 0x8)\nret: 0x6000\n[App] 0x401004!0x1004 mov x9, #6; -> x9=0x6\n[App] 0x401008!0x1008 str x9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000\n[App] 0x40100c!0x100c ret; x0=0x0\n[App] 0x400004!0x4 nop\n";
fn event()->SavedEventObservation{serde_json::from_value(serde_json::json!({"owner":{"trace":{"artifact":"request.json","pointer":"/trace_files/0"},"function":"App+0x1000","call_seq":0,"entry_seq":1,"exit_seq":6,"resume_seq":7},"event_index":0,"callsite":{"seq":1,"offset":"App+0x1000"},"resume":{"seq":4,"offset":"App+0x1004"},"target":{"module":null,"entry":null,"symbol":"memcpy"},"memory_reads":[{"address":"0x5000","size":8,"bytes":"0100000000000000"}],"memory_writes":[{"address":"0x6000","size":8,"bytes":"0100000000000000"}]})).unwrap()}
#[test]fn observed_barrier_before_actual_formation_has_exact_raw_winner(){
 let path=std::env::temp_dir().join(format!("history-event-{}",uuid::Uuid::new_v4()));std::fs::write(&path,RAW).unwrap();let e=TraceEngine::new();let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"history-event").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
 let selected=TargetHistorySelectionDto{seq:5,address:"0x7000".into(),size:8,rw:Some(TargetObservationRw::Write)};
 let p=e.get_target_write_history_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&selected,6,&[event()]).unwrap();assert!(p.coverage.complete,"{}",serde_json::to_string(&p.gaps).unwrap());assert_eq!(p.selected_snapshot.bytes,vec![Some(6),Some(0),Some(0),Some(0),Some(0),Some(0),Some(0),Some(0)]);assert_eq!(p.selected_snapshot.definitions[0].last_writer_seq,Some(5));assert_eq!(p.capture_snapshot.definitions[0].last_writer_seq,Some(5));assert_eq!(p.writes.len(),1);assert_eq!(p.writes[0].seq,5);
 let p=e.get_target_write_history(&sid,0,1,"App+0x1000",&["App".into()],&selected,6).unwrap();assert!(!p.coverage.complete);assert!(p.gaps.iter().any(|g|g.seq==1 && g.kind=="external_effect_unobserved"));

 let mut bad=event();bad.resume.seq=5;assert!(e.get_target_write_history_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&selected,6,&[bad]).is_err());
 e.close_session(&sid).unwrap();
 for (suffix,store) in [
  ("", "str w9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000"),
  ("[App] 0x40100b!0x100b str x9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000\n", "str x9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000"),
  ("[App] 0x40100b!0x100b cas x10, x11, [x3]; x3=0x7000 x10=0x6 x11=0x6 -> x10=0x6\n", "str x9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000"),
  ("[App] 0x40100b!0x100b svc #0\n", "str x9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000"),
 ] {
  let raw=RAW.replace("str x9, [x3]; x9=0x6 x3=0x7000 mem_w=0x7000",store).replace("[App] 0x40100c!0x100c ret",&format!("{suffix}[App] 0x40100c!0x100c ret"));std::fs::write(&path,raw).unwrap();
  let sid=e.create_session_from_file(std::fs::File::open(&path).unwrap(),"history-negative").unwrap().session_id;e.build_index(&sid,BuildOptions{force_rebuild:true,skip_strings:true},None).unwrap();
  let mut obs=event();let capture=if suffix.is_empty(){6}else{7};obs.owner.exit_seq=capture;obs.owner.resume_seq=capture+1;
  let p=e.get_target_write_history_with_saved_events(&sid,0,1,"App+0x1000",&["App".into()],&selected,capture,&[obs]).unwrap();assert!(!p.coverage.complete,"{}",serde_json::to_string(&p).unwrap());
  e.close_session(&sid).unwrap();
 }
 std::fs::remove_file(path).unwrap();
}
