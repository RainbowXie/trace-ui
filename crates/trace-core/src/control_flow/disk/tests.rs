use super::{*,format::*};
use std::{fs::File, io::Cursor, sync::atomic::{AtomicBool,Ordering}};
fn le32(v:&[u32])->Vec<u8>{v.iter().flat_map(|v|v.to_le_bytes()).collect()}
fn le64(v:&[u64])->Vec<u8>{v.iter().flat_map(|v|v.to_le_bytes()).collect()}
fn table(parts: &[(u64,u64,Vec<u8>)])->Vec<u8>{
    let mut b=vec![0;parts.len()*16];
    for (i,(count,width,data)) in parts.iter().enumerate(){
        assert_eq!(data.len() as u64,count*width);
        while b.len()%8!=0 {b.push(0)}
        let off=b.len() as u64;
        b[i*16..i*16+8].copy_from_slice(&off.to_le_bytes());
        b[i*16+8..i*16+16].copy_from_slice(&count.to_le_bytes());b.extend(data);
    } b
}
// A confirmed child owns two occurrences; raw special line occupies seq 2.
fn fixture()->Vec<(u64,Vec<u8>)>{
    let modules=[le64(&[0,1]),b"m".to_vec()].concat();
    let addr=[le32(&[0,0]),le64(&[0x10]),le32(&[0,0]),le64(&[0x14])].concat();
    let root=[le32(&[NONE,NONE,NONE,0,NONE,NONE,0,0]),le64(&[0,0,0,0])].concat();
    let child=[le32(&[0,0,0,1,3,4,1,0]),le64(&[0x100,0x110,0x114,0x104])].concat();
    let block0=[le32(&[0,0,1,2]),le64(&[0,1,0,1])].concat();
    let block1=[le32(&[0,1,3,4]),le64(&[1,1,1,1])].concat();
    let blocks=table(&[(2,48,[block0,block1].concat()),(2,16,le32(&[0,1,1,2,1,1,3,4])),
        (2,16,[le32(&[0,0]),le64(&[1]),le32(&[0,1]),le64(&[1])].concat()),(2,4,le32(&[1,1])),
        (2,16,[le32(&[1,0]),le64(&[1]),le32(&[1,1]),le64(&[1])].concat())]);
    let edge=[le32(&[1,0,1,2,0,0]),le64(&[1,0,1])].concat();
    let edges=table(&[(1,48,edge),(1,4,le32(&[1]))]);
    let functions=table(&[(1,24,[le32(&[0,0]),le64(&[0,1])].concat()),(1,4,le32(&[1]))]);
    vec![(1,modules),(2,addr),(2,[root,child].concat()),(0,vec![]),(2,blocks),
        (2,le32(&[1,3])),(2,le32(&[2,4])),(2,le32(&[0,1])),(2,le32(&[1,1])),
        (2,le64(&[0,0,0,2])),(1,edges),(1,functions),(1,[le32(&[5,0]),le64(&[0])].concat())]
}
struct Env { dir: std::path::PathBuf, trace:OpenedTrace, cancel:AtomicBool }
impl Env {
 fn new()->Self{
    let dir=std::env::temp_dir().join(format!("cfg-disk-test-{}",uuid::Uuid::new_v4()));std::fs::create_dir(&dir).unwrap();
    let path=dir.join("trace");std::fs::write(&path,b"call\nentry\nspecial\nexit\nresume").unwrap();
    let cancel=AtomicBool::new(false);let trace=OpenedTrace::open(File::open(path).unwrap(),TraceFormat::GumTrace,&cancel).unwrap();
    Self{dir,trace,cancel}
 }
 fn target(&self)->std::path::PathBuf{self.dir.join(self.trace.fd_cache_name())}
 fn write(&self)->ControlFlowStore{
    let mut w=CacheWriter::create(&self.target(),&self.trace,5,&self.cancel).unwrap();
    for (s,(count,b)) in SECTIONS.into_iter().zip(fixture()){w.write_section(s,count,b.len() as u64,Cursor::new(b),&self.cancel).unwrap();}
    w.publish(&self.trace,&self.cancel).unwrap()
 }
}
impl Drop for Env{fn drop(&mut self){let _=std::fs::remove_dir_all(&self.dir);}}
#[test]fn real_disk_reopen_and_independent_lines(){
 let e=Env::new();let s=e.write();assert_eq!(s.total_lines(),5);assert_eq!(s.line(&e.trace,2),Some(b"special".as_slice()));
 drop(s);let s=ControlFlowStore::open(&e.target(),&e.trace,&e.cancel).unwrap();assert_eq!(s.section(Section::OccurrenceBlockIds).count,2);
 assert_eq!(s.line(&e.trace,4),Some(b"resume".as_slice()));
}
#[test]fn cancel_preserves_old_cache_and_cleans_only_candidate(){
 let e=Env::new();e.write();let old=std::fs::read(e.target()).unwrap();
 let mut w=CacheWriter::create(&e.target(),&e.trace,5,&e.cancel).unwrap();
 for(s,(n,b))in SECTIONS.into_iter().zip(fixture()){w.write_section(s,n,b.len() as u64,Cursor::new(b),&e.cancel).unwrap();}
 e.cancel.store(true,Ordering::Relaxed);assert!(matches!(w.publish(&e.trace,&e.cancel),Err(crate::error::TraceError::Cancelled)));
 assert_eq!(std::fs::read(e.target()).unwrap(),old);
 assert!(!std::fs::read_dir(&e.dir).unwrap().any(|v|v.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
}
fn rehash(b:&mut[u8]){use sha2::{Digest,Sha256};let h=Sha256::digest(&b[HEADER..]);b[64..96].copy_from_slice(&h);}
#[test]fn malicious_offset_id_hash_and_parallel_capacity_rejected(){
 let e=Env::new();e.write();let original=std::fs::read(e.target()).unwrap();
 for variant in 0..11 {
    let mut b=original.clone();
    match variant {
        0=>{b[HEADER..HEADER+8].copy_from_slice(&u64::MAX.to_le_bytes());rehash(&mut b);}
        1=>{let o=HEADER+Section::OccurrenceBlockIds as usize*24;let off=u64_at(&b,o)as usize;b[off..off+4].copy_from_slice(&99u32.to_le_bytes());rehash(&mut b);}
        2=>b[PAYLOAD]^=1,
        3=>{let o=HEADER+Section::OccurrenceEndSeqs as usize*24+16;b[o..o+8].copy_from_slice(&u64::MAX.to_le_bytes());rehash(&mut b);}
        4=>{b.pop();}
        variant=>{
            let o=HEADER+Section::Blocks as usize*24;let off=u64_at(&b,o) as usize;let local=off+u64_at(&b,off+64) as usize;
            match variant {
                5=>b[local+8..local+16].copy_from_slice(&0u64.to_le_bytes()),
                6=>b[local..local+4].copy_from_slice(&0u32.to_le_bytes()),
                7=>b[local+4..local+8].copy_from_slice(&99u32.to_le_bytes()),
                8=>b[local+16..local+24].copy_from_slice(&[1u32.to_le_bytes(),0u32.to_le_bytes()].concat()),
                9=>{let overlap=u64_at(&b,off+48);b[off+64..off+72].copy_from_slice(&overlap.to_le_bytes());},
                _=>b[off+72..off+80].copy_from_slice(&u64::MAX.to_le_bytes()),
            }
            rehash(&mut b);
        }
    }
    std::fs::write(e.target(),b).unwrap();assert!(ControlFlowStore::open(&e.target(),&e.trace,&e.cancel).is_err(),"variant {variant}");
 }
 assert!(bytes(u64::MAX,4).is_err());assert!(checked_slice(&[0;8],u64::MAX,8).is_err());
 assert!(u32::try_from(u64::from(u32::MAX)+1).is_err());
}
#[test]fn short_long_duplicate_sections_fail_without_publish(){
 let e=Env::new();e.write();let old=std::fs::read(e.target()).unwrap();
 for (length,data)in[(8,vec![0;7]),(8,vec![0;9])]{
    let mut w=CacheWriter::create(&e.target(),&e.trace,5,&e.cancel).unwrap();assert!(w.write_section(Section::Modules,0,length,Cursor::new(data),&e.cancel).is_err());
 }
 let mut w=CacheWriter::create(&e.target(),&e.trace,5,&e.cancel).unwrap();assert!(w.write_section(Section::Edges,0,0,Cursor::new([]),&e.cancel).is_err());drop(w);
 assert_eq!(old,std::fs::read(e.target()).unwrap());
}
#[test]fn retained_fd_change_and_writable_fd_rejected(){
 let e=Env::new();let writable=std::fs::OpenOptions::new().read(true).write(true).open(e.dir.join("trace")).unwrap();
 assert!(OpenedTrace::open(writable,TraceFormat::GumTrace,&e.cancel).is_err());
 std::fs::write(e.dir.join("trace"),b"same\nother\nspecial\nexit\nresume").unwrap();assert!(e.trace.verify_identity(&e.cancel).is_err());
}
