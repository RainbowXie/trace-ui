//! FD-only control-flow sessions, separate from full dependency sessions.
use crate::{control_flow::disk::{*,format::*}, error::{Result,TraceError}};
use std::{fs::{File,OpenOptions},io::{BufRead,BufReader,Read,Seek,SeekFrom},os::unix::fs::OpenOptionsExt,path::PathBuf,sync::{Arc,RwLock,atomic::{AtomicBool,Ordering}}};

pub(super) struct DiskCfgSession {
    pub trace: OpenedTrace,
    pub store: RwLock<Option<ControlFlowStore>>,
    pub cancel: AtomicBool,
    pub building: AtomicBool,
    pub closed: AtomicBool,
    target: PathBuf,
}
fn detected_format(file:&File,c:&AtomicBool)->Result<TraceFormat> {
    // Only a bounded line buffer, before OpenedTrace's mmap. No label reopen.
    let mut input=file.try_clone()?;
    input.seek(SeekFrom::Start(0))?;
    let mut reader=BufReader::new(input);
    let mut line=Vec::new();
    loop {
        cancel(c)?;line.clear();
        let n=reader.by_ref().take(1024*1024+1).read_until(b'\n',&mut line)?;
        if n==0{return Err(bad("no recognizable instruction format"));}
        if n>1024*1024{return Err(bad("raw line byte capacity exceeded"));}
        for (parser,format) in [(trace_parser::types::TraceFormat::Gumtrace,TraceFormat::GumTrace),(trace_parser::types::TraceFormat::Unidbg,TraceFormat::Unidbg)] {
            if trace_parser::gumtrace::line_matches_format_signature(&line,parser){return Ok(format);}
        }
    }
}
fn legacy_header(file:&mut File)->Result<bool> {
    let metadata=file.metadata()?;
    if !metadata.is_file(){return Err(bad("cache is not regular"));}
    let mut h=[0u8;HEADER];
    file.read_exact(&mut h)?;
    if &h[..8]!=b"TCFG0001" || u32_at(&h,8)!=1{return Ok(false);}
    // Recognize only the complete old fixed header; payload is never read as v2.
    if metadata.len()<PAYLOAD as u64 || u64_at(&h,56)!=metadata.len() || !matches!(u32_at(&h,12),1|2)
        || u64_at(&h,16)==0 || u32_at(&h,96)==0 || h[100..].iter().any(|b|*b!=0){return Err(bad("invalid legacy header"));}
    Ok(true)
}
impl super::TraceEngine {
    pub(super) fn disk_handle(&self,id:&str)->Result<Option<Arc<DiskCfgSession>>> {
        Ok(self.disk_cfg_sessions.read().map_err(|e|TraceError::Internal(e.to_string()))?.get(id).cloned())
    }
    /// Creates a retained-FD session only; does not build full dependency state.
    /// The label is diagnostic and never reopened or used for cache identity.
    pub fn create_control_flow_session_from_file(&self,file:File,_label:&str)->Result<String> {
        let c=AtomicBool::new(false);
        let flags=unsafe{libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&file),libc::F_GETFL)};
        if flags<0{return Err(std::io::Error::last_os_error().into());}
        if flags & libc::O_ACCMODE!=libc::O_RDONLY || !file.metadata()?.is_file(){return Err(bad("trace must be a read-only regular FD"));}
        let format=detected_format(&file,&c)?;
        let trace=OpenedTrace::open(file,format,&c)?;
        let dir=crate::cache::cache_dir().ok_or_else(||bad("internal cache directory unavailable"))?;
        std::fs::create_dir_all(&dir)?;
        if !std::fs::symlink_metadata(&dir)?.is_dir(){return Err(bad("cache directory is not a directory"));}
        let target=dir.join(trace.fd_cache_name());
        let id=format!("disk-cfg:{}",uuid::Uuid::new_v4()); // disjoint from full-session UUID IDs
        self.disk_cfg_sessions.write().map_err(|e|TraceError::Internal(e.to_string()))?.insert(id.clone(),Arc::new(DiskCfgSession{trace,target,store:RwLock::new(None),cancel:AtomicBool::new(false),building:AtomicBool::new(false),closed:AtomicBool::new(false)}));
        Ok(id)
    }
    /// Only NotFound or a recognized complete v1 header triggers disk-v2 build.
    /// A corrupt v2/unknown/truncated/permission-denied cache is an explicit error.
    pub fn build_disk_control_flow_index(&self,id:&str,force:bool,budget:BuildBudget)->Result<()> {
        let h=self.disk_handle(id)?.ok_or_else(||TraceError::SessionNotFound(id.into()))?;
        if h.building.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err(){return Err(TraceError::OperationInProgress("disk CFG build".into()));}
        struct Reset<'a>(&'a AtomicBool);impl Drop for Reset<'_>{fn drop(&mut self){self.0.store(false,Ordering::SeqCst);}}
        let _reset=Reset(&h.building);h.cancel.store(false,Ordering::SeqCst);
        if h.closed.load(Ordering::SeqCst){return Err(TraceError::Cancelled);}
        h.trace.verify_identity(&h.cancel)?;
        let mut store=h.store.write().map_err(|e|TraceError::Internal(e.to_string()))?;
        let rebuild=match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(&h.target){
            Ok(mut f)=>{
                if !f.metadata()?.is_file(){return Err(bad("cache is not regular"));}
                if force{true}else{legacy_header(&mut f)?}
            },
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>true,
            Err(e)=>return Err(e.into()),
        };
        let candidate=if rebuild{build_control_flow_store(&h.trace,&h.target,&h.cancel,budget)?}else{ControlFlowStore::open(&h.target,&h.trace,&h.cancel)?};
        h.trace.verify_identity(&h.cancel)?;cancel(&h.cancel)?;*store=Some(candidate);Ok(())
    }
    /// Full content hash/fstat check of the same retained FD before output.
    pub fn verify_control_flow_session_identity(&self,id:&str)->Result<()> {
        let h=self.disk_handle(id)?.ok_or_else(||TraceError::SessionNotFound(id.into()))?;
        h.trace.verify_identity(&h.cancel)
    }
}
