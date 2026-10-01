use super::{format::*, store::ControlFlowStore, trace::{hash, OpenedTrace}};
use crate::error::Result;
use memmap2::MmapOptions;
use std::{fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom, Write}, os::unix::fs::OpenOptionsExt, path::{Path,PathBuf}, sync::atomic::AtomicBool};

/// Bounded section copy. The caller supplies exact encoded section length and
/// count; this writer does not serialize or retain builder-owned object trees.
/// Sections must be supplied once in the fixed version-2 order.
pub struct CacheWriter {
    file: File, candidate: PathBuf, target: PathBuf, next: usize,
    entries: [(u64,u64,u64);13], trace_hash: [u8;32], trace_len: u64,
    format: TraceFormat, total: u32, published: bool,
}
impl CacheWriter {
    pub fn create(target: &Path, trace: &OpenedTrace, total_lines: u32, c: &AtomicBool) -> Result<Self> {
        cancel(c)?; trace.verify_identity(c)?;
        if total_lines==0 { return Err(bad("zero total lines")); }
        let parent=target.parent().filter(|p|!p.as_os_str().is_empty()).ok_or_else(||bad("target needs cache directory"))?;
        if !parent.is_dir() { return Err(bad("cache directory missing")); }
        if let Ok(m)=std::fs::symlink_metadata(target) { if !m.is_file() { return Err(bad("target is not regular file")); } }
        let candidate=parent.join(format!(".cfg-{}.tmp",uuid::Uuid::new_v4()));
        let mut file=OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&candidate)?;
        let initial=file.write_all(&[0;PAYLOAD]);
        if let Err(e)=initial { let _=std::fs::remove_file(&candidate); return Err(e.into()); }
        Ok(Self { file,candidate,target:target.to_owned(),next:0,entries:[(0,0,0);13],trace_hash:trace.hash,trace_len:trace.len(),format:trace.format,total:total_lines,published:false })
    }
    pub fn write_section(&mut self, section: Section, count: u64, length: u64, mut input: impl Read, c: &AtomicBool) -> Result<()> {
        cancel(c)?;
        if self.next>=13 || section!=SECTIONS[self.next] { return Err(bad("section missing/duplicate/order")); }
        let current=self.file.stream_position()?;
        let aligned=current.checked_add(7).ok_or_else(||bad("write alignment overflow"))? & !7;
        let end=aligned.checked_add(length).ok_or_else(||bad("write section overflow"))?;
        self.file.write_all(&[0;7][..usize::try_from(aligned-current).unwrap()])?;
        let mut remaining=length; let mut buffer=[0u8;64*1024];
        while remaining>0 {
            cancel(c)?;
            let wanted=remaining.min(buffer.len() as u64) as usize;
            let n=input.read(&mut buffer[..wanted])?;
            if n==0 { return Err(bad("short section stream")); }
            self.file.write_all(&buffer[..n])?; remaining-=n as u64;
        }
        cancel(c)?;
        let mut extra=[0u8;1];
        if input.read(&mut extra)?!=0 { return Err(bad("long section stream")); }
        if self.file.stream_position()?!=end { return Err(bad("write position mismatch")); }
        self.entries[self.next]=(aligned,length,count); self.next+=1;
        Ok(())
    }
    /// Rename is the publication linearization point. A directory-fsync error
    /// after it is an IO error with the complete new cache already published;
    /// Drop never deletes a published target or an older cache.
    pub fn publish(mut self, trace: &OpenedTrace, c: &AtomicBool) -> Result<ControlFlowStore> {
        cancel(c)?;
        if self.next!=13 || trace.hash!=self.trace_hash || trace.len()!=self.trace_len || trace.format!=self.format { return Err(bad("unfinished writer/trace mismatch")); }
        let file_len=self.file.stream_position()?;
        let mut header=[0u8;PAYLOAD];
        header[..8].copy_from_slice(MAGIC); header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&(self.format as u32).to_le_bytes());
        header[16..24].copy_from_slice(&self.trace_len.to_le_bytes()); header[24..56].copy_from_slice(&self.trace_hash);
        header[56..64].copy_from_slice(&file_len.to_le_bytes()); header[96..100].copy_from_slice(&self.total.to_le_bytes());
        for (i,(off,len,count)) in self.entries.iter().enumerate() {
            for (j,v) in [off,len,count].iter().enumerate() { let o=HEADER+i*24+j*8; header[o..o+8].copy_from_slice(&v.to_le_bytes()); }
        }
        self.file.seek(SeekFrom::Start(0))?; self.file.write_all(&header)?; self.file.flush()?;
        {
            let mmap=unsafe{MmapOptions::new().map(&self.file)?};
            let digest=hash(&mmap[HEADER..],c)?;
            self.file.seek(SeekFrom::Start(64))?; self.file.write_all(&digest)?;
        }
        self.file.flush()?; self.file.sync_all()?;
        let store=ControlFlowStore::open(&self.candidate,trace,c)?;
        trace.verify_identity(c)?; cancel(c)?;
        // Recheck target type at the boundary; rename never follows a symlink.
        if let Ok(m)=std::fs::symlink_metadata(&self.target) { if !m.is_file() { return Err(bad("target changed type")); } }
        std::fs::rename(&self.candidate,&self.target)?; self.published=true;
        File::open(self.target.parent().unwrap())?.sync_all()?;
        Ok(store)
    }
}
impl Drop for CacheWriter {
    fn drop(&mut self) { if !self.published { let _=std::fs::remove_file(&self.candidate); } }
}
