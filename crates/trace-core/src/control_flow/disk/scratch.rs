//! One build-wide byte quota for all simultaneous streams and sort runs.
use super::format::{bad, cancel};
use crate::error::Result;
use memmap2::{Mmap, MmapOptions};
use std::{cell::Cell, rc::Rc, fs::{File, OpenOptions}, io::{Read, Write, Seek, SeekFrom}, path::{Path, PathBuf}, sync::atomic::AtomicBool};
#[derive(Clone)]
pub(crate) struct ScratchQuota(Rc<Quota>);
struct Quota { live: Cell<u64>, peak: Cell<u64>, limit: u64 }
impl ScratchQuota {
    pub fn new(limit: u64) -> Self { Self(Rc::new(Quota { live: Cell::new(0), peak: Cell::new(0), limit })) }
    pub fn reserve(&self, n: u64) -> Result<()> {
        let live=self.0.live.get().checked_add(n).ok_or_else(||bad("build scratch overflow"))?;
        if live>self.0.limit { return Err(bad("build scratch byte capacity exceeded")); }
        self.0.live.set(live); self.0.peak.set(self.0.peak.get().max(live)); Ok(())
    }
    pub fn peak(&self) -> u64 { self.0.peak.get() }
    pub fn release(&self, n: u64) { self.0.live.set(self.0.live.get().checked_sub(n).expect("scratch accounting")); }
}
pub(crate) struct Workspace { pub path: PathBuf, pub quota: ScratchQuota, next: Cell<u64> }
impl Workspace {
    pub fn new(parent: &Path, limit: u64) -> Result<Self> {
        let path=parent.join(format!(".cfg-build-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        Ok(Self { path, quota: ScratchQuota::new(limit), next: Cell::new(0) })
    }
    pub fn stream(&self) -> Result<Stream> {
        let id=self.next.get(); self.next.set(id.checked_add(1).ok_or_else(||bad("scratch file ordinal"))?);
        let path=self.path.join(format!("stream-{id}"));
        use std::os::unix::fs::OpenOptionsExt;
        let file=OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path)?;
        Ok(Stream { file, path, quota:self.quota.clone(), len:0 })
    }
}
impl Drop for Workspace { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.path); } }
pub(crate) struct Stream { pub file: File, path: PathBuf, quota: ScratchQuota, pub len: u64 }
impl Stream {
    pub fn write(&mut self, data: &[u8], c: &AtomicBool) -> Result<()> {
        cancel(c)?; self.quota.reserve(data.len() as u64)?;
        self.len=self.len.checked_add(data.len() as u64).ok_or_else(||bad("stream length"))?;
        self.file.write_all(data)?; Ok(())
    }
    pub fn path_for_build(&self) -> &Path { &self.path }
    pub fn rewind(&mut self) -> Result<()> { self.file.seek(SeekFrom::Start(0))?; Ok(()) }
    pub fn map(&self) -> Result<Option<Mmap>> {
        if self.len==0 { Ok(None) } else { Ok(Some(unsafe { MmapOptions::new().map(&self.file)? })) }
    }
    pub fn copy(&mut self, from: &mut impl Read, c: &AtomicBool) -> Result<()> {
        let mut buf=[0;65536]; loop { cancel(c)?; let n=from.read(&mut buf)?; if n==0 { break; } self.write(&buf[..n],c)?; } Ok(())
    }
}
impl Drop for Stream { fn drop(&mut self) { let _=std::fs::remove_file(&self.path); self.quota.release(self.len); } }
