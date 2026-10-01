use super::format::*;
use crate::error::Result;
use memmap2::{Mmap, MmapOptions};
use sha2::{Digest, Sha256};
use std::{fs::File, os::unix::{fs::MetadataExt, io::AsRawFd}, sync::atomic::AtomicBool};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Signature { dev: u64, ino: u64, len: u64, mt: i64, mn: i64, ct: i64, cn: i64 }
fn signature(file: &File) -> Result<Signature> {
    let m = file.metadata()?;
    if !m.is_file() { return Err(bad("not a regular file")); }
    Ok(Signature { dev: m.dev(), ino: m.ino(), len: m.len(), mt: m.mtime(), mn: m.mtime_nsec(), ct: m.ctime(), cn: m.ctime_nsec() })
}
pub(crate) fn hash(data: &[u8], c: &AtomicBool) -> Result<[u8;32]> {
    let mut h = Sha256::new();
    for chunk in data.chunks(64 * 1024) { cancel(c)?; h.update(chunk); }
    cancel(c)?;
    Ok(h.finalize().into())
}
/// Retains the actual read-only FD, not a label or reopenable path. Caller must
/// provide the parser's detected format and ensure no concurrent trace writes.
/// fstat/hash detects changes but cannot prevent SIGBUS on malicious truncation.
pub struct OpenedTrace {
    file: File, mmap: Mmap, signature: Signature,
    pub(crate) hash: [u8;32], pub(crate) format: TraceFormat,
}
impl OpenedTrace {
    pub fn open(file: File, detected_format: TraceFormat, c: &AtomicBool) -> Result<Self> {
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 { return Err(std::io::Error::last_os_error().into()); }
        if flags & libc::O_ACCMODE != libc::O_RDONLY { return Err(bad("trace FD must be read-only")); }
        let before = signature(&file)?;
        if before.len == 0 { return Err(bad("empty trace")); }
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let hash = hash(&mmap, c)?;
        if signature(&file)? != before { return Err(bad("trace changed during open")); }
        Ok(Self { file, mmap, signature: before, hash, format: detected_format })
    }
    pub fn data(&self) -> &[u8] { &self.mmap }
    pub fn content_hash(&self) -> [u8;32] { self.hash }
    pub fn len(&self) -> u64 { self.signature.len }
    pub fn is_empty(&self) -> bool { self.signature.len == 0 }
    pub fn verify_identity(&self, c: &AtomicBool) -> Result<()> {
        if signature(&self.file)? != self.signature { return Err(bad("trace signature changed")); }
        if hash(&self.mmap, c)? != self.hash || signature(&self.file)? != self.signature {
            return Err(bad("trace content changed"));
        }
        Ok(())
    }
    /// FD-only cache locator, not freshness proof. No FD number/label in key.
    pub fn fd_cache_name(&self) -> String {
        format!("fd-{}{}", hex(&self.hash), SUFFIX)
    }
}
fn hex(b: &[u8]) -> String { b.iter().map(|v| format!("{v:02x}")).collect() }
/// Trusted existing path locator; never opens or authenticates the trace.
pub fn path_cache_name(path: &str) -> String {
    format!("{}{}", hex(&Sha256::digest(path.as_bytes())), SUFFIX)
}
