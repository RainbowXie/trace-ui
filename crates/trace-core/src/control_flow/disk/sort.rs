//! Fixed-width lexicographic external sort for internal build scratch records.
//! Keys must be encoded in comparison order (e.g. big-endian numeric fields).
//! Only this instance's exclusive directory is removed; no global cache sweep.
use super::format::{bad, cancel};
use crate::error::Result;
use super::scratch::ScratchQuota;
use std::{fs::{self, File, OpenOptions}, io::{BufReader, BufWriter, Read, Write}, path::{Path, PathBuf}, sync::atomic::{AtomicBool, AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy)]
pub struct SortBudget {
    pub run_records: usize,
    pub fan_in: usize,
    pub scratch_bytes: u64,
}
/// Sorter holds one bounded run and at most fan_in input FDs plus one output.
/// Run paths are computed by ordinal, never retained in an unbounded Vec.
pub struct ExternalSort<const WIDTH: usize> {
    directory: PathBuf,
    budget: SortBudget,
    buffer: Vec<[u8; WIDTH]>,
    runs: u64,
    live_bytes: u64,
    next_file: u64,
    pub merge_passes: u64,
    finished: bool,
    shared: Option<ScratchQuota>,
}
impl<const WIDTH: usize> ExternalSort<WIDTH> {
    pub fn create(parent: &Path, budget: SortBudget) -> Result<Self> {
        if WIDTH == 0 || budget.run_records == 0 || !(2..=64).contains(&budget.fan_in) {
            return Err(bad("invalid sort run/fan-in budget"));
        }
        budget.run_records.checked_mul(WIDTH).ok_or_else(|| bad("sort run capacity overflow"))?;
        let directory = loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let p = parent.join(format!(".control-flow-sort-{}-{n}", std::process::id()));
            match fs::create_dir(&p) {
                Ok(()) => break p,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        };
        Ok(Self { directory, budget, buffer: Vec::new(), runs: 0, live_bytes: 0, next_file: 0, merge_passes: 0, finished: false, shared: None })
    }
    pub(crate) fn create_shared(parent: &Path, budget: SortBudget, quota: ScratchQuota) -> Result<Self> {
        let mut sort = Self::create(parent, budget)?;
        sort.shared = Some(quota);
        Ok(sort)
    }
    fn path(&self, id: u64) -> PathBuf { self.directory.join(id.to_string()) }
    fn reserve_disk(&mut self, bytes: u64) -> Result<()> {
        let total = self.live_bytes.checked_add(bytes).ok_or_else(|| bad("scratch bytes overflow"))?;
        if total > self.budget.scratch_bytes { return Err(bad("sort scratch byte capacity exceeded")); }
        if let Some(q) = &self.shared { q.reserve(bytes)?; }
        self.live_bytes = total;
        Ok(())
    }
    fn create_file(&mut self) -> Result<(u64, File)> {
        let id = self.next_file;
        self.next_file = id.checked_add(1).ok_or_else(|| bad("scratch ordinal overflow"))?;
        let f = OpenOptions::new().write(true).create_new(true).open(self.path(id))?;
        Ok((id,f))
    }
    pub fn push(&mut self, record: [u8; WIDTH], abort: &AtomicBool) -> Result<()> {
        cancel(abort)?;
        if self.finished { return Err(bad("sort already finished")); }
        self.buffer.push(record);
        if self.buffer.len() == self.budget.run_records { self.flush_run(abort)?; }
        Ok(())
    }
    fn flush_run(&mut self, abort: &AtomicBool) -> Result<()> {
        if self.buffer.is_empty() { return Ok(()); }
        cancel(abort)?;
        self.buffer.sort_unstable();
        cancel(abort)?;
        let bytes = u64::try_from(self.buffer.len()).map_err(|_| bad("sort count capacity"))?
            .checked_mul(WIDTH as u64).ok_or_else(|| bad("sort bytes overflow"))?;
        self.reserve_disk(bytes)?;
        let (_, f) = self.create_file()?;
        let mut out = BufWriter::with_capacity(64 * 1024, f);
        for r in &self.buffer { cancel(abort)?; out.write_all(r)?; }
        out.flush()?;
        self.buffer.clear();
        self.runs = self.runs.checked_add(1).ok_or_else(|| bad("run count overflow"))?;
        Ok(())
    }
    /// Returns a sorted stream tied to this scratch owner. Consume it before
    /// dropping the sorter. No deduplication or hash-only equality is performed.
    pub fn finish(&mut self, abort: &AtomicBool) -> Result<File> {
        if self.finished { return Err(bad("sort already finished")); }
        self.finished = true;
        self.flush_run(abort)?;
        if self.runs == 0 { let (id, mut f) = self.create_file()?; f.flush()?; return Ok(File::open(self.path(id))?); }
        let mut first = 0;
        let mut count = self.runs;
        while count > 1 {
            cancel(abort)?;
            let output_first = self.next_file;
            let mut outputs = 0u64;
            let mut group_start = 0u64;
            while group_start < count {
                let group = (count - group_start).min(self.budget.fan_in as u64);
                let mut readers = Vec::with_capacity(group as usize);
                let mut heads = Vec::with_capacity(group as usize);
                let mut sizes = Vec::with_capacity(group as usize);
                for j in 0..group {
                    let f = File::open(self.path(first + group_start + j))?;
                    sizes.push(f.metadata()?.len());
                    let mut r = BufReader::with_capacity(64 * 1024, f);
                    heads.push(read_record::<WIDTH>(&mut r)?);
                    readers.push(r);
                }
                let (_, f) = self.create_file()?;
                let mut out = BufWriter::with_capacity(64 * 1024, f);
                loop {
                    cancel(abort)?;
                    let winner = heads.iter().enumerate().filter_map(|(i,r)| r.as_ref().map(|r| (i,r)))
                        .min_by(|a,b| a.1.cmp(b.1)).map(|(i,_)| i);
                    let Some(i) = winner else { break; };
                    self.reserve_disk(WIDTH as u64)?;
                    out.write_all(heads[i].as_ref().unwrap())?;
                    heads[i] = read_record::<WIDTH>(&mut readers[i])?;
                }
                out.flush()?;
                drop(out);
                drop(readers);
                for (j, bytes) in sizes.into_iter().enumerate() {
                    fs::remove_file(self.path(first + group_start + j as u64))?;
                    self.live_bytes = self.live_bytes.checked_sub(bytes).ok_or_else(|| bad("scratch accounting underflow"))?;
                    if let Some(q) = &self.shared { q.release(bytes); }
                }
                outputs = outputs.checked_add(1).ok_or_else(|| bad("merge count overflow"))?;
                group_start = group_start.checked_add(group).ok_or_else(|| bad("merge ordinal overflow"))?;
            }
            first = output_first;
            count = outputs;
            self.merge_passes = self.merge_passes.checked_add(1).ok_or_else(|| bad("merge pass overflow"))?;
        }
        cancel(abort)?;
        Ok(File::open(self.path(first))?)
    }
}
pub fn read_record<const WIDTH: usize>(r: &mut impl Read) -> Result<Option<[u8; WIDTH]>> {
    if WIDTH == 0 { return Err(bad("zero width record")); }
    let mut record = [0; WIDTH];
    let n = r.read(&mut record[..1])?;
    if n == 0 { return Ok(None); }
    r.read_exact(&mut record[1..])?;
    Ok(Some(record))
}
impl<const WIDTH: usize> Drop for ExternalSort<WIDTH> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
        if let Some(q) = &self.shared { q.release(self.live_bytes); }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn tiny_runs_force_multiple_disk_merge_passes() {
        let abort = AtomicBool::new(false);
        let budget = SortBudget { run_records: 2, fan_in: 2, scratch_bytes: 4096 };
        let mut sort = ExternalSort::<8>::create(&std::env::temp_dir(), budget).unwrap();
        let directory = sort.directory.clone();
        for i in (0u64..17).rev() { sort.push(i.to_be_bytes(), &abort).unwrap(); }
        let mut stream = sort.finish(&abort).unwrap();
        assert_eq!(sort.merge_passes, 4);
        for i in 0u64..17 { assert_eq!(read_record::<8>(&mut stream).unwrap(), Some(i.to_be_bytes())); }
        assert!(read_record::<8>(&mut stream).unwrap().is_none());
        drop(stream); drop(sort); assert!(!directory.exists());
    }
    #[test] fn quotas_cancel_and_truncated_records_fail() {
        let abort = AtomicBool::new(false);
        let mut sort = ExternalSort::<8>::create(&std::env::temp_dir(), SortBudget { run_records: 1, fan_in: 2, scratch_bytes: 8 }).unwrap();
        sort.push([1;8], &abort).unwrap();
        assert!(sort.push([2;8], &abort).is_err());
        abort.store(true, Ordering::Relaxed);
        assert!(sort.finish(&abort).is_err());
        assert!(read_record::<8>(&mut &[0u8;3][..]).is_err());
    }
}
