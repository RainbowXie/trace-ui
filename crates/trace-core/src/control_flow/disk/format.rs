//! Internal CFG v1 encoding. All integers are little endian; no native casts.
//! The 128-byte header is followed by 13 fixed-position 24-byte directory entries
//! (offset, byte length, logical count: u64 each). Payload starts at byte 440,
//! aligned to 8. No section tags exist: version 1 fixes the order below.
//! Header: magic[8], version:u32, format:u32, trace_len:u64, trace_hash[32],
//! file_len:u64, payload_hash[32], total_lines:u32, reserved[28]. The payload
//! hash covers the directory and every byte after it, including padding.
//!
//! Modules: (count+1) u64 byte-pool offsets, then UTF-8 bytes (<=4096/module).
//! StableAddresses: 16 bytes: module:u32, reserved:u32=0, offset:u64.
//! Activations: 64 bytes: function,parent,call,entry,exit,resume,status,reason
//! (u32), then call_pc,entry_pc,exit_pc,expected_resume (u64). NONE=u32::MAX.
//! ID 0 is root (status=0, function/parent/call/exit/resume=NONE, reason=0).
//! status 1 confirmed (reason=0); status 2 unresolved (reason=1 trace-end,
//! 2 displaced, 3 no-next-insn). Absent entry/exit/resume use NONE, never zero.
//! BoundaryEvents: 24 bytes: seq,activation,kind,address,related,reserved:u32;
//! kind=0 call,1 entry,2 exit,3 resume,4 bypassed; optional IDs use NONE.
//! Blocks: 64-byte four-pair (offset,count): records[48], variants[16],
//! function-block references[16], source activation IDs[4]. Block record:
//! function,address,representative_start,representative_end:u32;
//! variant_start,variant_count,source_start,source_count:u64. Variant record:
//! block,activation,start,end:u32, sorted unique by (activation,start,end)
//! within each block. The first variant is the representative. Ranges are
//! half-open raw seq ranges, exclude
//! callee instructions by using separate variants, and contain no text/digest.
//! Function-block record: function,block:u32, executions:u64. Source IDs are
//! sorted unique confirmed activations of the block's function.
//! Four occurrence sections are u32 arrays ordered by (activation,start).
//! ActivationRanges: 16 bytes (occurrence_start,count:u64), one per activation.
//! Edges: 32-byte two-pair header: records[48], source IDs[4]. Edge record:
//! activation,from,to,kind,function,reserved:u32; count,source_start,count:u64.
//! activation=NONE denotes function aggregate, otherwise activation-local;
//! kind=0 fallthrough,1 conditional,2 jump,3 call_resume,4 return.
//! Sources are sorted unique confirmed IDs of this function; local edges have
//! exactly their activation as source. Records ordered (function,activation,
//! from,to,kind). No zero counts or duplicated keys.
//! FunctionIndex: 32-byte two-pair header: records[24], activation IDs[4].
//! Records: function,reserved:u32; start,count:u64, sorted unique by function.
//! IDs are ordered by (call_seq,id), each confirmed activation exactly once.
//! LineIndex: total_lines:u32,reserved:u32, then u64 offsets every 256 raw lines.
//! Its directory count is the sample count; total_lines matches the header.
use crate::error::{Result, TraceError};

pub const SUFFIX: &str = ".control-flow.cache";
pub const NONE: u32 = u32::MAX;
pub const HEADER: usize = 128;
pub const DIRECTORY: usize = 13 * 24;
pub const PAYLOAD: usize = HEADER + DIRECTORY;
pub const MAGIC: &[u8; 8] = b"TCFG0001";
pub const VERSION: u32 = 1;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TraceFormat { GumTrace = 1, Unidbg = 2 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Section {
    Modules, StableAddresses, Activations, ActivationBoundaryEvents, Blocks,
    OccurrenceStartSeqs, OccurrenceEndSeqs, OccurrenceBlockIds,
    OccurrenceActivationIds, ActivationOccurrenceRanges, Edges,
    FunctionActivationIndex, LineIndex,
}
pub const SECTIONS: [Section; 13] = [Section::Modules, Section::StableAddresses,
    Section::Activations, Section::ActivationBoundaryEvents, Section::Blocks,
    Section::OccurrenceStartSeqs, Section::OccurrenceEndSeqs, Section::OccurrenceBlockIds,
    Section::OccurrenceActivationIds, Section::ActivationOccurrenceRanges,
    Section::Edges, Section::FunctionActivationIndex, Section::LineIndex];
pub fn bad(message: &str) -> TraceError { TraceError::CacheError(format!("control-flow: {message}")) }
pub fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o+4].try_into().unwrap()) }
pub fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o+8].try_into().unwrap()) }
pub fn checked_slice(b: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
    let end = offset.checked_add(length).ok_or_else(|| bad("range overflow"))?;
    let start = usize::try_from(offset).map_err(|_| bad("offset capacity"))?;
    let end = usize::try_from(end).map_err(|_| bad("end capacity"))?;
    b.get(start..end).ok_or_else(|| bad("range outside file"))
}
pub fn bytes(count: u64, width: u64) -> Result<u64> {
    count.checked_mul(width).ok_or_else(|| bad("count overflow"))
}
pub fn seq(seq: u32, total: u32) -> Result<()> {
    if seq >= total { Err(bad("seq outside trace")) } else { Ok(()) }
}
pub fn cancel(c: &std::sync::atomic::AtomicBool) -> Result<()> {
    if c.load(std::sync::atomic::Ordering::Relaxed) { Err(TraceError::Cancelled) } else { Ok(()) }
}
