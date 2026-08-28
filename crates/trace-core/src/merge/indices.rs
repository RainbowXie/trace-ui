//! 各索引结构的 chunk 合并。

use bitvec::prelude::BitVec;
use rustc_hash::FxHashMap;

use crate::line_index::LineIndex;
use crate::query::mem_access::MemAccessIndex;
use crate::query::strings::StringIndex;
use crate::scanner::PairSplitDeps;

/// Merge multiple MemAccessIndex. Records within same address preserve chunk order.
pub fn merge_mem_access_indices(indices: Vec<MemAccessIndex>) -> MemAccessIndex {
    let mut merged = MemAccessIndex::new();
    for idx in indices {
        for (addr, record) in idx.iter_all() {
            merged.add(addr, record.clone());
        }
    }
    merged
}

/// Merge LineIndex from chunks. Each chunk used global byte offsets and
/// LineIndexBuilder with correct start_line, so sampled_offsets are globally aligned.
/// Simply concatenate sampled_offsets and sum totals.
pub fn merge_line_indices(indices: Vec<LineIndex>) -> LineIndex {
    LineIndex::merge(indices)
}

/// Merge init_mem_loads BitVecs and apply corrections.
pub fn merge_init_mem_loads(chunk_inits: Vec<BitVec>, corrections: &[(u32, bool)]) -> BitVec {
    let total_bits: usize = chunk_inits.iter().map(|b| b.len()).sum();
    let mut merged = BitVec::with_capacity(total_bits);
    for chunk in chunk_inits {
        merged.extend_from_bitslice(&chunk);
    }
    for &(line, value) in corrections {
        if (line as usize) < merged.len() {
            merged.set(line as usize, value);
        }
    }
    merged
}

/// Merge pair_split HashMaps from chunks + fixup additions.
pub fn merge_pair_splits(
    chunk_splits: Vec<FxHashMap<u32, PairSplitDeps>>,
    fixup_splits: Vec<(u32, PairSplitDeps)>,
) -> FxHashMap<u32, PairSplitDeps> {
    let mut merged = FxHashMap::default();
    for chunk in chunk_splits {
        merged.extend(chunk);
    }
    for (line, split) in fixup_splits {
        merged.insert(line, split);
    }
    merged
}

/// Merge StringIndex from chunks. Concatenate and sort by seq.
pub fn merge_string_indices(indices: Vec<StringIndex>) -> StringIndex {
    let mut all_strings = Vec::new();
    for idx in indices {
        all_strings.extend(idx.strings);
    }
    all_strings.sort_by_key(|r| r.seq);
    StringIndex {
        strings: all_strings,
    }
}
