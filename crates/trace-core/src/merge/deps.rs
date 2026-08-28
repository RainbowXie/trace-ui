//! 控制依赖解析与 CompactDeps 重建。

use bitvec::prelude::BitVec;
use rustc_hash::FxHashMap;

use crate::scanner::{CompactDeps, CONTROL_DEP_BIT};

/// Add control deps for lines before the first local conditional branch.
/// Only adds for lines where needs_control_dep is true (non-pair, parsed, !data_only).
pub fn resolve_control_deps(
    chunk_start: u32,
    first_local_cond: Option<u32>,
    prev_last_cond: Option<u32>,
    chunk_end: u32,
    needs_control_dep: &BitVec,
    data_only: bool,
) -> Vec<(u32, u32)> {
    if data_only {
        return Vec::new();
    }
    let Some(prev_cond) = prev_last_cond else {
        return Vec::new();
    };
    let end = first_local_cond.unwrap_or(chunk_end);
    let mut patches = Vec::new();
    for line in chunk_start..end {
        let local_idx = (line - chunk_start) as usize;
        if local_idx < needs_control_dep.len() && needs_control_dep[local_idx] {
            patches.push((line, prev_cond | CONTROL_DEP_BIT));
        }
    }
    patches
}

/// Rebuild a single CompactDeps from multiple chunk deps + patch edges.
/// patch_edges are (source_line, dep_line) tuples from the fixup phase.
/// Uses push_unique for deduplication within each row.
pub fn rebuild_compact_deps(
    chunk_deps: &[CompactDeps],
    chunk_start_lines: &[u32],
    patch_edges: &[(u32, u32)],
    progress_fn: Option<&dyn Fn(f64)>,
) -> CompactDeps {
    // Group patch_edges by source line for efficient lookup
    let mut patches: FxHashMap<u32, Vec<u32>> = FxHashMap::default();
    for &(from, to) in patch_edges {
        patches.entry(from).or_default().push(to);
    }

    // Calculate total capacity
    let total_lines: usize = chunk_deps.iter().map(|c| c.offsets.len()).sum();
    let total_deps: usize =
        chunk_deps.iter().map(|c| c.data.len()).sum::<usize>() + patch_edges.len();

    let mut merged = CompactDeps::with_capacity(total_lines, total_deps);

    let report_interval = (total_lines / 100).max(1);
    let mut rows_processed = 0usize;

    for (chunk_id, chunk) in chunk_deps.iter().enumerate() {
        let num_rows = chunk.offsets.len();
        for local_row in 0..num_rows {
            let global_line = chunk_start_lines[chunk_id] + local_row as u32;
            merged.start_row();

            // Add original deps from this chunk
            for &dep in chunk.row(local_row) {
                merged.push_unique(dep);
            }

            // Add patch deps from fixup
            if let Some(extras) = patches.get(&global_line) {
                for &dep in extras {
                    merged.push_unique(dep);
                }
            }

            rows_processed += 1;
            if let Some(ref cb) = progress_fn {
                if rows_processed % report_interval == 0 {
                    cb(rows_processed as f64 / total_lines as f64);
                }
            }
        }
    }

    merged
}
