//! Phase 2 编排：merge_all_chunks 主函数。

use std::collections::HashMap;

use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::parallel_types::{CallTreeEvent, ChunkResult, GumtraceAnnotEvent};
use crate::query::mem_access::MemAccessIndex;
use crate::query::registers::RegCheckpoints;
use crate::query::strings::StringRw;
use crate::scan_unified::{Phase2State, ScanResult};
use crate::scanner::{push_unique, MemLastDef, PairSplitDeps, RegLastDef, ScanState};
use trace_parser::types::{RegId, TraceFormat};

use super::{
    fix_reg_checkpoints, merge_init_mem_loads, merge_line_indices, merge_pair_splits,
    replay_call_tree_events, replay_gumtrace_annotations, resolve_control_deps,
    resolve_partial_unresolved_loads, resolve_unresolved_load, resolve_unresolved_pair_load,
    resolve_unresolved_reg_uses,
};

/// Phase 2 orchestrator: merge all chunk results into a single ScanResult.
///
/// Performs sequential forward propagation to resolve cross-chunk dependencies,
/// then merges all data structures into unified output.
pub fn merge_all_chunks(
    chunk_results: Vec<ChunkResult>,
    format: TraceFormat,
    data_only: bool,
    skip_strings: bool,
    progress_fn: Option<&dyn Fn(f64)>,
    cancel_flag: Option<&std::sync::atomic::AtomicBool>,
) -> std::result::Result<ScanResult, crate::error::TraceError> {
    let num_chunks = chunk_results.len();
    let mut all_patch_edges: Vec<(u32, u32)> = Vec::new();
    let mut all_pair_fixups: Vec<(u32, PairSplitDeps)> = Vec::new();
    let mut init_corrections: Vec<(u32, bool)> = Vec::new();
    let mut all_call_events: Vec<CallTreeEvent> = Vec::new();
    let mut all_gumtrace_events: Vec<GumtraceAnnotEvent> = Vec::new();

    // Sequential forward propagation of global state
    let mut global_mem_last_def: FxHashMap<u64, (u32, u64)> = FxHashMap::default();
    let mut global_reg_last_def = RegLastDef::new();
    let mut global_last_cond_branch: Option<u32> = None;

    // Lightweight deferred pair deps — resolved inline from global state (no cloning)
    struct DeferredPairDep {
        line: u32,
        chunk_idx: usize,
        extra_half1: SmallVec<[u32; 4]>,
        extra_half2: SmallVec<[u32; 4]>,
        extra_shared: SmallVec<[u32; 2]>,
    }
    let mut deferred_pair_deps: Vec<DeferredPairDep> = Vec::new();

    let num_chunks_f64 = num_chunks as f64;

    // Pass 1: Forward propagation + fixup (borrow chunk_results)
    for (i, chunk) in chunk_results.iter().enumerate() {
        if i > 0 {
            // === Resolve fully unresolved loads ===
            for load in &chunk.unresolved_loads {
                resolve_unresolved_load(
                    load,
                    &global_mem_last_def,
                    &global_reg_last_def,
                    &mut all_patch_edges,
                    &mut init_corrections,
                );
            }

            // === Resolve partially unresolved loads (mixed case) ===
            resolve_partial_unresolved_loads(
                &chunk.partial_unresolved_loads,
                &global_mem_last_def,
                &mut all_patch_edges,
                &mut init_corrections,
            );

            // === Resolve fully unresolved pair loads ===
            for pair in &chunk.unresolved_pair_loads {
                let (split, edges) = resolve_unresolved_pair_load(
                    pair,
                    &global_mem_last_def,
                    &global_reg_last_def,
                    global_last_cond_branch,
                    data_only,
                );
                all_pair_fixups.push((pair.line, split));
                all_patch_edges.extend(edges);
            }

            // === Resolve partial pair loads inline (no snapshot cloning) ===
            if !chunk.partial_unresolved_pair_loads.is_empty() {
                for partial in &chunk.partial_unresolved_pair_loads {
                    let mut extra_half1 = SmallVec::<[u32; 4]>::new();
                    let mut extra_half2 = SmallVec::<[u32; 4]>::new();
                    let mut extra_shared = SmallVec::<[u32; 2]>::new();

                    if partial.half1_unresolved {
                        for offset in 0..partial.elem_width as u64 {
                            if let Some(&(raw, _)) =
                                global_mem_last_def.get(&(partial.addr + offset))
                            {
                                push_unique(&mut extra_half1, raw);
                                all_patch_edges.push((partial.line, raw));
                            }
                        }
                    }
                    if partial.half2_unresolved {
                        for offset in partial.elem_width as u64..2 * partial.elem_width as u64 {
                            if let Some(&(raw, _)) =
                                global_mem_last_def.get(&(partial.addr + offset))
                            {
                                push_unique(&mut extra_half2, raw);
                                all_patch_edges.push((partial.line, raw));
                            }
                        }
                    }
                    if partial.base_reg_unresolved {
                        if let Some(base) = partial.base_reg {
                            if let Some(&raw) = global_reg_last_def.get(&base) {
                                push_unique(&mut extra_shared, raw);
                                all_patch_edges.push((partial.line, raw));
                            }
                        }
                    }

                    if !extra_half1.is_empty()
                        || !extra_half2.is_empty()
                        || !extra_shared.is_empty()
                    {
                        deferred_pair_deps.push(DeferredPairDep {
                            line: partial.line,
                            chunk_idx: i,
                            extra_half1,
                            extra_half2,
                            extra_shared,
                        });
                    }
                }
            }

            // === Resolve unresolved register uses ===
            let reg_patches =
                resolve_unresolved_reg_uses(&chunk.unresolved_reg_uses, &global_reg_last_def);
            all_patch_edges.extend(reg_patches);

            // === Resolve control deps ===
            let ctrl_patches = resolve_control_deps(
                chunk.start_line,
                chunk.first_local_cond_branch,
                global_last_cond_branch,
                chunk.end_line,
                &chunk.needs_control_dep,
                data_only,
            );
            all_patch_edges.extend(ctrl_patches);
        }

        // Update global state from this chunk's boundary
        for (&addr, &val) in &chunk.boundary.final_mem_last_def {
            global_mem_last_def.insert(addr, val);
        }
        // Per-register merge: only overwrite registers actually defined in this chunk
        let chunk_reg = chunk.boundary.final_reg_last_def.inner();
        let global_reg = global_reg_last_def.inner_mut();
        for idx in 0..RegId::COUNT {
            if chunk_reg[idx] != u32::MAX {
                global_reg[idx] = chunk_reg[idx];
            }
        }
        if chunk.boundary.final_last_cond_branch.is_some() {
            global_last_cond_branch = chunk.boundary.final_last_cond_branch;
        }

        // Report Pass 1 progress: maps to 0.0-0.10
        if let Some(ref cb) = progress_fn {
            cb(0.10 * (i + 1) as f64 / num_chunks_f64);
        }
    }

    // === Compact global_mem_last_def immediately after Pass 1 ===
    // HashMap 存储 200M+ 条目可达 10-16GB（桶数组 + entries）。
    // 立即转为 sorted Vec（~4GB）释放 HashMap 的巨大开销。
    // Pass 1 之后不再需要 HashMap 的查询能力。
    let global_mem_sorted: Vec<(u64, u32, u64)> = {
        let mut sorted: Vec<(u64, u32, u64)> = global_mem_last_def
            .drain()
            .map(|(addr, (line, val))| (addr, line, val))
            .collect();
        drop(global_mem_last_def); // 立即释放 HashMap 桶数组
        if let Some(ref cb) = progress_fn {
            cb(0.12);
        }
        sorted.sort_unstable_by_key(|(addr, _, _)| *addr);
        sorted
    };

    if let Some(ref cb) = progress_fn {
        cb(0.15);
    }

    type StringAccessList = Vec<(u64, u64, u8, u32, StringRw)>;

    // === Pass 2: Decompose chunk_results (move out data) ===
    let mut chunk_deps = Vec::with_capacity(num_chunks);
    let mut chunk_inits = Vec::with_capacity(num_chunks);
    let mut chunk_pair_splits = Vec::with_capacity(num_chunks);
    let mut chunk_reg_ckpts = Vec::with_capacity(num_chunks);
    let mut chunk_line_indices = Vec::with_capacity(num_chunks);
    let mut chunk_mem_indices = Vec::with_capacity(num_chunks);
    let mut chunk_string_accesses: Vec<StringAccessList> = Vec::with_capacity(num_chunks);
    let mut all_consumed_seqs = Vec::new();
    let mut chunk_start_lines = Vec::with_capacity(num_chunks);
    let mut total_parsed_count = 0u32;
    let mut total_mem_op_count = 0u32;

    let mut prev_final_reg_values = [u64::MAX; RegId::COUNT];

    for (i, chunk) in chunk_results.into_iter().enumerate() {
        chunk_start_lines.push(chunk.start_line);
        chunk_deps.push(chunk.deps);
        chunk_inits.push(chunk.init_mem_loads);
        chunk_pair_splits.push(chunk.pair_split);
        chunk_line_indices.push(chunk.line_index);
        chunk_mem_indices.push(chunk.mem_access_index);
        chunk_string_accesses.push(chunk.string_accesses);
        all_consumed_seqs.extend(chunk.consumed_seqs);

        // Move events (not clone) — saves ~20GB for large files
        all_call_events.extend(chunk.call_tree_events);
        all_gumtrace_events.extend(chunk.gumtrace_annot_events);
        total_parsed_count += chunk.boundary.final_parsed_count;
        total_mem_op_count += chunk.boundary.final_mem_op_count;

        // Fix reg checkpoints using previous chunk's final values
        let mut ckpts = chunk.reg_checkpoints;
        if i > 0 {
            fix_reg_checkpoints(&mut ckpts, &prev_final_reg_values);
        }
        chunk_reg_ckpts.push(ckpts);
        prev_final_reg_values = chunk.boundary.final_reg_values;
    }

    // === Apply deferred pair deps (lightweight, no snapshot needed) ===
    for dep in &deferred_pair_deps {
        let pair_split = &mut chunk_pair_splits[dep.chunk_idx];
        let split = pair_split.entry(dep.line).or_default();
        for &d in &dep.extra_half1 {
            push_unique(&mut split.half1_deps, d);
        }
        for &d in &dep.extra_half2 {
            push_unique(&mut split.half2_deps, d);
        }
        for &d in &dep.extra_shared {
            push_unique(&mut split.shared, d);
        }
    }

    if let Some(ref cb) = progress_fn {
        cb(0.20);
    }

    let phase2_timer = std::time::Instant::now();

    // === Rebuild unified data structures ===

    // Total lines (compute before dropping chunk_deps)
    let total_lines = chunk_start_lines.last().copied().unwrap_or(0)
        + chunk_deps
            .last()
            .map(|d| d.offsets.len() as u32)
            .unwrap_or(0);

    // Build DepsStorage::Chunked — avoids the expensive O(n) rebuild_compact_deps.
    // Group patch_edges by source line (sorted) for efficient binary-search lookup.
    use rustc_hash::FxHashMap as PatchMap;
    let mut patch_map: PatchMap<u32, Vec<u32>> = PatchMap::default();
    for &(from, to) in &all_patch_edges {
        patch_map.entry(from).or_default().push(to);
    }
    // Dedup within each group (same logic as rebuild_compact_deps used push_unique)
    for deps in patch_map.values_mut() {
        deps.sort_unstable();
        deps.dedup();
    }
    let mut patch_groups: Vec<(u32, Vec<u32>)> = patch_map.into_iter().collect();
    patch_groups.sort_unstable_by_key(|&(line, _)| line);

    let merged_deps = crate::scanner::DepsStorage::Chunked {
        chunks: chunk_deps,
        chunk_start_lines: chunk_start_lines.clone(),
        patch_groups,
    };
    drop(all_patch_edges); // Free patch edges

    eprintln!(
        "[perf] DepsStorage::Chunked built (skipped rebuild_compact_deps): {:?}",
        phase2_timer.elapsed()
    );

    if let Some(ref cb) = progress_fn {
        cb(0.70);
    }

    let t = std::time::Instant::now();
    // CallTree
    let call_tree = replay_call_tree_events(&all_call_events, total_lines);

    // Gumtrace annotations
    let (call_annotations, extra_consumed) = if format == TraceFormat::Gumtrace {
        replay_gumtrace_annotations(&all_gumtrace_events)
    } else {
        (HashMap::new(), Vec::new())
    };

    eprintln!("[perf] CallTree + annotations: {:?}", t.elapsed());

    if let Some(ref cb) = progress_fn {
        cb(0.73);
    }

    let t = std::time::Instant::now();
    // consumed_seqs
    all_consumed_seqs.extend(extra_consumed);
    all_consumed_seqs.sort_unstable();

    // MemAccessIndex — 逐 chunk 合并（0.75-0.85）
    let total_mem_chunks = chunk_mem_indices.len();
    let mem_accesses = {
        let mut merged = MemAccessIndex::new();
        for (ci, chunk_idx) in chunk_mem_indices.into_iter().enumerate() {
            for (addr, record) in chunk_idx.iter_all() {
                merged.add(addr, record.clone());
            }
            if let Some(ref cb) = progress_fn {
                cb(0.75 + 0.10 * (ci + 1) as f64 / total_mem_chunks as f64);
            }
        }
        merged
    };

    eprintln!(
        "[perf] MemAccessIndex merge: {:?} ({} addresses, {} records)",
        t.elapsed(),
        mem_accesses.total_addresses(),
        mem_accesses.total_records()
    );

    if let Some(ref cb) = progress_fn {
        cb(0.85);
    }

    // RegCheckpoints: merge all snapshots
    let merged_ckpts = {
        let mut all_snapshots = Vec::new();
        for ckpt in chunk_reg_ckpts {
            all_snapshots.extend(ckpt.snapshots);
        }
        RegCheckpoints {
            interval: 1000,
            snapshots: all_snapshots,
        }
    };

    let t = std::time::Instant::now();
    // StringIndex — 从 scan_chunk 收集的内存访问记录精确构建（0.85-0.97）
    // 记录已按 chunk 顺序排列（每个 chunk 内部是 seq 顺序），直接逐 chunk 处理
    // = 全局 seq 顺序，无需排序
    let string_index = if !skip_strings {
        let total_accesses: usize = chunk_string_accesses.iter().map(|w| w.len()).sum();
        let report_interval = (total_accesses / 100).max(1);
        let mut processed = 0usize;

        let estimated_pages = {
            let mut min_addr = u64::MAX;
            let mut max_addr = 0u64;
            for chunk in &chunk_string_accesses {
                for &(addr, _, _, _, _) in chunk {
                    min_addr = min_addr.min(addr);
                    max_addr = max_addr.max(addr);
                }
            }
            if max_addr > min_addr {
                // 上限 1M 页（~4GB 地址范围），避免稀疏地址空间导致 OOM
                (((max_addr - min_addr) / 4096 + 1) as usize).min(1_000_000)
            } else {
                1024
            }
        };
        let mut sb = crate::query::strings::StringBuilder::with_capacity(estimated_pages);
        for chunk_accesses in chunk_string_accesses.into_iter() {
            for &(addr, data, size, seq, rw) in &chunk_accesses {
                sb.process_access(addr, data, size, seq, rw);
                processed += 1;
                if processed % report_interval == 0 {
                    // Check cancellation
                    if let Some(flag) = cancel_flag {
                        if flag.load(std::sync::atomic::Ordering::Relaxed) {
                            return Err(crate::error::TraceError::Cancelled);
                        }
                    }
                    if let Some(ref cb) = progress_fn {
                        cb(0.85 + 0.12 * (processed as f64 / total_accesses as f64));
                    }
                }
            }
        }

        if let Some(ref cb) = progress_fn {
            cb(0.97);
        }

        let t2 = std::time::Instant::now();
        let si = sb.finish();
        eprintln!(
            "[perf] StringBuilder.finish(): {:?} ({} strings)",
            t2.elapsed(),
            si.strings.len()
        );

        eprintln!(
            "[perf] StringIndex total (build+finish, xref deferred): {:?}",
            t.elapsed()
        );
        si
    } else {
        Default::default()
    };

    // LineIndex
    let line_index = merge_line_indices(chunk_line_indices);

    // init_mem_loads
    let init_mem_loads = merge_init_mem_loads(chunk_inits, &init_corrections);

    // pair_split
    let pair_split = merge_pair_splits(chunk_pair_splits, all_pair_fixups);

    if let Some(ref cb) = progress_fn {
        cb(0.98);
    }

    // Build ScanState — use pre-compacted sorted Vec (already freed HashMap in Pass 1)
    let mem_last_def_map = MemLastDef::Sorted(global_mem_sorted);

    let scan_state = ScanState {
        reg_last_def: global_reg_last_def,
        mem_last_def: mem_last_def_map,
        last_cond_branch: global_last_cond_branch,
        deps: merged_deps,
        line_count: total_lines,
        parsed_count: total_parsed_count,
        mem_op_count: total_mem_op_count,
        resolved_targets: FxHashMap::default(),
        unknown_mnemonics: FxHashMap::default(),
        init_mem_loads,
        pair_split,
    };

    let phase2 = Phase2State {
        call_tree,
        mem_accesses,
        reg_checkpoints: merged_ckpts,
        string_index,
    };

    if let Some(ref cb) = progress_fn {
        cb(1.0);
    }

    Ok(ScanResult {
        scan_state,
        phase2,
        line_index,
        format,
        call_annotations,
        consumed_seqs: all_consumed_seqs,
    })
}
