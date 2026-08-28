//! Unresolved load / partial load 的全局状态解析。

use rustc_hash::FxHashMap;

use crate::parallel_types::{
    PartialUnresolvedLoad, PartialUnresolvedPairLoad, UnresolvedLoad, UnresolvedPairLoad,
    UnresolvedRegUse,
};
use crate::scanner::{push_unique, PairSplitDeps, RegLastDef, CONTROL_DEP_BIT};

/// Resolve a fully unresolved load using global state.
/// Determines pass-through exactly as single-threaded scan would.
pub fn resolve_unresolved_load(
    load: &UnresolvedLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    let mut all_same_store = true;
    let mut first_store_raw: Option<u32> = None;
    let mut store_val: Option<u64> = None;
    let mut has_init_mem = false;

    for offset in 0..load.width as u64 {
        if let Some(&(def_line, def_val)) = global_mem_last_def.get(&(load.addr + offset)) {
            patch_edges.push((load.line, def_line));
            match first_store_raw {
                None => {
                    first_store_raw = Some(def_line);
                    store_val = Some(def_val);
                }
                Some(first) if first != def_line => {
                    all_same_store = false;
                }
                _ => {}
            }
        } else {
            has_init_mem = true;
            all_same_store = false;
        }
    }

    // Pass-through check: exact same logic as scan_unified
    let is_pass_through = all_same_store
        && store_val.is_some()
        && load.load_value.is_some()
        && store_val.unwrap() == load.load_value.unwrap();

    if !is_pass_through {
        // Not pass-through → add register deps
        for r in &load.uses {
            if let Some(&def_line) = global_reg_last_def.get(r) {
                patch_edges.push((load.line, def_line));
            }
        }
    }

    // Correct init_mem_loads
    if !has_init_mem {
        init_corrections.push((load.line, false));
    }
}

/// Resolve partially unresolved loads — supplement missing mem deps.
/// Pass-through is already determined as false (mixed case). Reg deps already added.
pub fn resolve_partial_unresolved_loads(
    partials: &[PartialUnresolvedLoad],
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    patch_edges: &mut Vec<(u32, u32)>,
    init_corrections: &mut Vec<(u32, bool)>,
) {
    for partial in partials {
        let mut all_found = true;
        for &addr in &partial.missing_addrs {
            if let Some(&(def_line, _)) = global_mem_last_def.get(&addr) {
                patch_edges.push((partial.line, def_line));
            } else {
                all_found = false;
            }
        }
        if all_found {
            init_corrections.push((partial.line, false));
        }
    }
}

/// Resolve a fully unresolved pair load. Builds complete PairSplitDeps from global state.
pub fn resolve_unresolved_pair_load(
    pair: &UnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    global_last_cond_branch: Option<u32>,
    data_only: bool,
) -> (PairSplitDeps, Vec<(u32, u32)>) {
    let mut split = PairSplitDeps::default();
    let mut patch_edges = Vec::new();
    let ew = pair.elem_width;

    // half1 mem deps (first elem_width bytes)
    for offset in 0..ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half1_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // half2 mem deps (second elem_width bytes)
    for offset in ew as u64..2 * ew as u64 {
        if let Some(&(raw, _)) = global_mem_last_def.get(&(pair.addr + offset)) {
            push_unique(&mut split.half2_deps, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: base reg dep
    if let Some(base) = pair.base_reg {
        if let Some(&raw) = global_reg_last_def.get(&base) {
            push_unique(&mut split.shared, raw);
            patch_edges.push((pair.line, raw));
        }
    }
    // shared: control dep
    if !data_only {
        if let Some(cb) = global_last_cond_branch {
            push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
            patch_edges.push((pair.line, cb | CONTROL_DEP_BIT));
        }
    }

    (split, patch_edges)
}

/// Resolve a partially unresolved pair load. Supplements missing half deps in existing PairSplitDeps.
pub fn resolve_partial_pair_load(
    partial: &PartialUnresolvedPairLoad,
    global_mem_last_def: &FxHashMap<u64, (u32, u64)>,
    global_reg_last_def: &RegLastDef,
    pair_split: &mut FxHashMap<u32, PairSplitDeps>,
    patch_edges: &mut Vec<(u32, u32)>,
) {
    let ew = partial.elem_width;
    let split = pair_split.entry(partial.line).or_default();

    if partial.half1_unresolved {
        for offset in 0..ew as u64 {
            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                push_unique(&mut split.half1_deps, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
    if partial.half2_unresolved {
        for offset in ew as u64..2 * ew as u64 {
            if let Some(&(raw, _)) = global_mem_last_def.get(&(partial.addr + offset)) {
                push_unique(&mut split.half2_deps, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
    if partial.base_reg_unresolved {
        if let Some(base) = partial.base_reg {
            if let Some(&raw) = global_reg_last_def.get(&base) {
                push_unique(&mut split.shared, raw);
                patch_edges.push((partial.line, raw));
            }
        }
    }
}

/// Resolve register uses that had no local definition.
pub fn resolve_unresolved_reg_uses(
    uses: &[UnresolvedRegUse],
    global_reg_last_def: &RegLastDef,
) -> Vec<(u32, u32)> {
    let mut patch_edges = Vec::new();
    for u in uses {
        if let Some(&def_line) = global_reg_last_def.get(&u.reg) {
            patch_edges.push((u.line, def_line));
        }
    }
    patch_edges
}
