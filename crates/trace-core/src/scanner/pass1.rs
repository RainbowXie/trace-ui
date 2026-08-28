//! Pass 1 主扫描循环：按字节流前向构建依赖图。
//!
//! 从 `scanner` 模块抽出以控制文件规模；`crate::scanner::scan_pass1_bytes_with_progress`
//! 路径由 scanner/mod.rs 的 `pub use` 保持。

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use memchr::memchr;
use rustc_hash::FxHashMap;

use trace_parser::def_use;
use trace_parser::insn_class::{self, InsnClass};
use trace_parser::parser;
use trace_parser::types::*;

use super::*;

pub fn scan_pass1_bytes_with_progress(
    data: &[u8],
    options: Pass1Options<'_>,
    progress_fn: Option<&dyn Fn(usize, usize)>,
) -> Result<ScanState> {
    let Pass1Options {
        data_only,
        start_seq,
        end_seq,
        line_targets,
        profile,
        no_prune,
    } = options;
    // Pre-count lines for capacity pre-allocation.
    // This memchr scan (~0.3s for 2.88GB) also pre-faults all mmap pages into
    // physical memory, warming the page cache for the main loop. Removing this
    // causes ~5s regression on Windows due to cold page faults during parsing.
    let line_count_est = memchr::memchr_iter(b'\n', data).count()
        + if !data.is_empty() && data.last() != Some(&b'\n') {
            1
        } else {
            0
        };

    let mut state = ScanState {
        reg_last_def: RegLastDef::new(),
        mem_last_def: MemLastDef::default(),
        last_cond_branch: None,
        deps: DepsStorage::single(CompactDeps::with_capacity(
            line_count_est,
            line_count_est * 2,
        )),
        line_count: 0,
        parsed_count: 0,
        mem_op_count: 0,
        resolved_targets: FxHashMap::default(),
        unknown_mnemonics: FxHashMap::default(),
        init_mem_loads: bitvec::prelude::BitVec::repeat(false, line_count_est),
        pair_split: FxHashMap::default(),
    };

    // Profiling accumulators
    let mut t_io = Duration::ZERO;
    let mut t_parse = Duration::ZERO;
    let mut t_classify = Duration::ZERO;
    let mut t_deps = Duration::ZERO;
    let mut t_update = Duration::ZERO;
    let mut pruned_count = 0u64;

    let mut pos = 0usize;
    let len = data.len();
    let progress_interval = len / 100 + 1;
    let mut last_progress_pos = 0usize;

    while pos < len {
        // 进度报告
        if let Some(cb) = &progress_fn {
            if pos - last_progress_pos >= progress_interval {
                cb(pos, len);
                last_progress_pos = pos;
            }
        }

        let t0 = profile.then(Instant::now);

        // Find next newline (or end of data)
        let line_end = match memchr(b'\n', &data[pos..]) {
            Some(p) => pos + p,
            None => len,
        };

        // Trim trailing \r (Windows CRLF)
        let end = if line_end > pos && data[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };

        // SAFETY: trace lines are ASCII (ARM64 disassembly text from unidbg)
        let raw_line = unsafe { std::str::from_utf8_unchecked(&data[pos..end]) };
        pos = if line_end < len { line_end + 1 } else { len };

        if let Some(t) = t0 {
            t_io += t.elapsed();
        }

        let i = state.line_count;
        state.deps.start_row();

        // Range limiting: skip lines outside [start_seq, end_seq]
        if i < start_seq || end_seq.is_some_and(|end| i > end) {
            state.line_count += 1;
            continue;
        }

        // Parse; unparseable lines get an empty dep set
        let t1 = profile.then(Instant::now);

        let Some(line) = parser::parse_line(raw_line) else {
            if let Some(t) = t1 {
                t_parse += t.elapsed();
            }
            state.line_count += 1;
            continue;
        };

        if let Some(t) = t1 {
            t_parse += t.elapsed();
        }

        // Classify instruction + Determine DEF/USE
        let t2 = profile.then(Instant::now);

        let class = insn_class::classify_and_refine(&line);

        // 收集未知助记符（classify 回退到 Nop 但不属于已知 NOP 指令）
        if class == InsnClass::Nop && !insn_class::is_known_nop(line.mnemonic.as_str()) {
            let entry = state
                .unknown_mnemonics
                .entry(line.mnemonic.as_str().to_string())
                .or_insert((i, 0));
            entry.1 += 1;
        }

        let (defs, uses) = def_use::determine_def_use(class, &line);

        if let Some(t) = t2 {
            t_classify += t.elapsed();
        }

        // --- @LINE target resolution (with fallback) ---
        if let Some(targets) = line_targets.get(&i) {
            for target in targets {
                match target {
                    LineTarget::Reg(reg) => {
                        if defs.contains(reg) {
                            state.resolved_targets.insert((i, target.clone()), i);
                        } else if let Some(&prev) = state.reg_last_def.get(reg) {
                            eprintln!("[info] reg {:?} not DEF'd at line {}, resolved to last DEF at line {}", reg, i + 1, prev + 1);
                            state.resolved_targets.insert((i, target.clone()), prev);
                        } else {
                            bail!(
                                "line {} does not DEF register {:?} and no prior DEF exists",
                                i + 1,
                                reg
                            );
                        }
                    }
                    LineTarget::Mem(addr) => {
                        let is_store = line.mem_op.as_ref().is_some_and(|m| {
                            if !m.is_write {
                                return false;
                            }
                            let width = mem_access_width(class, m.elem_width, &line);
                            (0..width as u64).any(|off| m.abs + off == *addr)
                        });
                        if is_store {
                            state.resolved_targets.insert((i, target.clone()), i);
                        } else if let Some((prev, _)) = state.mem_last_def.get(addr) {
                            eprintln!("[info] mem 0x{:x} not STORE'd at line {}, resolved to last STORE at line {}", addr, i + 1, prev + 1);
                            state.resolved_targets.insert((i, target.clone()), prev);
                        } else {
                            bail!("line {} does not STORE to address 0x{:x} and no prior STORE exists", i + 1, addr);
                        }
                    }
                }
            }
        }

        // --- Dependency tracking ---
        let t3 = profile.then(Instant::now);
        let is_pair = class == InsnClass::LoadPair || class == InsnClass::StorePair;

        // For non-pair LOAD: do mem deps (3b) first to determine pass-through,
        // then conditionally skip register deps (3a).
        let is_non_pair_load = !is_pair && line.mem_op.as_ref().is_some_and(|m| !m.is_write);
        let mut is_pass_through = false;

        if is_non_pair_load && !no_prune {
            let mem = line.mem_op.as_ref().unwrap();
            let width = mem_access_width(class, mem.elem_width, &line);
            let mut has_init_mem = false;
            let mut all_same_store = true;
            let mut first_store_raw: Option<u32> = None;
            let mut store_val: Option<u64> = None;

            for offset in 0..width as u64 {
                if let Some((def_line, def_val)) = state.mem_last_def.get(&(mem.abs + offset)) {
                    state.deps.push_unique(def_line);
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
            if has_init_mem {
                state.init_mem_loads.set(i as usize, true);
            }

            // Pass-through: all bytes from same STORE, both values extracted, values equal
            if all_same_store
                && store_val.is_some()
                && mem.value.is_some()
                && store_val.unwrap() == mem.value.unwrap()
            {
                is_pass_through = true;
                pruned_count += 1;
            }
        }

        // Step 3a: Register data dependencies
        // Skip for pair (handled in 3d) and for pass-through LOADs (address deps pruned)
        if !is_pair && !is_pass_through {
            for r in &uses {
                if let Some(&def_line) = state.reg_last_def.get(r) {
                    state.deps.push_unique(def_line);
                }
            }
        }

        // Step 3b: Memory data dependencies
        // Non-pair LOADs with pruning enabled are already handled above;
        // handle: pair LOADs, non-pair LOADs with pruning disabled
        if let Some(ref mem) = line.mem_op {
            if !mem.is_write && (!is_non_pair_load || no_prune) {
                let width = mem_access_width(class, mem.elem_width, &line);
                let mut has_init_mem = false;
                for offset in 0..width as u64 {
                    if let Some((def_line, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                        if !is_pair {
                            state.deps.push_unique(def_line);
                        }
                    } else {
                        has_init_mem = true;
                    }
                }
                if has_init_mem {
                    state.init_mem_loads.set(i as usize, true);
                }
            }
        }

        // Step 3c: Control dependencies (skip for pair — handled in 3d)
        if !is_pair && !data_only {
            if let Some(cb) = state.last_cond_branch {
                state.deps.push_unique(cb | CONTROL_DEP_BIT);
            }
        }

        // Step 3d: Pair-specific split tracking (LoadPair/StorePair)
        if class == InsnClass::LoadPair || class == InsnClass::StorePair {
            if let Some(ref mem) = line.mem_op {
                let ew = mem.elem_width;
                let mut split = PairSplitDeps::default();

                match class {
                    InsnClass::LoadPair => {
                        // half1 mem deps (first elem_width bytes)
                        for offset in 0..ew as u64 {
                            if let Some((raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                                push_unique(&mut split.half1_deps, raw);
                            }
                        }
                        // half2 mem deps (second elem_width bytes)
                        for offset in ew as u64..2 * ew as u64 {
                            if let Some((raw, _)) = state.mem_last_def.get(&(mem.abs + offset)) {
                                push_unique(&mut split.half2_deps, raw);
                            }
                        }
                    }
                    InsnClass::StorePair => {
                        // half1: first source register dep
                        if let Some(r) = line.operands.first().and_then(|op| op.as_reg()) {
                            if let Some(&raw) = state.reg_last_def.get(&r) {
                                push_unique(&mut split.half1_deps, raw);
                            }
                        }
                        // half2: second source register dep
                        if let Some(r) = line.operands.get(1).and_then(|op| op.as_reg()) {
                            if let Some(&raw) = state.reg_last_def.get(&r) {
                                push_unique(&mut split.half2_deps, raw);
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // shared: base reg dep
                if let Some(base) = line.base_reg {
                    if let Some(&raw) = state.reg_last_def.get(&base) {
                        push_unique(&mut split.shared, raw);
                    }
                }
                // shared: control dep
                if !data_only {
                    if let Some(cb) = state.last_cond_branch {
                        push_unique(&mut split.shared, cb | CONTROL_DEP_BIT);
                    }
                }

                state.pair_split.insert(i, split);
            }
        }

        if let Some(t) = t3 {
            t_deps += t.elapsed();
        }

        // --- State update ---
        let t4 = profile.then(Instant::now);

        // Step 4: Update regLastDef
        if class == InsnClass::LoadPair {
            // After SIMD expansion, defs may be [rt1_lo, rt1_hi, rt2_lo, rt2_hi, base?]
            // or [rt1, rt2, base?] for scalar. Split data defs at midpoint.
            let has_base_wb = line.writeback && line.base_reg.is_some();
            let data_defs = if has_base_wb {
                &defs[..defs.len() - 1]
            } else {
                &defs[..]
            };
            let mid = data_defs.len() / 2;

            for r in &data_defs[..mid] {
                state.reg_last_def.insert(*r, i); // half1: no tag
            }
            for r in &data_defs[mid..] {
                state.reg_last_def.insert(*r, i | PAIR_HALF2_BIT); // half2
            }
            if has_base_wb {
                state
                    .reg_last_def
                    .insert(*defs.last().unwrap(), i | PAIR_SHARED_BIT);
            }
        } else if class == InsnClass::StorePair {
            // StorePair: writeback base is the only DEF (if present)
            for r in &defs {
                state.reg_last_def.insert(*r, i | PAIR_SHARED_BIT);
            }
        } else {
            for r in &defs {
                state.reg_last_def.insert(*r, i);
            }
        }

        // Step 5: Update memLastDef (byte granularity, with masked value for pruning)
        if let Some(ref mem) = line.mem_op {
            if mem.is_write {
                let masked_val = mem.value.unwrap_or(0);
                if class == InsnClass::StorePair {
                    // StorePair: tag second half bytes with PAIR_HALF2_BIT
                    // value=0 for pair (value extraction skipped, won't match in pruning)
                    let ew = mem.elem_width;
                    for offset in 0..ew as u64 {
                        state.mem_last_def.insert(mem.abs + offset, (i, masked_val));
                    }
                    for offset in ew as u64..2 * ew as u64 {
                        state
                            .mem_last_def
                            .insert(mem.abs + offset, (i | PAIR_HALF2_BIT, 0));
                    }
                } else {
                    let width = mem_access_width(class, mem.elem_width, &line);
                    for offset in 0..width as u64 {
                        state.mem_last_def.insert(mem.abs + offset, (i, masked_val));
                    }
                }
            }
        }

        // Step 6: Update lastCondBranch
        match class {
            InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => {
                state.last_cond_branch = Some(i);
            }
            _ => {}
        }

        if let Some(t) = t4 {
            t_update += t.elapsed();
        }

        if line.mem_op.is_some() {
            state.mem_op_count += 1;
        }
        state.parsed_count += 1;
        state.line_count += 1;
    }

    // Print profiling results
    if profile {
        let total = t_io + t_parse + t_classify + t_deps + t_update;
        let total_s = total.as_secs_f64();
        let pct = |d: Duration| {
            if total_s > 0.0 {
                d.as_secs_f64() / total_s * 100.0
            } else {
                0.0
            }
        };
        eprintln!("\n[profile] ─── 扫描阶段内部耗时分解 ───");
        eprintln!(
            "[profile] I/O (mmap+memchr): {:7.2}s ({:5.1}%)",
            t_io.as_secs_f64(),
            pct(t_io)
        );
        eprintln!(
            "[profile] 解析 (parse_line): {:7.2}s ({:5.1}%)",
            t_parse.as_secs_f64(),
            pct(t_parse)
        );
        eprintln!(
            "[profile] 分类+DEF/USE     : {:7.2}s ({:5.1}%)",
            t_classify.as_secs_f64(),
            pct(t_classify)
        );
        eprintln!(
            "[profile] 依赖追踪         : {:7.2}s ({:5.1}%)",
            t_deps.as_secs_f64(),
            pct(t_deps)
        );
        eprintln!(
            "[profile] 状态更新         : {:7.2}s ({:5.1}%)",
            t_update.as_secs_f64(),
            pct(t_update)
        );
        eprintln!("[profile] 合计 (含计时开销): {:7.2}s", total_s);
        eprintln!("[profile] 已解析行数       : {}", state.parsed_count);
        eprintln!("[profile] 总行数           : {}", state.line_count);
        eprintln!("[profile] mem_last_def 条目: {}", state.mem_last_def.len());
        eprintln!("[profile] deps 总边数      : {}", state.deps.total_deps());
        eprintln!("[profile] pass-through 剪枝: {} loads", pruned_count);
        eprintln!("[profile] ──────────────────────────────");
    }

    // Check for line targets that were never reached
    for (&line_num, targets) in line_targets {
        if line_num >= state.line_count {
            if let Some(target) = targets.first() {
                match target {
                    LineTarget::Reg(reg) => bail!(
                        "line {} out of range (trace has {} lines), target: {:?}",
                        line_num + 1,
                        state.line_count,
                        reg
                    ),
                    LineTarget::Mem(addr) => bail!(
                        "line {} out of range (trace has {} lines), target: 0x{:x}",
                        line_num + 1,
                        state.line_count,
                        addr
                    ),
                }
            }
        }
    }

    Ok(state)
}
