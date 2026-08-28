//! merge 模块的单元测试。

use super::*;
use crate::chunk_scan::{scan_chunk, ScanChunkConfig};
use rustc_hash::FxHashMap;
use smallvec::smallvec;
use trace_parser::types::RegId;

use crate::parallel_types::{
    CallTreeEvent, GumtraceAnnotEvent, PartialUnresolvedLoad, SpecialLineData, UnresolvedLoad,
    UnresolvedPairLoad, UnresolvedRegUse,
};
use crate::query::registers::RegCheckpoints;
use crate::scanner::{CompactDeps, PairSplitDeps, RegLastDef, CONTROL_DEP_BIT};
use trace_parser::types::TraceFormat;

#[test]
fn test_resolve_load_passthrough() {
    let mut global_mem = FxHashMap::default();
    for i in 0..8u64 {
        global_mem.insert(0x8000 + i, (10u32, 0x42u64));
    }
    let load = UnresolvedLoad {
        line: 20,
        addr: 0x8000,
        width: 8,
        load_value: Some(0x42),
        uses: smallvec![RegId(1), RegId(2)],
    };
    let mut global_reg = RegLastDef::new();
    global_reg.insert(RegId(1), 5);
    global_reg.insert(RegId(2), 8);

    let mut patch_edges = Vec::new();
    let mut init_corrections = Vec::new();
    resolve_unresolved_load(
        &load,
        &global_mem,
        &global_reg,
        &mut patch_edges,
        &mut init_corrections,
    );

    // Pass-through: only memory dep (one unique store line), no register deps
    assert!(patch_edges.iter().all(|&(from, _)| from == 20));
    assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
    assert!(!patch_edges.iter().any(|&(_, to)| to == 5)); // no reg dep x1
    assert!(!patch_edges.iter().any(|&(_, to)| to == 8)); // no reg dep x2
    assert_eq!(init_corrections, vec![(20, false)]);
}

#[test]
fn test_resolve_load_not_passthrough_different_value() {
    let mut global_mem = FxHashMap::default();
    for i in 0..8u64 {
        global_mem.insert(0x8000 + i, (10u32, 0x99u64));
    }
    let load = UnresolvedLoad {
        line: 20,
        addr: 0x8000,
        width: 8,
        load_value: Some(0x42), // != 0x99
        uses: smallvec![RegId(1)],
    };
    let mut global_reg = RegLastDef::new();
    global_reg.insert(RegId(1), 5);

    let mut patch_edges = Vec::new();
    let mut init_corrections = Vec::new();
    resolve_unresolved_load(
        &load,
        &global_mem,
        &global_reg,
        &mut patch_edges,
        &mut init_corrections,
    );

    assert!(patch_edges.iter().any(|&(_, to)| to == 10)); // mem dep
    assert!(patch_edges.iter().any(|&(_, to)| to == 5)); // reg dep
}

#[test]
fn test_resolve_load_init_mem() {
    // No global store exists → truly initial memory
    let global_mem = FxHashMap::default();
    let load = UnresolvedLoad {
        line: 20,
        addr: 0x8000,
        width: 4,
        load_value: None,
        uses: smallvec![RegId(1)],
    };
    let mut global_reg = RegLastDef::new();
    global_reg.insert(RegId(1), 5);

    let mut patch_edges = Vec::new();
    let mut init_corrections = Vec::new();
    resolve_unresolved_load(
        &load,
        &global_mem,
        &global_reg,
        &mut patch_edges,
        &mut init_corrections,
    );

    // No mem deps (no store found), but reg deps added (not pass-through)
    assert!(patch_edges.iter().any(|&(_, to)| to == 5));
    // init_mem_loads should NOT be corrected (it IS truly initial)
    assert!(init_corrections.is_empty());
}

#[test]
fn test_resolve_partial_loads() {
    let mut global_mem = FxHashMap::default();
    global_mem.insert(0x8002u64, (15u32, 0u64));
    global_mem.insert(0x8003u64, (15u32, 0u64));

    let partials = vec![PartialUnresolvedLoad {
        line: 25,
        missing_addrs: smallvec![0x8002, 0x8003],
    }];

    let mut patch_edges = Vec::new();
    let mut init_corrections = Vec::new();
    resolve_partial_unresolved_loads(
        &partials,
        &global_mem,
        &mut patch_edges,
        &mut init_corrections,
    );

    assert!(patch_edges.iter().any(|&(from, to)| from == 25 && to == 15));
    assert_eq!(init_corrections, vec![(25, false)]);
}

#[test]
fn test_resolve_pair_load() {
    let mut global_mem = FxHashMap::default();
    for i in 0..4u64 {
        global_mem.insert(0x8000 + i, (10, 0));
    }
    for i in 4..8u64 {
        global_mem.insert(0x8000 + i, (15, 0));
    }
    let mut global_reg = RegLastDef::new();
    global_reg.insert(RegId(3), 7);

    let pair = UnresolvedPairLoad {
        line: 25,
        addr: 0x8000,
        elem_width: 4,
        base_reg: Some(RegId(3)),
        defs: smallvec![RegId(0), RegId(1), RegId(3)],
    };
    let (split, _patches) =
        resolve_unresolved_pair_load(&pair, &global_mem, &global_reg, None, false);
    assert!(split.half1_deps.contains(&10));
    assert!(split.half2_deps.contains(&15));
    assert!(split.shared.contains(&7));
}

#[test]
fn test_resolve_reg_uses() {
    let mut global_reg = RegLastDef::new();
    global_reg.insert(RegId(5), 42);
    let uses = vec![
        UnresolvedRegUse {
            line: 100,
            reg: RegId(5),
        },
        UnresolvedRegUse {
            line: 101,
            reg: RegId(6),
        }, // not defined
    ];
    let patches = resolve_unresolved_reg_uses(&uses, &global_reg);
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0], (100, 42));
}

#[test]
fn test_resolve_control_deps() {
    use bitvec::prelude::*;
    let mut needs = BitVec::new();
    // 10 lines: chunk starts at 100
    for i in 0..10 {
        needs.push(i != 3 && i != 7); // lines 103 and 107 don't need control dep
    }
    let patches = resolve_control_deps(100, Some(105), Some(95), 110, &needs, false);
    // Lines 100-104 (before first_local_cond=105), except 103
    assert!(patches.contains(&(100, 95 | CONTROL_DEP_BIT)));
    assert!(patches.contains(&(101, 95 | CONTROL_DEP_BIT)));
    assert!(patches.contains(&(102, 95 | CONTROL_DEP_BIT)));
    assert!(!patches.iter().any(|&(line, _)| line == 103)); // pair/unparsed
    assert!(patches.contains(&(104, 95 | CONTROL_DEP_BIT)));
    assert!(!patches.iter().any(|&(line, _)| line >= 105)); // after first local cond
}

#[test]
fn test_rebuild_compact_deps() {
    // Chunk 0: 3 lines (lines 0,1,2)
    let mut c0 = CompactDeps::with_capacity(3, 6);
    c0.start_row(); // line 0: no deps
    c0.start_row();
    c0.push_unique(0); // line 1 → line 0
    c0.start_row();
    c0.push_unique(1); // line 2 → line 1

    // Chunk 1: 2 lines (lines 3,4)
    let mut c1 = CompactDeps::with_capacity(2, 4);
    c1.start_row(); // line 3: no local deps
    c1.start_row();
    c1.push_unique(3); // line 4 → line 3

    let patch_edges = vec![
        (3u32, 2u32), // line 3 depends on line 2 (cross-chunk)
    ];

    let merged = rebuild_compact_deps(&[c0, c1], &[0, 3], &patch_edges, None);

    // Verify
    assert_eq!(merged.row(0).len(), 0); // line 0: no deps
    assert_eq!(merged.row(1), &[0]); // line 1 → 0
    assert_eq!(merged.row(2), &[1]); // line 2 → 1

    let mut line3: Vec<u32> = merged.row(3).to_vec();
    line3.sort();
    assert_eq!(line3, vec![2]); // line 3 → 2 (from patch)

    assert_eq!(merged.row(4), &[3]); // line 4 → 3
}

#[test]
fn test_rebuild_compact_deps_dedup() {
    let mut c0 = CompactDeps::with_capacity(2, 4);
    c0.start_row(); // line 0
    c0.start_row();
    c0.push_unique(0); // line 1 → 0

    // Patch also adds line 1 → 0 (duplicate)
    let patch_edges = vec![(1u32, 0u32)];

    let merged = rebuild_compact_deps(&[c0], &[0], &patch_edges, None);
    assert_eq!(merged.row(1).len(), 1); // deduped to single entry
    assert_eq!(merged.row(1), &[0]);
}

#[test]
fn test_replay_call_tree_basic() {
    let events = vec![
        CallTreeEvent::Call {
            seq: 5,
            target: 0x2000,
        },
        CallTreeEvent::Ret { seq: 10 },
        CallTreeEvent::Call {
            seq: 15,
            target: 0x3000,
        },
        CallTreeEvent::Call {
            seq: 20,
            target: 0x4000,
        },
        CallTreeEvent::Ret { seq: 25 },
        CallTreeEvent::Ret { seq: 30 },
    ];
    let tree = replay_call_tree_events(&events, 35);
    // Root + 3 calls
    assert_eq!(tree.nodes.len(), 4);
    assert_eq!(tree.nodes[0].children_ids, vec![1, 2]);
    assert_eq!(tree.nodes[1].entry_seq, 5);
    assert_eq!(tree.nodes[1].exit_seq, 10);
    assert_eq!(tree.nodes[2].entry_seq, 15);
    assert_eq!(tree.nodes[2].children_ids, vec![3]);
    assert_eq!(tree.nodes[3].entry_seq, 20);
    assert_eq!(tree.nodes[3].exit_seq, 25);
}

#[test]
fn test_replay_call_tree_blr_intercept() {
    // BLR at seq 10 with PC 0x2010, next line addr = 0x2014 = PC+4 → intercepted
    let events = vec![
        CallTreeEvent::Call {
            seq: 10,
            target: 0x3000,
        },
        CallTreeEvent::BlrPending {
            seq: 10,
            pc: 0x2010,
        },
        CallTreeEvent::LineAddr {
            seq: 11,
            addr: 0x2014,
        }, // PC+4 → intercepted
    ];
    let tree = replay_call_tree_events(&events, 20);
    // Root + 1 call that was immediately returned
    assert_eq!(tree.nodes.len(), 2);
    assert_eq!(tree.nodes[1].entry_seq, 10);
    assert_eq!(tree.nodes[1].exit_seq, 10); // ret at seq 10 (11-1)
}

#[test]
fn test_replay_call_tree_func_name() {
    let events = vec![
        CallTreeEvent::Call {
            seq: 5,
            target: 0x2000,
        },
        CallTreeEvent::SetFuncName {
            entry_seq: 5,
            name: "malloc".to_string(),
        },
        CallTreeEvent::Ret { seq: 10 },
    ];
    let tree = replay_call_tree_events(&events, 15);
    assert_eq!(tree.nodes[1].func_name, Some("malloc".to_string()));
}

#[test]
fn test_replay_gumtrace_annotations() {
    let events = vec![
        GumtraceAnnotEvent::BranchInstr { seq: 10 },
        GumtraceAnnotEvent::SpecialLine {
            seq: 11,
            special: SpecialLineData::CallFunc {
                name: "strcmp".to_string(),
                is_jni: false,
                raw: "call func: strcmp".to_string(),
            },
        },
        GumtraceAnnotEvent::SpecialLine {
            seq: 12,
            special: SpecialLineData::Arg {
                index: "0".to_string(),
                value: "0x1234".to_string(),
                raw: "args0: 0x1234".to_string(),
            },
        },
        GumtraceAnnotEvent::SpecialLine {
            seq: 13,
            special: SpecialLineData::Ret {
                value: "0".to_string(),
                raw: "ret: 0".to_string(),
            },
        },
    ];

    let (annotations, extra) = replay_gumtrace_annotations(&events);
    assert_eq!(annotations.len(), 1);
    assert!(annotations.contains_key(&10));
    let ann = &annotations[&10];
    assert_eq!(ann.func_name, "strcmp");
    assert_eq!(ann.args.len(), 1);
    assert_eq!(ann.ret_value, Some("0".to_string()));
    assert!(extra.is_empty());
}

#[test]
fn test_replay_gumtrace_orphan_lines() {
    let events = vec![
        GumtraceAnnotEvent::BranchInstr { seq: 5 },
        GumtraceAnnotEvent::SpecialLine {
            seq: 6,
            special: SpecialLineData::CallFunc {
                name: "test".to_string(),
                is_jni: false,
                raw: "call func: test".to_string(),
            },
        },
        GumtraceAnnotEvent::OrphanLine { seq: 7 }, // unrecognized line while annotation active
        GumtraceAnnotEvent::SpecialLine {
            seq: 8,
            special: SpecialLineData::Ret {
                value: "1".to_string(),
                raw: "ret: 1".to_string(),
            },
        },
    ];

    let (annotations, extra) = replay_gumtrace_annotations(&events);
    assert_eq!(annotations.len(), 1);
    assert_eq!(extra, vec![7]); // orphan line added to consumed
}

#[test]
fn test_fix_reg_checkpoints() {
    let mut ckpts = RegCheckpoints::new(1000);
    let mut vals = [u64::MAX; RegId::COUNT];
    ckpts.save_checkpoint(&vals); // first checkpoint: all unknown
    vals[0] = 0x55;
    ckpts.save_checkpoint(&vals); // second: x0 = 0x55, rest unknown

    let mut prev_final = [u64::MAX; RegId::COUNT];
    prev_final[0] = 0x42;
    prev_final[1] = 0x99;

    fix_reg_checkpoints(&mut ckpts, &prev_final);

    assert_eq!(ckpts.snapshots[0].0[0], 0x42); // was MAX, now prev value
    assert_eq!(ckpts.snapshots[0].0[1], 0x99); // was MAX, now prev value
    assert_eq!(ckpts.snapshots[1].0[0], 0x55); // was set in chunk, kept
    assert_eq!(ckpts.snapshots[1].0[1], 0x99); // was MAX, now prev value
}

#[test]
fn test_merge_init_mem_loads() {
    use bitvec::prelude::*;
    let mut b1: BitVec = BitVec::new();
    b1.push(true);
    b1.push(false);
    b1.push(true);
    let mut b2: BitVec = BitVec::new();
    b2.push(false);
    b2.push(true);

    let corrections = vec![(0u32, false), (4, false)]; // clear bits 0 and 4

    let merged = merge_init_mem_loads(vec![b1, b2], &corrections);
    assert_eq!(merged.len(), 5);
    assert!(!merged[0]); // corrected from true
    assert!(!merged[1]); // original
    assert!(merged[2]); // original
    assert!(!merged[3]); // original
    assert!(!merged[4]); // corrected from true
}

#[test]
fn test_merge_mem_access_indices() {
    use crate::query::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};
    let mut idx1 = MemAccessIndex::new();
    idx1.add(
        0x1000,
        MemAccessRecord {
            seq: 1,
            insn_addr: 0x100,
            rw: MemRw::Read,
            data: 0,
            size: 4,
        },
    );
    let mut idx2 = MemAccessIndex::new();
    idx2.add(
        0x1000,
        MemAccessRecord {
            seq: 5,
            insn_addr: 0x200,
            rw: MemRw::Write,
            data: 42,
            size: 4,
        },
    );
    idx2.add(
        0x2000,
        MemAccessRecord {
            seq: 6,
            insn_addr: 0x204,
            rw: MemRw::Read,
            data: 0,
            size: 1,
        },
    );

    let merged = merge_mem_access_indices(vec![idx1, idx2]);
    assert_eq!(merged.total_addresses(), 2);
    assert_eq!(merged.total_records(), 3);
    let records_at_1000 = merged.get(0x1000).unwrap();
    assert_eq!(records_at_1000.len(), 2);
}

#[test]
fn test_merge_string_indices() {
    use crate::query::strings::{StringEncoding, StringIndex, StringRecord, StringRw};
    let idx1 = StringIndex {
        strings: vec![
            StringRecord {
                addr: 0x1000,
                content: "hello".to_string(),
                encoding: StringEncoding::Ascii,
                byte_len: 5,
                seq: 10,
                xref_count: 0,
                rw: StringRw::Write,
            },
            StringRecord {
                addr: 0x2000,
                content: "world".to_string(),
                encoding: StringEncoding::Ascii,
                byte_len: 5,
                seq: 30,
                xref_count: 0,
                rw: StringRw::Write,
            },
        ],
    };
    let idx2 = StringIndex {
        strings: vec![StringRecord {
            addr: 0x3000,
            content: "foo".to_string(),
            encoding: StringEncoding::Ascii,
            byte_len: 3,
            seq: 20,
            xref_count: 0,
            rw: StringRw::Write,
        }],
    };

    let merged = merge_string_indices(vec![idx1, idx2]);
    assert_eq!(merged.strings.len(), 3);
    // sorted by seq
    assert_eq!(merged.strings[0].seq, 10);
    assert_eq!(merged.strings[1].seq, 20);
    assert_eq!(merged.strings[2].seq, 30);
}

#[test]
fn test_merge_pair_splits() {
    let mut c1: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();
    c1.insert(10, PairSplitDeps::default());
    let mut c2: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();
    c2.insert(20, PairSplitDeps::default());

    let fixups = vec![(30u32, PairSplitDeps::default())];

    let merged = merge_pair_splits(vec![c1, c2], fixups);
    assert_eq!(merged.len(), 3);
    assert!(merged.contains_key(&10));
    assert!(merged.contains_key(&20));
    assert!(merged.contains_key(&30));
}

#[test]
fn test_external_return_x0_definition_propagates_across_chunks() {
    let first_part = concat!(
        "[test.so] 0x1000!0x0 mov x0, #0x1\n",
        "[test.so] 0x1004!0x4 blr x1\n",
        "call func: external()\n",
        "ret: 0x2\n",
    );
    let trace = concat!(
        "[test.so] 0x1000!0x0 mov x0, #0x1\n",
        "[test.so] 0x1004!0x4 blr x1\n",
        "call func: external()\n",
        "ret: 0x2\n",
        "[test.so] 0x1008!0x8 str x0, [sp]; x0=0x2 sp=0x2000 mem_w=0x2000\n",
    );
    let split = first_part.len();
    let data = trace.as_bytes();

    let chunk0 = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: 0,
            end_byte: split,
            start_line: 0,
            format: TraceFormat::Gumtrace,
            data_only: true,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );
    let chunk1 = scan_chunk(
        data,
        ScanChunkConfig {
            start_byte: split,
            end_byte: data.len(),
            start_line: 4,
            format: TraceFormat::Gumtrace,
            data_only: true,
            no_prune: false,
            skip_strings: true,
            progress_cb: None,
        },
    );
    let merged = merge_all_chunks(
        vec![chunk0, chunk1],
        TraceFormat::Gumtrace,
        true,
        true,
        None,
        None,
    )
    .unwrap();
    let deps = &merged.scan_state.deps;

    assert!(deps.patch_row(4).contains(&3));
    assert!(!deps.row(4).contains(&0));
}
