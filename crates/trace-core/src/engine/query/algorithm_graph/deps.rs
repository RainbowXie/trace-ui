use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::api_types::{GraphActivationSelectorDto, GraphDependencyEdgeDto};
use crate::error::Result;
use crate::query::activation::ActivationTree;
use crate::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};

use super::boundaries::{map_endpoint, BoundaryIndex};

pub(super) fn backward_closure(
    deps: &crate::flat::deps::DepsView<'_>,
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    seeds: &[u32],
) -> BTreeSet<u32> {
    let mut visited = BTreeSet::new();
    let mut queued = seeds.iter().copied().collect::<BTreeSet<_>>();
    let mut queue = seeds.iter().copied().collect::<VecDeque<_>>();
    while let Some(consumer_raw) = queue.pop_front() {
        if !visited.insert(consumer_raw) {
            continue;
        }
        for producer_raw in dependency_sources(deps, pair_split, consumer_raw) {
            for next in producer_seeds(pair_split, producer_raw) {
                if queued.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }
    visited.into_iter().map(|raw| raw & LINE_MASK).collect()
}

pub(super) fn dependency_edges(
    state: &crate::session::SessionState,
    tree: &ActivationTree,
    selectors: &BTreeMap<u32, GraphActivationSelectorDto>,
    boundary_index: &BoundaryIndex,
    deps: &crate::flat::deps::DepsView<'_>,
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    closure: &BTreeSet<u32>,
) -> Result<Vec<GraphDependencyEdgeDto>> {
    let mut edges = Vec::new();
    for consumer_seq in closure {
        for consumer_raw in target_dependency_seeds(pair_split, *consumer_seq) {
            let mut producers = dependency_sources(deps, pair_split, consumer_raw);
            producers.sort_unstable();
            producers.dedup();
            for producer_raw in producers.iter().copied() {
                let producer_seq = producer_raw & LINE_MASK;
                if !closure.contains(&producer_seq) {
                    continue;
                }
                let kind = if (producer_raw & CONTROL_DEP_BIT) != 0 {
                    "control"
                } else {
                    "data"
                };
                edges.push(GraphDependencyEdgeDto {
                    producer: map_endpoint(state, tree, selectors, boundary_index, producer_seq)?,
                    consumer: map_endpoint(state, tree, selectors, boundary_index, *consumer_seq)?,
                    kind: kind.to_owned(),
                    pair_part: dependency_pair_part(
                        pair_split,
                        consumer_raw,
                        producer_raw,
                        producers.iter().copied(),
                    )
                    .map(str::to_owned),
                });
            }
        }
    }
    Ok(edges)
}

pub(super) fn target_memory_producers(
    state: &crate::session::SessionState,
    target_seq: u32,
    target_address: u64,
    target_size: u32,
    target_rw: Option<&str>,
) -> Vec<u32> {
    if target_rw != Some("read") {
        return Vec::new();
    }
    let Some(index) = state.line_index_view() else {
        return Vec::new();
    };
    let mut producers = Vec::new();
    for seq in (0..target_seq).rev() {
        let Some(raw) = index.get_line(&state.mmap, seq) else {
            continue;
        };
        let Ok(line) = std::str::from_utf8(raw) else {
            continue;
        };
        if !line.contains("mem[WRITE]") && !line.contains("mem_w=") {
            continue;
        }
        let Some(address) = parse_memory_address(line) else {
            continue;
        };
        let Some(width) = parse_memory_width(line) else {
            continue;
        };
        let target_end = target_address.saturating_add(target_size as u64);
        let write_end = address.saturating_add(width);
        if address < target_end && target_address < write_end {
            producers.push(seq);
            if target_size > 8 {
                producers.push(seq | PAIR_HALF2_BIT);
            }
            break;
        }
    }
    producers
}

pub(super) fn parse_memory_address(line: &str) -> Option<u64> {
    trace_parser::strict_memory::memory_marker(line).map(|(_, address)| address)
}

pub(super) fn parse_memory_width(line: &str) -> Option<u64> {
    let mem = trace_parser::strict_memory::memory_op(line)?;
    Some(u64::from(mem.elem_width) * u64::from(mem.value_count))
}

pub(super) fn target_dependency_seeds(
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    target_seq: u32,
) -> Vec<u32> {
    if pair_split.contains_key(&target_seq) {
        vec![target_seq, target_seq | PAIR_HALF2_BIT]
    } else {
        vec![target_seq]
    }
}

pub(super) fn dependency_sources(
    deps: &crate::flat::deps::DepsView<'_>,
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    consumer_raw: u32,
) -> Vec<u32> {
    let consumer_seq = consumer_raw & LINE_MASK;
    if let Some(split) = pair_split.get(&consumer_seq) {
        let mut sources = split.shared.to_vec();
        if (consumer_raw & PAIR_SHARED_BIT) == 0 {
            sources.extend_from_slice(if (consumer_raw & PAIR_HALF2_BIT) != 0 {
                split.half2_deps
            } else {
                split.half1_deps
            });
        }
        return sources;
    }
    deps.row(consumer_seq as usize)
        .iter()
        .chain(deps.patch_row(consumer_seq as usize))
        .copied()
        .collect()
}

fn producer_seeds(
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    producer_raw: u32,
) -> Vec<u32> {
    let seq = producer_raw & LINE_MASK;
    if !pair_split.contains_key(&seq) {
        return vec![producer_raw];
    }
    if (producer_raw & (PAIR_HALF2_BIT | PAIR_SHARED_BIT)) != 0 {
        return vec![producer_raw];
    }
    vec![producer_raw, seq | PAIR_HALF2_BIT]
}

pub(super) fn dependency_pair_part(
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    consumer_raw: u32,
    producer_raw: u32,
    mut all_producers: impl Iterator<Item = u32>,
) -> Option<&'static str> {
    let consumer_seq = consumer_raw & LINE_MASK;
    if pair_split.contains_key(&consumer_seq) {
        let split = pair_split.get(&consumer_seq).expect("checked pair split");
        let producer_seq = producer_raw & LINE_MASK;
        if split
            .shared
            .iter()
            .any(|dep| (*dep & LINE_MASK) == producer_seq)
        {
            return Some("shared");
        }
        let half1 = split
            .half1_deps
            .iter()
            .any(|dep| (*dep & LINE_MASK) == producer_seq);
        let half2 = split
            .half2_deps
            .iter()
            .any(|dep| (*dep & LINE_MASK) == producer_seq);
        return match (half1, half2) {
            (true, false) => Some("half1"),
            (false, true) => Some("half2"),
            (true, true) if (consumer_raw & PAIR_HALF2_BIT) != 0 => Some("half2"),
            (true, true) => Some("half1"),
            (false, false) => None,
        };
    }
    let producer_seq = producer_raw & LINE_MASK;
    if (producer_raw & PAIR_SHARED_BIT) != 0 {
        Some("shared")
    } else if (producer_raw & PAIR_HALF2_BIT) != 0 {
        Some("half2")
    } else if pair_split.contains_key(&producer_seq)
        || all_producers.any(|raw| (raw & LINE_MASK) == producer_seq && (raw & PAIR_HALF2_BIT) != 0)
    {
        Some("half1")
    } else {
        None
    }
}
