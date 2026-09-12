//! selected occurrence 的机械动态依赖闭包。
//!
//! 此查询只返回 raw trace occurrence 与 Confirmed Activation 边界；Analysis Case
//! 的 SourceReference、节点 identity 和 Agent 分类由上层状态机生成，避免 trace-ui
//! 复制持久化领域规则。

use std::collections::{BTreeSet, VecDeque};

use sha2::{Digest, Sha256};

use crate::api_types::{
    AlgorithmGraphFactBundleDto, GraphActivationDto, GraphCallEdgeDto, GraphDependencyEdgeDto,
    GraphFactUnresolvedDto, GraphInstructionEndpointDto,
};
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};

impl crate::engine::TraceEngine {
    pub fn get_algorithm_graph_facts(
        &self,
        session_id: &str,
        target_seq: u32,
        target_address: u64,
        target_size: u32,
        target_rw: Option<&str>,
    ) -> Result<AlgorithmGraphFactBundleDto> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        if target_seq >= state.total_lines {
            return Err(TraceError::InvalidArgument(format!(
                "target_seq {target_seq} 超出 trace 范围"
            )));
        }
        validate_target_occurrence(&state, target_seq, target_address, target_size, target_rw)?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let deps = state.deps_view().ok_or(TraceError::IndexNotReady)?;
        let pair_split = state.pair_split_view().ok_or(TraceError::IndexNotReady)?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        let memory_producers =
            target_memory_producers(&state, target_seq, target_address, target_size, target_rw);
        let mut target_seeds = target_dependency_seeds(&pair_split, target_seq);
        target_seeds.extend(memory_producers.iter().copied());
        target_seeds.sort_unstable();
        target_seeds.dedup();
        let mut visited = BTreeSet::new();
        let mut occurrence_seqs = BTreeSet::new();
        let mut queued = target_seeds.iter().copied().collect::<BTreeSet<_>>();
        let mut queue = target_seeds.into_iter().collect::<VecDeque<_>>();
        let mut dependency_edges = memory_producers
            .iter()
            .copied()
            .map(|producer_raw| {
                let producer_seq = producer_raw & LINE_MASK;
                Ok(GraphDependencyEdgeDto {
                    producer: endpoint(tree, producer_seq, &line_index, &state.mmap)?,
                    consumer: endpoint(tree, target_seq, &line_index, &state.mmap)?,
                    kind: "data".to_owned(),
                    pair_part: dependency_pair_part(
                        &pair_split,
                        target_seq,
                        producer_raw,
                        memory_producers.iter().copied(),
                    )
                    .map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        while let Some(consumer_raw) = queue.pop_front() {
            let consumer_seq = consumer_raw & LINE_MASK;
            if !visited.insert(consumer_raw) {
                continue;
            }
            occurrence_seqs.insert(consumer_seq);
            let mut producers = dependency_sources(&deps, &pair_split, consumer_raw);
            producers.sort_unstable();
            producers.dedup();
            for producer_raw in producers.iter().copied() {
                let producer_seq = producer_raw & LINE_MASK;
                let kind = if (producer_raw & CONTROL_DEP_BIT) != 0 {
                    "control"
                } else {
                    "data"
                };
                let pair_part = dependency_pair_part(
                    &pair_split,
                    consumer_raw,
                    producer_raw,
                    producers.iter().copied(),
                );
                dependency_edges.push(GraphDependencyEdgeDto {
                    producer: endpoint(tree, producer_seq, &line_index, &state.mmap)?,
                    consumer: endpoint(tree, consumer_seq, &line_index, &state.mmap)?,
                    kind: kind.to_owned(),
                    pair_part: pair_part.map(str::to_owned),
                });
                occurrence_seqs.insert(producer_seq);
                for next in producer_seeds(&pair_split, producer_raw) {
                    if queued.insert(next) {
                        queue.push_back(next);
                    }
                }
            }
        }

        let mut activation_ids = BTreeSet::new();
        for seq in &occurrence_seqs {
            if let Some(activation) = tree.activation_for_seq(*seq) {
                collect_ancestor_ids(tree, activation.id, &mut activation_ids);
            }
        }
        let mut activations = activation_ids
            .iter()
            .filter_map(|id| tree.activations.get(*id as usize))
            .map(|activation| graph_activation(activation, &line_index, &state.mmap))
            .collect::<Result<Vec<_>>>()?;
        activations.sort();

        let activation_id_set = activation_ids;
        let mut call_edges = Vec::new();
        for activation in tree.activations.iter().filter(|item| item.id != 0) {
            let Some(parent_id) = activation.parent_id else {
                continue;
            };
            if parent_id == 0
                || !activation_id_set.contains(&parent_id)
                || !activation_id_set.contains(&activation.id)
            {
                continue;
            }
            let parent = &tree.activations[parent_id as usize];
            call_edges.push(GraphCallEdgeDto {
                caller: graph_activation(parent, &line_index, &state.mmap)?,
                callee: graph_activation(activation, &line_index, &state.mmap)?,
                call_seq: activation.call_seq,
            });
        }
        call_edges.sort_by_key(|edge| edge.call_seq);
        dependency_edges.sort_by(|left, right| {
            left.consumer
                .cmp(&right.consumer)
                .then_with(|| left.producer.cmp(&right.producer))
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.pair_part.cmp(&right.pair_part))
        });

        let unresolved = occurrence_seqs
            .iter()
            .filter(|seq| tree.activation_for_seq(**seq).is_none())
            .map(|seq| GraphFactUnresolvedDto {
                kind: "instruction_owner_unresolved".to_owned(),
                seqs: vec![*seq],
                detail: "instruction occurrence is outside every Confirmed Activation".to_owned(),
            })
            .collect::<Vec<_>>();

        let mut bundle = AlgorithmGraphFactBundleDto {
            target_seq,
            activations,
            call_edges,
            dependency_edges,
            unresolved,
            content_identity: String::new(),
        };
        let bytes =
            serde_json::to_vec(&bundle).map_err(|error| TraceError::Internal(error.to_string()))?;
        bundle.content_identity = format!("{:x}", Sha256::digest(bytes));
        Ok(bundle)
    }
}

fn validate_target_occurrence(
    state: &crate::session::SessionState,
    target_seq: u32,
    target_address: u64,
    target_size: u32,
    target_rw: Option<&str>,
) -> Result<()> {
    if target_size == 0 {
        return Err(TraceError::InvalidArgument(
            "target_size must be positive".to_owned(),
        ));
    }
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let raw = index.get_line(&state.mmap, target_seq).ok_or_else(|| {
        TraceError::InvalidArgument("selected Target sequence is not an instruction".to_owned())
    })?;
    let line = std::str::from_utf8(raw)
        .map_err(|_| TraceError::InvalidArgument("selected Target line is not UTF-8".to_owned()))?;
    if parse_memory_address(line) != Some(target_address) {
        return Err(TraceError::InvalidArgument(
            "selected Target address does not match the trace occurrence".to_owned(),
        ));
    }
    let width = parse_memory_width(line).ok_or_else(|| {
        TraceError::InvalidArgument("selected Target memory width is unresolved".to_owned())
    })?;
    if target_size as u64 > width {
        return Err(TraceError::InvalidArgument(
            "selected Target size exceeds the trace memory occurrence".to_owned(),
        ));
    }
    if let Some(expected) = target_rw {
        let actual = if line.contains("mem[WRITE]") || line.contains("mem_w=") {
            "write"
        } else if line.contains("mem[READ]") || line.contains("mem_r=") {
            "read"
        } else {
            return Err(TraceError::InvalidArgument(
                "selected Target read/write direction is unresolved".to_owned(),
            ));
        };
        if actual != expected {
            return Err(TraceError::InvalidArgument(
                "selected Target read/write direction does not match the trace occurrence"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

fn target_memory_producers(
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

fn parse_memory_address(line: &str) -> Option<u64> {
    let marker = "abs=0x";
    let start = line.find(marker)? + marker.len();
    let digits = line[start..]
        .bytes()
        .take_while(u8::is_ascii_hexdigit)
        .count();
    u64::from_str_radix(&line[start..start + digits], 16).ok()
}

fn parse_memory_width(line: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let instruction = lower.split('"').nth(1).or_else(|| {
        lower
            .split('!')
            .nth(1)
            .and_then(|part| part.split_whitespace().nth(1))
    })?;
    let mnemonic = instruction.split_whitespace().next()?;
    Some(match mnemonic {
        "strb" | "ldrb" => 1,
        "strh" | "ldrh" => 2,
        word if word.starts_with("stp") || word.starts_with("ldp") => 16,
        word if word.starts_with("str") || word.starts_with("ldr") => 8,
        _ => return None,
    })
}

fn target_dependency_seeds(
    pair_split: &crate::flat::pair_split::PairSplitView<'_>,
    target_seq: u32,
) -> Vec<u32> {
    if pair_split.contains_key(&target_seq) {
        vec![target_seq, target_seq | PAIR_HALF2_BIT]
    } else {
        vec![target_seq]
    }
}

fn dependency_sources(
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

fn dependency_pair_part(
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

fn collect_ancestor_ids(tree: &ActivationTree, mut id: u32, ids: &mut BTreeSet<u32>) {
    while id != 0 {
        if !ids.insert(id) {
            break;
        }
        id = tree.activations[id as usize].parent_id.unwrap_or(0);
    }
}

fn endpoint(
    tree: &ActivationTree,
    seq: u32,
    line_index: &crate::flat::line_index::LineIndexView<'_>,
    mmap: &[u8],
) -> Result<GraphInstructionEndpointDto> {
    Ok(GraphInstructionEndpointDto {
        seq,
        activation: tree
            .activation_for_seq(seq)
            .map(|activation| graph_activation(activation, line_index, mmap))
            .transpose()?,
    })
}

fn graph_activation(
    activation: &ConfirmedActivation,
    line_index: &crate::flat::line_index::LineIndexView<'_>,
    mmap: &[u8],
) -> Result<GraphActivationDto> {
    let function = line_index
        .get_line(mmap, activation.entry_seq)
        .and_then(|raw| std::str::from_utf8(raw).ok())
        .and_then(super::activation::stable_site)
        .ok_or_else(|| {
            TraceError::InvalidArgument(format!(
                "Activation entry seq {} 缺少稳定 module+offset",
                activation.entry_seq
            ))
        })?;
    Ok(GraphActivationDto {
        function,
        call_seq: activation.call_seq,
        entry_seq: activation.entry_seq,
        exit_seq: activation.exit_seq,
        resume_seq: activation.resume_seq,
    })
}
