//! selected occurrence 的机械动态依赖闭包。
//!
//! 查询只返回 raw trace occurrence、请求中已确认的 Activation selector 和非函数
//! 机械边界。Analysis Case 的 SourceReference、节点 identity 与 Agent 分类由上层生成。

mod boundaries;
mod deps;

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::api_types::{
    AlgorithmGraphFactBundleDto, GraphActivationSelectorDto, GraphCallEdgeDto,
    GraphDependencyEdgeDto, GraphFactUnresolvedDto, GraphMechanicalEndpointDto,
};
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::scanner::LINE_MASK;

use boundaries::{collect_boundaries, map_endpoint};
use deps::{target_dependency_seeds, target_memory_producers};

impl crate::engine::TraceEngine {
    pub fn get_algorithm_graph_facts(
        &self,
        session_id: &str,
        target_seq: u32,
        target_address: u64,
        target_size: u32,
        target_rw: Option<&str>,
        activation_selectors: &[GraphActivationSelectorDto],
    ) -> Result<AlgorithmGraphFactBundleDto> {
        self.get_algorithm_graph_facts_for_modules(
            session_id,
            target_seq,
            target_address,
            target_size,
            target_rw,
            activation_selectors,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_algorithm_graph_facts_for_modules(
        &self,
        session_id: &str,
        target_seq: u32,
        target_address: u64,
        target_size: u32,
        target_rw: Option<&str>,
        activation_selectors: &[GraphActivationSelectorDto],
        target_modules: &[String],
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
        let selectors = validate_selectors(&state, tree, activation_selectors)?;
        let deps = state.deps_view().ok_or(TraceError::IndexNotReady)?;
        let pair_split = state.pair_split_view().ok_or(TraceError::IndexNotReady)?;

        let memory_producers =
            target_memory_producers(&state, target_seq, target_address, target_size, target_rw);
        let mut target_seeds = target_dependency_seeds(&pair_split, target_seq);
        target_seeds.extend(memory_producers.iter().copied());
        target_seeds.sort_unstable();
        target_seeds.dedup();

        let closure = deps::backward_closure(&deps, &pair_split, &target_seeds);
        let global_map =
            super::function_facts::global_map::StableGlobalMap::collect(&state, target_modules)?;
        let mut boundary_index =
            collect_boundaries(&state, tree, &selectors, &closure, &global_map)?;
        attach_unowned_boundaries(&state, tree, &selectors, &closure, &mut boundary_index)?;
        let mut dependency_edges = deps::dependency_edges(
            &state,
            tree,
            &selectors,
            &boundary_index,
            &deps,
            &pair_split,
            &closure,
        )?;
        dependency_edges.extend(
            memory_producers
                .iter()
                .copied()
                .map(|producer_raw| {
                    let producer_seq = producer_raw & LINE_MASK;
                    Ok(GraphDependencyEdgeDto {
                        producer: map_endpoint(
                            &state,
                            tree,
                            &selectors,
                            &boundary_index,
                            producer_seq,
                        )?,
                        consumer: map_endpoint(
                            &state,
                            tree,
                            &selectors,
                            &boundary_index,
                            target_seq,
                        )?,
                        kind: "data".to_owned(),
                        pair_part: deps::dependency_pair_part(
                            &pair_split,
                            target_seq,
                            producer_raw,
                            memory_producers.iter().copied(),
                        )
                        .map(str::to_owned),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        );
        for seq in boundary_index.by_seq.iter().filter_map(|(seq, endpoint)| {
            matches!(endpoint, GraphMechanicalEndpointDto::Unresolved { .. }).then_some(*seq)
        }) {
            if closure.contains(&seq)
                && !dependency_edges.iter().any(|edge| {
                    edge.producer.seq() == Some(seq) || edge.consumer.seq() == Some(seq)
                })
            {
                dependency_edges.push(GraphDependencyEdgeDto {
                    producer: map_endpoint(&state, tree, &selectors, &boundary_index, seq)?,
                    consumer: map_endpoint(&state, tree, &selectors, &boundary_index, target_seq)?,
                    kind: "data".to_owned(),
                    pair_part: None,
                });
            }
        }
        dependency_edges.extend(boundary_index.immediate_edges.iter().cloned());
        dependency_edges.sort_by(dependency_order);
        dependency_edges.dedup();

        let target = map_endpoint(&state, tree, &selectors, &boundary_index, target_seq)?;
        if !matches!(target, GraphMechanicalEndpointDto::Instruction { .. }) {
            return Err(TraceError::InvalidArgument(
                "selected Target must resolve to an instruction endpoint".to_owned(),
            ));
        }

        let activation_ids = related_activation_ids(tree, &selectors, &closure);
        let mut activations = activation_ids
            .iter()
            .filter_map(|id| selectors.get(id).cloned())
            .collect::<Vec<_>>();
        activations.sort();

        let mut call_edges = Vec::new();
        for id in &activation_ids {
            let activation = &tree.activations[*id as usize];
            let Some(parent_id) = activation.parent_id.filter(|parent| *parent != 0) else {
                continue;
            };
            if !activation_ids.contains(&parent_id) {
                continue;
            }
            let caller = selectors.get(&parent_id).ok_or_else(|| {
                TraceError::InvalidArgument("related caller has no requested selector".to_owned())
            })?;
            let callee = selectors.get(id).ok_or_else(|| {
                TraceError::InvalidArgument("related callee has no requested selector".to_owned())
            })?;
            call_edges.push(GraphCallEdgeDto {
                caller: caller.clone(),
                callee: callee.clone(),
                call_seq: activation.call_seq,
            });
        }
        call_edges.sort_by_key(|edge| edge.call_seq);

        let unresolved = boundary_index
            .unresolved
            .iter()
            .map(|boundary| GraphFactUnresolvedDto {
                kind: boundary.kind.clone(),
                seqs: vec![boundary.seq],
                detail: boundary.detail.clone(),
            })
            .collect::<Vec<_>>();
        let external_call_events = boundary_index.external_events.clone();

        let mut bundle = AlgorithmGraphFactBundleDto {
            target_seq,
            target,
            activations,
            call_edges,
            external_call_events,
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

fn validate_selectors(
    state: &crate::session::SessionState,
    tree: &ActivationTree,
    selectors: &[GraphActivationSelectorDto],
) -> Result<BTreeMap<u32, GraphActivationSelectorDto>> {
    let mut seen = BTreeSet::new();
    let mut by_id = BTreeMap::new();
    for selector in selectors {
        if !seen.insert(selector.clone()) {
            return Err(TraceError::InvalidArgument(
                "duplicate Activation selector".to_owned(),
            ));
        }
        validate_trace_reference(&selector.trace)?;
        let matches = tree
            .activations
            .iter()
            .filter(|activation| activation_matches(state, activation, selector))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(TraceError::InvalidArgument(format!(
                "Activation selector must match exactly once: {} call_seq={} entry_seq={}",
                selector.function, selector.call_seq, selector.entry_seq
            )));
        }
        if by_id.insert(matches[0].id, selector.clone()).is_some() {
            return Err(TraceError::InvalidArgument(
                "multiple selectors resolve to one Activation".to_owned(),
            ));
        }
    }
    Ok(by_id)
}

fn validate_trace_reference(reference: &crate::api_types::GraphTraceReferenceDto) -> Result<()> {
    let Some(index) = reference.pointer.strip_prefix("/trace_files/") else {
        return Err(TraceError::InvalidArgument(
            "Activation selector trace pointer is invalid".to_owned(),
        ));
    };
    if reference.artifact != "request.json" || index.parse::<usize>().is_err() {
        return Err(TraceError::InvalidArgument(
            "Activation selector trace must point to request.json.trace_files[]".to_owned(),
        ));
    }
    Ok(())
}

fn activation_matches(
    state: &crate::session::SessionState,
    activation: &ConfirmedActivation,
    selector: &GraphActivationSelectorDto,
) -> bool {
    activation.id != 0
        && activation.unresolved_reason.is_none()
        && activation.call_seq == selector.call_seq
        && activation.entry_seq == selector.entry_seq
        && activation.exit_seq == selector.exit_seq
        && activation.resume_seq == selector.resume_seq
        && state
            .line_index_view()
            .and_then(|index| index.get_line(&state.mmap, activation.entry_seq))
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .and_then(super::activation::stable_site)
            .as_deref()
            == Some(selector.function.as_str())
}

fn related_activation_ids(
    tree: &ActivationTree,
    selectors: &BTreeMap<u32, GraphActivationSelectorDto>,
    closure: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();
    for seq in closure {
        let Some(owner) = tree.activation_for_seq(*seq) else {
            continue;
        };
        let mut id = owner.id;
        while id != 0 {
            if selectors.contains_key(&id) {
                ids.insert(id);
            }
            id = tree.activations[id as usize].parent_id.unwrap_or(0);
        }
    }
    ids
}

fn attach_unowned_boundaries(
    state: &crate::session::SessionState,
    tree: &ActivationTree,
    selectors: &BTreeMap<u32, GraphActivationSelectorDto>,
    closure: &BTreeSet<u32>,
    boundaries: &mut boundaries::BoundaryIndex,
) -> Result<()> {
    for seq in closure {
        if boundaries.by_seq.contains_key(seq) || tree.activation_for_seq(*seq).is_some() {
            continue;
        }
        let mut owners = selectors
            .values()
            .filter(|selector| selector.entry_seq <= *seq && *seq <= selector.exit_seq);
        let owner = owners.next().cloned().ok_or_else(|| {
            TraceError::InvalidArgument(format!(
                "Graph occurrence seq {seq} has no requested Activation owner"
            ))
        })?;
        if owners.next().is_some() {
            return Err(TraceError::InvalidArgument(format!(
                "Graph occurrence seq {seq} matches more than one requested Activation owner"
            )));
        }
        let line = state
            .line_index_view()
            .and_then(|lines| lines.get_line(&state.mmap, *seq))
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .unwrap_or("");
        boundaries.push_unresolved(
            &owner,
            if trace_parser::gumtrace::parse_special_line(line).is_some() {
                "non_function_boundary_unresolved"
            } else {
                "instruction_owner_unresolved"
            },
            *seq,
            "target dependency occurrence has no uniquely requested Activation owner",
        )?;
    }
    Ok(())
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
    if deps::parse_memory_address(line) != Some(target_address) {
        return Err(TraceError::InvalidArgument(
            "selected Target address does not match the trace occurrence".to_owned(),
        ));
    }
    let width = deps::parse_memory_width(line).ok_or_else(|| {
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

fn dependency_order(
    left: &GraphDependencyEdgeDto,
    right: &GraphDependencyEdgeDto,
) -> std::cmp::Ordering {
    left.consumer
        .cmp(&right.consumer)
        .then_with(|| left.producer.cmp(&right.producer))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.pair_part.cmp(&right.pair_part))
}
