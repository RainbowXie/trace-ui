use std::collections::{BTreeMap, BTreeSet};

use crate::api_types::{
    GraphActivationSelectorDto, GraphExternalCallEventDto, GraphMechanicalEndpointDto,
};
use crate::error::{Result, TraceError};
use crate::query::activation::ActivationTree;

use super::super::activation::stable_site;

#[derive(Debug, Clone)]
pub(super) struct UnresolvedBoundary {
    pub(super) kind: String,
    pub(super) seq: u32,
    pub(super) detail: String,
}

#[derive(Default)]
pub(super) struct BoundaryIndex {
    pub(super) by_seq: BTreeMap<u32, GraphMechanicalEndpointDto>,
    pub(super) external_events: Vec<GraphExternalCallEventDto>,
    pub(super) unresolved: Vec<UnresolvedBoundary>,
}

pub(super) fn collect_boundaries(
    state: &crate::session::SessionState,
    tree: &ActivationTree,
    selectors: &BTreeMap<u32, GraphActivationSelectorDto>,
    closure: &BTreeSet<u32>,
    global_map: &super::super::function_facts::global_map::StableGlobalMap,
) -> Result<BoundaryIndex> {
    let mut index = BoundaryIndex::default();
    for (activation_id, selector) in selectors {
        let activation = &tree.activations[*activation_id as usize];
        let owned =
            super::super::function_facts::blocks::owned_instructions(state, tree, activation)?;
        let events = super::super::function_facts::events::collect_external_call_events(
            state, tree, activation, &owned,
        )?;
        for (event_index, event) in events.iter().enumerate() {
            let Some(resume_seq) = event.resume.as_ref().map(|resume| resume.seq) else {
                continue;
            };
            let special_seqs = event_special_seqs(state, event.callsite.seq, resume_seq);
            let relevant = closure.contains(&event.callsite.seq)
                || closure.contains(&resume_seq)
                || special_seqs.iter().any(|seq| closure.contains(seq));
            if !relevant {
                continue;
            }
            if !event.unresolved.is_empty() {
                for seq in special_seqs.iter().copied().chain([event.callsite.seq]) {
                    if closure.contains(&seq) {
                        index.unresolved.push(UnresolvedBoundary {
                            kind: "external_call_event_unresolved".to_owned(),
                            seq,
                            detail: format!(
                                "External Call Event at seq {} has incomplete target or effect",
                                event.callsite.seq
                            ),
                        });
                    }
                }
                continue;
            }
            let fact = GraphExternalCallEventDto {
                owner: selector.clone(),
                event_index: u32::try_from(event_index).map_err(|_| {
                    TraceError::InvalidArgument("External Call Event index exceeds u32".to_owned())
                })?,
                call_seq: event.callsite.seq,
                resume_seq,
            };
            let endpoint = GraphMechanicalEndpointDto::ExternalCallEvent {
                owner: selector.clone(),
                event_index: fact.event_index,
                call_seq: fact.call_seq,
                resume_seq: fact.resume_seq,
            };
            for seq in special_seqs {
                index.by_seq.insert(seq, endpoint.clone());
            }
            index.external_events.push(fact);
        }

        let return_producer = owned
            .iter()
            .rfind(|insn| line_arrow_register_value(&insn.line, "x0").is_some())
            .map(|insn| insn.seq);
        let (memory_reads, memory_writes, memory_unresolved) =
            super::super::function_facts::dataflow::collect_memory_facts(
                state,
                &owned,
                &Default::default(),
                return_producer,
            );
        let literal_reads = memory_reads.clone();
        let (memory_reads, global_reads, _, global_writes) =
            super::super::function_facts::globals::partition_memory_facts(
                &owned,
                global_map,
                memory_reads,
                memory_writes,
            );
        for (read_index, read) in memory_reads.iter().enumerate() {
            for seq in &read.read_seqs {
                if owned
                    .iter()
                    .find(|insn| insn.seq == *seq)
                    .is_some_and(|insn| literal_load_address(insn) == parse_address(&read.address))
                {
                    continue;
                }
                let endpoint = GraphMechanicalEndpointDto::DynamicSource {
                    owner: selector.clone(),
                    read_index: u32::try_from(read_index).map_err(|_| {
                        TraceError::InvalidArgument("memory read index exceeds u32".to_owned())
                    })?,
                    seq: *seq,
                    address: read.address.clone(),
                    size: read.size,
                    bytes: read.bytes.clone(),
                };
                if closure.contains(seq) {
                    index.by_seq.insert(*seq, endpoint);
                }
            }
        }
        for (access_index, read) in global_reads.iter().enumerate() {
            for seq in &read.read_seqs {
                if closure.contains(seq) {
                    index.by_seq.insert(
                        *seq,
                        GraphMechanicalEndpointDto::GlobalReference {
                            owner: selector.clone(),
                            access_index: u32::try_from(access_index).map_err(|_| {
                                TraceError::InvalidArgument(
                                    "global read index exceeds u32".to_owned(),
                                )
                            })?,
                            seq: *seq,
                            access: "read".to_owned(),
                            global: read.global.clone(),
                            size: read.size,
                            bytes: read.bytes.clone(),
                        },
                    );
                }
            }
        }
        let write_base = global_reads.len();
        for (write_index, write) in global_writes.iter().enumerate() {
            for seq in &write.write_seqs {
                if closure.contains(seq) {
                    index.by_seq.insert(
                        *seq,
                        GraphMechanicalEndpointDto::GlobalReference {
                            owner: selector.clone(),
                            access_index: u32::try_from(write_base + write_index).map_err(
                                |_| {
                                    TraceError::InvalidArgument(
                                        "global write index exceeds u32".to_owned(),
                                    )
                                },
                            )?,
                            seq: *seq,
                            access: "write".to_owned(),
                            global: write.global.clone(),
                            size: write.size,
                            bytes: write.bytes.clone(),
                        },
                    );
                }
            }
        }
        let mut literal_sources = BTreeMap::<u32, Vec<usize>>::new();
        for insn in &owned {
            if closure.contains(&insn.seq) && literal_load_address(insn).is_some() {
                literal_sources.entry(insn.seq).or_default();
            }
        }
        for (source_index, read) in literal_reads.iter().enumerate() {
            for seq in &read.read_seqs {
                if owned
                    .iter()
                    .find(|insn| insn.seq == *seq)
                    .is_some_and(|insn| literal_load_address(insn) == parse_address(&read.address))
                {
                    literal_sources.entry(*seq).or_default().push(source_index);
                }
            }
        }
        for (seq, sources) in &literal_sources {
            if sources.len() != 1 {
                index.unresolved.push(UnresolvedBoundary {
                    kind: "literal_source_incomplete".to_owned(),
                    seq: *seq,
                    detail: "literal load does not resolve to one complete FunctionCallRecord memory_read".to_owned(),
                });
                continue;
            }
            let source_index = sources[0];
            let read = &literal_reads[source_index];
            let Some(insn) = owned.iter().find(|insn| insn.seq == *seq) else {
                continue;
            };
            let Some(width) = insn
                .mnemonic
                .as_deref()
                .zip(insn.first_operand.as_deref())
                .and_then(|(mnemonic, operand)| {
                    super::super::function_facts::lines::access_width(mnemonic, operand)
                })
            else {
                continue;
            };
            if read.bytes.is_none() || read.size != width {
                index.unresolved.push(UnresolvedBoundary {
                    kind: "literal_source_incomplete".to_owned(),
                    seq: *seq,
                    detail: "literal load source does not cover the complete instruction width"
                        .to_owned(),
                });
                continue;
            }
            for seq in &read.read_seqs {
                let Some(insn) = owned.iter().find(|insn| insn.seq == *seq) else {
                    continue;
                };
                if closure.contains(seq)
                    && literal_load_address(insn) == parse_address(&read.address)
                {
                    index.by_seq.insert(
                        *seq,
                        GraphMechanicalEndpointDto::Constant {
                            owner: selector.clone(),
                            source_index: u32::try_from(source_index).map_err(|_| {
                                TraceError::InvalidArgument(
                                    "constant source index exceeds u32".to_owned(),
                                )
                            })?,
                            seq: *seq,
                            address: read.address.clone(),
                            size: read.size,
                            bytes: read.bytes.clone().expect("checked constant bytes"),
                        },
                    );
                }
            }
        }
        let initial_loads = state.init_mem_loads_view();
        for insn in &owned {
            let gumtrace_read = insn.line.contains("mem[READ]");
            let reads_memory = gumtrace_read || insn.line.contains("mem_r=");
            let has_complete_record = memory_reads
                .iter()
                .any(|read| read.read_seqs.contains(&insn.seq));
            if closure.contains(&insn.seq)
                && reads_memory
                && literal_load_address(insn).is_none()
                && (has_complete_record
                    || gumtrace_read
                    || initial_loads
                        .as_ref()
                        .is_none_or(|loads| loads.get(insn.seq as usize)))
            {
                if let Some(read_index) = memory_reads
                    .iter()
                    .position(|read| read.read_seqs.contains(&insn.seq))
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| {
                        TraceError::InvalidArgument(
                            "dynamic source memory_read index exceeds u32".to_owned(),
                        )
                    })?
                {
                    index.by_seq.insert(
                        insn.seq,
                        GraphMechanicalEndpointDto::DynamicSource {
                            owner: selector.clone(),
                            read_index,
                            seq: insn.seq,
                            address: memory_reads[read_index as usize].address.clone(),
                            size: memory_reads[read_index as usize].size,
                            bytes: memory_reads[read_index as usize].bytes.clone(),
                        },
                    );
                } else {
                    index.unresolved.push(UnresolvedBoundary {
                        kind: "dynamic_source_record_unresolved".to_owned(),
                        seq: insn.seq,
                        detail:
                            "initial memory source has no complete FunctionCallRecord memory_read"
                                .to_owned(),
                    });
                }
            }
        }
        for unresolved in memory_unresolved {
            for seq in unresolved.seqs {
                if closure.contains(&seq) {
                    index.unresolved.push(UnresolvedBoundary {
                        kind: unresolved.kind.clone(),
                        seq,
                        detail: unresolved.detail.clone(),
                    });
                }
            }
        }
    }
    index.external_events.sort();
    index.external_events.dedup();
    index
        .unresolved
        .sort_by(|left, right| left.seq.cmp(&right.seq).then(left.kind.cmp(&right.kind)));
    index
        .unresolved
        .dedup_by(|left, right| left.seq == right.seq && left.kind == right.kind);
    Ok(index)
}

pub(super) fn map_endpoint(
    state: &crate::session::SessionState,
    tree: &ActivationTree,
    selectors: &BTreeMap<u32, GraphActivationSelectorDto>,
    boundary_index: &BoundaryIndex,
    seq: u32,
) -> Result<GraphMechanicalEndpointDto> {
    if let Some(endpoint) = boundary_index.by_seq.get(&seq) {
        return Ok(endpoint.clone());
    }
    let owner = tree.activation_for_seq(seq).ok_or_else(|| {
        TraceError::InvalidArgument(format!(
            "Graph occurrence seq {seq} has no Confirmed Activation owner"
        ))
    })?;
    let selector = selectors.get(&owner.id).ok_or_else(|| {
        TraceError::InvalidArgument(format!(
            "Graph occurrence seq {seq} belongs to an Activation without a requested selector"
        ))
    })?;
    if state
        .line_index_view()
        .and_then(|lines| lines.get_line(&state.mmap, seq))
        .and_then(|raw| std::str::from_utf8(raw).ok())
        .and_then(stable_site)
        .is_none()
    {
        return Err(TraceError::InvalidArgument(format!(
            "Graph occurrence seq {seq} is not an instruction or recognized boundary"
        )));
    }
    Ok(GraphMechanicalEndpointDto::Instruction {
        seq,
        owner: selector.clone(),
    })
}

fn literal_load_address(insn: &super::super::function_facts::blocks::OwnedInsn) -> Option<u64> {
    let address = insn
        .mnemonic
        .as_deref()
        .zip(insn.first_operand.as_deref())
        .and_then(|(mnemonic, operand)| {
            super::super::function_facts::dataflow::literal_load_address(mnemonic, operand)
        })?;
    (super::super::function_facts::lines::line_mem_annotation(&insn.line, "mem_r") == Some(address))
        .then_some(address)
}

fn parse_address(address: &str) -> Option<u64> {
    crate::parse_hex_addr(address).ok()
}

fn event_special_seqs(
    state: &crate::session::SessionState,
    call_seq: u32,
    resume_seq: u32,
) -> Vec<u32> {
    let Some(lines) = state.line_index_view() else {
        return Vec::new();
    };
    ((call_seq + 1)..resume_seq)
        .filter(|seq| {
            lines
                .get_line(&state.mmap, *seq)
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .is_some_and(|line| {
                    matches!(
                        trace_parser::gumtrace::parse_special_line(line),
                        Some(trace_parser::gumtrace::SpecialLine::Ret { .. })
                    )
                })
        })
        .collect()
}

fn line_arrow_register_value(line: &str, register: &str) -> Option<u64> {
    let arrow = line.find(" -> ").or_else(|| line.find(" => "))?;
    let suffix = &line[arrow + 4..];
    let marker = format!("{register}=0x");
    let start = suffix.find(&marker)? + marker.len();
    let digits = suffix[start..]
        .bytes()
        .take_while(u8::is_ascii_hexdigit)
        .count();
    u64::from_str_radix(&suffix[start..start + digits], 16).ok()
}
