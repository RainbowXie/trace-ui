use super::*;
use crate::error::TraceError;
use crate::query::activation::{ActivationBuilder, InsnFact};
use std::sync::atomic::Ordering;
use trace_parser::insn_class::{classify, InsnClass};
use types::CfgEdgeKind;

fn invalid(detail: &str) -> TraceError {
    TraceError::InvalidArgument(detail.into())
}
pub(crate) fn kind(mnemonic: &str) -> CfgEdgeKind {
    match classify(mnemonic, None) {
        InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => CfgEdgeKind::Conditional,
        InsnClass::Branch => CfgEdgeKind::Branch,
        InsnClass::BranchReg => CfgEdgeKind::Indirect,
        InsnClass::BranchLink | InsnClass::BranchLinkReg => CfgEdgeKind::CallResume,
        InsnClass::Return => CfgEdgeKind::Return,
        _ => CfgEdgeKind::Sequential,
    }
}
fn parsed<'a>(
    line: &'a str,
    seq: u32,
    site: fn(&str) -> Option<String>,
    pc: fn(&str) -> Option<u64>,
) -> Result<Option<(String, u64, &'a str)>> {
    if line.trim().is_empty() || trace_parser::gumtrace::parse_special_line(line).is_some() {
        return Ok(None);
    }
    let parts = trace_parser::strict_memory::instruction_parts(line);
    match (site(line), pc(line), parts) {
        (Some(s), Some(p), Some((m, _))) if p <= u64::MAX - 4 => Ok(Some((s, p, m))),
        _ => Err(TraceError::ParseError {
            line: Some(seq),
            detail: "CFG requires a valid instruction with stable site and runtime PC".into(),
        }),
    }
}
fn visit(
    data: &[u8],
    cancel: &AtomicBool,
    mut f: impl FnMut(u32, usize, &str) -> Result<()>,
) -> Result<u32> {
    let mut offset = 0;
    let mut count = 0;
    for raw in data.split_inclusive(|b| *b == b'\n') {
        if count >= MAX_TRACE_LINES {
            return Err(invalid("control-flow memory line capacity exceeded"));
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        let text = std::str::from_utf8(raw)
            .map_err(|_| invalid("non UTF-8 trace"))?
            .trim_end_matches(['\n', '\r']);
        f(count as u32, offset, text)?;
        offset += raw.len();
        count += 1;
    }
    Ok(count as u32)
}
pub(super) fn build(
    data: &[u8],
    cancel: &AtomicBool,
    site: fn(&str) -> Option<String>,
    pc: fn(&str) -> Option<u64>,
) -> Result<ControlFlowIndex> {
    if data.len() > MAX_TRACE_BYTES {
        return Err(invalid("control-flow memory byte capacity exceeded"));
    }
    let line_count = data.iter().filter(|b| **b == b'\n').count()
        + usize::from(!data.is_empty() && !data.ends_with(b"\n"));
    if line_count > MAX_TRACE_LINES {
        return Err(invalid("control-flow memory line capacity exceeded"));
    }
    let mut builder = ActivationBuilder::new();
    let mut samples = Vec::new();
    let mut names = BTreeMap::new();
    let mut starts: BTreeMap<u32, HashSet<String>> = BTreeMap::new();
    let mut previous: BTreeMap<u32, CfgEdgeKind> = BTreeMap::new();
    let mut last_owner = 0;
    let total = visit(data, cancel, |seq, offset, line| {
        if seq % 256 == 0 {
            samples.push(offset as u64);
        }
        let Some((s, p, m)) = parsed(line, seq, site, pc)? else {
            return Ok(());
        };
        let owner = builder.on_insn(InsnFact::new(seq, p));
        names.entry(owner).or_insert_with(|| s.clone());
        if !previous.contains_key(&owner)
            || last_owner != owner
            || previous[&owner] != CfgEdgeKind::Sequential
        {
            starts.entry(owner).or_default().insert(s);
        }
        let k = kind(m);
        previous.insert(owner, k);
        last_owner = owner;
        if k == CfgEdgeKind::CallResume {
            builder.on_call(seq, p);
        }
        Ok(())
    })?;
    let tree = builder.finish(total);
    let mut functions: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    // 起点以函数为scope，不把其他函数同地址/名称的执行混入。
    let mut targets_by_function: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for &id in &tree.confirmed_ids {
        let name = names
            .get(&id)
            .ok_or_else(|| invalid("missing activation entry"))?
            .clone();
        functions.entry(name.clone()).or_default().push(id);
        targets_by_function
            .entry(name)
            .or_default()
            .extend(starts.remove(&id).unwrap_or_default());
    }
    let mut owned: Vec<Vec<Occurrence>> = (0..tree.activations.len()).map(|_| Vec::new()).collect();
    let mut replay = ActivationBuilder::new();
    let mut blocks = Vec::new();
    let mut block_ids = BTreeMap::new();
    let mut last_owner = 0;
    visit(data, cancel, |seq, _, line| {
        let Some((s, p, m)) = parsed(line, seq, site, pc)? else {
            return Ok(());
        };
        let owner = replay.on_insn(InsnFact::new(seq, p));
        let k = kind(m);
        if tree
            .confirmed_ids
            .binary_search_by_key(&tree.activations[owner as usize].entry_seq, |id| {
                tree.activations[*id as usize].entry_seq
            })
            .is_ok()
        {
            let name = &names[&owner];
            let list = &mut owned[owner as usize];
            let new_block = list
                .last()
                .is_none_or(|o| o.outgoing != CfgEdgeKind::Sequential)
                || owner != last_owner
                || targets_by_function[name].contains(&s);
            if new_block {
                let next = blocks.len() as u32;
                let id = *block_ids
                    .entry((name.clone(), s.clone()))
                    .or_insert_with(|| {
                        blocks.push(s);
                        next
                    });
                list.push(Occurrence {
                    start: seq,
                    end: seq,
                    block: id,
                    activation: owner,
                    outgoing: k,
                });
            } else {
                let current = list.last_mut().unwrap();
                current.end = seq;
                current.outgoing = k;
            }
        }
        last_owner = owner;
        if k == CfgEdgeKind::CallResume {
            replay.on_call(seq, p);
        }
        Ok(())
    })?;
    let mut occurrences = Vec::new();
    let mut ranges = Vec::new();
    for list in owned {
        let start = occurrences.len();
        occurrences.extend(list);
        ranges.push(start..occurrences.len());
    }
    Ok(ControlFlowIndex {
        lines: LineIndexArchive {
            sampled_offsets: samples,
            total,
        },
        tree,
        functions,
        blocks,
        occurrences,
        ranges,
        site,
    })
}
