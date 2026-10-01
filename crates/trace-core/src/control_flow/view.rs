use super::{types::*, ControlFlowIndex};
use crate::error::{Result, TraceError};
use std::collections::{BTreeMap, BTreeSet};
fn invalid(text: &str) -> TraceError {
    TraceError::InvalidArgument(text.into())
}
impl ControlFlowIndex {
    pub fn activation_cfg(
        &self,
        data: &[u8],
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        blocks: &CfgPage,
        occurrences: &CfgPage,
    ) -> Result<CfgView> {
        let ids = self
            .functions
            .get(function)
            .ok_or_else(|| invalid("no confirmed function in selected trace"))?;
        let id = ids
            .iter()
            .copied()
            .find(|id| {
                let a = &self.tree.activations[*id as usize];
                a.call_seq == call_seq && a.entry_seq == entry_seq
            })
            .ok_or_else(|| invalid("selector is not a confirmed activation of this function"))?;
        self.view(data, function, &[id], blocks, occurrences)
    }
    pub fn function_cfg(
        &self,
        data: &[u8],
        function: &str,
        blocks: &CfgPage,
        occurrences: &CfgPage,
    ) -> Result<CfgView> {
        let ids = self
            .functions
            .get(function)
            .ok_or_else(|| invalid("no confirmed function in selected trace"))?;
        self.view(data, function, ids, blocks, occurrences)
    }
    /// 返回实际指令所在的occurrence；special行即便在seq范围内也返回None。
    pub fn occurrence_for_seq(&self, data: &[u8], seq: u32) -> Result<Option<CfgOccurrence>> {
        let Some(line) = self.lines.view().get_line(data, seq) else {
            return Ok(None);
        };
        let text = std::str::from_utf8(line).map_err(|_| invalid("invalid trace text"))?;
        if trace_parser::strict_memory::instruction_parts(text).is_none() {
            return Ok(None);
        }
        Ok(self
            .occurrences
            .iter()
            .find(|o| o.start <= seq && seq <= o.end)
            .map(|o| CfgOccurrence {
                activation_id: o.activation,
                block_id: o.block,
                start_seq: o.start,
                end_seq: o.end,
            }))
    }
    fn instructions(&self, data: &[u8], start: u32, end: u32) -> Result<Vec<String>> {
        let mut result = Vec::new();
        for seq in start..=end {
            let raw = self
                .lines
                .view()
                .get_line(data, seq)
                .ok_or_else(|| invalid("representative range outside trace"))?;
            let text = std::str::from_utf8(raw).map_err(|_| invalid("invalid trace text"))?;
            if let Some((mnemonic, operand)) = trace_parser::strict_memory::instruction_parts(text)
            {
                // 不包含寄存器/内存状态：变体只比较实际指令序列。
                let site = (self.site)(text)
                    .ok_or_else(|| invalid("missing representative stable site"))?;
                result.push(
                    format!("{}: {} {}", site, mnemonic, operand)
                        .trim_end()
                        .to_owned(),
                );
            }
        }
        Ok(result)
    }
    fn view(
        &self,
        data: &[u8],
        function: &str,
        ids: &[u32],
        block_page: &CfgPage,
        occurrence_page: &CfgPage,
    ) -> Result<CfgView> {
        if block_page.limit > 10_000 || occurrence_page.limit > 10_000 {
            return Err(invalid("CFG page capacity exceeded"));
        }
        let mut blocks: BTreeMap<u32, (u64, BTreeSet<u32>, Vec<(u32, u32)>)> = BTreeMap::new();
        let mut edges: BTreeMap<(u32, u32, CfgEdgeKind), (u64, BTreeSet<u32>)> = BTreeMap::new();
        let mut total_occurrences = 0;
        let mut occurrences = Vec::new();
        for &id in ids {
            let list = &self.occurrences[self.ranges[id as usize].clone()];
            for o in list {
                let b = blocks.entry(o.block).or_default();
                b.0 += 1;
                b.1.insert(id);
                b.2.push((o.start, o.end));
                if total_occurrences >= occurrence_page.offset
                    && occurrences.len() < occurrence_page.limit
                {
                    occurrences.push(CfgOccurrence {
                        activation_id: id,
                        block_id: o.block,
                        start_seq: o.start,
                        end_seq: o.end,
                    });
                }
                total_occurrences += 1;
            }
            for pair in list.windows(2) {
                let e = edges
                    .entry((pair[0].block, pair[1].block, pair[0].outgoing))
                    .or_default();
                e.0 += 1;
                e.1.insert(id);
            }
        }
        let total_blocks = blocks.len();
        let mut block_views = Vec::new();
        for (id, (count, sources, ranges)) in blocks
            .into_iter()
            .skip(block_page.offset)
            .take(block_page.limit)
        {
            let mut representatives: Vec<CfgRepresentative> = Vec::new();
            for (start, end) in ranges {
                let instructions = self.instructions(data, start, end)?;
                if !representatives
                    .iter()
                    .any(|r| r.instructions == instructions)
                {
                    representatives.push(CfgRepresentative {
                        start_seq: start,
                        end_seq: end,
                        instructions,
                    });
                }
            }
            block_views.push(CfgBlock {
                id,
                site: self.blocks[id as usize].clone(),
                count,
                activation_ids: sources.into_iter().collect(),
                representatives,
            });
        }
        let unresolved_boundaries = self
            .tree
            .activations
            .iter()
            .filter(|a| {
                a.id != 0
                    && a.unresolved_reason.is_some()
                    && (a.parent_id.is_some_and(|p| ids.contains(&p))
                        || self
                            .lines
                            .view()
                            .get_line(data, a.entry_seq)
                            .and_then(|raw| std::str::from_utf8(raw).ok())
                            .and_then(self.site)
                            .as_deref()
                            == Some(function))
            })
            .map(|a| CfgBoundary {
                call_seq: a.call_seq,
                entry_seq: a.entry_seq,
                reason: format!("{:?}", a.unresolved_reason.unwrap()),
            })
            .collect();
        Ok(CfgView {
            function: function.into(),
            activations: ids
                .iter()
                .map(|id| {
                    let a = &self.tree.activations[*id as usize];
                    CfgActivation {
                        id: *id,
                        call_seq: a.call_seq,
                        entry_seq: a.entry_seq,
                    }
                })
                .collect(),
            blocks: block_views,
            edges: edges
                .into_iter()
                .map(|((from, to, kind), (count, sources))| CfgEdge {
                    from,
                    to,
                    kind,
                    count,
                    activation_ids: sources.into_iter().collect(),
                })
                .collect(),
            occurrences,
            total_blocks,
            total_occurrences,
            unresolved_boundaries,
        })
    }
}
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\l")
        .replace('\r', "")
}
/// 只接受完整块页；DOT不展开occurrence，节点保持稳定块身份，正文保留全部观察序列。
pub fn render_dot(view: &CfgView) -> Result<String> {
    if view.blocks.len() != view.total_blocks {
        return Err(invalid("DOT requires all blocks (no pagination)"));
    }
    let mut dot = format!("digraph cfg {{\n  label=\"{}\";\n", escape(&view.function));
    for b in &view.blocks {
        let mut label = format!("{}\ncount={}\n", b.site, b.count);
        for (i, r) in b.representatives.iter().enumerate() {
            if b.representatives.len() > 1 {
                label.push_str(&format!("observed sequence {}\n", i + 1));
            }
            for text in &r.instructions {
                label.push_str(text);
                label.push('\n');
            }
        }
        dot.push_str(&format!("  b{} [label=\"{}\"];\n", b.id, escape(&label)));
    }
    for e in &view.edges {
        dot.push_str(&format!(
            "  b{} -> b{} [label=\"{:?} count={}\"];\n",
            e.from, e.to, e.kind, e.count
        ));
    }
    dot.push_str("}\n");
    Ok(dot)
}
