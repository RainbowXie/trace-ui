//! CallTree 查询方法：get_call_tree / get_call_tree_children / get_call_tree_node_count。

use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::flat::line_index::LineIndexView;
use crate::phase2::extract_insn_offset;
use crate::query::call_tree::CallTreeNode;

/// 将 CallTreeNode 转为 DTO
fn node_to_dto(
    n: &CallTreeNode,
    line_index: Option<&LineIndexView<'_>>,
    data: &[u8],
) -> CallTreeNodeDto {
    let func_addr = {
        if let Some(li) = line_index {
            if let Some(line_bytes) = li.get_line(data, n.entry_seq) {
                if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                    let offset = extract_insn_offset(line_str);
                    if offset != 0 {
                        format!("0x{:x}", offset)
                    } else {
                        format!("0x{:x}", n.func_addr)
                    }
                } else {
                    format!("0x{:x}", n.func_addr)
                }
            } else {
                format!("0x{:x}", n.func_addr)
            }
        } else {
            format!("0x{:x}", n.func_addr)
        }
    };

    CallTreeNodeDto {
        id: n.id,
        func_addr,
        func_name: n.func_name.clone(),
        entry_seq: n.entry_seq,
        exit_seq: n.exit_seq,
        parent_id: n.parent_id,
        children_ids: n.children_ids.clone(),
        line_count: n.exit_seq.saturating_sub(n.entry_seq) + 1,
    }
}

impl crate::engine::TraceEngine {
    pub fn get_call_tree(&self, session_id: &str) -> Result<Vec<CallTreeNodeDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree.as_ref().ok_or(TraceError::IndexNotReady)?;

        let data: &[u8] = &state.mmap;
        let line_index = state.line_index_view();

        let nodes: Vec<CallTreeNodeDto> = call_tree
            .nodes
            .iter()
            .map(|n| node_to_dto(n, line_index.as_ref(), data))
            .collect();

        Ok(nodes)
    }

    pub fn get_call_tree_children(
        &self,
        session_id: &str,
        node_id: u32,
        include_self: bool,
    ) -> Result<Vec<CallTreeNodeDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree.as_ref().ok_or(TraceError::IndexNotReady)?;

        let data: &[u8] = &state.mmap;
        let line_index = state.line_index_view();

        let node = call_tree
            .nodes
            .get(node_id as usize)
            .ok_or_else(|| TraceError::InvalidArgument(format!("节点 {} 不存在", node_id)))?;

        let mut result = Vec::new();

        if include_self {
            result.push(node_to_dto(node, line_index.as_ref(), data));
        }

        for &child_id in &node.children_ids {
            if let Some(child) = call_tree.nodes.get(child_id as usize) {
                result.push(node_to_dto(child, line_index.as_ref(), data));
            }
        }

        Ok(result)
    }

    pub fn get_call_tree_node_count(&self, session_id: &str) -> Result<u32> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree.as_ref().ok_or(TraceError::IndexNotReady)?;

        Ok(call_tree.nodes.len() as u32)
    }
}
