//! 仅查询响应，不是 Analysis Case Evidence 或持久化 Artifact。
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgEdgeKind {
    Sequential,
    Conditional,
    Branch,
    Indirect,
    CallResume,
    Return,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgPage {
    pub offset: usize,
    pub limit: usize,
}
impl Default for CfgPage {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgOccurrence {
    pub activation_id: u32,
    /// Reference within this session's CFG index, not a cross-index identity.
    pub block_id: u32,
    pub start_seq: u32,
    /// Inclusive last raw seq; disk half-open ranges are converted at query time.
    pub end_seq: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgRepresentative {
    pub start_seq: u32,
    pub end_seq: u32,
    pub instructions: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgBlock {
    /// Index-local ID. Stable identity is (containing function, site); numeric
    /// allocation may differ between the small memory and disk implementations.
    pub id: u32,
    pub site: String,
    pub count: u64,
    pub activation_ids: Vec<u32>,
    pub representatives: Vec<CfgRepresentative>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u32,
    pub to: u32,
    pub kind: CfgEdgeKind,
    pub count: u64,
    pub activation_ids: Vec<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgBoundary {
    pub call_seq: u32,
    pub entry_seq: u32,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgActivation {
    pub id: u32,
    pub call_seq: u32,
    pub entry_seq: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CfgView {
    pub function: String,
    pub activations: Vec<CfgActivation>,
    pub blocks: Vec<CfgBlock>,
    pub edges: Vec<CfgEdge>,
    pub occurrences: Vec<CfgOccurrence>,
    pub total_blocks: usize,
    pub total_occurrences: usize,
    pub unresolved_boundaries: Vec<CfgBoundary>,
}
