use serde::{Deserialize, Serialize};
use trace_parser::types::TraceFormat;

mod private_frame_operands;
pub use private_frame_operands::*;
mod output_slots;
pub use output_slots::*;
mod caller_return;
pub use caller_return::*;
mod address_provenance;
pub use address_provenance::*;
mod runtime_mapping;
pub use runtime_mapping::*;

// ── Progress ──

pub type ProgressCallback = Box<dyn Fn(Progress) + Send + Sync>;

#[derive(Clone, Serialize)]
pub struct Progress {
    pub session_id: String,
    pub phase: Phase,
    pub fraction: f64,
    pub message: Option<String>,
}

#[derive(Clone, Serialize)]
pub enum Phase {
    Scanning,
    Flattening,
    LoadingCache,
}

// ── Session ──

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: String,
    pub file_path: String,
    pub file_size: u64,
    pub total_lines: u32,
    pub index_ready: bool,
    pub building: bool,
    pub has_slice_result: bool,
    pub trace_format: Option<TraceFormat>,
}

// ── Build ──

pub struct BuildOptions {
    pub force_rebuild: bool,
    pub skip_strings: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildResult {
    pub total_lines: u32,
    pub has_string_index: bool,
    pub from_cache: bool,
}

// ── Browse ──

#[derive(Serialize, Clone)]
pub struct CallInfoDto {
    pub func_name: String,
    pub is_jni: bool,
    pub summary: String,
    pub tooltip: String,
}

#[derive(Serialize, Clone)]
pub struct TraceLine {
    pub seq: u32,
    pub address: String,
    pub so_offset: String,
    pub so_name: Option<String>,
    pub disasm: String,
    pub changes: String,
    pub reg_before: String,
    pub mem_rw: Option<String>,
    pub mem_addr: Option<String>,
    pub mem_size: Option<u8>,
    pub raw: String,
    pub call_info: Option<CallInfoDto>,
}

// ── Search ──

pub struct SearchOptions {
    pub case_sensitive: bool,
    pub use_regex: bool,
    pub fuzzy: bool,
    pub max_results: Option<u32>,
}

#[derive(Serialize)]
pub struct SearchResultLite {
    pub match_seqs: Vec<u32>,
    pub total_scanned: u32,
    pub total_matches: u32,
    pub truncated: bool,
}

#[derive(Serialize)]
pub struct SearchMatch {
    pub seq: u32,
    pub address: String,
    pub so_offset: String,
    pub so_name: Option<String>,
    pub disasm: String,
    pub changes: String,
    pub reg_before: String,
    pub mem_rw: Option<String>,
    pub call_info: Option<CallInfoDto>,
    pub hidden_content: Option<String>,
}

// ── Slice ──

pub struct SliceOptions {
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    pub data_only: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceResult {
    pub marked_count: u32,
    pub total_lines: u32,
    pub percentage: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportConfig {
    pub from_specs: Vec<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
}

// ── Memory ──

#[derive(Serialize)]
pub struct MemorySnapshot {
    pub base_addr: String,
    pub bytes: Vec<u8>,
    pub known: Vec<bool>,
    pub length: u32,
}

#[derive(Serialize)]
pub struct MemHistoryRecord {
    pub seq: u32,
    pub rw: String,
    pub data: String,
    pub size: u8,
    pub insn_addr: String,
    pub disasm: String,
}

#[derive(Serialize)]
pub struct MemHistoryMeta {
    pub total: usize,
    pub center_index: usize,
    pub samples: Vec<MemHistoryRecord>,
}

// ── Call Tree ──

#[derive(Serialize)]
pub struct CallTreeNodeDto {
    pub id: u32,
    pub func_addr: String,
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    pub line_count: u32,
}

// ── Confirmed Activation ──

/// 一次已确认函数调用激活的 DTO。边界字段全部来自实际指令（非 seq 猜测）。
#[derive(Serialize)]
pub struct ConfirmedActivationDto {
    pub id: u32,
    /// 展示身份：session + call anchor（function-boundaries.md §1）；
    /// root 是 "trace_root"
    pub activation: String,
    /// 函数稳定身份（module+offset，common-types.md 语法）；无稳定来源时 None
    pub func_addr: Option<String>,
    pub func_name: Option<String>,
    pub call_seq: u32,
    /// callsite 稳定身份（所有状态下都是真实观察）
    pub call_pc: Option<String>,
    pub entry_seq: u32,
    pub entry_pc: Option<String>,
    pub exit_seq: u32,
    pub exit_pc: Option<String>,
    pub expected_resume: Option<String>,
    pub resume_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    /// None = 已确认；Some = 未闭合原因
    pub unresolved_reason: Option<String>,
}

/// 没有记录函数体的调用事实（不生成 ConfirmedActivation）。
#[derive(Serialize)]
pub struct BypassedCallDto {
    pub call_seq: u32,
    /// 稳定身份；无法规范化时 None（fail-closed，不冒充）
    pub call_pc: Option<String>,
    pub expected_resume: Option<String>,
    pub resume_seq: u32,
    pub parent_id: Option<u32>,
}

/// ActivationTree 分页查询结果：确认激活窗口 + bypassed 调用窗口 + 全量计数。
#[derive(Serialize)]
pub struct ActivationTreeDto {
    /// 分页窗口内的 activation（含 root，index 0）
    pub activations: Vec<ConfirmedActivationDto>,
    /// 分页窗口内的 bypassed 调用（按 call_seq 顺序）
    pub bypassed_calls: Vec<BypassedCallDto>,
    /// 全量计数（不受分页影响）
    pub total_activations: u32,
    pub total_bypassed: u32,
    /// 排除 root 的 confirmed/unresolved 计数（root 是 trace 上下文，不是调用）
    pub confirmed_count: u32,
    pub unresolved_count: u32,
    pub offset: u32,
    /// 两数组独立分页，各自标记剩余
    pub activations_has_more: bool,
    pub bypassed_has_more: bool,
}

/// 指令归属（agent-api.md §2）：seq → 所属 Activation / 函数 / 边界状态。
///
/// 边界无损表达：一条指令可同时闭合一个调用（resume 或 bypassed 直接
/// resume）并开启另一个调用（连续两条 BL 的第二条既是前一调用的 resume
/// 又是新调用）。`closes`/`opens` 并列表达，Basic Block 切分据此判定
/// "resume 开始新块、call 结束当前块"的叠加。
#[derive(Serialize)]
pub struct InstructionOwnerDto {
    pub seq: u32,
    /// 无归属（root / trace_root 上下文）时为 None
    pub activation: Option<ConfirmedActivationDto>,
    /// 边界位置摘要：entry/exit/resume/call/body/root/not_an_instruction。
    /// 多条件叠加时优先级 resume > call > entry > exit > body > root。
    pub position: String,
    /// 本指令闭合的调用（position == "resume"时指向被闭合 child）：
    /// activation id 或 bypassed 序号（"bypassed:N"）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closes: Option<String>,
    /// 本指令开启的调用（position == "call"）：activation id 或
    /// bypassed 序号（"bypassed:N"）；entry 即 call 的 callee_id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opens: Option<String>,
    /// 补充说明（not_an_instruction 原因等；可为空）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// FunctionCallRecord 构建器的一次 Activation 机械事实快照。
#[derive(Serialize)]
pub struct FunctionFactBundleDto {
    pub function: String,
    pub trace_anchors: FunctionTraceAnchorsDto,
    pub abi: FunctionAbiDto,
    pub executed_block_sequence: Vec<ExecutedBlockEntryDto>,
    pub memory_reads: Vec<FunctionMemoryReadDto>,
    pub global_reads: Vec<FunctionGlobalReadDto>,
    pub memory_writes: Vec<FunctionMemoryWriteDto>,
    pub global_writes: Vec<FunctionGlobalWriteDto>,
    pub external_call_events: Vec<FunctionExternalCallEventDto>,
    pub unresolved: Vec<FunctionFactUnresolvedDto>,
}

#[derive(Serialize)]
pub struct FunctionTraceAnchorsDto {
    pub call: FunctionAnchorDto,
    pub entry: FunctionAnchorDto,
    pub exit: FunctionAnchorDto,
    pub resume: FunctionAnchorDto,
}

#[derive(Serialize, Debug)]
pub struct FunctionAnchorDto {
    pub seq: u32,
    pub offset: String,
}

#[derive(Serialize)]
pub struct FunctionAbiDto {
    pub entry_sp: Option<String>,
    pub arguments: std::collections::BTreeMap<String, Option<String>>,
    pub stack_arguments: Vec<FunctionStackArgumentDto>,
    pub returns: std::collections::BTreeMap<String, Option<String>>,
}

#[derive(Serialize)]
pub struct FunctionStackArgumentDto {
    pub offset: i64,
    pub size: u32,
    pub value: Option<String>,
    pub read_seqs: Vec<u32>,
}

#[derive(Serialize)]
pub struct ExecutedBlockEntryDto {
    pub block: String,
    pub entry_seq: u32,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct FunctionMemoryReadDto {
    pub address: String,
    pub size: u32,
    pub bytes: Option<String>,
    pub read_seqs: Vec<u32>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct FunctionMemoryWriteDto {
    pub address: String,
    pub size: u32,
    pub bytes: Option<String>,
    pub write_seqs: Vec<u32>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct FunctionGlobalReadDto {
    pub global: String,
    pub size: u32,
    pub bytes: Option<String>,
    pub read_seqs: Vec<u32>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct FunctionGlobalWriteDto {
    pub global: String,
    pub size: u32,
    pub bytes: Option<String>,
    pub write_seqs: Vec<u32>,
}

#[derive(Serialize, Debug)]
pub struct FunctionExternalCallEventDto {
    pub callsite: FunctionAnchorDto,
    pub resume: Option<FunctionAnchorDto>,
    pub target: FunctionExternalTargetDto,
    pub call_sp: Option<String>,
    pub arguments: std::collections::BTreeMap<String, Option<String>>,
    pub stack_arguments: Vec<FunctionExternalStackArgumentDto>,
    pub returns: std::collections::BTreeMap<String, Option<String>>,
    pub memory_reads: Vec<FunctionEventMemoryRecordDto>,
    pub global_reads: Vec<FunctionEventGlobalRecordDto>,
    pub memory_writes: Vec<FunctionEventMemoryRecordDto>,
    pub global_writes: Vec<FunctionEventGlobalRecordDto>,
    pub unresolved: Vec<FunctionEventUnresolvedDto>,
}

#[derive(Serialize, Debug)]
pub struct FunctionExternalTargetDto {
    pub module: Option<String>,
    pub entry: Option<String>,
    pub symbol: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct FunctionExternalStackArgumentDto {
    pub offset: i64,
    pub size: u32,
    pub value: Option<String>,
    pub evidence_seqs: Vec<u32>,
}

#[derive(Serialize, Debug)]
pub struct FunctionEventMemoryRecordDto {
    pub address: String,
    pub size: u32,
    pub bytes: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct FunctionEventGlobalRecordDto {
    pub global: String,
    pub size: u32,
    pub bytes: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct FunctionEventUnresolvedDto {
    pub kind: String,
    pub detail: String,
}

#[derive(Serialize, Debug)]
pub struct FunctionFactUnresolvedDto {
    pub kind: String,
    pub seqs: Vec<u32>,
    pub location: Option<String>,
    pub detail: String,
}

// ── Algorithm Graph mechanical facts ──

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct GraphTraceReferenceDto {
    pub artifact: String,
    pub pointer: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct GraphActivationSelectorDto {
    pub trace: GraphTraceReferenceDto,
    pub function: String,
    pub call_seq: u32,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub resume_seq: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmGraphFactBundleDto {
    pub target_seq: u32,
    pub target: GraphMechanicalEndpointDto,
    pub activations: Vec<GraphActivationSelectorDto>,
    pub call_edges: Vec<GraphCallEdgeDto>,
    pub external_call_events: Vec<GraphExternalCallEventDto>,
    pub dependency_edges: Vec<GraphDependencyEdgeDto>,
    pub unresolved: Vec<GraphFactUnresolvedDto>,
    pub content_identity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphCallEdgeDto {
    pub caller: GraphActivationSelectorDto,
    pub callee: GraphActivationSelectorDto,
    pub call_seq: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphMechanicalEndpointDto {
    Instruction {
        seq: u32,
        owner: GraphActivationSelectorDto,
    },
    ExternalCallEvent {
        owner: GraphActivationSelectorDto,
        event_index: u32,
        call_seq: u32,
        resume_seq: u32,
    },
    DynamicSource {
        owner: GraphActivationSelectorDto,
        read_index: u32,
        seq: u32,
        address: String,
        size: u32,
        bytes: Option<String>,
    },
    GlobalReference {
        owner: GraphActivationSelectorDto,
        access_index: u32,
        seq: u32,
        access: String,
        global: String,
        size: u32,
        bytes: Option<String>,
    },
    Constant {
        owner: GraphActivationSelectorDto,
        source_index: u32,
        seq: u32,
        address: String,
        size: u32,
        bytes: String,
    },
    Unresolved {
        owner: GraphActivationSelectorDto,
        unresolved_index: u32,
        seq: u32,
    },
}

impl GraphMechanicalEndpointDto {
    pub fn seq(&self) -> Option<u32> {
        Some(match self {
            Self::Instruction { seq, .. }
            | Self::DynamicSource { seq, .. }
            | Self::GlobalReference { seq, .. }
            | Self::Constant { seq, .. }
            | Self::Unresolved { seq, .. } => *seq,
            Self::ExternalCallEvent { .. } => return None,
        })
    }

    pub fn owner(&self) -> &GraphActivationSelectorDto {
        match self {
            Self::Instruction { owner, .. }
            | Self::ExternalCallEvent { owner, .. }
            | Self::DynamicSource { owner, .. }
            | Self::GlobalReference { owner, .. }
            | Self::Constant { owner, .. }
            | Self::Unresolved { owner, .. } => owner,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct GraphExternalCallEventDto {
    pub owner: GraphActivationSelectorDto,
    pub event_index: u32,
    pub call_seq: u32,
    pub resume_seq: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphDependencyEdgeDto {
    pub producer: GraphMechanicalEndpointDto,
    pub consumer: GraphMechanicalEndpointDto,
    pub kind: String,
    pub pair_part: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GraphFactUnresolvedDto {
    pub kind: String,
    pub seqs: Vec<u32>,
    pub detail: String,
}

// ── Strings ──

pub struct StringQueryOptions {
    pub min_len: u32,
    pub offset: u32,
    pub limit: u32,
    pub search: Option<String>,
}

#[derive(Serialize)]
pub struct StringRecordDto {
    pub idx: u32,
    pub addr: String,
    pub content: String,
    pub encoding: String,
    pub byte_len: u32,
    pub seq: u32,
    pub xref_count: u32,
    pub rw: String,
}

#[derive(Serialize)]
pub struct StringsResult {
    pub strings: Vec<StringRecordDto>,
    pub total: u32,
}

#[derive(Serialize)]
pub struct StringXRef {
    pub seq: u32,
    pub rw: String,
    pub insn_addr: String,
    pub disasm: String,
}

// ── Dep Tree ──

pub struct DepTreeOptions {
    pub data_only: bool,
    pub max_nodes: Option<u32>,
}

// ── DEF/USE ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefUseChain {
    pub def_seq: Option<u32>,
    pub use_seqs: Vec<u32>,
    pub redefined_seq: Option<u32>,
}

// ── Functions ──

#[derive(Serialize)]
pub struct FunctionCallOccurrence {
    pub seq: u32,
    pub summary: String,
}

#[derive(Serialize)]
pub struct FunctionCallEntry {
    pub func_name: String,
    pub is_jni: bool,
    pub occurrences: Vec<FunctionCallOccurrence>,
}

#[derive(Serialize)]
pub struct FunctionCallsResult {
    pub functions: Vec<FunctionCallEntry>,
    pub total_calls: usize,
}

// ── Cache ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    pub files_deleted: u32,
    pub bytes_freed: u64,
}
