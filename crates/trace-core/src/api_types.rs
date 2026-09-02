use serde::{Deserialize, Serialize};
use trace_parser::types::TraceFormat;

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
    /// 已确认入口 PC（call 后第一条实际执行的 callee 指令）
    pub func_addr: String,
    pub func_name: Option<String>,
    pub call_seq: u32,
    pub call_pc: String,
    pub entry_seq: u32,
    pub entry_pc: String,
    pub exit_seq: u32,
    pub exit_pc: String,
    pub expected_resume: String,
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
    pub call_pc: String,
    pub expected_resume: String,
    pub resume_seq: u32,
    pub parent_id: Option<u32>,
}

/// ActivationTree 查询结果：确认激活 + bypassed 调用。
#[derive(Serialize)]
pub struct ActivationTreeDto {
    pub activations: Vec<ConfirmedActivationDto>,
    pub bypassed_calls: Vec<BypassedCallDto>,
}

/// 指令归属（agent-api.md §2）：seq → 所属 Activation / 函数 / 边界状态。
#[derive(Serialize)]
pub struct InstructionOwnerDto {
    pub seq: u32,
    /// 无归属（root / trace_root 上下文）时为 None
    pub activation: Option<ConfirmedActivationDto>,
    /// 序列中的边界位置：entry/exit/resume/call 或 body/root
    pub position: String,
    /// position == "call" 时指向被调用的 child activation id（BL 行归属 caller）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_id: Option<u32>,
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
