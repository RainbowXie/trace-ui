//! 临时 FD 查询结果；不属于持久化 Evidence。
use serde::Serialize;

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AddressOriginDto {
    AbiRegister {
        seq: u32,
        register: String,
        value: String,
    },
    EntrySp {
        seq: u32,
        value: String,
    },
    StackArgument {
        seq: u32,
        stack_offset: i64,
        size: u32,
        value: String,
    },
    GlobalAdrp {
        seq: u32,
        register: String,
        value: String,
        global: String,
    },
}
#[derive(Clone, Serialize)]
pub struct AddressDefinitionStepDto {
    pub seq: u32,
    pub operation: String,
    pub source_operand: String,
    pub target_operand: String,
    pub pre_value: String,
    pub post_value: String,
}
#[derive(Serialize)]
pub struct AddressAccessDto {
    pub seq: u32,
    pub address: String,
    pub size: Option<u32>,
    pub rw: String,
    pub address_operand: String,
    pub origin_anchor: Option<AddressOriginDto>,
    pub definition_steps: Vec<AddressDefinitionStepDto>,
    pub integer_delta: Option<i64>,
    pub frame_access: Option<FrameAccessDto>,
}
/// Concrete ranges only; neither containment nor balance proves non-escape.
#[derive(Serialize)]
pub struct FrameAccessDto {
    pub owner_entry_seq: u32,
    pub pre_sp: String,
    pub post_sp: String,
    pub access_start: String,
    pub access_end: String,
    pub live_frame_start: String,
    pub live_frame_end: String,
    pub within_live_frame: bool,
}
#[derive(Serialize)]
pub struct FrameSpStepDto {
    pub seq: u32,
    pub operation: String,
    pub source_operand: String,
    pub target_operand: String,
    pub pre_sp: String,
    pub post_sp: String,
}
#[derive(Serialize)]
pub struct FrameDto {
    pub owner_call_seq: u32,
    pub owner_entry_seq: u32,
    pub owner_exit_seq: u32,
    pub owner_resume_seq: u32,
    pub entry_sp: String,
    pub exit_sp: Option<String>,
    /// Only explicit return-boundary SP restoration, not object privacy.
    pub balanced: bool,
    pub steps: Vec<FrameSpStepDto>,
    pub gaps: Vec<AddressGapDto>,
}
#[derive(Serialize)]
pub struct AddressGapDto {
    pub seq: u32,
    pub kind: String,
    pub detail: String,
}
#[derive(Serialize)]
pub struct AddressCoverageDto {
    /// Inclusive instruction window: first executes before scan, last after scan.
    pub first_seq: u32,
    pub last_seq: u32,
    /// Includes special lines; not a count of instructions.
    pub scanned_lines: u32,
    pub access_count: usize,
    pub complete: bool,
}
#[derive(Serialize)]
pub struct AddressProvenanceDto {
    pub trace_session: String,
    pub call_seq: u32,
    pub entry_seq: u32,
    pub function: String,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub target_modules: Vec<String>,
    pub coverage: AddressCoverageDto,
    pub accesses: Vec<AddressAccessDto>,
    pub frames: Vec<FrameDto>,
    pub gaps: Vec<AddressGapDto>,
}
