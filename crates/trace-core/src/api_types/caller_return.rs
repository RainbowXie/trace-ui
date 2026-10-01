//! Temporary caller-use facts, never persisted as Evidence. Only X0 is supported.
use super::{AddressCoverageDto, AddressDefinitionStepDto, AddressGapDto};
use serde::Serialize;

#[derive(Serialize)]
pub struct ReturnCallerDto {
    pub call_seq: u32,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub closed: bool,
}
#[derive(Serialize)]
pub struct ReturnAnchorDto {
    pub register: String,
    pub value: String,
    /// Actual instruction producing the value (post-state), never RET's synthetic DEF.
    pub definition_seq: u32,
    /// Root return instruction pre-state.
    pub exit_seq: u32,
    /// Caller resume instruction execution-before state, cross-checked against replay.
    pub resume_seq: u32,
}
#[derive(Serialize)]
pub struct CallerReturnUseDto {
    pub register: String,
    pub value: String,
    pub use_seq: u32,
    pub address: String,
    pub size: u32,
    pub rw: String,
    pub address_operand: String,
    pub definition_steps: Vec<AddressDefinitionStepDto>,
    pub integer_delta: i64,
    /// This chain has no intervening source/ownership gap; overall coverage may be incomplete.
    pub chain_complete: bool,
}
#[derive(Serialize)]
pub struct CallerReturnUsesDto {
    pub trace_session: String,
    pub call_seq: u32,
    pub entry_seq: u32,
    pub function: String,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub target_modules: Vec<String>,
    pub caller: ReturnCallerDto,
    pub anchors: Vec<ReturnAnchorDto>,
    pub uses: Vec<CallerReturnUseDto>,
    pub coverage: AddressCoverageDto,
    pub gaps: Vec<AddressGapDto>,
}
