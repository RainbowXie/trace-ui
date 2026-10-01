//! Bounded, ephemeral raw instruction ingredients; never permission to exclude memory.
use super::{AddressCoverageDto, AddressGapDto};
use serde::Serialize;
#[derive(Serialize)]
pub struct PrivateOperandRoleDto {
    pub role: String,
    pub operand: String,
    pub register: String,
    pub width: u32,
    pub pre_value: Option<String>,
    pub post_value: Option<String>,
}
#[derive(Serialize)]
pub struct PrivateMemoryDto {
    pub address: String,
    pub size: u32,
    pub rw: String,
    /// Store prestate or load poststate observation only; null is unknown.
    pub bytes: Vec<Option<u8>>,
}
#[derive(Serialize)]
pub struct PrivateInstructionDto {
    pub seq: u32,
    pub raw_line: String,
    pub site: Option<String>,
    pub owner_entry_seq: Option<u32>,
    pub mnemonic: Option<String>,
    pub operand: Option<String>,
    pub roles: Vec<PrivateOperandRoleDto>,
    pub immediate: Option<i64>,
    pub memory: Option<PrivateMemoryDto>,
}
#[derive(Serialize)]
pub struct PrivateFrameOperandsDto {
    pub trace_session: String,
    pub call_seq: u32,
    pub entry_seq: u32,
    pub function: String,
    pub target_modules: Vec<String>,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub instructions: Vec<PrivateInstructionDto>,
    /// Complete means supported leaf/frame raw ingredients, NOT private memory.
    pub coverage: AddressCoverageDto,
    pub gaps: Vec<AddressGapDto>,
}
