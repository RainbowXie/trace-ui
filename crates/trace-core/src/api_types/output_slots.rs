//! Temporary fd-query DTOs, not persisted Tuple pointer slots.
use super::{AddressCoverageDto, AddressDefinitionStepDto, AddressGapDto, ReturnCallerDto};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSlotRangeDto {
    pub address: String,
    pub size: u32,
}
#[derive(Serialize)]
pub struct OutputSlotUseDto {
    pub slot_address: String,
    pub slot_size: u32,
    pub store_seq: u32,
    pub store_owner_entry_seq: u32,
    pub store_operand: String,
    pub store_value: String,
    pub store_bytes: Vec<u8>,
    pub load_seq: u32,
    pub load_owner_entry_seq: u32,
    pub load_destination: String,
    pub load_value: String,
    pub use_seq: u32,
    pub use_owner_entry_seq: u32,
    pub address: String,
    pub size: u32,
    pub rw: String,
    pub address_operand: String,
    pub integer_delta: i64,
    pub definition_steps: Vec<AddressDefinitionStepDto>,
    pub chain_complete: bool,
    /// True only if this exact store is still the last definition of all eight
    /// bytes immediately before root.resume. False is transient, not final proof.
    pub final_output_definition: bool,
}
#[derive(Serialize)]
pub struct OutputSlotUsesDto {
    pub trace_session: String,
    pub call_seq: u32,
    pub entry_seq: u32,
    pub function: String,
    pub target_modules: Vec<String>,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub slot_ranges: Vec<OutputSlotRangeDto>,
    pub caller: ReturnCallerDto,
    pub uses: Vec<OutputSlotUseDto>,
    pub coverage: AddressCoverageDto,
    pub gaps: Vec<AddressGapDto>,
}
