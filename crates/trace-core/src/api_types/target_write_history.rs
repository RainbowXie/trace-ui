//! 临时目标写入历史；不作为持久化 Evidence。
use super::{AddressCoverageDto, AddressGapDto, RuntimeMappingDto};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetObservationRw {
    Read,
    Write,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetHistorySelectionDto {
    pub seq: u32,
    pub address: String,
    pub size: u32,
    pub rw: Option<TargetObservationRw>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TargetHistoryOwnerDto {
    pub call_seq: u32,
    pub entry_seq: u32,
    pub in_root_closure: bool,
}
#[derive(Serialize)]
pub struct TargetHistoryEffectDto {
    /// 普通指令的真实 seq；不是执行前 capture 的 seq。
    pub seq: u32,
    pub phase: &'static str,
}
#[derive(Serialize)]
pub struct TargetHistoryWriteDto {
    pub seq: u32,
    pub owner: Option<TargetHistoryOwnerDto>,
    pub address: String,
    pub size: u32,
    /// 以下 bytes 是原始写入裁剪到目标后的部分；不改变原 address/size。
    pub target_offset: u32,
    pub write_offset: u32,
    pub bytes: Vec<Option<u8>>,
    pub effect: TargetHistoryEffectDto,
}
#[derive(Serialize)]
pub struct TargetHistoryDefinitionRunDto {
    pub target_offset: u32,
    pub size: u32,
    pub last_writer_seq: Option<u32>,
    pub owner: Option<TargetHistoryOwnerDto>,
}
#[derive(Serialize)]
pub struct TargetHistorySnapshotDto {
    pub seq: u32,
    pub phase: &'static str,
    pub bytes: Vec<Option<u8>>,
    pub definitions: Vec<TargetHistoryDefinitionRunDto>,
}
#[derive(Serialize)]
pub struct TargetWriteHistoryDto {
    pub trace_session: String,
    pub call_seq: u32,
    pub entry_seq: u32,
    pub function: String,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub selected: TargetHistorySelectionDto,
    pub capture_seq: u32,
    pub runtime_mapping: Option<RuntimeMappingDto>,
    pub writes: Vec<TargetHistoryWriteDto>,
    pub selected_snapshot: TargetHistorySnapshotDto,
    pub capture_snapshot: TargetHistorySnapshotDto,
    /// complete 证明两时点全字节有闭包内已知定义和完整观测，不证明期间未改写。
    pub coverage: AddressCoverageDto,
    pub gaps: Vec<AddressGapDto>,
}
