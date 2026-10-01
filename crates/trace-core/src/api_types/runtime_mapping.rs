//! 临时 trace 坐标查询响应；不证明模块内存 segment 归属或指针来源。
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RuntimeMappingSourceDto {
    pub seq: u32,
    pub runtime_pc: String,
    pub stable_offset: String,
}

#[derive(Debug, Serialize)]
pub struct RuntimeModuleMappingDto {
    pub module: String,
    pub runtime_base: String,
    pub source: RuntimeMappingSourceDto,
}

#[derive(Debug, Serialize)]
pub struct RuntimeMappingDto {
    pub call_seq: u32,
    pub entry_seq: u32,
    pub function: String,
    pub exit_seq: u32,
    pub resume_seq: u32,
    pub target_modules: Vec<String>,
    pub mappings: Vec<RuntimeModuleMappingDto>,
}
