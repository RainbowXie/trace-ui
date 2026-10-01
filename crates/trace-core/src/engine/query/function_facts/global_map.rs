use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Result, TraceError};

use super::super::activation::stable_runtime_site;

pub(crate) struct StableGlobalMap {
    pub(super) bases: BTreeMap<String, u64>,
    pub(super) target_modules: BTreeSet<String>,
    sources: BTreeMap<String, crate::api_types::RuntimeMappingSourceDto>,
}

impl crate::engine::TraceEngine {
    /// 从选定闭合调用和 raw trace 取得临时坐标，不推断 segment 或 global 归属。
    pub fn get_runtime_mapping(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        target_modules: &[String],
    ) -> Result<crate::api_types::RuntimeMappingDto> {
        use super::super::activation::stable_site;
        use crate::api_types::{RuntimeMappingDto, RuntimeModuleMappingDto};
        let invalid = |message: &str| TraceError::InvalidArgument(message.to_owned());
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.is_empty()
            || target_modules.len() > 500
            || modules.len() != target_modules.len()
            || modules.iter().any(|module| {
                let site = format!("{module}+0x0");
                stable_site(&format!("[{module}] 0x0!0x0 nop")).as_deref() != Some(&site)
            })
        {
            return Err(invalid(
                "invalid or duplicate target_modules (expected 1..=500 canonical names)",
            ));
        }
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let activation = tree
            .activations
            .iter()
            .find(|item| item.call_seq == call_seq && item.entry_seq == entry_seq)
            .ok_or_else(|| invalid("runtime mapping selector not found"))?;
        if activation.id == 0
            || activation.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= activation.exit_seq
                && activation.exit_seq < activation.resume_seq
                && activation.resume_seq < state.total_lines)
        {
            return Err(invalid(
                "runtime mapping requires a closed Confirmed Activation",
            ));
        }
        let lines = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        for seq in [
            call_seq,
            entry_seq,
            activation.exit_seq,
            activation.resume_seq,
        ] {
            let line = lines
                .get_line(&state.mmap, seq)
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .ok_or_else(|| invalid("runtime mapping boundary missing"))?;
            if trace_parser::strict_memory::instruction_parts(line).is_none()
                || stable_runtime_site(line).is_none()
            {
                return Err(invalid(
                    "runtime mapping boundary lacks an instruction site",
                ));
            }
            if seq == entry_seq && stable_site(line).as_deref() != Some(function) {
                return Err(invalid("runtime mapping function site mismatch"));
            }
        }
        let map = StableGlobalMap::collect(&state, target_modules)?;
        let mut mappings = Vec::new();
        for module in &modules {
            let base = map
                .bases
                .get(module)
                .ok_or_else(|| invalid("target module missing from trace"))?;
            let source = map
                .sources
                .get(module)
                .ok_or_else(|| invalid("target module lacks an instruction source"))?;
            mappings.push(RuntimeModuleMappingDto {
                module: module.clone(),
                runtime_base: format!("0x{base:x}"),
                source: crate::api_types::RuntimeMappingSourceDto {
                    seq: source.seq,
                    runtime_pc: source.runtime_pc.clone(),
                    stable_offset: source.stable_offset.clone(),
                },
            });
        }
        Ok(RuntimeMappingDto {
            call_seq,
            entry_seq,
            function: function.to_owned(),
            exit_seq: activation.exit_seq,
            resume_seq: activation.resume_seq,
            target_modules: modules.into_iter().collect(),
            mappings,
        })
    }
}

impl StableGlobalMap {
    pub(crate) fn collect(
        state: &crate::session::SessionState,
        target_modules: &[String],
    ) -> Result<Self> {
        let target_modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if target_modules.is_empty() {
            return Ok(Self {
                bases: BTreeMap::new(),
                target_modules,
                sources: BTreeMap::new(),
            });
        }
        let lines = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let mut bases = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for seq in 0..state.total_lines {
            let Some(raw) = lines.get_line(&state.mmap, seq) else {
                continue;
            };
            let Ok(line) = std::str::from_utf8(raw) else {
                continue;
            };
            let Some((module, runtime, offset)) = stable_runtime_site(line) else {
                continue;
            };
            if !target_modules.contains(&module) {
                continue;
            }
            let base = runtime.checked_sub(offset).ok_or_else(|| {
                TraceError::InvalidArgument(format!(
                    "module {module} runtime address is below its stable offset"
                ))
            })?;
            if trace_parser::strict_memory::instruction_parts(line).is_some() {
                sources.entry(module.clone()).or_insert_with(|| {
                    crate::api_types::RuntimeMappingSourceDto {
                        seq,
                        runtime_pc: format!("0x{runtime:x}"),
                        stable_offset: format!("0x{offset:x}"),
                    }
                });
            }
            if bases
                .insert(module.clone(), base)
                .is_some_and(|old| old != base)
            {
                return Err(TraceError::InvalidArgument(format!(
                    "module {module} has inconsistent runtime bases"
                )));
            }
        }
        Ok(Self {
            bases,
            target_modules,
            sources,
        })
    }
}
