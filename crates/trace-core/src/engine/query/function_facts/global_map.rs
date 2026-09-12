use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Result, TraceError};

use super::super::activation::stable_runtime_site;

pub(crate) struct StableGlobalMap {
    pub(super) bases: BTreeMap<String, u64>,
    pub(super) limits: BTreeMap<String, u64>,
    pub(super) target_modules: BTreeSet<String>,
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
                limits: BTreeMap::new(),
                target_modules,
            });
        }
        let lines = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let mut bases = BTreeMap::new();
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
            if bases
                .insert(module.clone(), base)
                .is_some_and(|old| old != base)
            {
                return Err(TraceError::InvalidArgument(format!(
                    "module {module} has inconsistent runtime bases"
                )));
            }
        }
        let mut ordered = bases
            .iter()
            .map(|(module, base)| (base, module))
            .collect::<Vec<_>>();
        ordered.sort();
        let mut limits = BTreeMap::new();
        for (index, (base, module)) in ordered.iter().enumerate() {
            let limit = ordered.get(index + 1).map_or(u64::MAX, |(next, _)| **next);
            if **base >= limit {
                return Err(TraceError::InvalidArgument(
                    "target module runtime ranges overlap".to_owned(),
                ));
            }
            limits.insert((*module).clone(), limit);
        }
        Ok(Self {
            bases,
            limits,
            target_modules,
        })
    }
}
