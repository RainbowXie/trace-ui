//! 函数调用查询方法：get_function_calls。

use std::collections::HashMap;

use crate::api_types::*;
use crate::error::{Result, TraceError};

impl crate::engine::TraceEngine {
    pub fn get_function_calls(&self, session_id: &str) -> Result<FunctionCallsResult> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        // Group by func_name
        let mut groups: HashMap<String, (bool, Vec<FunctionCallOccurrence>)> = HashMap::new();
        for (&seq, ann) in &state.call_annotations {
            let entry = groups
                .entry(ann.func_name.clone())
                .or_insert_with(|| (ann.is_jni, Vec::new()));
            entry.1.push(FunctionCallOccurrence {
                seq,
                summary: ann.summary(),
            });
        }

        let mut total_calls = 0usize;
        let mut functions: Vec<FunctionCallEntry> = groups
            .into_iter()
            .map(|(func_name, (is_jni, mut occs))| {
                occs.sort_by_key(|o| o.seq);
                total_calls += occs.len();
                FunctionCallEntry {
                    func_name,
                    is_jni,
                    occurrences: occs,
                }
            })
            .collect();

        // Sort by first occurrence seq
        functions.sort_by_key(|f| f.occurrences.first().map(|o| o.seq).unwrap_or(u32::MAX));

        Ok(FunctionCallsResult {
            functions,
            total_calls,
        })
    }
}
