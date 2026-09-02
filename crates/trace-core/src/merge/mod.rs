//! Cross-chunk merge and fixup logic

#![allow(dead_code)]

mod deps;
mod events;
mod indices;
mod loads;
pub mod orchestrator;
#[cfg(test)]
mod tests;

pub use deps::{rebuild_compact_deps, resolve_control_deps};
pub use events::{
    fix_reg_checkpoints, replay_activation_events, replay_call_tree_events,
    replay_gumtrace_annotations,
};
pub use indices::{
    merge_init_mem_loads, merge_line_indices, merge_mem_access_indices, merge_pair_splits,
    merge_string_indices,
};
pub use loads::{
    resolve_partial_pair_load, resolve_partial_unresolved_loads, resolve_unresolved_load,
    resolve_unresolved_pair_load, resolve_unresolved_reg_uses,
};
pub use orchestrator::merge_all_chunks;
