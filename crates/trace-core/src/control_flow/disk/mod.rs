//! Rebuildable disk control-flow cache and bounded independent builder.
//! Never falls back to the full dependency index.
pub mod format;
pub mod ownership;
pub mod sort;
mod scratch;
mod build;
mod aggregate;
pub use build::{build_control_flow_store, BuildBudget};
mod trace;
mod store;
mod writer;
pub use trace::{OpenedTrace, path_cache_name};
pub use store::{ControlFlowStore, FlatSection};
pub use writer::CacheWriter;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod build_tests;
