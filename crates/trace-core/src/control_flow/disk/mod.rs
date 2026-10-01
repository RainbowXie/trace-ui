//! Rebuildable internal control-flow cache. This module does not build CFGs,
//! query graphs, or fall back to the full dependency index.
pub mod format;
pub mod ownership;
pub mod sort;
mod trace;
mod store;
mod writer;
pub use trace::{OpenedTrace, path_cache_name};
pub use store::{ControlFlowStore, FlatSection};
pub use writer::CacheWriter;
#[cfg(test)]
mod tests;
