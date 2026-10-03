//! TraceEngine query methods：get_* / scan_* / build_* 查询接口。

pub(crate) mod activation;
mod algorithm_graph;
pub(crate) mod saved_events;
mod call_tree;
mod crypto;
mod dep_tree;
pub(super) mod function_facts;
mod functions;
mod memory;
mod strings;
