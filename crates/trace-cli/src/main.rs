use std::sync::Arc;
use trace_core::TraceEngine;

mod fact_helper;
mod graph_helper;
mod helper;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if helper::requested() {
        return helper::run();
    }
    if fact_helper::requested() {
        return fact_helper::run();
    }
    if graph_helper::requested() {
        return graph_helper::run();
    }
    let engine = Arc::new(TraceEngine::new());
    trace_mcp::start_stdio(engine).await
}
