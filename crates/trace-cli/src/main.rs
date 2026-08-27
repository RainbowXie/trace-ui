use std::sync::Arc;
use trace_core::TraceEngine;

mod helper;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if helper::requested() {
        return helper::run();
    }
    let engine = Arc::new(TraceEngine::new());
    trace_mcp::start_stdio(engine).await
}
