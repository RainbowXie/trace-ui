//! Analysis Case Algorithm Graph adapter 使用的 fd helper。
//!
//! 调用方已经完成 pathname 的 no-follow 打开与 `fstat`；helper 只消费继承 fd，
//! 防止校验后路径被替换时读取到另一份 trace。

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

use serde::Deserialize;
use trace_core::api_types::{AlgorithmGraphFactBundleDto, GraphActivationSelectorDto};
use trace_core::{BuildOptions, TraceEngine};

const MAX_GRAPH_FACT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphHelperRequest {
    target_seq: u32,
    target_address: u64,
    target_size: u32,
    target_rw: Option<String>,
    activations: Vec<GraphActivationSelectorDto>,
    #[serde(default)]
    target_modules: Vec<String>,
}

pub(crate) fn requested() -> bool {
    std::env::args().any(|arg| arg == "--algorithm-graph-helper")
}

#[cfg(not(unix))]
pub(crate) fn run() -> anyhow::Result<()> {
    anyhow::bail!("fd helper is only supported on Unix")
}

#[cfg(unix)]
pub(crate) fn run() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let trace_fd = parse_fd_arg(&args, "--trace-fd")?;
    if trace_fd < 3 {
        anyhow::bail!("trace fd must not use reserved standard descriptors 0, 1, or 2");
    }
    let trace = unsafe { File::from_raw_fd(trace_fd) };
    if !trace.metadata()?.is_file() {
        anyhow::bail!("trace fd is not a regular file");
    }
    let request: GraphHelperRequest = serde_json::from_slice(&read_stdin_bounded()?)
        .map_err(|error| anyhow::anyhow!("invalid graph helper request: {error}"))?;

    let engine = Arc::new(TraceEngine::new());
    let session = engine.create_session_from_file(trace, &format!("inherited-fd:{trace_fd}"))?;
    engine.build_index(
        &session.session_id,
        BuildOptions {
            force_rebuild: false,
            skip_strings: true,
        },
        None,
    )?;
    let facts = engine.get_algorithm_graph_facts_for_modules(
        &session.session_id,
        request.target_seq,
        request.target_address,
        request.target_size,
        request.target_rw.as_deref(),
        &request.activations,
        &request.target_modules,
    )?;
    write_response(&facts)
}

#[cfg(unix)]
fn parse_fd_arg(args: &[String], flag: &str) -> anyhow::Result<RawFd> {
    let position = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| anyhow::anyhow!("missing required {flag} argument"))?;
    args.get(position + 1)
        .ok_or_else(|| anyhow::anyhow!("missing value after {flag}"))?
        .parse::<RawFd>()
        .map_err(|error| anyhow::anyhow!("invalid descriptor for {flag}: {error}"))
}

#[cfg(unix)]
fn read_stdin_bounded() -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_CONTROL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONTROL_BYTES {
        anyhow::bail!("control request exceeds {MAX_CONTROL_BYTES} byte limit");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn write_response(facts: &AlgorithmGraphFactBundleDto) -> anyhow::Result<()> {
    let mut encoded = Vec::new();
    {
        let mut bounded =
            super::fact_helper::BoundedWriter::new(&mut encoded, MAX_GRAPH_FACT_BUNDLE_BYTES);
        serde_json::to_writer(&mut bounded, facts)?;
        bounded.write_all(b"\n")?;
    }
    let mut stdout = io::stdout().lock();
    stdout.write_all(&encoded)?;
    stdout.flush()?;
    Ok(())
}
