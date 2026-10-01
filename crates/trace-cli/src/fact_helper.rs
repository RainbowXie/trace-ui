//! The fd-based function facts helper used by the Analysis Case adapter.
//!
//! The adapter has already validated the trace file. It passes its open
//! descriptor to this process so this helper never has to reopen a pathname
//! (and therefore cannot observe a replacement file).

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use trace_core::engine::{
    write_function_fact_projection, FactActivationSelector, FactSourceReference, FunctionFactContext,
};

#[cfg(unix)]
use std::os::fd::{FromRawFd, RawFd};

use serde::{Deserialize, Serialize};
use trace_core::BuildOptions;
use trace_core::TraceEngine;

const MAX_FACT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactHelperRequest {
    call_seq: u32,
    entry_seq: u32,
    #[serde(default)]
    function: Option<String>,
    #[serde(default)]
    target_modules: Vec<String>,
}

/// Source references are caller-bound to the retained FD, not reopened here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactSourceContext {
    artifact: String,
    pointer: String,
}

impl FactSourceContext {
    fn borrowed(&self) -> FactSourceReference<'_> {
        FactSourceReference {
            artifact: &self.artifact,
            pointer: &self.pointer,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactActivationContext {
    trace: FactSourceContext,
    function: String,
    call_seq: u32,
    entry_seq: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedFactRequest {
    kind: BoundedFactKind,
    trace: FactSourceContext,
    activation: FactActivationContext,
    target_modules: Vec<String>,
}

#[derive(Debug, Deserialize)]
enum BoundedFactKind {
    #[serde(rename = "function_facts_bounded")]
    FunctionFactsBounded,
}

impl BoundedFactRequest {
    fn context(&self) -> FunctionFactContext<'_> {
        FunctionFactContext {
            trace: self.trace.borrowed(),
            activation: FactActivationSelector {
                trace: self.activation.trace.borrowed(),
                function: &self.activation.function,
                call_seq: self.activation.call_seq,
                entry_seq: self.activation.entry_seq,
            },
        }
    }

    fn validate_modules(&self) -> anyhow::Result<()> {
        for (index, module) in self.target_modules.iter().enumerate() {
            let bytes = module.as_bytes();
            // common-types.md canonical module grammar; preserve request order.
            if bytes.is_empty()
                || bytes.len() > 128
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes[1..].iter().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
                })
                || self.target_modules[..index].contains(module)
            {
                anyhow::bail!("invalid or duplicate target_modules");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMappingRequest {
    kind: RuntimeMappingKind,
    call_seq: u32,
    entry_seq: u32,
    function: String,
    target_modules: Vec<String>,
}

#[derive(Debug, Deserialize)]
enum RuntimeMappingKind {
    #[serde(rename = "runtime_mapping")]
    RuntimeMapping,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressProvenanceRequest {
    kind: AddressProvenanceKind,
    call_seq: u32,
    entry_seq: u32,
    function: String,
    target_modules: Vec<String>,
}

#[derive(Debug, Deserialize)]
enum AddressProvenanceKind {
    #[serde(rename = "address_provenance")]
    AddressProvenance,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerReturnRequest {
    kind: CallerReturnKind,
    call_seq: u32,
    entry_seq: u32,
    function: String,
    target_modules: Vec<String>,
}
#[derive(Debug, Deserialize)]
enum CallerReturnKind {
    #[serde(rename = "caller_return_uses")]
    CallerReturnUses,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputSlotRequest {
    kind: OutputSlotKind,
    call_seq: u32,
    entry_seq: u32,
    function: String,
    target_modules: Vec<String>,
    slot_ranges: Vec<trace_core::api_types::OutputSlotRangeDto>,
}
#[derive(Debug, Deserialize)]
enum OutputSlotKind {
    #[serde(rename = "output_slot_uses")]
    OutputSlotUses,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateFrameRequest {
    kind: PrivateFrameKind,
    call_seq: u32,
    entry_seq: u32,
    function: String,
    target_modules: Vec<String>,
}
#[derive(Debug, Deserialize)]
enum PrivateFrameKind {
    #[serde(rename = "private_frame_operands")]
    PrivateFrameOperands,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetHistoryRequest {
    kind: TargetHistoryKind,
    call_seq: u32,
    entry_seq: u32,
    function: String,
    target_modules: Vec<String>,
    selected: trace_core::api_types::TargetHistorySelectionDto,
    capture_seq: u32,
}
#[derive(Debug, Deserialize)]
enum TargetHistoryKind {
    #[serde(rename = "target_write_history")]
    TargetWriteHistory,
}

pub(crate) fn requested() -> bool {
    std::env::args().any(|arg| arg == "--function-facts-helper" || arg == "--function-fact-helper")
}

#[cfg(not(unix))]
pub(crate) fn run() -> anyhow::Result<()> {
    anyhow::bail!("fd helper is only supported on Unix")
}

#[cfg(unix)]
pub(crate) fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let trace_fd = parse_fd_arg(&args, "--trace-fd")?;
    validate_inherited_fd(trace_fd)?;

    let trace = unsafe { File::from_raw_fd(trace_fd) };
    ensure_regular(&trace, "trace fd")?;

    let request_bytes = read_stdin_bounded()?;
    // 只按显式 kind 分派，再从原始字节 strict 解析；不跨协议 fallback。
    let control: serde_json::Value = serde_json::from_slice(&request_bytes)?;
    let bounded_request = match control.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == "function_facts_bounded" => {
            let request: BoundedFactRequest = serde_json::from_slice(&request_bytes)?;
            request.validate_modules()?;
            Some(request)
        }
        _ => None,
    };
    let history_request = match control.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == "target_write_history" => Some(
            serde_json::from_slice::<TargetHistoryRequest>(&request_bytes)?,
        ),
        _ => None,
    };
    let private_request = match control.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == "private_frame_operands" => Some(
            serde_json::from_slice::<PrivateFrameRequest>(&request_bytes)?,
        ),
        _ => None,
    };
    let output_request = match control.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == "output_slot_uses" => Some(
            serde_json::from_slice::<OutputSlotRequest>(&request_bytes)?,
        ),
        _ => None,
    };
    let return_request = match control.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == "caller_return_uses" => Some(
            serde_json::from_slice::<CallerReturnRequest>(&request_bytes)?,
        ),
        _ => None,
    };
    let address_request = match control.get("kind") {
        Some(serde_json::Value::String(kind)) if kind == "address_provenance" => Some(
            serde_json::from_slice::<AddressProvenanceRequest>(&request_bytes)?,
        ),
        _ => None,
    };
    let mapping_request = match control.get("kind") {
        None => None,
        Some(serde_json::Value::String(kind)) if kind == "runtime_mapping" => Some(
            serde_json::from_slice::<RuntimeMappingRequest>(&request_bytes)?,
        ),
        Some(serde_json::Value::String(kind)) if kind == "address_provenance" || kind == "caller_return_uses" || kind == "output_slot_uses" || kind == "private_frame_operands" || kind == "target_write_history" || kind == "function_facts_bounded" => None,
        Some(_) => anyhow::bail!("unknown fact helper request kind"),
    };
    let fact_request = if bounded_request.is_none() && mapping_request.is_none() && address_request.is_none() && return_request.is_none() && output_request.is_none() && private_request.is_none() && history_request.is_none() {
        Some(serde_json::from_slice::<FactHelperRequest>(&request_bytes)?)
    } else {
        None
    };

    let engine = Arc::new(TraceEngine::new());
    let session_info = engine
        .create_session_from_file(trace, &format!("inherited-fd:{trace_fd}"))
        .map_err(|error| anyhow::anyhow!("failed to create session from trace fd: {error}"))?;
    let sid = session_info.session_id;

    engine
        .build_index(
            &sid,
            BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .map_err(|error| anyhow::anyhow!("failed to build index: {error}"))?;

    if let Some(request) = bounded_request {
        let BoundedFactKind::FunctionFactsBounded = request.kind;
        let context = request.context();
        let bundle = engine.get_function_facts_bounded(
            &sid,
            context,
            &request.target_modules,
            &AtomicBool::new(false),
        )?;
        // Formal projection (trace/activation/anchors) has its own fixed 64 MiB
        // gate. Compact legacy-shaped wire bytes are a separate transport gate.
        write_function_fact_projection(context, &bundle, &mut io::sink())?;
        return write_response(&bundle);
    }
    if let Some(request) = history_request {
        let TargetHistoryKind::TargetWriteHistory = request.kind;
        return write_response(&engine.get_target_write_history(
            &sid, request.call_seq, request.entry_seq, &request.function,
            &request.target_modules, &request.selected, request.capture_seq,
        )?);
    }
    if let Some(request) = private_request {
        let PrivateFrameKind::PrivateFrameOperands = request.kind;
        return write_response(&engine.get_private_frame_operands(
            &sid, request.call_seq, request.entry_seq, &request.function, &request.target_modules,
        )?);
    }
    if let Some(request) = output_request {
        let OutputSlotKind::OutputSlotUses = request.kind;
        return write_response(&engine.get_output_slot_uses(
            &sid, request.call_seq, request.entry_seq, &request.function,
            &request.target_modules, &request.slot_ranges,
        )?);
    }
    if let Some(request) = return_request {
        let CallerReturnKind::CallerReturnUses = request.kind;
        return write_response(&engine.get_caller_return_uses(
            &sid, request.call_seq, request.entry_seq, &request.function, &request.target_modules,
        )?);
    }
    if let Some(request) = address_request {
        let AddressProvenanceKind::AddressProvenance = request.kind;
        let proof = engine.get_address_provenance(
            &sid,
            request.call_seq,
            request.entry_seq,
            &request.function,
            &request.target_modules,
        )?;
        return write_response(&proof);
    }
    if let Some(request) = mapping_request {
        let RuntimeMappingKind::RuntimeMapping = request.kind;
        let mapping = engine.get_runtime_mapping(
            &sid,
            request.call_seq,
            request.entry_seq,
            &request.function,
            &request.target_modules,
        )?;
        return write_response(&mapping);
    }
    // Compatibility only: the no-kind legacy fact request is not construction-bounded.
    let request = fact_request.expect("explicit protocol dispatch");
    let bundle = engine
        .get_function_facts_for_modules(
            &sid,
            request.call_seq,
            request.entry_seq,
            &request.target_modules,
        )
        .map_err(|error| anyhow::anyhow!("get_function_facts failed: {error}"))?;

    if let Some(ref expected_function) = request.function {
        if &bundle.function != expected_function {
            anyhow::bail!(
                "function site mismatch: expected {expected_function}, got {}",
                bundle.function
            );
        }
    }

    write_response(&bundle)?;
    Ok(())
}

#[cfg(unix)]
fn parse_fd_arg(args: &[String], flag: &str) -> anyhow::Result<RawFd> {
    let position = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| anyhow::anyhow!("missing required {flag} argument"))?;
    let value = args
        .get(position + 1)
        .ok_or_else(|| anyhow::anyhow!("missing value after {flag}"))?;
    value
        .parse::<RawFd>()
        .map_err(|error| anyhow::anyhow!("invalid descriptor '{value}' for {flag}: {error}"))
}

#[cfg(unix)]
fn validate_inherited_fd(trace_fd: RawFd) -> anyhow::Result<()> {
    if trace_fd < 3 {
        anyhow::bail!("trace fd must not use reserved standard descriptors 0, 1, or 2");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_regular(file: &File, label: &str) -> anyhow::Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("{label} metadata failed: {error}"))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{label} is not a regular file");
    }
    Ok(())
}

#[cfg(unix)]
fn read_stdin_bounded() -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut stdin = io::stdin()
        .lock()
        .take((MAX_CONTROL_BYTES as u64).saturating_add(1));
    stdin
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("control request read failed: {error}"))?;
    if bytes.len() > MAX_CONTROL_BYTES {
        anyhow::bail!("control request exceeds {MAX_CONTROL_BYTES} byte limit");
    }
    Ok(bytes)
}

/// 限制写入字节总量的 Writer，超过 limit 立即报错。
pub struct BoundedWriter<W: Write> {
    inner: W,
    written: usize,
    limit: usize,
}

impl<W: Write> BoundedWriter<W> {
    pub fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            written: 0,
            limit,
        }
    }

    #[cfg(test)]
    pub fn written(&self) -> usize {
        self.written
    }

    #[cfg(test)]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self
            .limit
            .checked_sub(self.written)
            .ok_or_else(|| io::Error::other("byte limit exceeded"))?;
        if buf.len() > remaining {
            return Err(io::Error::other(format!(
                "output exceeds {} byte limit (attempted {} bytes)",
                self.limit,
                self.written + buf.len()
            )));
        }
        let n = self.inner.write(buf)?;
        self.written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(unix)]
fn encode_response(bundle: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut bounded = BoundedWriter::new(&mut buffer, MAX_FACT_BUNDLE_BYTES);
    serde_json::to_writer(&mut bounded, bundle)
        .map_err(|error| anyhow::anyhow!("response encoding failed: {error}"))?;
    bounded
        .write_all(b"\n")
        .map_err(|error| anyhow::anyhow!("trailing newline failed: {error}"))?;
    Ok(buffer)
}

#[cfg(unix)]
fn write_response(bundle: &impl Serialize) -> anyhow::Result<()> {
    let encoded = encode_response(bundle)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&encoded)
        .and_then(|_| stdout.flush())
        .map_err(|error| anyhow::anyhow!("response write failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_aborts_when_exceeding_limit() {
        let mut out = Vec::new();
        let mut writer = BoundedWriter::new(&mut out, 10);
        assert!(writer.write_all(b"12345").is_ok());
        assert_eq!(writer.written(), 5);
        let err = writer.write_all(b"123456").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("output exceeds 10 byte limit"));
    }

    #[test]
    fn bounded_writer_succeeds_within_limit() {
        let mut out = Vec::new();
        let mut writer = BoundedWriter::new(&mut out, 10);
        assert!(writer.write_all(b"1234567890").is_ok());
        assert_eq!(writer.written(), 10);
        let inner = writer.into_inner();
        assert_eq!(inner, b"1234567890");
    }
}
