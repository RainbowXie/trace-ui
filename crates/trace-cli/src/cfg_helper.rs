//! 单个已打开只读 trace 的 CFG 查询协议；不是 Evidence 或持久化格式。
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use trace_core::control_flow::{
    render_dot,
    types::{CfgPage, CfgView},
};
use trace_core::TraceEngine;

const MAX_CONTROL_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_DOT_EDGES: usize = 100_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    offset: usize,
    limit: usize,
}
impl Page {
    fn checked(self) -> anyhow::Result<CfgPage> {
        anyhow::ensure!(self.limit <= 10_000, "CFG page capacity exceeded");
        anyhow::ensure!(
            self.offset.checked_add(self.limit).is_some(),
            "CFG page overflow"
        );
        Ok(CfgPage {
            offset: self.offset,
            limit: self.limit,
        })
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    Json,
    Dot,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "query", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Activation {
        function: String,
        call_seq: u32,
        entry_seq: u32,
        format: Format,
        #[serde(default, deserialize_with = "present_page")]
        blocks: Option<Page>,
        #[serde(default, deserialize_with = "present_page")]
        occurrences: Option<Page>,
    },
    Function {
        function: String,
        format: Format,
        #[serde(default, deserialize_with = "present_page")]
        blocks: Option<Page>,
        #[serde(default, deserialize_with = "present_page")]
        occurrences: Option<Page>,
    },
}
fn present_page<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Page>, D::Error> {
    Page::deserialize(deserializer).map(Some)
}
#[derive(Serialize)]
struct Response<'a> {
    query: &'static str,
    function: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_seq: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_seq: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<&'a CfgView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dot: Option<&'a str>,
}

pub(crate) fn requested() -> bool {
    std::env::args().any(|arg| arg == "--cfg-helper")
}
pub(crate) fn run() -> anyhow::Result<()> {
    if let Err(error) = execute() {
        // 只输出有界诊断，失败时 stdout 仍为空。
        let message = format!("cfg helper failed: {error}");
        let bounded: String = message.chars().take(4096).collect();
        let _ = writeln!(io::stderr().lock(), "{bounded}");
        std::process::exit(1);
    }
    Ok(())
}
#[cfg(not(unix))]
fn execute() -> anyhow::Result<()> {
    anyhow::bail!("fd helper is only supported on Unix")
}

#[cfg(unix)]
fn execute() -> anyhow::Result<()> {
    use std::fs::File;
    use std::os::fd::FromRawFd;
    let args: Vec<String> = std::env::args().collect();
    let fd = parse_args(&args)?;
    // fcntl 核验访问模式；调用方仍负责 no-follow 打开和来源授权。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    anyhow::ensure!(flags >= 0, "invalid inherited trace descriptor");
    anyhow::ensure!(
        flags & libc::O_ACCMODE == libc::O_RDONLY,
        "trace fd must be read-only"
    );
    let trace = unsafe { File::from_raw_fd(fd) };
    anyhow::ensure!(
        trace.metadata()?.is_file(),
        "trace fd is not a regular file"
    );
    let mut control = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_CONTROL_BYTES + 1) as u64)
        .read_to_end(&mut control)?;
    anyhow::ensure!(
        control.len() <= MAX_CONTROL_BYTES,
        "control request capacity exceeded"
    );
    let request: Request = serde_json::from_slice(&control)?;
    let (query, function, anchors, format, blocks, occurrences) = match request {
        Request::Activation {
            function,
            call_seq,
            entry_seq,
            format,
            blocks,
            occurrences,
        } => (
            "activation",
            function,
            Some((call_seq, entry_seq)),
            format,
            blocks,
            occurrences,
        ),
        Request::Function {
            function,
            format,
            blocks,
            occurrences,
        } => ("function", function, None, format, blocks, occurrences),
    };
    validate_function(&function)?;
    let (blocks, occurrences) = pages(&format, blocks, occurrences)?;
    let engine = TraceEngine::new();
    let session = engine.create_session_from_file(trace, &format!("inherited-fd:{fd}"))?;
    engine.build_control_flow_index(&session.session_id)?;
    let view = if let Some((call, entry)) = anchors {
        engine.get_activation_cfg(
            &session.session_id,
            call,
            entry,
            &function,
            blocks,
            occurrences,
        )?
    } else {
        engine.get_function_cfg(&session.session_id, &function, blocks, occurrences)?
    };
    let dot = if matches!(format, Format::Dot) {
        anyhow::ensure!(
            view.blocks.len() == view.total_blocks,
            "DOT requires complete blocks"
        );
        anyhow::ensure!(
            view.edges.len() <= MAX_DOT_EDGES,
            "DOT edge capacity exceeded"
        );
        // 完整候选预算先检查，再调用同一 core renderer；不导出局部首页。
        encode(&view, MAX_RESPONSE_BYTES)?;
        Some(render_dot(&view)?)
    } else {
        None
    };
    let response = Response {
        query,
        function: &function,
        call_seq: anchors.map(|a| a.0),
        entry_seq: anchors.map(|a| a.1),
        view: if dot.is_none() { Some(&view) } else { None },
        dot: dot.as_deref(),
    };
    let encoded = encode(&response, MAX_RESPONSE_BYTES)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&encoded)?;
    stdout.flush()?;
    Ok(())
}
fn parse_args(args: &[String]) -> anyhow::Result<i32> {
    anyhow::ensure!(
        args.len() == 4 && args[1] == "--cfg-helper" && args[2] == "--trace-fd",
        "expected --cfg-helper --trace-fd N only"
    );
    let fd: i32 = args[3].parse()?;
    anyhow::ensure!(fd >= 3, "trace fd must not use standard descriptors");
    Ok(fd)
}
fn validate_function(function: &str) -> anyhow::Result<()> {
    let (module, hex) = function
        .split_once("+0x")
        .ok_or_else(|| anyhow::anyhow!("expected canonical stable function site"))?;
    let bytes = module.as_bytes();
    anyhow::ensure!(
        !bytes.is_empty()
            && bytes.len() <= 128
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b)),
        "invalid stable function module"
    );
    anyhow::ensure!(
        !hex.is_empty()
            && hex.len() <= 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (hex == "0" || !hex.starts_with('0')),
        "invalid canonical function offset"
    );
    Ok(())
}
fn pages(
    format: &Format,
    blocks: Option<Page>,
    occurrences: Option<Page>,
) -> anyhow::Result<(CfgPage, CfgPage)> {
    match format {
        Format::Json => Ok((
            blocks
                .ok_or_else(|| anyhow::anyhow!("JSON requires blocks page"))?
                .checked()?,
            occurrences
                .ok_or_else(|| anyhow::anyhow!("JSON requires occurrences page"))?
                .checked()?,
        )),
        Format::Dot => {
            anyhow::ensure!(
                blocks.is_none() && occurrences.is_none(),
                "DOT does not accept pagination"
            );
            Ok((
                CfgPage {
                    offset: 0,
                    limit: 10_000,
                },
                CfgPage {
                    offset: 0,
                    limit: 0,
                },
            ))
        }
    }
}
fn encode<T: Serialize>(value: &T, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    let mut writer = super::fact_helper::BoundedWriter::new(&mut encoded, limit);
    serde_json::to_writer(&mut writer, value)?;
    writer.write_all(b"\n")?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cfg_request_is_strict_and_bounded() {
        for text in [
            r#"{"query":"function","function":"m+0x1","format":"json","session":"x"}"#,
            r#"{"query":"activation","function":"m+0x1","format":"dot","call_seq":4294967296,"entry_seq":2}"#,
            r#"{"query":"function","function":"m+0x1","format":"json","blocks":{"offset":0,"limit":1,"other":1}}"#,
        ] {
            assert!(serde_json::from_str::<Request>(text).is_err());
        }
        assert!(pages(&Format::Json, None, None).is_err());
        assert!(pages(
            &Format::Dot,
            Some(Page {
                offset: 0,
                limit: 1
            }),
            None
        )
        .is_err());
        assert!(Page {
            offset: usize::MAX,
            limit: 1
        }
        .checked()
        .is_err());
        assert!(Page {
            offset: 0,
            limit: 10_001
        }
        .checked()
        .is_err());
        assert!(encode(&"oversize", 2).is_err());
        for site in ["m+0x01", "m+0xA", "/m+0x1", "m+0x10000000000000000"] {
            assert!(validate_function(site).is_err());
        }
        assert!(validate_function("libmetasec_ov.so+0x143438").is_ok());
        assert!(parse_args(
            &["cli", "--cfg-helper", "--trace-fd", "3", "--other"].map(str::to_owned)
        )
        .is_err());
    }
}
