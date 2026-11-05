use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::{Result, TraceError};
use crate::session::SessionState;

use super::super::activation::{stable_runtime_parts, stable_runtime_site};
use super::block_stream::{oversize_error, RAW_LINE_LIMIT};

// 单行工作区上限与越界错误都由 block_stream 定义：两条路径必须共用同一条
// 资源边界，否则同一份 trace 会在行扫描与模块索引上得到不同判定。

/// 旁路缓存后缀（TCACHE03 header + bincode），文件名 `<identity-hash>.modules.bin`。
const MODULES_CACHE_SUFFIX: &str = ".modules";

/// 载荷布局标识。TCACHE03 头部只绑定 trace 身份，不描述 bincode 形状；
/// `ModuleIndex` 形状变更必须换成新标识，旧文件才会在反序列化**之前**被
/// 拒绝——按新形状读旧字节会得到垃圾长度并让 bincode 申请荒谬内存。
const MODULES_MAGIC: &[u8; 8] = b"TMODULE1";

pub(crate) struct StableGlobalMap {
    pub(super) bases: BTreeMap<String, u64>,
    pub(super) target_modules: BTreeSet<String>,
    sources: BTreeMap<String, crate::api_types::RuntimeMappingSourceDto>,
}

/// 一个模块在整份 trace 内的基址观测结果。
///
/// 变体携带**按行序第一个**冲突/下溢的行号：原实现逐模块顺序扫描并在第一个
/// 出错行返回，错误优先级因此由行序（`collect`）或模块序列
/// （`validate_mappings`）决定，这里保留同样的证据而不是只存一个布尔标记。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum BaseStatus {
    Unique(u64),
    Underflow(u32),
    Inconsistent(u32),
}

/// 该模块首条带指令结构签名的稳定位置（runtime mapping 的 source 只认它）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Source {
    pub(super) seq: u32,
    pub(super) runtime: u64,
    pub(super) offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ModuleRecord {
    pub(super) base: BaseStatus,
    pub(super) source: Option<Source>,
}

/// 整份 trace 的模块基址索引。模块数量远小于行数，因此可以整份持久化：
/// 一次单遍扫描后，后续子进程在 O(模块数) 内完成校验与映射读取。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ModuleIndex {
    pub(super) modules: BTreeMap<String, ModuleRecord>,
    /// 首个超出单行工作区上限的行号，`None` = 全文都在上限内。
    pub(super) oversize_seq: Option<u32>,
}

impl ModuleIndex {
    fn load(state: &SessionState) -> Option<Self> {
        let bytes = crate::cache::load_bincode_raw(
            &state.cache_identity,
            state.mmap.len() as u64,
            &state.trace_hash,
            MODULES_CACHE_SUFFIX,
        )?;
        let payload = bytes.strip_prefix(MODULES_MAGIC.as_slice())?;
        bincode::deserialize(payload).ok()
    }

    fn store(&self, state: &SessionState) {
        let mut payload = Vec::from(MODULES_MAGIC.as_slice());
        let Ok(()) = bincode::serialize_into(&mut payload, self) else {
            return;
        };
        crate::cache::save_bincode_raw(
            &state.cache_identity,
            state.mmap.len() as u64,
            &state.trace_hash,
            MODULES_CACHE_SUFFIX,
            &payload,
        );
    }

    /// 连续字节流单遍扫描：按 LF 切行（去 CR），逐行取模块名与其 runtime/offset。
    ///
    /// 原实现用 `LineIndexView::get_line` 逐行取样，每 256 行才有一个采样点，
    /// 单次全表遍历因此被放大到 128.5 倍；这里直接沿 mmap 推进，不触碰采样索引。
    fn scan(state: &SessionState, cancel: Option<&AtomicBool>) -> Result<Self> {
        let data: &[u8] = &state.mmap;
        let mut modules: BTreeMap<String, ModuleRecord> = BTreeMap::new();
        let mut oversize_seq = None;
        let mut seq: u32 = 0;
        let mut start = 0usize;
        while start < data.len() {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(TraceError::Cancelled);
            }
            let end = memchr::memchr(b'\n', &data[start..])
                .map(|relative| start + relative)
                .unwrap_or(data.len());
            let raw = &data[start..end];
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            if oversize_seq.is_none() && raw.len() > RAW_LINE_LIMIT {
                oversize_seq = Some(seq);
            }
            if let Ok(line) = std::str::from_utf8(raw) {
                if let Some((module, runtime, offset)) = stable_runtime_parts(line) {
                    match modules.get_mut(module) {
                        Some(record) => apply_line(record, runtime, offset, seq, line),
                        None => {
                            // 只有新模块才分配模块名：重复出现的行不产生分配。
                            modules.insert(
                                module.to_owned(),
                                ModuleRecord::first(runtime, offset, seq, line),
                            );
                        }
                    }
                }
            }
            start = end + 1;
            // 行号就是采样索引的 seq；索引本身是 u32，超出即不可寻址。
            seq = seq.saturating_add(1);
        }
        Ok(Self {
            modules,
            oversize_seq,
        })
    }
}

impl ModuleRecord {
    fn first(runtime: u64, offset: u64, seq: u32, line: &str) -> Self {
        let mut record = Self {
            base: match runtime.checked_sub(offset) {
                Some(base) => BaseStatus::Unique(base),
                None => BaseStatus::Underflow(seq),
            },
            source: None,
        };
        record.remember_source(runtime, offset, seq, line);
        record
    }

    /// source 取该模块**首条**带指令结构签名的行；一旦记下就不再解析，
    /// 后续同模块行只有基址参与判定。
    fn remember_source(&mut self, runtime: u64, offset: u64, seq: u32, line: &str) {
        if self.source.is_none() && trace_parser::strict_memory::instruction_parts(line).is_some() {
            self.source = Some(Source {
                seq,
                runtime,
                offset,
            });
        }
    }
}

fn apply_line(record: &mut ModuleRecord, runtime: u64, offset: u64, seq: u32, line: &str) {
    record.remember_source(runtime, offset, seq, line);
    match record.base {
        BaseStatus::Unique(base) => {
            record.base = match runtime.checked_sub(offset) {
                Some(next) if next == base => BaseStatus::Unique(base),
                Some(_) => BaseStatus::Inconsistent(seq),
                None => BaseStatus::Underflow(seq),
            };
        }
        // 第一个错误已经确定：原实现此时已返回，后续行不得改写判定。
        BaseStatus::Underflow(_) | BaseStatus::Inconsistent(_) => {}
    }
}

/// 取整份 trace 的模块基址索引：缓存命中即返回，否则单遍扫描后落盘。
///
/// `cancel` 只覆盖扫描本身；缓存命中不读原文，没有可取消的工作。
pub(super) fn module_index(state: &SessionState, cancel: Option<&AtomicBool>) -> Result<ModuleIndex> {
    if let Some(index) = ModuleIndex::load(state) {
        return Ok(index);
    }
    let index = ModuleIndex::scan(state, cancel)?;
    index.store(state);
    Ok(index)
}

/// 校验目标模块在整份 trace 内的基址一致性。
///
/// 调用方已要求行索引就绪；本实现只读 mmap，不再依赖采样行索引逐行取样。
pub(super) fn validate_mappings(
    state: &SessionState,
    modules: &[String],
    cancel: &AtomicBool,
) -> Result<()> {
    if modules.is_empty() {
        return Ok(());
    }
    let index = module_index(state, Some(cancel))?;
    for module in modules {
        let Some(record) = index.modules.get(module) else {
            continue;
        };
        let module_error = match record.base {
            BaseStatus::Unique(_) => None,
            BaseStatus::Underflow(seq) => Some((seq, false)),
            BaseStatus::Inconsistent(seq) => Some((seq, true)),
        };
        // 原实现逐模块按行序扫描，且 `check_raw` 先于基址解析执行：整份 trace
        // 的单行上限错误若出现在该模块的基址冲突之前——或与它同行——就先报
        // 资源错误。
        match (module_error, index.oversize_seq) {
            (Some((seq, _)), Some(oversize)) if oversize <= seq => return Err(oversize_error()),
            (Some((_, true)), _) => {
                return Err(TraceError::InvalidArgument(format!(
                    "module {module} has inconsistent runtime bases"
                )))
            }
            (Some((_, false)), _) => {
                return Err(TraceError::InvalidArgument(format!(
                    "module {module} runtime address is below its stable offset"
                )))
            }
            (None, Some(_)) => return Err(oversize_error()),
            (None, None) => {}
        }
    }
    Ok(())
}

impl StableGlobalMap {
    pub(crate) fn collect(state: &SessionState, target_modules: &[String]) -> Result<Self> {
        let target_modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        let mut bases = BTreeMap::new();
        let mut sources = BTreeMap::new();
        if target_modules.is_empty() {
            return Ok(Self {
                bases,
                target_modules,
                sources,
            });
        }
        // collect 从不借用行文本，因此忽略单行上限证据（与原有行为一致）。
        let index = module_index(state, None)?;
        let mut first_error: Option<(u32, String, bool)> = None;
        for module in &target_modules {
            let Some(record) = index.modules.get(module) else {
                continue;
            };
            match record.base {
                BaseStatus::Unique(base) => {
                    bases.insert(module.clone(), base);
                }
                // 原实现沿行序推进，报告的是全表范围内最早出现的那个模块错误。
                BaseStatus::Underflow(seq) => {
                    first_error = earliest(first_error, seq, module, false);
                }
                BaseStatus::Inconsistent(seq) => {
                    first_error = earliest(first_error, seq, module, true);
                }
            }
            if let Some(source) = &record.source {
                sources.insert(
                    module.clone(),
                    crate::api_types::RuntimeMappingSourceDto {
                        seq: source.seq,
                        runtime_pc: format!("0x{:x}", source.runtime),
                        stable_offset: format!("0x{:x}", source.offset),
                    },
                );
            }
        }
        if let Some((_, module, inconsistent)) = first_error {
            return Err(TraceError::InvalidArgument(if inconsistent {
                format!("module {module} has inconsistent runtime bases")
            } else {
                format!("module {module} runtime address is below its stable offset")
            }));
        }
        Ok(Self {
            bases,
            target_modules,
            sources,
        })
    }
}

fn earliest(
    current: Option<(u32, String, bool)>,
    seq: u32,
    module: &str,
    inconsistent: bool,
) -> Option<(u32, String, bool)> {
    if current
        .as_ref()
        .is_some_and(|(existing, _, _)| *existing <= seq)
    {
        return current;
    }
    Some((seq, module.to_owned(), inconsistent))
}

impl crate::engine::TraceEngine {
    /// 从选定闭合调用和 raw trace 取得临时坐标，不推断 segment 或 global 归属。
    pub fn get_runtime_mapping(
        &self,
        session_id: &str,
        call_seq: u32,
        entry_seq: u32,
        function: &str,
        target_modules: &[String],
    ) -> Result<crate::api_types::RuntimeMappingDto> {
        use super::super::activation::stable_site;
        use crate::api_types::{RuntimeMappingDto, RuntimeModuleMappingDto};
        let invalid = |message: &str| TraceError::InvalidArgument(message.to_owned());
        let modules = target_modules.iter().cloned().collect::<BTreeSet<_>>();
        if modules.is_empty()
            || target_modules.len() > 500
            || modules.len() != target_modules.len()
            || modules.iter().any(|module| {
                let site = format!("{module}+0x0");
                stable_site(&format!("[{module}] 0x0!0x0 nop")).as_deref() != Some(&site)
            })
        {
            return Err(invalid(
                "invalid or duplicate target_modules (expected 1..=500 canonical names)",
            ));
        }
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|error| TraceError::Internal(error.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let activation = tree
            .activations
            .iter()
            .find(|item| item.call_seq == call_seq && item.entry_seq == entry_seq)
            .ok_or_else(|| invalid("runtime mapping selector not found"))?;
        if activation.id == 0
            || activation.unresolved_reason.is_some()
            || !(call_seq < entry_seq
                && entry_seq <= activation.exit_seq
                && activation.exit_seq < activation.resume_seq
                && activation.resume_seq < state.total_lines)
        {
            return Err(invalid(
                "runtime mapping requires a closed Confirmed Activation",
            ));
        }
        let lines = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        for seq in [
            call_seq,
            entry_seq,
            activation.exit_seq,
            activation.resume_seq,
        ] {
            let line = lines
                .get_line(&state.mmap, seq)
                .and_then(|raw| std::str::from_utf8(raw).ok())
                .ok_or_else(|| invalid("runtime mapping boundary missing"))?;
            if trace_parser::strict_memory::instruction_parts(line).is_none()
                || stable_runtime_site(line).is_none()
            {
                return Err(invalid(
                    "runtime mapping boundary lacks an instruction site",
                ));
            }
            if seq == entry_seq && stable_site(line).as_deref() != Some(function) {
                return Err(invalid("runtime mapping function site mismatch"));
            }
        }
        let map = StableGlobalMap::collect(&state, target_modules)?;
        let mut mappings = Vec::new();
        for module in &modules {
            let base = map
                .bases
                .get(module)
                .ok_or_else(|| invalid("target module missing from trace"))?;
            let source = map
                .sources
                .get(module)
                .ok_or_else(|| invalid("target module lacks an instruction source"))?;
            mappings.push(RuntimeModuleMappingDto {
                module: module.clone(),
                runtime_base: format!("0x{base:x}"),
                source: crate::api_types::RuntimeMappingSourceDto {
                    seq: source.seq,
                    runtime_pc: source.runtime_pc.clone(),
                    stable_offset: source.stable_offset.clone(),
                },
            });
        }
        Ok(RuntimeMappingDto {
            call_seq,
            entry_seq,
            function: function.to_owned(),
            exit_seq: activation.exit_seq,
            resume_seq: activation.resume_seq,
            target_modules: modules.into_iter().collect(),
            mappings,
        })
    }
}
