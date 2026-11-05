use std::collections::HashMap;
use std::sync::atomic::Ordering;

use crate::api_types::{BuildOptions, BuildResult, Phase, Progress, ProgressCallback};
use crate::cache;
use crate::error::{Result, TraceError};
use crate::flat::archives::{CachedStore, Phase2Archive, ScanArchive};
use crate::flat::convert;
use crate::flat::line_index::LineIndexArchive;
use crate::parallel::scan_unified_parallel;
use crate::scan_unified::{ProgressFn, ScanResult};

/// 内部枚举：区分缓存命中 vs 新鲜扫描结果
///
/// CacheHit 的 10 个字段整体 Box（large_enum_variant）：缓存命中是冷路径，
/// 一次堆分配换取枚举尺寸不膨胀。
enum IndexResult {
    CacheHit(Box<CacheHitData>),
    ScanResult(Box<ScanResult>),
}

struct CacheHitData {
    phase2_store: CachedStore<Phase2Archive>,
    call_tree: crate::query::call_tree::CallTree,
    /// V7 缓存必携带（build 时已验反序列化成功）；此处 Option 仅匹配
    /// 反序列化接口签名，None 不可能出现（出现即上层已判 miss）。
    activation_tree: crate::query::activation::ActivationTree,
    string_index: Option<crate::query::strings::StringIndex>,
    /// `None` = 本次查询不访问 `deps`/`pair_split`，跳过了 `.scan.cache`。
    scan_store: Option<CachedStore<ScanArchive>>,
    reg_last_def: Option<crate::scanner::RegLastDef>,
    lidx_store: CachedStore<LineIndexArchive>,
    total_lines: u32,
    format: trace_parser::types::TraceFormat,
    call_annotations: HashMap<u32, trace_parser::gumtrace::CallAnnotation>,
    consumed_seqs: Vec<u32>,
}

/// 缓存命中路径是否必须加载 `.scan.cache`。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanCacheRequirement {
    Required,
    Deferred,
}

impl super::TraceEngine {
    pub fn build_index(
        &self,
        session_id: &str,
        options: BuildOptions,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        self.build_index_with(session_id, options, ScanCacheRequirement::Required, on_progress)
    }

    /// 为只依赖 `Phase2Archive` 与 `LineIndexArchive` 的 fact 查询建立索引。
    ///
    /// 这类查询（runtime mapping 等 6 类 helper 请求）从不读 `deps`/`pair_split`，
    /// 缓存命中时无需加载 931 MiB 的 `.scan.cache`；冷路径仍然完整扫描并落盘，
    /// 因此后续需要扫描索引的查询仍能命中同一批缓存。
    pub fn build_fact_index(
        &self,
        session_id: &str,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        self.build_index_with(
            session_id,
            BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            ScanCacheRequirement::Deferred,
            on_progress,
        )
    }

    fn build_index_with(
        &self,
        session_id: &str,
        options: BuildOptions,
        scan_cache: ScanCacheRequirement,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let handle = self.get_handle(session_id)?;

        // 防止重复构建：CAS false -> true
        handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TraceError::OperationInProgress("build_index".to_string()))?;

        // 重置取消标志
        handle.build_cancel.store(false, Ordering::SeqCst);

        let result = self.build_index_inner(session_id, &handle, options, scan_cache, on_progress);

        // 无论成功或失败，都重置 building 标志
        handle.building.store(false, Ordering::SeqCst);

        result
    }

    fn build_index_inner(
        &self,
        session_id: &str,
        handle: &crate::session::SessionHandle,
        options: BuildOptions,
        scan_cache: ScanCacheRequirement,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let (mmap_arc, cache_identity, trace_hash) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (
                state.mmap.clone(),
                state.cache_identity.clone(),
                state.trace_hash,
            )
        };

        let data: &[u8] = &mmap_arc;
        let trace_len = data.len() as u64;
        let force = options.force_rebuild;
        let skip_strings = options.skip_strings;

        // 检测格式
        let detected_format = trace_parser::gumtrace::detect_format(data);
        eprintln!(
            "[index] detected_format={:?}, force={}, cache_identity={}",
            detected_format, force, cache_identity
        );

        // 尝试从缓存加载（p2 + lidx 命中时成立；需要 deps 的查询另需 scan 命中）
        if !force {
            if let (Some(p2_mmap), Some(lidx_mmap)) = (
                cache::load_phase2_cache(&cache_identity, trace_len, &trace_hash),
                cache::load_lidx_cache(&cache_identity, trace_len, &trace_hash),
            ) {
                let scan_mmap = match scan_cache {
                    ScanCacheRequirement::Required => {
                        cache::load_scan_cache(&cache_identity, trace_len, &trace_hash)
                    }
                    // 不访问 deps 的查询不读 .scan.cache：省掉 931 MiB 的
                    // mmap、布局预检与摘要校验。
                    ScanCacheRequirement::Deferred => None,
                };
                if scan_cache == ScanCacheRequirement::Required && scan_mmap.is_none() {
                    return self.rescan(
                        session_id, handle, skip_strings, scan_cache, on_progress,
                    );
                }
                // 通知进度：缓存加载
                if let Some(ref cb) = on_progress {
                    cb(Progress {
                        session_id: session_id.to_string(),
                        phase: Phase::LoadingCache,
                        fraction: 0.5,
                        message: None,
                    });
                }

                let string_index = cache::load_string_cache(&cache_identity, trace_len, &trace_hash);

                let (call_annotations, consumed_seqs) =
                    if detected_format == trace_parser::types::TraceFormat::Gumtrace {
                        cache::load_gumtrace_extra(&cache_identity, trace_len, &trace_hash)
                            .unwrap_or_else(|| (HashMap::new(), Vec::new()))
                    } else {
                        (HashMap::new(), Vec::new())
                    };

                let phase2_store = CachedStore::Mapped(p2_mmap);
                // CallTree/ActivationTree 反序列化失败（位损坏/旧布局）= 该缓存
                // 不可信。不能返回错误（缓存损坏挡住一切），也不能带 None
                // 进入 CacheHit（查询永久 IndexNotReady 且下次仍命中同一坏
                // 缓存）——正确行为是放弃本次命中，回退全量重扫。
                let cache_payload = phase2_store.deserialize_call_tree().and_then(|call_tree| {
                    phase2_store
                        .deserialize_activation_tree()
                        .map(|activation_tree| (call_tree, activation_tree))
                });
                let (call_tree, activation_tree) = match cache_payload {
                    Some(t) => t,
                    None => {
                        eprintln!("[index] p2 cache payload corrupt; falling back to full rescan");
                        return self.rescan(
                            session_id, handle, skip_strings, scan_cache, on_progress,
                        );
                    }
                };

                let scan_store = scan_mmap.map(CachedStore::Mapped);
                let reg_last_def = scan_store
                    .as_ref()
                    .map(CachedStore::deserialize_reg_last_def);

                let lidx_store = CachedStore::Mapped(lidx_mmap);
                let total_lines = lidx_store.total_lines();
                // 三个文件独立原子发布只能保证“每个文件完整”，不能保证
                // 读者没有跨代混合。scan 与 lidx 的共享行数是加载时可验证的
                // generation 边界；跳过 scan 时改用 p2 里 ActivationTree 的
                // root exit（同一份构建的 total_lines）作同一道边界。不一致时
                // 放弃整组缓存并重扫。
                let stale = match &scan_store {
                    Some(scan) => {
                        let scan_lines = scan.line_count();
                        if scan_lines != total_lines {
                            eprintln!(
                                "[index] cache generation mismatch: scan_lines={scan_lines} lidx_lines={total_lines}; falling back to full rescan"
                            );
                        }
                        scan_lines != total_lines
                    }
                    None => {
                        // root activation 的 exit_seq 就是同一份构建的 total_lines。
                        // 反序列化可以接受 activations 为空的树，取首元素前必须
                        // 过滤：没有 root 就无从确定 generation，等同于跨代混合。
                        let p2_lines = activation_tree.activations.first().map(|root| root.exit_seq);
                        if p2_lines != Some(total_lines) {
                            eprintln!(
                                "[index] cache generation mismatch: p2_lines={p2_lines:?} lidx_lines={total_lines}; falling back to full rescan"
                            );
                        }
                        p2_lines != Some(total_lines)
                    }
                };
                if stale {
                    return self.rescan(
                        session_id, handle, skip_strings, scan_cache, on_progress,
                    );
                }

                eprintln!(
                    "[index] section cache hit: total_lines={}, format={:?}",
                    total_lines, detected_format
                );

                let result = IndexResult::CacheHit(Box::new(CacheHitData {
                    phase2_store,
                    call_tree,
                    activation_tree,
                    string_index,
                    scan_store,
                    reg_last_def,
                    lidx_store,
                    total_lines,
                    format: detected_format,
                    call_annotations,
                    consumed_seqs,
                }));

                return self.apply_index_result(session_id, handle, result, true);
            }
        }

        // 无缓存：发送初始进度
        if let Some(ref cb) = on_progress {
            cb(Progress {
                session_id: session_id.to_string(),
                phase: Phase::Scanning,
                fraction: 0.0,
                message: None,
            });
        }

        // 构造 ProgressFn（包装 on_progress 回调）
        // ProgressCallback 已是 Box<dyn Fn(Progress) + Send + Sync + 'static>，
        // 将其包在 Arc 里即可跨线程共享、并满足 ProgressFn 的 'static 约束。
        let sid = session_id.to_string();
        let progress_fn: Option<ProgressFn> = on_progress.map(|cb| {
            let cb_arc: std::sync::Arc<dyn Fn(Progress) + Send + Sync> = std::sync::Arc::from(cb);
            let progress_box: ProgressFn = Box::new(move |processed: usize, total: usize| {
                let fraction = if total == 0 {
                    0.0
                } else {
                    processed as f64 / total as f64
                };
                cb_arc(Progress {
                    session_id: sid.clone(),
                    phase: Phase::Scanning,
                    fraction,
                    message: None,
                });
            });
            progress_box
        });

        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let mut scan_result =
            scan_unified_parallel(data, false, false, skip_strings, progress_fn, num_cpus)
                .map_err(|e| TraceError::Internal(format!("统一扫描失败: {}", e)))?;

        // 格式检查：没有有效行
        if scan_result.scan_state.parsed_count == 0 && scan_result.scan_state.line_count > 0 {
            return Err(TraceError::ParseError {
                line: None,
                detail: "文件格式不正确：未检测到有效的 ARM64 trace 指令行".to_string(),
            });
        }

        // 格式检查：unidbg 缺少内存注解
        if scan_result.scan_state.parsed_count > 0
            && scan_result.scan_state.mem_op_count == 0
            && scan_result.format == trace_parser::types::TraceFormat::Unidbg
        {
            return Err(TraceError::ParseError {
                line: None,
                detail: "Trace 日志缺少内存访问注解（mem[WRITE]/mem[READ] 和 abs= 字段）。\n\n\
                         trace-ui 需要定制化的 unidbg 日志格式，标准 unidbg 输出不包含这些字段。\n\
                         请参考项目文档中的 unidbg 定制说明，启用内存读写打印后重新生成 trace 日志。"
                    .to_string(),
            });
        }

        // Compact
        eprintln!("[index] scan complete, compacting...");
        scan_result.scan_state.compact();
        eprintln!("[index] compact done");

        self.apply_index_result(
            session_id,
            handle,
            IndexResult::ScanResult(Box::new(scan_result)),
            false,
        )
    }

    /// 放弃缓存命中并全量重扫：缓存损坏或跨代混合时必须重建，而不是带着
    /// 半可信的索引继续查询。
    fn rescan(
        &self,
        session_id: &str,
        handle: &crate::session::SessionHandle,
        skip_strings: bool,
        scan_cache: ScanCacheRequirement,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        self.build_index_inner(
            session_id,
            handle,
            BuildOptions {
                force_rebuild: true,
                skip_strings,
            },
            scan_cache,
            on_progress,
        )
    }

    fn apply_index_result(
        &self,
        _session_id: &str,
        handle: &crate::session::SessionHandle,
        result: IndexResult,
        _from_cache: bool,
    ) -> Result<BuildResult> {
        match result {
            IndexResult::CacheHit(data) => {
                let CacheHitData {
                    phase2_store,
                    call_tree,
                    activation_tree,
                    string_index,
                    scan_store,
                    reg_last_def,
                    lidx_store,
                    total_lines,
                    format,
                    call_annotations,
                    consumed_seqs,
                } = *data;
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let has_string_index = string_index
                    .as_ref()
                    .map(|si| !si.strings.is_empty())
                    .unwrap_or(false);

                state.total_lines = total_lines;
                state.trace_format = format;
                state.call_annotations = call_annotations;
                state.consumed_seqs = consumed_seqs;
                state.rebuild_call_search_texts();

                state.call_tree = Some(call_tree);
                state.activation_tree = Some(activation_tree);
                state.string_index = string_index;
                state.reg_last_def = reg_last_def;
                state.phase2_store = Some(phase2_store);
                state.scan_store = scan_store;
                state.lidx_store = Some(lidx_store);

                eprintln!("[index] session populated from section cache");

                Ok(BuildResult {
                    total_lines,
                    has_string_index,
                    from_cache: true,
                })
            }

            IndexResult::ScanResult(scan_result) => {
                // 1. 在 write lock 外构建 archives
                let phase2 = scan_result.phase2;
                let call_tree = phase2.call_tree.clone();
                let activation_tree = phase2.activation_tree.clone();
                let string_index = phase2.string_index;

                let phase2_archive = Phase2Archive {
                    mem_accesses: convert::mem_access_to_flat(&phase2.mem_accesses),
                    reg_checkpoints: convert::reg_checkpoints_to_flat(&phase2.reg_checkpoints),
                    call_tree: phase2.call_tree,
                    activation_tree: phase2.activation_tree,
                };

                // fill_xref_counts：Phase2Archive 构建完成后，使用 flat view 计算 xref
                // 此时使用 flat 数据而非原始 MemAccessIndex，内存更友好
                let mut string_index = string_index;
                if !string_index.strings.is_empty() {
                    let mem_view = phase2_archive.mem_accesses.view();
                    eprintln!("[index] computing xref counts from flat view...");
                    let t_xref = std::time::Instant::now();
                    crate::query::strings::StringBuilder::fill_xref_counts_view(
                        &mut string_index,
                        &mem_view,
                    );
                    eprintln!("[index] xref counts done: {:?}", t_xref.elapsed());
                }

                let scan_state = &scan_result.scan_state;
                let scan_archive = ScanArchive {
                    deps: convert::deps_to_flat(&scan_state.deps),
                    mem_last_def: convert::mem_last_def_to_flat(&scan_state.mem_last_def),
                    pair_split: convert::pair_split_to_flat(&scan_state.pair_split),
                    init_mem_loads: convert::bitvec_to_flat(&scan_state.init_mem_loads),
                    reg_last_def_inner: scan_state.reg_last_def.inner().to_vec(),
                    line_count: scan_state.line_count,
                    parsed_count: scan_state.parsed_count,
                    mem_op_count: scan_state.mem_op_count,
                };
                let reg_last_def = scan_state.reg_last_def.clone();

                let lidx_archive = convert::line_index_to_archive(&scan_result.line_index);

                // 2. 序列化为 bytes
                eprintln!("[index] serializing archives to cache bytes...");
                let p2_bytes = phase2_archive.to_sections();
                let scan_bytes = scan_archive.to_sections();
                let lidx_bytes = lidx_archive.to_sections();
                let si_bytes = bincode::serialize(&string_index).ok();
                eprintln!(
                    "[index] serialization done: p2={}B scan={}B lidx={}B",
                    p2_bytes.len(),
                    scan_bytes.len(),
                    lidx_bytes.len()
                );

                // 3. write lock：仅存储数据到 session
                let (
                    cache_identity,
                    gum_extra,
                    total_lines,
                    has_string_index,
                    trace_len,
                    trace_hash,
                ) = {
                    let mut state = handle
                        .state
                        .write()
                        .map_err(|e| TraceError::Internal(e.to_string()))?;

                    let total_lines = scan_result.line_index.total_lines();
                    let has_string_index = !string_index.strings.is_empty();

                    state.total_lines = total_lines;
                    state.trace_format = scan_result.format;

                    state.call_tree = Some(call_tree);
                    state.activation_tree = Some(activation_tree);
                    state.string_index = Some(string_index);
                    state.reg_last_def = Some(reg_last_def);
                    state.phase2_store = Some(CachedStore::Owned(phase2_archive));
                    state.scan_store = Some(CachedStore::Owned(scan_archive));
                    state.lidx_store = Some(CachedStore::Owned(lidx_archive));

                    state.call_annotations = scan_result.call_annotations;
                    state.consumed_seqs = scan_result.consumed_seqs;
                    state.rebuild_call_search_texts();

                    let gum_extra = if state.trace_format
                        == trace_parser::types::TraceFormat::Gumtrace
                        && !state.call_annotations.is_empty()
                    {
                        Some((state.call_annotations.clone(), state.consumed_seqs.clone()))
                    } else {
                        None
                    };

                    (
                        state.cache_identity.clone(),
                        gum_extra,
                        total_lines,
                        has_string_index,
                        state.mmap.len() as u64,
                        state.trace_hash,
                    )
                };
                // write lock 已释放

                // 4. 同步写缓存
                eprintln!("[index] writing cache files...");
                cache::save_sections_raw(&cache_identity, trace_len, &trace_hash, ".p2.cache", &p2_bytes);
                cache::save_sections_raw(&cache_identity, trace_len, &trace_hash, ".scan.cache", &scan_bytes);
                cache::save_sections_raw(
                    &cache_identity,
                    trace_len,
                    &trace_hash,
                    ".lidx.cache",
                    &lidx_bytes,
                );
                if let Some(ref si_b) = si_bytes {
                    cache::save_bincode_raw(&cache_identity, trace_len, &trace_hash, ".strings", si_b);
                }
                if let Some((ref anns, ref seqs)) = gum_extra {
                    cache::save_gumtrace_extra(&cache_identity, trace_len, &trace_hash, anns, seqs);
                }
                eprintln!("[index] cache save complete");

                Ok(BuildResult {
                    total_lines,
                    has_string_index,
                    from_cache: false,
                })
            }
        }
    }

    pub fn cancel_build(&self, session_id: &str) {
        if session_id.starts_with("disk-cfg:") {
            if let Ok(Some(handle)) = self.disk_handle(session_id) {
                handle.cancel.store(true, Ordering::SeqCst);
            }
            return;
        }
        if let Ok(handle) = self.get_handle(session_id) {
            handle.build_cancel.store(true, Ordering::SeqCst);
        }
        // 静默忽略 session 不存在的情况
    }
}
