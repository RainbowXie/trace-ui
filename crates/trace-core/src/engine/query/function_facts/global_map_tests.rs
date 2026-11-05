//! 模块基址流式扫描与旁路缓存的回归测试：结果必须与旧的逐行取样实现一致。

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

use crate::api_types::BuildOptions;
use crate::TraceEngine;

use super::super::activation::stable_runtime_site;
use super::global_map::{module_index, validate_mappings, BaseStatus, StableGlobalMap};

struct Isolated {
    dir: std::path::PathBuf,
}
impl Drop for Isolated {
    fn drop(&mut self) {
        crate::cache::set_cache_dir_override(None);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn isolated() -> Isolated {
    let dir = std::env::temp_dir().join(format!("facts-modules-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    crate::cache::set_cache_dir_override(Some(dir.join("cache")));
    Isolated { dir }
}

fn error_text<T>(result: crate::error::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error.to_string(),
    }
}

fn session(trace: &str, label: &str) -> (TraceEngine, String, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "facts-modules-{label}-{}.log",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, trace).unwrap();
    let engine = TraceEngine::new();
    let sid = engine
        .create_session(path.to_str().unwrap())
        .unwrap()
        .session_id;
    engine
        .build_index(
            &sid,
            BuildOptions {
                force_rebuild: true,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    (engine, sid, path)
}

const TRACE: &str = "[App] 0x400000!0x0 bl #0x401000; x0=0x6000 sp=0x8000\n\
[App] 0x401004!0x1004 ldr x9, [x0]; x0=0x6000 mem_r=0x6000 -> x9=0x1\n\
[lib.so] 0x900000!0x40 ldr x9, [x0]; x0=0x7000 mem_r=0x7000 -> x9=0x2\n\
[App] 0x401008!0x1008 ret; x0=0x6000\n";

/// 流式单遍扫描必须与旧的逐行 `get_line` 参考实现给出同一组模块基址与
/// 首个指令 source。
#[test]
fn streamed_module_bases_match_per_line_reference() {
    let _lock = crate::cache::cache_dir_override_test_lock();
    let _iso = isolated();
    let (engine, sid, path) = session(TRACE, "reference");
    let handle = engine.get_handle(&sid).unwrap();
    let state = handle.state.read().unwrap();
    let scanned = module_index(&state, None).unwrap();
    let index = state.line_index_view().unwrap();
    let mut reference = BTreeMap::new();
    let mut reference_sources = BTreeMap::new();
    for seq in 0..state.total_lines {
        let Some(raw) = index.get_line(&state.mmap, seq) else {
            continue;
        };
        let Ok(line) = std::str::from_utf8(raw) else {
            continue;
        };
        let Some((module, runtime, offset)) = stable_runtime_site(line) else {
            continue;
        };
        reference.insert(module.clone(), runtime.checked_sub(offset).unwrap());
        if trace_parser::strict_memory::instruction_parts(line).is_some() {
            reference_sources
                .entry(module)
                .or_insert((seq, runtime, offset));
        }
    }
    let mut bases = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (module, record) in &scanned.modules {
        match record.base {
            BaseStatus::Unique(base) => {
                bases.insert(module.clone(), base);
            }
            BaseStatus::Underflow(_) | BaseStatus::Inconsistent(_) => {
                panic!("一致 trace 不得出现模块错误: {module}")
            }
        }
        if let Some(source) = &record.source {
            sources.insert(module.clone(), (source.seq, source.runtime, source.offset));
        }
    }
    assert_eq!(bases, reference);
    assert_eq!(sources, reference_sources);
    assert_eq!(scanned.oversize_seq, None);
    drop(state);
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
}

/// 基址冲突必须先按行序记录、再按调用方语义报错：`collect` 依行序
/// （原实现沿行推进），`validate_mappings` 依模块序列（原实现逐模块扫描）。
#[test]
fn module_error_order_matches_full_scan_semantics() {
    let _lock = crate::cache::cache_dir_override_test_lock();
    let _iso = isolated();
    let trace = "[Zmod] 0x1000!0x0 nop\n\
[Amod] 0x2000!0x0 nop\n\
[Amod] 0x2100!0x0 nop\n\
[Zmod] 0x1100!0x0 nop\n";
    let (engine, sid, path) = session(trace, "conflict");
    let modules = vec!["Zmod".to_owned(), "Amod".to_owned()];
    let handle = engine.get_handle(&sid).unwrap();
    let state = handle.state.read().unwrap();
    let collect_error = error_text(StableGlobalMap::collect(&state, &modules));
    assert_eq!(
        collect_error,
        "invalid argument: module Amod has inconsistent runtime bases"
    );
    let validate_error = error_text(validate_mappings(&state, &modules, &AtomicBool::new(false)));
    assert_eq!(
        validate_error,
        "invalid argument: module Zmod has inconsistent runtime bases"
    );
    // 第二次查询命中 .modules.bin 旁路缓存：错误判定必须逐字节一致。
    let cache_name = crate::cache::path_hash_for_test(path.to_str().unwrap());
    assert!(crate::cache::cache_dir()
        .unwrap()
        .join(format!("{cache_name}.modules.bin"))
        .exists());
    let cached_error = error_text(StableGlobalMap::collect(&state, &modules));
    assert_eq!(cached_error, collect_error);
    drop(state);
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
}

/// 单行上限与基址冲突落在同一行时：原实现先 `check_raw` 再解析，资源错误
/// 优先；`collect` 从不借用行文本，同一行对它仍是普通的基址冲突。
#[test]
fn oversize_row_wins_over_the_base_conflict_it_also_carries() {
    let _lock = crate::cache::cache_dir_override_test_lock();
    let _iso = isolated();
    let padding = "a".repeat(1024 * 1024);
    let trace = format!("[App] 0x400000!0x0 nop\n[App] 0x500000!0x0 nop {padding}\n");
    let (engine, sid, path) = session(&trace, "oversize");
    let modules = vec!["App".to_owned()];
    let handle = engine.get_handle(&sid).unwrap();
    let state = handle.state.read().unwrap();
    for pass in ["first scan", "cached index"] {
        assert_eq!(
            error_text(validate_mappings(&state, &modules, &AtomicBool::new(false))),
            "internal error: function facts raw-line working memory resource limit exceeded",
            "{pass}: 同一行先判单行上限"
        );
        assert_eq!(
            error_text(StableGlobalMap::collect(&state, &modules)),
            "invalid argument: module App has inconsistent runtime bases",
            "{pass}: collect 不受单行上限影响"
        );
    }
    drop(state);
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
}

/// 目标模块根本不在 trace 里也不能盖掉整份 trace 的单行上限：原实现对每个
/// 模块都先逐行 `check_raw`，缺模块同样会撞上越界行。
#[test]
fn missing_target_module_still_reports_the_oversize_row() {
    let _lock = crate::cache::cache_dir_override_test_lock();
    let _iso = isolated();
    let padding = "a".repeat(1024 * 1024);
    let trace = format!("[App] 0x400000!0x0 nop {padding}\n");
    let (engine, sid, path) = session(&trace, "oversize-missing");
    let modules = vec!["MissingMod".to_owned()];
    let handle = engine.get_handle(&sid).unwrap();
    let state = handle.state.read().unwrap();
    for pass in ["first scan", "cached index"] {
        assert_eq!(
            error_text(validate_mappings(&state, &modules, &AtomicBool::new(false))),
            "internal error: function facts raw-line working memory resource limit exceeded",
            "{pass}: 缺模块不得跳过单行上限判定"
        );
    }
    // collect 从不借用行文本，缺模块对它只是「没有基址」。
    assert!(StableGlobalMap::collect(&state, &modules).is_ok());
    drop(state);
    engine.close_session(&sid).unwrap();
    std::fs::remove_file(path).unwrap();
}
