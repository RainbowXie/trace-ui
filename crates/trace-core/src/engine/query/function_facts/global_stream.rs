//! Global identity from bounded single-instruction rescans, without positions map.
use super::super::activation::stable_runtime_site;
use super::lines;
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;
use std::sync::atomic::AtomicBool;

pub(super) fn validate_mappings(
    state: &SessionState,
    modules: &[String],
    cancel: &AtomicBool,
) -> Result<()> {
    // 模块基址的全表扫描与旁路缓存属于 global_map 的模块索引：这里只保留
    // 查询侧入口，避免两处各扫一遍整份 trace。
    super::global_map::validate_mappings(state, modules, cancel)
}

fn immediate(s: &str) -> Option<u64> {
    let s = s.strip_prefix('#')?;
    if let Some(s) = s.strip_prefix("0x") {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(s, 16).ok()
    } else if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}
fn writes_first(m: &str) -> bool {
    !m.starts_with("st") && !matches!(m, "b" | "br" | "bl" | "blr" | "ret" | "cmp" | "cmn" | "tst")
}
fn base(operand: &str) -> Option<&str> {
    let rest = operand.get(operand.find('[')? + 1..)?;
    let name = rest[..rest.find([',', ']'])?].trim();
    Some(match name {
        "wsp" => "sp",
        "x29" => "fp",
        other => other,
    })
}
fn canonical_register(s: &str) -> bool {
    matches!(s, "sp" | "fp" | "wsp")
        || (s.len() <= 3
            && s.strip_prefix(['x', 'w'])
                .and_then(|s| s.parse::<u8>().ok())
                .is_some_and(|r| r <= 30))
}
pub(super) fn identity(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    cancel: &AtomicBool,
    target_modules: &[String],
    access: u32,
    address: u64,
    size: u32,
) -> Result<Option<String>> {
    if target_modules.is_empty() {
        return Ok(None);
    }
    let index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
    let raw = |seq| -> Result<&str> {
        let bytes = index
            .get_line(&state.mmap, seq)
            .ok_or_else(|| TraceError::Internal("global raw missing".into()))?;
        super::block_stream::check_raw(bytes)?;
        std::str::from_utf8(bytes).map_err(|e| TraceError::Internal(e.to_string()))
    };
    let access_line = raw(access)?;
    let Some((_, operands)) = trace_parser::strict_memory::instruction_parts(access_line) else {
        return Ok(None);
    };
    let Some(register) = base(operands) else {
        return Ok(None);
    };
    if !canonical_register(register) {
        return Ok(None);
    }
    let mut tracked = register;
    let mut before = access;
    let mut selected_steps = [0u32; 128];
    let mut selected_count = 0;
    let (adrp_seq, current, mut value, module, runtime, offset) = loop {
        let mut definition = None;
        let mut invalid = false;
        super::global_closure::scan(state, tree, root, cancel, |seq, line| {
            if seq >= before {
                return Ok(false);
            }
            let Some((m, op)) = trace_parser::strict_memory::instruction_parts(line) else {
                invalid = true;
                return Ok(true);
            };
            if super::super::saved_events::opaque_boundary(state, tree, seq, line) {
                definition = None;
                invalid = true;
            }
            let parsed = if line.contains("!0x") {
                trace_parser::gumtrace::parse_line_gumtrace_full(line)
            } else {
                trace_parser::parser::parse_line_full(line)
            };
            let alias_def = parsed.as_ref().is_some_and(|p| {
                trace_parser::def_use::determine_def_use(
                    trace_parser::insn_class::classify_and_refine(p),
                    p,
                )
                .0
                .contains(&trace_parser::types::parse_reg(tracked).unwrap())
            });
            if alias_def
                || (op.split(',').next().map(str::trim) == Some(tracked) && writes_first(m))
            {
                definition = Some(seq);
                invalid = false;
            }
            Ok(true)
        })?;
        if invalid {
            return Ok(None);
        }
        let Some(seq) = definition else {
            return Ok(None);
        };
        let line = raw(seq)?;
        let (m, op) = trace_parser::strict_memory::instruction_parts(line).expect("definition");
        let mut parts = op.split(',').map(str::trim);
        let first = parts.next();
        let second = parts.next();
        let third = parts.next();
        let extra = parts.next();
        if m == "adrp" {
            if first != Some(tracked) || third.is_some() {
                return Ok(None);
            }
            let Some(page) = second.and_then(immediate) else {
                return Ok(None);
            };
            if page & 0xfff != 0 || lines::arrow_register_value(line, tracked) != Some(page) {
                return Ok(None);
            }
            let Some((module, runtime, offset)) = stable_runtime_site(line) else {
                return Ok(None);
            };
            if !target_modules.contains(&module) {
                return Ok(None);
            }
            break (seq, tracked, page, module, runtime, offset);
        }
        if matches!(m, "add" | "sub") && extra.is_none() && third.and_then(immediate).is_some() {
            let Some(source) = second.filter(|s| canonical_register(s)) else {
                return Ok(None);
            };
            if selected_count == selected_steps.len() {
                return Err(TraceError::Internal("global address chain capacity".into()));
            }
            selected_steps[selected_count] = seq;
            selected_count += 1;
            tracked = source;
            before = seq;
        } else {
            return Ok(None);
        }
    };
    let Some(module_base) = runtime.checked_sub(offset) else {
        return Ok(None);
    };
    // 该模块在整份 trace 内的基址一致性已由 validate_mappings 在入口处
    // 整份验证过一次；这里不再为**每个**全局读写重扫全表（那是 10 余次
    // 128.5 倍全表放大的来源）。
    let mut current_storage = [0u8; 4];
    let mut current_len = current.len();
    current_storage[..current_len].copy_from_slice(current.as_bytes());
    let mut valid = true;
    super::global_closure::scan(state, tree, root, cancel, |seq, line| {
        if seq <= adrp_seq {
            return Ok(true);
        }
        if seq >= access {
            return Ok(false);
        }
        let Some((m, op)) = trace_parser::strict_memory::instruction_parts(line) else {
            valid = false;
            return Ok(false);
        };
        if super::super::saved_events::opaque_boundary(state, tree, seq, line) {
            valid = false;
            return Ok(false);
        }
        let mut parts = op.split(',').map(str::trim);
        let (first, second, third, extra) =
            (parts.next(), parts.next(), parts.next(), parts.next());
        let current = std::str::from_utf8(&current_storage[..current_len]).expect("register");
        if m == "ret"
            && current == "x0"
            && trace_parser::strict_memory::observed_register_value(line, "x0", false)
                != Some(value)
        {
            valid = false;
            return Ok(false);
        }
        if selected_steps[..selected_count].contains(&seq)
            && matches!(m, "add" | "sub")
            && extra.is_none()
            && second == Some(current)
            && third.and_then(immediate).is_some()
        {
            let delta = third.and_then(immediate).expect("immediate");
            let next = if m == "add" {
                value.checked_add(delta)
            } else {
                value.checked_sub(delta)
            };
            let Some(next) = next else {
                valid = false;
                return Ok(false);
            };
            let Some(dest) = first.filter(|s| canonical_register(s)) else {
                valid = false;
                return Ok(false);
            };
            if trace_parser::strict_memory::observed_register_value(line, current, false)
                != Some(value)
                || lines::arrow_register_value(line, dest) != Some(next)
            {
                valid = false;
                return Ok(false);
            }
            value = next;
            current_len = dest.len();
            current_storage[..current_len].copy_from_slice(dest.as_bytes());
        } else if (first == Some(current) && writes_first(m))
            || first.and_then(trace_parser::strict_memory::integer_register)
                == trace_parser::strict_memory::integer_register(current)
                && writes_first(m)
        {
            valid = false;
            return Ok(false);
        }
        Ok(true)
    })?;
    let current = std::str::from_utf8(&current_storage[..current_len]).expect("register");
    if !valid || base(operands) != Some(current) {
        return Ok(None);
    }
    let Some(start) = operands.find('[') else {
        return Ok(None);
    };
    let Some(end) = operands[start..].find(']').map(|end| end + start) else {
        return Ok(None);
    };
    let mut parts = operands[start + 1..end].split(',').map(str::trim);
    parts.next();
    if let Some(delta) = parts.next() {
        if parts.next().is_some() {
            return Ok(None);
        }
        value = if let Some(neg) = delta.strip_prefix("#-") {
            let delta = if let Some(hex) = neg.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                neg.parse().ok()
            };
            let Some(delta) = delta else {
                return Ok(None);
            };
            let Some(next) = value.checked_sub(delta) else {
                return Ok(None);
            };
            next
        } else {
            let Some(delta) = immediate(delta) else {
                return Ok(None);
            };
            let Some(next) = value.checked_add(delta) else {
                return Ok(None);
            };
            next
        };
    }
    let annotated = lines::line_mem_annotation(access_line, "mem_r")
        .or_else(|| lines::line_mem_annotation(access_line, "mem_w"));
    if annotated != Some(address)
        || value != address
        || address < module_base
        || address.checked_add(size as u64).is_none()
    {
        return Ok(None);
    }
    Ok(Some(format!("{module}+0x{:x}", address - module_base)))
}
