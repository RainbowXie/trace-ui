//! Confirmed Activation 查询方法：
//! get_activation_tree / get_activation_for_seq / get_instruction_owner。
//!
//! 稳定身份在查询层生成：函数与边界使用 module+offset（如 `libtiny.so+0x174250`），
//! Activation 展示身份 `<session>:call@<call_seq>`。ActivationTree 里的 PC 是
//! ASLR 运行时事实，只在 DTO 层换算为稳定身份。

use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation, UnresolvedReason};

fn reason_str(r: &UnresolvedReason) -> &'static str {
    match r {
        UnresolvedReason::TraceEndStillActive => "trace_end_still_active",
        UnresolvedReason::DisplacedByAnotherCall => "displaced_by_another_call",
        UnresolvedReason::NoNextInsn => "no_next_insn",
    }
}

/// 从一行 trace 文本解析稳定身份（module+offset）。
///
/// gumtrace：`[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 ...` → `libmetasec_ov.so+0x82ce0`
/// unidbg：`[ts][libtiny.so 0x174250] ... 0x40174250: "..."` → `libtiny.so+0x174250`
///
/// 从一行 trace 文本解析稳定身份（module+offset），输出规范化到
/// common-types.md 的稳定模块位置语法：`<module>+0x<offset>`，offset 为
/// 小写十六进制且无前导零（零写 0）。
///
/// 不满足语法（模块名含非 `[A-Za-z0-9._-]` 字符/过长/为 . 或 ..、
/// offset 非十六进制、行结构不匹配）时返回 None——调用方必须把该边界
/// 的稳定身份置空，禁止输出原始路径片段或运行时地址冒充稳定身份。
pub(crate) fn stable_site(line: &str) -> Option<String> {
    // gumtrace: 模块名在行首 [..] 内，offset 在 `!0x` 之后
    if let Some(bracket_end) = line.find("] 0x") {
        if let Some(module_start) = line[..bracket_end].find('[') {
            let module = &line[module_start + 1..bracket_end];
            let rest = &line[bracket_end + 4..];
            if let Some(bang) = rest.find('!') {
                // 校验 `!` 后确实是 0x 前缀（畸形行会产生错位 hex）
                if rest[bang..].starts_with("!0x") {
                    let after = &rest[bang + 3..]; // skip "!0x"
                    let end = after
                        .find(|c: char| !c.is_ascii_hexdigit())
                        .unwrap_or(after.len());
                    let offset = &after[..end];
                    if !offset.is_empty() {
                        return build_site(module, offset);
                    }
                }
            }
        }
    }
    // unidbg: `[libtiny.so 0x174250] [encoding]`
    if let Some(pos) = line.find("] [") {
        if let Some(bracket_start) = line[..pos].rfind('[') {
            let module_info = &line[bracket_start + 1..pos];
            if let Some(space_pos) = module_info.rfind(" 0x") {
                let module = &module_info[..space_pos];
                let hex = &module_info[space_pos + 3..];
                if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return build_site(module, hex);
                }
            }
        }
    }
    None
}

/// 按稳定模块位置语法拼装身份；模块名或 offset 不合法时返回 None。
fn build_site(module: &str, offset_hex: &str) -> Option<String> {
    if !is_valid_module(module) {
        return None;
    }
    // 规范化：小写、去前导零（零固定写 0）
    let lower = offset_hex.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches('0');
    let normalized = if trimmed.is_empty() { "0" } else { trimmed };
    Some(format!("{}+0x{}", module, normalized))
}

/// common-types.md 模块名语法：`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`，
/// 不能是 `.`、`..`。无法规范化的模块名（含 /、反斜杠、+、空白、Unicode）
/// 不写入稳定身份。
fn is_valid_module(module: &str) -> bool {
    if module.is_empty() || module == "." || module == ".." {
        return false;
    }
    let bytes = module.as_bytes();
    let first_ok = bytes[0].is_ascii_alphanumeric();
    let rest_ok = bytes.len() <= 128
        && bytes[1..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    first_ok && rest_ok
}

/// 边界点的稳定身份；无法规范化时 None（调用方置空，不冒充）。
fn site_or_none(line: Option<&[u8]>) -> Option<String> {
    line.and_then(|b| std::str::from_utf8(b).ok())
        .and_then(stable_site)
}

fn activation_to_dto(
    a: &ConfirmedActivation,
    session_id: &str,
    reader: &LineReader<'_>,
) -> ConfirmedActivationDto {
    // 哨兵语义（query/activation.rs）：
    // - resolved：entry/exit/resume 全真实；
    // - TraceEndStillActive：entry/exit 真实（截断时填的最后实际指令），
    //   resume_seq=0（未到达）；
    // - NoNextInsn/DisplacedByAnotherCall：entry/exit/resume 全 0。
    // 哨兵 0 不读 trace 第 0 行伪造身份；call/callsite 在所有状态下真实。
    let resolved = a.unresolved_reason.is_none();
    let truncated = matches!(
        a.unresolved_reason,
        Some(UnresolvedReason::TraceEndStillActive)
    );
    // entry/exit 在 resolved 或 truncated 下都是真实观察，都解析。
    let entry_exit_real = resolved || truncated;
    ConfirmedActivationDto {
        id: a.id,
        // 展示身份：root 是 trace_root（协议定义），其余 = session + call anchor
        activation: if a.id == 0 {
            "trace_root".to_string()
        } else {
            format!("{}:call@{}", session_id, a.call_seq)
        },
        func_addr: if entry_exit_real {
            site_or_none(reader.get(a.entry_seq))
        } else {
            None
        },
        func_name: a.func_name.clone(),
        call_seq: a.call_seq,
        call_pc: site_or_none(reader.get(a.call_seq)),
        entry_seq: a.entry_seq,
        entry_pc: if entry_exit_real {
            site_or_none(reader.get(a.entry_seq))
        } else {
            None
        },
        exit_seq: a.exit_seq,
        exit_pc: if entry_exit_real {
            site_or_none(reader.get(a.exit_seq))
        } else {
            None
        },
        // resume：resolved 才有；truncated 时未到达；其余哨兵 0
        expected_resume: if resolved {
            site_or_none(reader.get(a.resume_seq))
        } else {
            None
        },
        resume_seq: a.resume_seq,
        parent_id: a.parent_id,
        children_ids: a.children_ids.clone(),
        unresolved_reason: a
            .unresolved_reason
            .as_ref()
            .map(|r| reason_str(r).to_string()),
    }
}

/// 行读取辅助：把 LineIndex + mmap + trace 格式打包（借用安全）。
struct LineReader<'a> {
    data: &'a [u8],
    index: Option<crate::flat::line_index::LineIndexView<'a>>,
    total_lines: u32,
    format: trace_parser::types::TraceFormat,
}

impl<'a> LineReader<'a> {
    fn get(&self, seq: u32) -> Option<&'a [u8]> {
        self.index
            .as_ref()
            .and_then(|li| li.get_line(self.data, seq))
    }
}

impl crate::engine::TraceEngine {
    /// 整棵 Confirmed Activation 树的分页窗口 + bypassed 调用集合。
    ///
    /// confirmed/unresolved 计数排除 root（root 是 trace 上下文，不是调用）。
    /// bypassed_calls 同样分页（按 call_seq 顺序）。
    pub fn get_activation_tree(
        &self,
        session_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<ActivationTreeDto> {
        self.with_activation_context(session_id, |tree, reader| {
            let activations = &tree.activations;
            let skip = (offset as usize).min(activations.len());
            let take = (limit as usize).min(activations.len().saturating_sub(skip));
            let page = &activations[skip..skip + take];

            let b_skip = (offset as usize).min(tree.bypassed_calls.len());
            let b_take = (limit as usize).min(tree.bypassed_calls.len().saturating_sub(b_skip));
            let b_page = &tree.bypassed_calls[b_skip..b_skip + b_take];

            // 全量计数（不复制树：直接在切片上数）
            let non_root = &activations[1..];
            let confirmed = non_root
                .iter()
                .filter(|a| a.unresolved_reason.is_none())
                .count() as u32;
            let unresolved = (non_root.len() as u32).saturating_sub(confirmed);

            Ok(ActivationTreeDto {
                activations: page
                    .iter()
                    .map(|a| activation_to_dto(a, session_id, reader))
                    .collect(),
                bypassed_calls: b_page
                    .iter()
                    .map(|c| BypassedCallDto {
                        call_seq: c.call_seq,
                        call_pc: site_or_none(reader.get(c.call_seq)).unwrap_or_default(),
                        // expected_resume 位置的稳定身份 = resume 行本身
                        expected_resume: site_or_none(reader.get(c.resume_seq)).unwrap_or_default(),
                        resume_seq: c.resume_seq,
                        parent_id: c.parent_id,
                    })
                    .collect(),
                total_activations: activations.len() as u32,
                total_bypassed: tree.bypassed_calls.len() as u32,
                confirmed_count: confirmed,
                unresolved_count: unresolved,
                offset,
                // 两数组独立分页：各自标记是否还有剩余（单一 has_more 会把
                // activations 取尽但 bypassed 未尽的页误报为完成，静默丢失）
                activations_has_more: (skip + take) < activations.len(),
                bypassed_has_more: (b_skip + b_take) < tree.bypassed_calls.len(),
            })
        })
    }

    /// 按 seq 查询唯一归属的非 root Activation（嵌套时取最内层）。
    pub fn get_activation_for_seq(
        &self,
        session_id: &str,
        seq: u32,
    ) -> Result<Option<ConfirmedActivationDto>> {
        self.with_activation_context(session_id, |tree, reader| {
            if seq >= reader.total_lines {
                return Err(TraceError::InvalidArgument(format!(
                    "seq {} 超出 trace 总行数 {}",
                    seq, reader.total_lines
                )));
            }
            Ok(tree
                .activation_for_seq(seq)
                .map(|a| activation_to_dto(a, session_id, reader)))
        })
    }

    /// 指令归属（agent-api.md §2）：seq → Activation + 边界位置。
    ///
    /// 边界位置只在**实际指令**上定义（function-boundaries.md §4）；special line
    /// 与无法解析行返回 `not_an_instruction`。resume 指令属于 caller 上下文，
    /// position = "resume" 并带 callee_id 指向被闭合的 child。
    pub fn get_instruction_owner(&self, session_id: &str, seq: u32) -> Result<InstructionOwnerDto> {
        self.with_activation_context(session_id, |tree, reader| {
            if seq >= reader.total_lines {
                return Err(TraceError::InvalidArgument(format!(
                    "seq {} 超出 trace 总行数 {}",
                    seq, reader.total_lines
                )));
            }

            // 实际指令判定：直接用扫描侧同一个解析函数判定成功与否——
            // builder 只在 parse 成功后收到 InsnFact，归属查询必须同一口径。
            // 不用格式签名（签名比完整解析宽松：如 `[lib.so] 0x1!0x2 ` 签名
            // 通过但无指令文本 parse 拒绝）；也不自写启发式（畸形行会误报）。
            // special line 与无法解析行不参与归属（协议只定义
            // "实际执行的指令"的归属）
            let raw = reader.get(seq);
            let is_instruction = raw.is_some_and(|b| match reader.format {
                trace_parser::types::TraceFormat::Gumtrace => std::str::from_utf8(b)
                    .ok()
                    .and_then(trace_parser::gumtrace::parse_line_gumtrace)
                    .is_some(),
                trace_parser::types::TraceFormat::Unidbg => std::str::from_utf8(b)
                    .ok()
                    .and_then(trace_parser::parser::parse_line)
                    .is_some(),
            });
            if !is_instruction {
                return Ok(InstructionOwnerDto {
                    seq,
                    activation: None,
                    position: "not_an_instruction".to_string(),
                    closes: None,
                    opens: None,
                    detail: "special line 或无法解析行：不参与指令归属".to_string(),
                });
            }

            let owner = tree.activation_for_seq(seq);

            // 无损边界事实（可叠加）：一条指令可同时闭合一个调用并开启
            // 另一个调用（连续 BL / bypassed 直接 resume 到下一条 BL）。
            // - closes：本指令是某个调用的 resume（confirmed child 闭合，
            //   或 bypassed 调用的直接 resume——后者不在 activations 中，
            //   用 bypassed:N 引用）。
            // - opens：本指令是某个调用的 call 行。
            let closes = if let Some(child) = tree.find_resume(seq) {
                Some(format!("activation:{}", child))
            } else {
                tree.find_bypassed_resume_by_seq(seq)
                    .map(|i| format!("bypassed:{}", i))
            };
            let opens = if let Some(child) = tree.find_call(seq) {
                Some(format!("activation:{}", child))
            } else {
                tree.find_bypassed_by_call_seq(seq)
                    .map(|i| format!("bypassed:{}", i))
            };

            // position 摘要：叠加时优先 resume > call > entry > exit > body > root。
            // entry 指令自身是 BL/BLR 时同时有 entry+opens 两个事实，
            // 摘要报 call 但 opens/owner 保留完整信息。
            let position = if closes.is_some() {
                "resume".to_string()
            } else if opens.is_some() {
                "call".to_string()
            } else {
                match owner {
                    Some(a) if seq == a.entry_seq => "entry".to_string(),
                    Some(a) if seq == a.exit_seq => "exit".to_string(),
                    _ if owner.is_some() => "body".to_string(),
                    _ => "root".to_string(),
                }
            };

            let detail = match &closes {
                Some(c) if c.starts_with("bypassed:") => {
                    "bypassed 调用的直接 resume：caller 上下文执行，无函数体".to_string()
                }
                Some(_) => "expected resume 指令：caller 上下文执行，闭合 callee".to_string(),
                None if opens.as_deref().is_some_and(|o| o.starts_with("bypassed:")) => {
                    "调用指令：callee 无记录函数体（bypassed）".to_string()
                }
                None => String::new(),
            };

            Ok(InstructionOwnerDto {
                seq,
                activation: owner.map(|a| activation_to_dto(a, session_id, reader)),
                position,
                closes,
                opens,
                detail,
            })
        })
    }

    /// 拿到 ActivationTree + LineReader 后执行 `f`（RwLock guard 生命周期约束，
    /// 借用必须在闭包内完成）。
    fn with_activation_context<T>(
        &self,
        session_id: &str,
        f: impl FnOnce(&ActivationTree, &LineReader<'_>) -> Result<T>,
    ) -> Result<T> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let tree = state
            .activation_tree
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let reader = LineReader {
            data: &state.mmap,
            index: state.line_index_view(),
            total_lines: state.total_lines,
            format: state.trace_format,
        };
        f(tree, &reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 审查反例回归：畸形/垃圾行不得误报为指令（此前手写启发式仅看
    /// `] 0x`+`!`/`: "` 会把解析器拒绝的行判为指令，position 错标 body/root）。
    /// 判定必须与扫描侧喂 builder 的 parse 完全同口径。
    #[test]
    fn malformed_lines_are_not_instructions() {
        let cases = [
            "[mod] 0x1!yy nop",         // 审查反例一：offset 非 hex，签名与 parse 均拒
            "[lib.so] 0x1!0x2 ",        // 反例二：截断行（签名过但 parse 拒）
            "[WARN] [x] log: \"oops\"", // 反例三：带引号日志（签名过但 parse 拒）
            "call func: a(0x1)",        // special line
            "ret: 0x13",
            "",
        ];
        for line in cases {
            assert!(
                trace_parser::gumtrace::parse_line_gumtrace(line).is_none(),
                "gumtrace parse 不得把 {line:?} 判为指令"
            );
            assert!(
                trace_parser::parser::parse_line(line).is_none(),
                "unidbg parse 不得把 {line:?} 判为指令"
            );
        }
        // 正常指令行仍判为指令
        assert!(trace_parser::gumtrace::parse_line_gumtrace(
            "[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 sub x0, x29, #0x80; x0=0x1"
        )
        .is_some());
        assert!(trace_parser::parser::parse_line(
            "[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: \"stp x29, x30, [sp, #-0x60]!\""
        )
        .is_some());
    }

    /// stable_site：畸形行回退 None（不产生错误拼接的身份）。
    #[test]
    fn stable_site_rejects_malformed_lines() {
        assert_eq!(stable_site("[mod] 0x1!yy nop"), None, "! 后无 0x 前缀");
        assert_eq!(stable_site("[lib.so] 0x1!"), None, "截断");
        assert_eq!(
            stable_site("[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 sub x0"),
            Some("libmetasec_ov.so+0x82ce0".to_string())
        );
        // unidbg：[ts][module offset] [encoding]
        assert_eq!(
            stable_site("[07:17:13 488][libtiny.so 0x174250] [fd7bbaa9] 0x40174250: \"stp\""),
            Some("libtiny.so+0x174250".to_string())
        );
        // 无模块形态回退 None
        assert_eq!(
            stable_site("[00:00:00 000][e00300b9] 0x40174250: \"add\""),
            None
        );
    }
}
