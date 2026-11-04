//! 闭合调用的返回值被直接写入 caller 最终输出的有界证明；写入后再读出仍显式拒绝。
//!
//! fixture 用真实 Gumtrace 行：seq 2 是 `App+0x401000` 的调用点，seq 3 是入口，seq 5 是 `ret`；
//! caller `App+0x400000` 自身的调用点在 seq 0，因此 caller 帧闭合、窗口有完整负证。
//! resume 必须落在 call PC+4（`0x400008`），所以插入的 caller 指令使用 `0x40000c` / `0x400018`。
use trace_core::{api_types::CallerReturnUsesDto, BuildOptions, TraceEngine};

/// seq 7 的 `str x0, [x9]` 把返回值 `0x6` 直接写入 `0x8000`，其后 caller 只剩 `ret`。
const DIRECT_STORE: &str = "\
[App] 0x300000!0x0 bl #0x400000; x0=0x6
[App] 0x400000!0x400000 nop; x0=0x6 -> x0=0x6
[App] 0x400004!0x400004 bl #0x401000; x0=0x6
[App] 0x401000!0x401000 nop; x0=0x6 -> x0=0x6
[App] 0x401004!0x401004 mov x0, #0x6; -> x0=0x6
[App] 0x401008!0x401008 ret; x0=0x6
[App] 0x400008!0x400008 mov x9, #0x8000; x0=0x6 -> x9=0x8000
[App] 0x400010!0x400010 str x0, [x9]; x0=0x6 x9=0x8000 mem_w=0x8000
[App] 0x400014!0x400014 ret
[App] 0x300004!0x4 nop; x0=0x6
";

fn query(text: &str) -> CallerReturnUsesDto {
    let path = std::env::temp_dir().join(format!(
        "caller-return-direct-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, text).expect("trace");
    let engine = TraceEngine::new();
    let sid = engine
        .create_session_from_file(std::fs::File::open(&path).unwrap(), "caller-return-direct")
        .expect("session")
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
        .expect("index");
    let proof = engine
        .get_caller_return_uses(&sid, 2, 3, "App+0x401000", &["App".into()])
        .expect("caller return query");
    engine.close_session(&sid).expect("close");
    std::fs::remove_file(path).expect("cleanup");
    proof
}

/// 在 resume 行与 store 行之间插入一行 caller 指令。
fn before_store(line: &str) -> String {
    DIRECT_STORE.replace(
        "[App] 0x400010!0x400010 str x0, [x9];",
        &format!("{line}\n[App] 0x400010!0x400010 str x0, [x9];"),
    )
}

/// 在 store 行与 caller `ret` 之间插入行。
fn after_store(line: &str) -> String {
    DIRECT_STORE.replace(
        "[App] 0x400014!0x400014 ret",
        &format!("{line}\n[App] 0x400014!0x400014 ret"),
    )
}

fn kinds(proof: &CallerReturnUsesDto) -> Vec<&str> {
    proof.gaps.iter().map(|gap| gap.kind.as_str()).collect()
}

fn facts(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).expect("json facts")
}

#[test]
fn direct_returned_value_store_is_the_proven_final_output() {
    let proof = query(DIRECT_STORE);
    assert!(proof.coverage.complete, "{}", facts(&proof.gaps));
    assert!(proof.gaps.is_empty(), "{}", facts(&proof.gaps));
    assert_eq!(proof.uses.len(), 1, "{}", facts(&proof.uses));
    let store = &proof.uses[0];
    // 该 use 表示“返回值本身作为数据写入”，不是“返回值作为地址”。
    assert_eq!(store.value_role, "data");
    assert_eq!(store.register, "x0");
    assert_eq!(store.value, "0x6");
    assert_eq!(store.address, "0x8000");
    assert_eq!(store.size, 8);
    assert_eq!(store.rw, "write");
    assert_eq!(store.address_operand, "[x9]");
    assert!(store.definition_steps.is_empty(), "{}", facts(&store.definition_steps));
    assert_eq!(store.integer_delta, 0);
    assert!(store.chain_complete);
}

#[test]
fn same_value_redefinition_cannot_inherit_the_return() {
    // 同值再定义：即使新值仍等于返回值，后续 store 也不能继承来源。
    for line in [
        "[App] 0x40000c!0x40000c mov x0, x0; x0=0x6 -> x0=0x6",
        "[App] 0x40000c!0x40000c mov x0, x3; x3=0x6 -> x0=0x6",
        "[App] 0x40000c!0x40000c add x0, x0, #0x0; x0=0x6 -> x0=0x6",
    ] {
        let proof = query(&before_store(line));
        assert!(!proof.coverage.complete, "{line}");
        assert!(
            kinds(&proof).contains(&"store_data_escape"),
            "{line}: {}",
            facts(&proof.gaps)
        );
        assert!(proof.uses.is_empty(), "{line}: {}", facts(&proof.uses));
    }
}

#[test]
fn copied_return_register_store_is_not_direct() {
    let text = before_store("[App] 0x40000c!0x40000c mov x2, x0; x0=0x6 -> x2=0x6").replace(
        "str x0, [x9]; x0=0x6",
        "str x2, [x9]; x0=0x6 x2=0x6",
    );
    let proof = query(&text);
    assert!(!proof.coverage.complete, "{}", facts(&proof));
    assert!(
        kinds(&proof).contains(&"store_data_escape"),
        "{}",
        facts(&proof.gaps)
    );
    assert!(proof.uses.is_empty(), "{}", facts(&proof.uses));
}

#[test]
fn wrong_width_or_address_store_is_rejected() {
    // 4 字节只覆盖返回值的一部分，不能声称写入完整返回值。
    let narrow = query(&DIRECT_STORE.replace(
        "str x0, [x9]; x0=0x6 x9=0x8000 mem_w=0x8000",
        "str w0, [x9]; x0=0x6 x9=0x8000 mem_w=0x8000",
    ));
    assert!(!narrow.coverage.complete);
    assert!(
        kinds(&narrow).contains(&"store_data_escape"),
        "{}",
        facts(&narrow.gaps)
    );
    assert!(narrow.uses.is_empty(), "{}", facts(&narrow.uses));
    // 地址操作数算出的地址与内存注记不一致。
    let wrong_address = query(&DIRECT_STORE.replace("mem_w=0x8000", "mem_w=0x8001"));
    assert!(!wrong_address.coverage.complete);
    assert!(
        kinds(&wrong_address).contains(&"address_mismatch"),
        "{}",
        facts(&wrong_address.gaps)
    );
    assert!(
        wrong_address.uses.is_empty(),
        "{}",
        facts(&wrong_address.uses)
    );
}

#[test]
fn later_store_covering_the_same_bytes_is_rejected() {
    let proof = query(&after_store(
        "[App] 0x400018!0x400018 str x1, [x9]; x1=0x7 x9=0x8000 mem_w=0x8000",
    ));
    assert!(!proof.coverage.complete);
    assert!(
        kinds(&proof).contains(&"data_store_overwritten"),
        "{}",
        facts(&proof.gaps)
    );
}

#[test]
fn load_after_the_store_is_not_propagated() {
    let proof = query(&after_store(
        "[App] 0x400018!0x400018 ldr x1, [x9]; x9=0x8000 mem_r=0x8000 -> x1=0x6",
    ));
    assert!(!proof.coverage.complete);
    assert!(
        kinds(&proof).contains(&"data_store_reload"),
        "{}",
        facts(&proof.gaps)
    );
    assert!(
        proof
            .uses
            .iter()
            .all(|usage| usage.rw == "write" || usage.value_role == "data"),
        "{}",
        facts(&proof.uses)
    );
}

#[test]
fn later_register_redefinition_does_not_change_the_written_bytes() {
    // store 之后重新读取或重新定义 x0 不影响已经写入的字节。
    for line in [
        "[App] 0x400018!0x400018 mov x0, #0x1; x0=0x6 -> x0=0x1",
        "[App] 0x400018!0x400018 orr x0, x0, xzr; x0=0x6 -> x0=0x6",
    ] {
        let proof = query(&after_store(line));
        assert!(proof.coverage.complete, "{line}: {}", facts(&proof.gaps));
        assert_eq!(proof.uses.len(), 1, "{line}: {}", facts(&proof.uses));
        assert_eq!(proof.uses[0].value_role, "data");
    }
}

#[test]
fn unknown_call_effect_after_the_store_keeps_coverage_incomplete() {
    // 未记录的外部调用效果就在 store 之后：不能把写入过的字节当成已知最终状态。
    let proof = query(&after_store("call func: opaque(0x8000)\nret: 0x6"));
    assert!(!proof.coverage.complete);
    assert!(
        kinds(&proof).contains(&"unsupported_parse"),
        "{}",
        facts(&proof.gaps)
    );
}
