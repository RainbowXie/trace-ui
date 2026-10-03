//! Small production-index comparisons for the allocation-independent block API.
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use trace_core::error::TraceError;
use trace_core::{BuildOptions, TraceEngine};

// The later branch to App+0x204 must split its earlier linear occurrence too.
// A nested child is excluded, while its caller's BL and resume remain owned.
const TRACE: &str = "[App] 0x100!0x100 bl #0x200\n\
[App] 0x200!0x200 nop\n\
[App] 0x204!0x204 nop\n\
[App] 0x208!0x208 bl #0x300\n\
[App] 0x300!0x300 nop\n\
[App] 0x304!0x304 ret\n\
[App] 0x20c!0x20c b #0x204\n\
[App] 0x204!0x204 nop\n\
[App] 0x208!0x208 ret\n\
[App] 0x104!0x104 nop\n";

struct Fixture {
    engine: TraceEngine,
    sid: String,
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self { Self::with_trace(TRACE) }
    fn with_trace(trace: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("trace-block-stream-{}.log", uuid::Uuid::new_v4()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(trace.as_bytes()).unwrap();
        let engine = TraceEngine::new();
        // FD-only production session: no pathname reopen or disk cache writes.
        let sid = engine
            .create_session_from_file(file, "inherited-fd:block-stream-test")
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
        Self { engine, sid, path }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.engine.close_session(&self.sid).unwrap();
        std::fs::remove_file(&self.path).unwrap();
    }
}

#[test]
fn late_target_and_nested_owner_match_existing_facts() {
    let f = Fixture::new();
    let facts = f.engine.get_function_facts(&f.sid, 0, 1).unwrap();
    let expected: Vec<_> = facts
        .executed_block_sequence
        .iter()
        .map(|b| (b.block.clone(), b.entry_seq))
        .collect();
    let mut blocks = Vec::new();
    f.engine
        .visit_function_executed_blocks(
            &f.sid,
            0,
            1,
            "App+0x200",
            &AtomicBool::new(false),
            |site, seq| {
                blocks.push((site.to_owned(), seq));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(blocks, expected);
    assert_eq!(
        blocks,
        vec![
            ("App+0x200".into(), 1),
            ("App+0x204".into(), 2),
            ("App+0x20c".into(), 6),
            ("App+0x204".into(), 7),
        ]
    );
}

#[test]
fn raw_cursor_preserves_nested_and_blank_crlf_seq_numbers_without_final_lf() {
    let text=TRACE.replace("\n","\r\n").replace("[App] 0x304!", "\r\n[App] 0x304!");
    let f=Fixture::with_trace(text.trim_end_matches(['\r','\n']));let mut blocks=Vec::new();
    f.engine.visit_function_executed_blocks(&f.sid,0,1,"App+0x200",&AtomicBool::new(false),|site,seq|{blocks.push((site.to_owned(),seq));Ok(())}).unwrap();
    assert_eq!(blocks,vec![("App+0x200".into(),1),("App+0x204".into(),2),("App+0x20c".into(),7),("App+0x204".into(),8)]);
}
#[test]
fn rejecting_sink_and_cancellation_stop_without_success() {
    let f = Fixture::new();
    let mut calls = 0;
    let result = f.engine.visit_function_executed_blocks(
        &f.sid,
        0,
        1,
        "App+0x200",
        &AtomicBool::new(false),
        |_, _| {
            calls += 1;
            Err(TraceError::Internal(
                "test sink refused before retaining item".into(),
            ))
        },
    );
    assert!(matches!(result, Err(TraceError::Internal(_))));
    assert_eq!(calls, 1);

    let cancel = AtomicBool::new(false);
    calls = 0;
    let result =
        f.engine
            .visit_function_executed_blocks(&f.sid, 0, 1, "App+0x200", &cancel, |_, _| {
                calls += 1;
                cancel.store(true, Ordering::Relaxed);
                Ok(())
            });
    assert!(matches!(result, Err(TraceError::Cancelled)));
    assert_eq!(calls, 1);

    let result =
        f.engine
            .visit_function_executed_blocks(&f.sid, 0, 1, "App+0x200", &cancel, |_, _| {
                panic!("already cancelled")
            });
    assert!(matches!(result, Err(TraceError::Cancelled)));
}

#[test]
fn selector_mismatch_never_visits_sink() {
    let f = Fixture::new();
    for (call, entry, function) in [(0, 1, "App+0x204"), (0, 2, "App+0x200")] {
        let result = f.engine.visit_function_executed_blocks(
            &f.sid,
            call,
            entry,
            function,
            &AtomicBool::new(false),
            |_, _| panic!("invalid selector"),
        );
        assert!(matches!(result, Err(TraceError::InvalidArgument(_))));
    }
}
