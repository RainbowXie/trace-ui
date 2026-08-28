//! 纯逻辑单元测试：pattern 解析与 anchor 索引。

use super::parse_pattern_hex;
use super::scan::{ByteValue, SearchState};
use std::sync::Mutex;

pub(super) static CACHE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 测试 panic 会 poison 全局锁；缓存测试需要互相隔离的状态，
/// 必须用 poison 容忍的方式取锁，否则一个失败会连带全部缓存测试。
pub(super) fn cache_test_guard() -> std::sync::MutexGuard<'static, ()> {
    CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn pattern_parser_accepts_compact_and_spaced_hex() {
    assert_eq!(parse_pattern_hex("aabbcc").unwrap(), vec![0xaa, 0xbb, 0xcc]);
    assert_eq!(
        parse_pattern_hex("AA bb cc").unwrap(),
        vec![0xaa, 0xbb, 0xcc]
    );
}

#[test]
fn pattern_parser_rejects_odd_or_non_hex_input() {
    assert!(parse_pattern_hex("abc").is_err());
    assert!(parse_pattern_hex("aa:bb").is_err());
}

#[test]
fn anchor_index_keeps_only_positions_matching_the_requested_anchor() {
    let pattern = vec![0x11; 8];
    let mut state = SearchState::new(&pattern);
    for address in 0x1000..0x1800 {
        state.memory.set(
            address,
            ByteValue {
                value: 0x22,
                known: true,
            },
        );
        state.update_anchor_positions_around(address);
    }
    assert!(state.anchor_positions.is_empty());

    for address in 0x2000..0x2008 {
        state.memory.set(
            address,
            ByteValue {
                value: 0x11,
                known: true,
            },
        );
        state.update_anchor_positions_around(address);
    }
    assert_eq!(state.anchor_positions.len(), 1);
    assert!(state.anchor_positions.contains(&0x2000));
}
