//! 纯逻辑单元测试：pattern 解析与 anchor 索引。

use super::parse_pattern_hex;
use super::scan::{ByteValue, SearchState};

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
