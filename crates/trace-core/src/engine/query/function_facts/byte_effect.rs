//! Per-byte known/unknown effects reuse the existing little-endian replay rules.
use crate::api_types::FunctionMemoryWriteDto;
use crate::utils::checked_mem_addr;
use std::collections::BTreeMap;

pub(super) fn memory_bytes(line: &str, size: u32) -> Vec<Option<u8>> {
    trace_parser::strict_memory::memory_op(line)
        .map(|mem| {
            crate::memory_search::expand_mem_op(&mem)
                .into_iter()
                .map(|byte| byte.known.then_some(byte.value))
                .collect::<Vec<_>>()
        })
        .filter(|bytes| bytes.len() == size as usize)
        .unwrap_or_else(|| vec![None; size as usize])
}

#[derive(Default)]
pub(super) struct FinalByteMap {
    bytes: BTreeMap<u64, (Option<u8>, u32)>,
}
impl FinalByteMap {
    pub(super) fn apply(&mut self, address: u64, bytes: &[Option<u8>], seq: u32) -> bool {
        if bytes.is_empty() || checked_mem_addr(address, bytes.len() as u64 - 1).is_none() {
            return false;
        }
        for (offset, value) in bytes.iter().copied().enumerate() {
            self.bytes.insert(address + offset as u64, (value, seq));
        }
        true
    }
    pub(super) fn materialize(&self) -> Vec<FunctionMemoryWriteDto> {
        let mut out = Vec::new();
        let mut pending: Option<FunctionMemoryWriteDto> = None;
        let mut last_winner = 0;
        let mut last_address: Option<u64> = None;
        for (&address, &(value, winner)) in &self.bytes {
            let contiguous = pending.as_ref().is_some_and(|range| {
                last_address.and_then(|prior| checked_mem_addr(prior, 1)) == Some(address)
                    && range.bytes.is_some() == value.is_some()
                    && (value.is_some() || winner == last_winner)
            });
            if !contiguous {
                if let Some(range) = pending.take() {
                    out.push(range);
                }
                pending = Some(FunctionMemoryWriteDto {
                    address: format!("0x{address:x}"),
                    size: 0,
                    bytes: value.map(|_| String::new()),
                    write_seqs: Vec::new(),
                });
            }
            let range = pending.as_mut().expect("pending");
            range.size += 1;
            if let (Some(bytes), Some(value)) = (&mut range.bytes, value) {
                bytes.push_str(&format!("{value:02x}"));
            }
            if !range.write_seqs.contains(&winner) {
                range.write_seqs.push(winner);
            }
            last_winner = winner;
            last_address = Some(address);
        }
        if let Some(range) = pending {
            out.push(range);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recorded_pairs_and_prestate_only() {
        let pair = "[App] 0x2000!0x2000 stp w8, w0, [x19]; x19=0x7000 w8=0x14 w0=0x13 mem_w=0x7000";
        assert_eq!(
            memory_bytes(pair, 8),
            vec![
                Some(0x14),
                Some(0),
                Some(0),
                Some(0),
                Some(0x13),
                Some(0),
                Some(0),
                Some(0)
            ]
        );
        let missing = "[App] 0x2000!0x2000 stp x0, x1, [x2]; x0=0x12 mem_w=0x7000 -> x1=0x34";
        let bytes = memory_bytes(missing, 16);
        assert_eq!(bytes[0], Some(0x12));
        assert!(bytes[8..].iter().all(Option::is_none));
        let mut map = FinalByteMap::default();
        assert!(!map.apply(u64::MAX, &bytes, 1));
        assert!(map.materialize().is_empty());
        assert!(map.apply(0x7000, &bytes, 1));
        let writes = map.materialize();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].bytes.as_deref(), Some("1200000000000000"));
        assert_eq!((writes[1].address.as_str(), writes[1].size, &writes[1].bytes), ("0x7008", 8, &None));
        let q = "[App] 0x2000!0x2000 stp q0, q1, [x2]; q0=0x10000000000000002 q1=0x30000000000000004 mem_w=0x8000";
        let mut wide = FinalByteMap::default();
        assert!(wide.apply(0x8000, &memory_bytes(q, 32), 2));
        assert_eq!(wide.materialize()[0].bytes.as_deref(), Some("0200000000000000010000000000000004000000000000000300000000000000"));
    }
}
