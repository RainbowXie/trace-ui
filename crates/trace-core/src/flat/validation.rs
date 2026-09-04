use trace_parser::types::RegId;

use super::cache_format::SectionReader;
use super::mem_access::FlatMemAccessRecord;
use super::reg_checkpoints::REG_COUNT;

pub(super) struct Phase2Raw<'a> {
    pub addrs: &'a [u64],
    pub offsets: &'a [u32],
    pub records: &'a [FlatMemAccessRecord],
    pub checkpoint_interval: u32,
    pub checkpoint_count: u32,
    pub checkpoint_data: &'a [u64],
}

pub(super) fn phase2_raw<'a>(reader: &SectionReader<'a>) -> Option<Phase2Raw<'a>> {
    let addrs: &[u64] = reader.slice(0);
    let offsets: &[u32] = reader.slice(1);
    let records: &[FlatMemAccessRecord] = reader.slice(2);
    let checkpoint_interval = reader.u32_val(3);
    let checkpoint_count = reader.u32_val(4);
    let checkpoint_data: &[u64] = reader.slice(5);

    if offsets.len() != addrs.len().saturating_add(1)
        || !valid_csr_offsets(offsets, records.len())
        || addrs.windows(2).any(|w| w[0] >= w[1])
        || (checkpoint_count > 0 && checkpoint_interval == 0)
        || usize::try_from(checkpoint_count)
            .ok()
            .and_then(|count| count.checked_mul(REG_COUNT))
            != Some(checkpoint_data.len())
    {
        return None;
    }
    Some(Phase2Raw {
        addrs,
        offsets,
        records,
        checkpoint_interval,
        checkpoint_count,
        checkpoint_data,
    })
}

pub(super) struct ScanRaw<'a> {
    pub chunk_start_lines: &'a [u32],
    pub chunk_offsets_start: &'a [u32],
    pub chunk_data_start: &'a [u32],
    pub all_offsets: &'a [u32],
    pub all_data: &'a [u32],
    pub patch_lines: &'a [u32],
    pub patch_offsets: &'a [u32],
    pub patch_data: &'a [u32],
    pub mem_addrs: &'a [u64],
    pub mem_lines: &'a [u32],
    pub mem_values: &'a [u64],
    pub pair_keys: &'a [u32],
    pub pair_offsets: &'a [u32],
    pub pair_data: &'a [u32],
    pub bit_data: &'a [u8],
    pub bit_len: u32,
    pub reg_last_def_inner: &'a [u32],
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

pub(super) fn scan_raw<'a>(reader: &SectionReader<'a>) -> Option<ScanRaw<'a>> {
    let raw = ScanRaw {
        chunk_start_lines: reader.slice(0),
        chunk_offsets_start: reader.slice(1),
        chunk_data_start: reader.slice(2),
        all_offsets: reader.slice(3),
        all_data: reader.slice(4),
        patch_lines: reader.slice(5),
        patch_offsets: reader.slice(6),
        patch_data: reader.slice(7),
        mem_addrs: reader.slice(8),
        mem_lines: reader.slice(9),
        mem_values: reader.slice(10),
        pair_keys: reader.slice(11),
        pair_offsets: reader.slice(12),
        pair_data: reader.slice(13),
        bit_data: reader.slice(14),
        bit_len: reader.u32_val(15),
        reg_last_def_inner: reader.slice(16),
        line_count: reader.u32_val(17),
        parsed_count: reader.u32_val(18),
        mem_op_count: reader.u32_val(19),
    };

    if !valid_deps(&raw)
        || raw.mem_addrs.len() != raw.mem_lines.len()
        || raw.mem_addrs.len() != raw.mem_values.len()
        || raw.mem_addrs.windows(2).any(|w| w[0] >= w[1])
        || raw.pair_offsets.len()
            != raw
                .pair_keys
                .len()
                .checked_mul(3)
                .and_then(|len| len.checked_add(1))
                .unwrap_or(usize::MAX)
        || raw.pair_keys.windows(2).any(|w| w[0] >= w[1])
        || !valid_csr_offsets(raw.pair_offsets, raw.pair_data.len())
        || usize::try_from(raw.bit_len)
            .ok()
            .and_then(|len| len.checked_add(7))
            .map(|len| len / 8)
            != Some(raw.bit_data.len())
        || raw.reg_last_def_inner.len() != RegId::COUNT
        || raw.parsed_count > raw.line_count
        || raw.mem_op_count > raw.parsed_count
    {
        return None;
    }
    Some(raw)
}

fn valid_csr_offsets(offsets: &[u32], data_len: usize) -> bool {
    offsets.first().copied() == Some(0)
        && offsets.last().copied().map(|v| v as usize) == Some(data_len)
        && offsets.windows(2).all(|w| w[0] <= w[1])
}

fn valid_deps(raw: &ScanRaw<'_>) -> bool {
    if raw.chunk_start_lines.len() != raw.chunk_offsets_start.len()
        || raw.chunk_start_lines.len() != raw.chunk_data_start.len()
        || raw.chunk_start_lines.first().copied() != Some(0)
        || raw.chunk_start_lines.windows(2).any(|w| w[0] >= w[1])
        || raw
            .chunk_start_lines
            .last()
            .is_some_and(|&line| line > raw.line_count)
        || raw.patch_lines.windows(2).any(|w| w[0] >= w[1])
        || raw
            .patch_lines
            .last()
            .is_some_and(|&line| line >= raw.line_count)
    {
        return false;
    }
    if raw.patch_lines.is_empty() {
        if !raw.patch_offsets.is_empty() || !raw.patch_data.is_empty() {
            return false;
        }
    } else if raw.patch_offsets.len() != raw.patch_lines.len().saturating_add(1)
        || !valid_csr_offsets(raw.patch_offsets, raw.patch_data.len())
    {
        return false;
    }

    for index in 0..raw.chunk_start_lines.len() {
        let line_start = raw.chunk_start_lines[index] as usize;
        let line_end = raw
            .chunk_start_lines
            .get(index + 1)
            .copied()
            .unwrap_or(raw.line_count) as usize;
        let offsets_start = raw.chunk_offsets_start[index] as usize;
        let offsets_end = raw
            .chunk_offsets_start
            .get(index + 1)
            .copied()
            .map(|v| v as usize)
            .unwrap_or(raw.all_offsets.len());
        let data_start = raw.chunk_data_start[index] as usize;
        let data_end = raw
            .chunk_data_start
            .get(index + 1)
            .copied()
            .map(|v| v as usize)
            .unwrap_or(raw.all_data.len());
        let Some(expected_offsets) = line_end
            .checked_sub(line_start)
            .and_then(|rows| rows.checked_add(1))
        else {
            return false;
        };
        if offsets_end.checked_sub(offsets_start) != Some(expected_offsets)
            || offsets_end > raw.all_offsets.len()
            || data_end < data_start
            || data_end > raw.all_data.len()
            || !valid_csr_offsets(
                &raw.all_offsets[offsets_start..offsets_end],
                data_end - data_start,
            )
        {
            return false;
        }
    }
    true
}
