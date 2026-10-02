//! Static literals for the existing AArch64 little-endian replay convention.
//! No post-state register value participates in decoding. Big-endian traces are
//! not supported by this pipeline (as with byte_effect and strict_memory).

pub(crate) fn decode(line: &str) -> Option<(u32, String)> {
    let (mnemonic, operands) = trace_parser::strict_memory::instruction_parts(line)?;
    if mnemonic != "mov" {
        return None;
    }
    // Gumtrace without a semicolon leaves its post-state arrow in the
    // strict parser's operand slice. The arrow is a trace delimiter, not ISA.
    let operands = operands.split(" ->").next()?.split(" =>").next()?.trim();
    let mut parts = operands.split(',').map(str::trim);
    let register = parts.next()?;
    let literal = parts.next()?.strip_prefix('#')?;
    if parts.next().is_some() || register.len() < 2 {
        return None;
    }
    let size = match register.as_bytes()[0] {
        b'w' => 4,
        b'x' => 8,
        _ => return None,
    };
    let number = &register[1..];
    let index = number.parse::<u8>().ok()?;
    if index > 30 || number != index.to_string() {
        return None;
    }
    let value = if let Some(hex) = literal.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()?
    } else {
        if literal.is_empty() || !literal.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        literal.parse::<u64>().ok()?
    };
    if size == 4 && value > u32::MAX as u64 {
        return None;
    }
    // W defines exactly four bytes and zero-extends its X alias; do not widen
    // the Constant or mask an out-of-range literal to simulate truncation.
    let bytes = value.to_le_bytes()[..size as usize]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some((size, bytes))
}

pub(crate) fn candidate(line: &str) -> bool {
    trace_parser::strict_memory::instruction_parts(line).is_some_and(|(m, operands)| {
        matches!(m, "mov" | "movz" | "movn" | "movk")
            && operands
                .split(',')
                .nth(1)
                .is_some_and(|p| p.trim().starts_with('#'))
            && !operands.contains('[')
    })
}

/// The block list must have been mechanically built from this owner's complete
/// owned scan. A seq interval alone must never establish instruction ownership.
pub(crate) fn block_for_seq<'a>(
    tree: &crate::query::activation::ActivationTree,
    owner: &crate::query::activation::ConfirmedActivation,
    blocks: &'a [crate::api_types::ExecutedBlockEntryDto],
    seq: u32,
) -> Option<(usize, &'a crate::api_types::ExecutedBlockEntryDto)> {
    if tree.activation_for_seq(seq)?.id != owner.id {
        return None;
    }
    let index = blocks
        .partition_point(|block| block.entry_seq <= seq)
        .checked_sub(1)?;
    Some((index, &blocks[index]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn static_width_and_full_grammar() {
        let line = |op: &str| format!("[App] 0x100!0x100 {op}; x0=0xff -> x0=0xee");
        assert_eq!(
            super::decode(&line("mov w0, #0x12345678")),
            Some((4, "78563412".into()))
        );
        assert_eq!(
            super::decode(&line("mov x30, #1")),
            Some((8, "0100000000000000".into()))
        );
        assert_eq!(
            super::decode(&line("mov w0, #4294967295")),
            Some((4, "ffffffff".into()))
        );
        for op in [
            "mov w0, #4294967296",
            "mov x0, #18446744073709551616",
            "mov x0, #-1",
            "mov x0, #+1",
            "mov x0, #0x",
            "mov x0, #1, lsl #16",
            "mov sp, #1",
            "mov x31, #1",
            "mov x01, #1",
            "movk x0, #1",
            "movz x0, #1",
            "movn x0, #1",
        ] {
            assert!(super::decode(&line(op)).is_none(), "{op}");
        }
    }
}
