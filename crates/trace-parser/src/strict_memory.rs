//! Mechanical query validation, without the scanner's unknown-width defaults.
use crate::{gumtrace, parser, types::MemOp};

pub fn instruction_parts(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let text = if let Some(start) = gumtrace::gumtrace_instruction_prefix(bytes) {
        let tail = &line[start..];
        let end = tail
            .find(';')
            .or_else(|| {
                tail.split_whitespace()
                    .find(|part| part.contains("=0x"))
                    .and_then(|part| tail.find(part))
            })
            .unwrap_or(tail.len());
        tail[..end].trim()
    } else {
        let start = gumtrace::unidbg_instruction_prefix(bytes)? + 1;
        let end = line[start..].find('"')? + start;
        &line[start..end]
    };
    let (mnemonic, operand) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    Some((mnemonic, operand.trim()))
}

/// All printed markers must describe one unambiguous address and direction.
pub fn memory_marker(line: &str) -> Option<(bool, u64)> {
    let mut result = None;
    for (marker, write) in [
        ("mem_w=", true),
        ("mem_r=", false),
        ("mem[WRITE] abs=", true),
        ("mem[READ] abs=", false),
    ] {
        for (start, _) in line.match_indices(marker) {
            if start > 0 && line.as_bytes()[start - 1].is_ascii_alphanumeric() {
                return None;
            }
            let tail = line[start + marker.len()..].strip_prefix("0x")?;
            let len = tail.bytes().take_while(u8::is_ascii_hexdigit).count();
            if len == 0
                || tail
                    .as_bytes()
                    .get(len)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                return None;
            }
            let current = (write, u64::from_str_radix(&tail[..len], 16).ok()?);
            if result.is_some_and(|prior| prior != current) {
                return None;
            }
            result = Some(current);
        }
    }
    // Bare abs annotations cannot establish direction, but cannot contradict a
    // directional marker either (including cross-format annotations).
    for (start, _) in line.match_indices("abs=") {
        let tail = line[start + 4..].strip_prefix("0x")?;
        let len = tail.bytes().take_while(u8::is_ascii_hexdigit).count();
        if len == 0
            || tail
                .as_bytes()
                .get(len)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            return None;
        }
        let address = u64::from_str_radix(&tail[..len], 16).ok()?;
        if result.is_some_and(|(_, prior)| prior != address) {
            return None;
        }
    }
    result
}

fn register_width(name: &str) -> Option<u32> {
    match name {
        "fp" | "lr" | "xzr" => return Some(8),
        "wzr" => return Some(4),
        _ => {}
    }
    let (prefix, digits) = name.split_at_checked(1)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number = digits.parse::<u8>().ok()?;
    if digits != number.to_string() {
        return None;
    }
    match prefix {
        "w" if number <= 30 => Some(4),
        "x" if number <= 30 => Some(8),
        "b" if number <= 31 => Some(1),
        "h" if number <= 31 => Some(2),
        "s" if number <= 31 => Some(4),
        "d" if number <= 31 => Some(8),
        "q" if number <= 31 => Some(16),
        _ => None,
    }
}

pub fn access_width(mnemonic: &str, operand: &str) -> Option<u32> {
    let mut parts = operand.split(',').map(str::trim);
    let mut first = parts.next()?;
    let exclusive = matches!(
        mnemonic,
        "stxr" | "stlxr" | "stxrb" | "stlxrb" | "stxrh" | "stlxrh" | "stxp" | "stlxp"
    );
    if exclusive {
        if !first.starts_with('w') || register_width(first) != Some(4) {
            return None;
        }
        first = parts.next()?;
    }
    let width = register_width(first)?;
    if !operand.contains('[') && !matches!(mnemonic, "ldr" | "ldrsw") {
        return None;
    }
    let integer =
        matches!(first.as_bytes().first(), Some(b'w' | b'x')) || matches!(first, "fp" | "lr");
    let pair = matches!(
        mnemonic,
        "ldp" | "stp" | "ldnp" | "stnp" | "ldxp" | "ldaxp" | "ldpsw" | "stxp" | "stlxp"
    );
    if pair {
        let second = parts.next()?;
        if register_width(second) != Some(width) {
            return None;
        }
        let class = |name: &str| {
            if matches!(name, "fp" | "lr") {
                b'x'
            } else {
                name.as_bytes()[0]
            }
        };
        if class(first) != class(second) {
            return None;
        }
        if mnemonic == "ldpsw" {
            return (integer && width == 8).then_some(8);
        }
        if matches!(mnemonic, "ldxp" | "ldaxp" | "stxp" | "stlxp") && !integer {
            return None;
        }
        return (integer || matches!(class(first), b's' | b'd' | b'q')).then_some(width * 2);
    }
    match mnemonic {
        "strb" | "sturb" | "sttrb" | "ldrb" | "ldurb" | "ldtrb" | "ldarb" | "stlrb" | "stxrb"
        | "stlxrb" => (integer && width == 4).then_some(1),
        "strh" | "sturh" | "sttrh" | "ldrh" | "ldurh" | "ldtrh" | "ldarh" | "stlrh" | "stxrh"
        | "stlxrh" => (integer && width == 4).then_some(2),
        "ldrsb" | "ldursb" | "ldtrsb" => integer.then_some(1),
        "ldrsh" | "ldursh" | "ldtrsh" => integer.then_some(2),
        "ldrsw" | "ldursw" | "ldtrsw" => (integer && width == 8).then_some(4),
        "ldr" | "str" | "ldur" | "stur" => Some(width),
        "ldtr" | "sttr" | "ldar" | "ldxr" | "ldaxr" | "stlr" | "stxr" | "stlxr" => {
            integer.then_some(width)
        }
        _ => None,
    }
}

/// Decode only proven-width operations. Store data comes exclusively from prestate.
pub fn memory_op(line: &str) -> Option<MemOp> {
    let (mnemonic, operand) = instruction_parts(line)?;
    let width = access_width(mnemonic, operand)?;
    let (write, address) = memory_marker(line)?;
    if (mnemonic.starts_with("st") && !write) || (mnemonic.starts_with("ld") && write) {
        return None;
    }
    let parse = |raw: &str| {
        if gumtrace::gumtrace_instruction_prefix(raw.as_bytes()).is_some() {
            gumtrace::parse_line_gumtrace(raw)
        } else {
            parser::parse_line(raw)
        }
    };
    // Existing query fixtures also attach Unidbg memory annotations to Gumtrace
    // instruction prefixes. Normalize that printed marker for the same decoder.
    let normalized;
    let decode_line = if gumtrace::gumtrace_instruction_prefix(line.as_bytes()).is_some() {
        normalized = line
            .replace("mem[WRITE] abs=", "mem_w=")
            .replace("mem[READ] abs=", "mem_r=");
        normalized.as_str()
    } else {
        line
    };
    let full = parse(decode_line)?.mem_op?;
    let mut mem = if write {
        let end = decode_line
            .find(" -> ")
            .or_else(|| decode_line.find(" => "))
            .unwrap_or(decode_line.len());
        parse(&decode_line[..end])?.mem_op?
    } else {
        full.clone()
    };
    mem.exclusive_status = full.exclusive_status;
    if mem.abs != address || mem.is_write != write {
        return None;
    }
    let exclusive = matches!(
        mnemonic,
        "stxr" | "stlxr" | "stxrb" | "stlxrb" | "stxrh" | "stlxrh" | "stxp" | "stlxp"
    );
    let registers: Vec<_> = operand
        .split(',')
        .map(str::trim)
        .skip(usize::from(exclusive))
        .collect();
    let pair = matches!(
        mnemonic,
        "ldp" | "stp" | "ldnp" | "stnp" | "ldxp" | "ldaxp" | "ldpsw" | "stxp" | "stlxp"
    );
    mem.value_count = if pair { 2 } else { 1 };
    mem.elem_width = (width / u32::from(mem.value_count)) as u8;
    let arrow = line.find(" -> ").or_else(|| line.find(" => "));
    let region = if write {
        let start = if let Some(semi) = line.find(';') {
            semi + 1
        } else {
            // No-semicolon Gumtrace is already split by the production parser.
            line.find("=0x")
                .and_then(|eq| line[..eq].rfind(char::is_whitespace))
                .unwrap_or(line.len())
        };
        &line[start..arrow.unwrap_or(line.len())]
    } else {
        arrow.map(|pos| &line[pos + 4..]).unwrap_or("")
    };
    if exclusive {
        let status = operand.split(',').next()?.trim();
        let poststate = arrow.map(|pos| &line[pos + 4..]).unwrap_or("");
        mem.exclusive_status =
            observed_value(poststate, status, 4, false).map(|value| value as u64);
    }
    let value = observed_value(region, registers[0], mem.elem_width, write);
    let value2 = if pair {
        observed_value(region, registers[1], mem.elem_width, write)
    } else {
        None
    };
    if mem.elem_width == 16 {
        mem.value = None;
        mem.value2 = None;
        mem.value_lo = value.map(|v| v as u64);
        mem.value_hi = value.map(|v| (v >> 64) as u64);
        mem.value2_lo = value2.map(|v| v as u64);
        mem.value2_hi = value2.map(|v| (v >> 64) as u64);
    } else {
        mem.value = value.map(|v| v as u64);
        mem.value2 = value2.map(|v| v as u64);
    }
    Some(mem)
}

fn observed_value(region: &str, register: &str, width: u8, write: bool) -> Option<u128> {
    if matches!(register, "wzr" | "xzr") {
        return write.then_some(0);
    }
    let mut aliases = vec![register.to_string()];
    match register {
        "fp" => aliases.push("x29".into()),
        "lr" => aliases.push("x30".into()),
        "x29" => aliases.push("fp".into()),
        "x30" => aliases.push("lr".into()),
        _ => {}
    }
    if let Some(index) = register.strip_prefix('w') {
        aliases.push(format!("x{index}"));
    }
    if matches!(register.as_bytes()[0], b'b' | b'h' | b's' | b'd') {
        aliases.push(format!("q{}", &register[1..]));
    }
    let integer = matches!(register.as_bytes()[0], b'w' | b'x') || matches!(register, "fp" | "lr");
    let mut result = None;
    for token in region.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let Some((name, _)) = token.split_once('=') else {
            continue;
        };
        if !aliases.iter().any(|alias| alias == name) {
            continue;
        }
        // Reuse the production parser's complete hex validation, including overflow.
        let raw = parser::find_reg_value_u128(token.as_bytes(), name.as_bytes(), 0)?;
        if integer && raw > u128::from(u64::MAX) {
            return None;
        }
        let mask = if width == 16 {
            u128::MAX
        } else {
            (1u128 << (u32::from(width) * 8)) - 1
        };
        let value = raw & mask;
        if result.is_some_and(|prior| prior != value) {
            return None;
        }
        result = Some(value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_formats_and_observed_values() {
        let gum = "[App] 0x2000!0x2000 str w0, [x1]; x0=0x123456789 mem_w=0x6000 -> x0=0xdead";
        let mem = memory_op(gum).unwrap();
        assert_eq!(
            (mem.abs, mem.elem_width, mem.value),
            (0x6000, 4, Some(0x23456789))
        );
        let alias = "[App] 0x2000!0x2000 stp x29, x30, [sp]; fp=0x12 lr=0x34 mem_w=0x7000";
        let mem = memory_op(alias).unwrap();
        assert_eq!((mem.value, mem.value2), (Some(0x12), Some(0x34)));
        let unidbg = r#"[22:39:18 210][lib.so 0x10c] [b9001008] 0x4000010c: "str w8, [x0, #0x10]" ; mem[WRITE] abs=0xbffff010 w8=0xf => w8=0xdead"#;
        assert_eq!(memory_op(unidbg).unwrap().value, Some(0xf));
        let q = "[App] 0x2000!0x2000 stp q0, q1, [x2]; q0=0x10000000000000002 q1=0x30000000000000004 mem_w=0x7000";
        let mem = memory_op(q).unwrap();
        assert_eq!(
            (
                mem.elem_width,
                mem.value_count,
                mem.value_lo,
                mem.value_hi,
                mem.value2_lo,
                mem.value2_hi
            ),
            (16, 2, Some(2), Some(1), Some(4), Some(3))
        );
        for values in [
            "x0=0x12oops",
            "x0=0x10000000000000000",
            "x0=0x12 x0=0x13",
            "x0=0x12 x0=0x",
        ] {
            let line = format!("[App] 0x2000!0x2000 str x0, [x1]; {values} mem_w=0x6000");
            assert_eq!(memory_op(&line).unwrap().value, None);
        }
        for (mnemonic, values, expected) in [("str", "", Some(0)), ("ldr", " -> xzr=0x0", None)] {
            let marker = if mnemonic == "str" { "mem_w" } else { "mem_r" };
            let line = format!("[App] 0x2000!0x2000 {mnemonic} xzr, [x1]; {marker}=0x6000{values}");
            assert_eq!(memory_op(&line).unwrap().value, expected);
        }
    }
    #[test]
    fn strict_addresses_and_widths() {
        assert_eq!(memory_marker("mem_w=0x6000"), Some((true, 0x6000)));
        assert_eq!(memory_marker("mem[READ] abs=0x6000"), Some((false, 0x6000)));
        for line in [
            "mem_w=0x6000oops",
            "mem_w=0x",
            "mem_w=0x1 mem_r=0x1",
            "mem_w=0x1 mem_w=0x2",
            "mem_w=0x1 abs=0x2",
            "mem_w=0x1 mem[WRITE] abs=0x2",
        ] {
            assert_eq!(memory_marker(line), None);
        }
        for (m, o, w) in [
            ("str", "w0, [x1]", 4),
            ("stp", "w0, w1, [x2]", 8),
            ("stp", "q0, q1, [x2]", 32),
            ("ldpsw", "x0, x1, [x2]", 8),
        ] {
            assert_eq!(access_width(m, o), Some(w));
        }
        for (m, o) in [
            ("strange", "x0, [x1]"),
            ("str", "x999, [x1]"),
            ("stp", "w0, x1, [x2]"),
            ("stp", "x0, [x1]"),
            ("ldpsw", "w0, w1, [x2]"),
        ] {
            assert_eq!(access_width(m, o), None);
        }
    }
}
