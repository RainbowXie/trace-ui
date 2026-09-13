use std::collections::BTreeMap;

use crate::api_types::{
    FunctionGlobalReadDto, FunctionGlobalWriteDto, FunctionMemoryReadDto, FunctionMemoryWriteDto,
};

use super::super::activation::stable_runtime_site;
use super::blocks::OwnedInsn;
use super::global_map::StableGlobalMap;
use super::lines::{arrow_register_value, base_register};

impl StableGlobalMap {
    fn stable_global_for_access(
        &self,
        owned: &[OwnedInsn],
        access_index: usize,
        address: u64,
        size: u32,
    ) -> Option<String> {
        let mut tracked = base_register(owned.get(access_index)?.first_operand.as_deref()?)?;
        for insn in owned[..access_index].iter().rev() {
            let mnemonic = insn.mnemonic.as_deref()?;
            let operands = insn.first_operand.as_deref()?;
            let parts = operands.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.first().copied() != Some(tracked.as_str()) || !writes_first_operand(mnemonic) {
                continue;
            }
            match mnemonic {
                "adrp" => {
                    let (module, runtime, offset) = stable_runtime_site(&insn.line)?;
                    if !self.target_modules.contains(&module) {
                        return None;
                    }
                    let base = *self.bases.get(&module)?;
                    let adrp_page = arrow_register_value(&insn.line, &tracked)?;
                    if runtime.checked_sub(offset)? != base || address < base {
                        return None;
                    }
                    let expected_address = resolve_fixed_address_chain(
                        owned,
                        access_index,
                        insn,
                        &tracked,
                        adrp_page,
                    )?;
                    let annotated = access_address(owned.get(access_index)?)?;
                    if expected_address != address || annotated != address {
                        return None;
                    }
                    address.checked_add(u64::from(size))?;
                    return Some(format!("{module}+0x{:x}", address - base));
                }
                "add" | "sub" if parts.len() == 3 && parse_immediate(parts[2]).is_some() => {
                    tracked = parts[1].to_owned();
                }
                _ => return None,
            }
        }
        None
    }
}

fn resolve_fixed_address_chain(
    owned: &[OwnedInsn],
    access_index: usize,
    adrp: &OwnedInsn,
    register: &str,
    mut value: u64,
) -> Option<u64> {
    let adrp_parts = adrp
        .first_operand
        .as_deref()?
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    if adrp_parts.len() != 2 || adrp_parts[0] != register {
        return None;
    }
    let operand_page = parse_immediate(adrp_parts[1])?;
    if arrow_register_value(&adrp.line, register)? != operand_page || value != operand_page {
        return None;
    }
    let adrp_index = owned.iter().position(|insn| insn.seq == adrp.seq)?;
    let mut current = register.to_owned();
    for insn in &owned[adrp_index + 1..access_index] {
        let mnemonic = insn.mnemonic.as_deref()?;
        let parts = insn
            .first_operand
            .as_deref()?
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>();
        if matches!(mnemonic, "add" | "sub")
            && parts.len() == 3
            && parts[1] == current
            && parse_immediate(parts[2]).is_some()
        {
            let immediate = parse_immediate(parts[2])?;
            value = if mnemonic == "add" {
                value.checked_add(immediate)?
            } else {
                value.checked_sub(immediate)?
            };
            if arrow_register_value(&insn.line, parts[0])? != value {
                return None;
            }
            current = parts[0].to_owned();
        } else if parts.first().copied() == Some(current.as_str()) && writes_first_operand(mnemonic)
        {
            return None;
        }
    }
    let access = owned.get(access_index)?;
    if base_register(access.first_operand.as_deref()?)? != current {
        return None;
    }
    apply_memory_immediate(value, access.first_operand.as_deref()?)
}

fn apply_memory_immediate(base: u64, operands: &str) -> Option<u64> {
    let start = operands.find('[')?;
    let end = operands[start..].find(']')? + start;
    let parts = operands[start + 1..end]
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [_] => Some(base),
        [_, immediate] if immediate.starts_with("#-") => {
            base.checked_sub(parse_immediate(immediate.strip_prefix("#-")?)?)
        }
        [_, immediate] => base.checked_add(parse_immediate(immediate)?),
        _ => None,
    }
}

fn access_address(insn: &OwnedInsn) -> Option<u64> {
    super::lines::line_mem_annotation(&insn.line, "mem_r")
        .or_else(|| super::lines::line_mem_annotation(&insn.line, "mem_w"))
}

fn parse_immediate(value: &str) -> Option<u64> {
    let value = value.strip_prefix('#')?;
    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()
    } else {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        value.parse().ok()
    }
}

fn writes_first_operand(mnemonic: &str) -> bool {
    !mnemonic.starts_with("st")
        && !matches!(
            mnemonic,
            "b" | "br" | "bl" | "blr" | "ret" | "cmp" | "cmn" | "tst"
        )
}

pub(crate) fn partition_memory_facts(
    owned: &[OwnedInsn],
    globals: &StableGlobalMap,
    memory_reads: Vec<FunctionMemoryReadDto>,
    memory_writes: Vec<FunctionMemoryWriteDto>,
) -> (
    Vec<FunctionMemoryReadDto>,
    Vec<FunctionGlobalReadDto>,
    Vec<FunctionMemoryWriteDto>,
    Vec<FunctionGlobalWriteDto>,
) {
    let positions = owned
        .iter()
        .enumerate()
        .map(|(position, insn)| (insn.seq, position))
        .collect::<BTreeMap<_, _>>();
    let mut plain_reads = Vec::new();
    let mut global_reads = Vec::new();
    for read in memory_reads {
        let Some(global) = stable_global_for_all(
            globals,
            owned,
            &positions,
            &read.address,
            read.size,
            &read.read_seqs,
        ) else {
            plain_reads.push(read);
            continue;
        };
        global_reads.push(FunctionGlobalReadDto {
            global,
            size: read.size,
            bytes: read.bytes,
            read_seqs: read.read_seqs,
        });
    }
    let mut plain_writes = Vec::new();
    let mut global_writes = Vec::new();
    for write in memory_writes {
        let Some(global) = stable_global_for_all(
            globals,
            owned,
            &positions,
            &write.address,
            write.size,
            &write.write_seqs,
        ) else {
            plain_writes.push(write);
            continue;
        };
        global_writes.push(FunctionGlobalWriteDto {
            global,
            size: write.size,
            bytes: write.bytes,
            write_seqs: write.write_seqs,
        });
    }
    (plain_reads, global_reads, plain_writes, global_writes)
}

fn stable_global_for_all(
    globals: &StableGlobalMap,
    owned: &[OwnedInsn],
    positions: &BTreeMap<u32, usize>,
    address: &str,
    size: u32,
    seqs: &[u32],
) -> Option<String> {
    let address = crate::parse_hex_addr(address).ok()?;
    if seqs.is_empty() {
        return None;
    }
    let mut identities = seqs
        .iter()
        .map(|seq| globals.stable_global_for_access(owned, *positions.get(seq)?, address, size))
        .collect::<Option<Vec<_>>>()?;
    identities.sort();
    identities.dedup();
    (identities.len() == 1).then(|| identities.remove(0))
}
