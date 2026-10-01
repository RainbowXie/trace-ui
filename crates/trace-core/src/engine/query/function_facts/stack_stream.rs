//! Stack slots are resolved in their final representation before reservation.
use super::{
    block_stream::{scan_owned, BorrowedOwnedInsn},
    budget::Budget,
    lines,
};
use crate::api_types::FunctionStackArgumentDto;
use crate::error::{Result, TraceError};
use crate::query::activation::{ActivationTree, ConfirmedActivation};
use crate::session::SessionState;
use serde::Serialize;
use std::sync::atomic::AtomicBool;

fn candidate(insn: &BorrowedOwnedInsn<'_>, sp: u64) -> Option<(u64, u32)> {
    let address = lines::line_mem_annotation(insn.line, "mem_r")?;
    if address < sp {
        return None;
    }
    let (mnemonic, operand) = trace_parser::strict_memory::instruction_parts(insn.line)?;
    let tail = &operand[operand.find('[')? + 1..];
    let base = tail[..tail.find([',', ']'])?].trim();
    if !matches!(base, "sp" | "wsp" | "fp" | "x29") {
        return None;
    }
    Some((address - sp, lines::access_width(mnemonic, operand)?))
}
fn overlaps(a: u64, size: u32, b: u64, bsize: u32) -> bool {
    let (Some(aend), Some(bend)) = (a.checked_add(size as u64), b.checked_add(bsize as u64)) else {
        return false;
    };
    a < bend && b < aend
}
struct SlotSeqs<'a> {
    state: &'a SessionState,
    tree: &'a ActivationTree,
    root: &'a ConfirmedActivation,
    cancel: &'a AtomicBool,
    sp: u64,
    key: (u64, u32),
}
impl Serialize for SlotSeqs<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut out = serializer.serialize_seq(None)?;
        scan_owned(self.state, self.tree, self.root, self.cancel, |insn| {
            if candidate(&insn, self.sp) == Some(self.key) {
                out.serialize_element(&insn.seq)
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
            }
            Ok(true)
        })
        .map_err(S::Error::custom)?;
        out.end()
    }
}
pub(super) fn collect(
    state: &SessionState,
    tree: &ActivationTree,
    root: &ConfirmedActivation,
    sp: u64,
    cancel: &AtomicBool,
    budget: &mut Budget,
) -> Result<Vec<FunctionStackArgumentDto>> {
    let mut slots = Vec::new();
    let mut previous = None;
    loop {
        let mut next = None;
        scan_owned(state, tree, root, cancel, |insn| {
            if let Some(key) = candidate(&insn, sp) {
                if previous.is_none_or(|p| key > p) && next.is_none_or(|n| key < n) {
                    next = Some(key);
                }
            }
            Ok(true)
        })?;
        let Some(key @ (offset, size)) = next else {
            break;
        };
        let mut value = None;
        scan_owned(state, tree, root, cancel, |insn| {
            if candidate(&insn, sp) != Some(key) || value.is_some() {
                return Ok(true);
            }
            let (m, op) =
                trace_parser::strict_memory::instruction_parts(insn.line).expect("candidate");
            if lines::is_pair_access(m) || size > 8 {
                return Ok(true);
            }
            let mut written_before = false;
            scan_owned(state, tree, root, cancel, |write| {
                if write.seq >= insn.seq {
                    return Ok(false);
                }
                if let Some(address) = lines::line_mem_annotation(write.line, "mem_w") {
                    if let Some((wm, wo)) =
                        trace_parser::strict_memory::instruction_parts(write.line)
                    {
                        if overlaps(
                            address,
                            lines::access_width(wm, wo).unwrap_or(64),
                            sp + offset,
                            size,
                        ) {
                            written_before = true;
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            })?;
            if !written_before {
                value = op
                    .split(',')
                    .next()
                    .and_then(|r| lines::arrow_register_value(insn.line, r.trim()));
            }
            Ok(true)
        })?;
        // Stack-local formatting scratch, not a pre-budget String.
        let mut hex = [0u8; 18];
        if let Some(v) = value {
            hex[..2].copy_from_slice(b"0x");
            const DIGITS: &[u8] = b"0123456789abcdef";
            for pos in 0..16 {
                hex[2 + pos] = DIGITS[((v >> (4 * (15 - pos))) & 15) as usize];
            }
        }
        let value = value.map(|_| std::str::from_utf8(&hex).expect("hex"));
        #[derive(Serialize)]
        struct Preview<'a, 'b> {
            offset: i64,
            size: u32,
            value: Option<&'a str>,
            read_seqs: SlotSeqs<'b>,
        }
        budget.item(
            &Preview {
                offset: offset as i64,
                size,
                value,
                read_seqs: SlotSeqs {
                    state,
                    tree,
                    root,
                    cancel,
                    sp,
                    key,
                },
            },
            3,
            slots.is_empty(),
        )?;
        let mut seqs = Vec::new();
        scan_owned(state, tree, root, cancel, |insn| {
            if candidate(&insn, sp) == Some(key) {
                super::collector::reserve_vec(&mut seqs)?;
                seqs.push(insn.seq);
            }
            Ok(true)
        })?;
        super::collector::reserve_vec(&mut slots)?;
        slots.push(FunctionStackArgumentDto {
            offset: offset as i64,
            size,
            value: value.map(str::to_owned),
            read_seqs: seqs,
        });
        previous = Some(key);
    }
    Ok(slots)
}
