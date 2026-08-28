use crate::insn_class::InsnClass;
use crate::types::{Operand, ParsedLine, RegId};
use smallvec::SmallVec;

/// Expand a SIMD lo-lane RegId to both lo+hi lanes (128-bit full operation).
/// Non-SIMD registers pass through unchanged.
fn expand_simd_full(vec: &mut SmallVec<[RegId; 4]>, reg: RegId) {
    vec.push(reg);
    if let Some(hi) = reg.simd_hi() {
        vec.push(hi);
    }
}

/// Determine which lane (lo or hi) a lane_index maps to given elem_width.
/// byte_offset = lane_index * elem_width; >= 8 means hi lane.
fn simd_lane_reg(reg: RegId, lane_index: u8, elem_width: u8) -> RegId {
    let byte_offset = lane_index as u32 * elem_width as u32;
    if byte_offset >= 8 {
        reg.simd_hi().unwrap_or(reg)
    } else {
        reg
    }
}

/// Determine the DEF (written) and USE (read) registers for a parsed instruction.
///
/// This function explicitly matches ALL 42 InsnClass variants with no wildcard `_ =>`
/// fallback, ensuring compile-time exhaustiveness checking. Each variant encodes a
/// unique DEF/USE pattern derived from the ARM64 ISA semantics (design doc v9).
///
/// Returns `(defs, uses)` as SmallVec with capacity 4 (covers most instructions).
pub fn determine_def_use(
    class: InsnClass,
    line: &ParsedLine,
) -> (SmallVec<[RegId; 4]>, SmallVec<[RegId; 4]>) {
    let mut defs: SmallVec<[RegId; 4]> = SmallVec::new();
    let mut uses: SmallVec<[RegId; 4]> = SmallVec::new();
    let ops = &line.operands;

    match class {
        // =====================================================================
        // Standard pure-write pattern: DEF=ops[0], USE=ops[1..]
        // Covers: ALU, Multiply, Move, Bitfield, Extend, FloatArith
        // =====================================================================
        InsnClass::AluReg
        | InsnClass::AluImm
        | InsnClass::AluShift
        | InsnClass::Multiply
        | InsnClass::Move
        | InsnClass::Bitfield
        | InsnClass::Extend
        | InsnClass::FloatArith => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // SIMD pure-write: DEF=lo+hi of ops[0], USE=lo+hi of ops[1..]
        // =====================================================================
        InsnClass::SimdArith | InsnClass::SimdMisc | InsnClass::SimdMove => {
            if let Some(rd) = first_reg_non_zero(ops) {
                expand_simd_full(&mut defs, rd);
            }
            for op in ops.iter().skip(1) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    expand_simd_full(&mut uses, r);
                }
            }
        }

        // =====================================================================
        // E: FlagSet — cmp, cmn, tst, fcmp, fcmpe
        // DEF=nzcv, USE=all operands (Rn, Rm or imm)
        // =====================================================================
        InsnClass::FlagSet => {
            defs.push(RegId::NZCV);
            collect_uses_from(ops, 0, &mut uses);
        }

        // =====================================================================
        // E: CondFlagSet — ccmp, ccmn, cfinv
        // DEF=nzcv, USE=nzcv + operand registers
        // =====================================================================
        InsnClass::CondFlagSet => {
            defs.push(RegId::NZCV);
            uses.push(RegId::NZCV);
            collect_uses_from(ops, 0, &mut uses);
        }

        // =====================================================================
        // F: AluFlags — adds, subs, ands, bics, negs
        // DEF=Rd + nzcv, USE=ops[1..]
        // =====================================================================
        InsnClass::AluFlags => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            defs.push(RegId::NZCV);
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // F: FlagUse — csel, csinc, csinv, csneg, fcsel
        // F: AluCarry — adc, sbc, ngc
        // DEF=Rd, USE=ops[1..] + nzcv
        // =====================================================================
        InsnClass::FlagUse | InsnClass::AluCarry => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            collect_uses_from(ops, 1, &mut uses);
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // F: AluCarryFlags — adcs, sbcs, ngcs
        // DEF=Rd + nzcv, USE=ops[1..] + nzcv
        // =====================================================================
        InsnClass::AluCarryFlags => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
            }
            defs.push(RegId::NZCV);
            collect_uses_from(ops, 1, &mut uses);
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // D: ScalarRMW — movk, bfi, bfxil, bfc
        // DEF=Rd, USE=Rd(old) + ops[1..]
        // =====================================================================
        InsnClass::ScalarRMW => {
            if let Some(rd) = first_reg_non_zero(ops) {
                defs.push(rd);
                uses.push(rd); // old value is a USE
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // M: SimdRMW — ins, bsl, bit, bif, mla, mls, fmov Vd.D[1]
        // Lane or full 128-bit RMW with lo+hi expansion
        // =====================================================================
        InsnClass::SimdRMW => {
            if let Some(rd) = first_reg_non_zero(ops) {
                if let (Some(lane_idx), Some(ew)) = (line.lane_index, line.lane_elem_width) {
                    // Lane operation (ins, fmov v.d[1]): only target lane
                    let target = simd_lane_reg(rd, lane_idx, ew);
                    defs.push(target);
                    uses.push(target); // old value of target lane
                } else {
                    // Full 128-bit RMW (bsl, aese, sha256h, mla, etc.)
                    expand_simd_full(&mut defs, rd);
                    expand_simd_full(&mut uses, rd);
                }
            }
            // Source operands: conservatively expand SIMD to lo+hi
            for op in ops.iter().skip(1) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut uses, r);
                    } else {
                        uses.push(r);
                    }
                }
            }
        }

        // =====================================================================
        // G: LoadReg — ldr, ldrb, ldrh, ldrsw, etc.
        // DEF=Rt [+ base if writeback], USE=base + mem
        // =====================================================================
        InsnClass::LoadReg => {
            if let Some(rt) = first_reg_non_zero(ops) {
                defs.push(rt);
            }
            collect_uses_from(ops, 1, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // G: LoadPair — ldp, ldpsw, ldnp
        // DEF=Rt1 + Rt2 [+ base if writeback], USE=base + mem
        // =====================================================================
        InsnClass::LoadPair => {
            for op in ops.iter().take(2) {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut defs, r);
                    } else {
                        defs.push(r);
                    }
                }
            }
            collect_uses_from(ops, 2, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // H: StoreReg — str, strb, strh, stlr, etc.
        // DEF=[base if writeback], USE=all operands
        // =====================================================================
        InsnClass::StoreReg => {
            collect_uses_from(ops, 0, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // H: StorePair — stp, stnp
        // Data operands may be SIMD → expand lo+hi
        // =====================================================================
        InsnClass::StorePair => {
            // Data operands may be SIMD → expand lo+hi
            for op in ops.iter() {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut uses, r);
                    } else {
                        uses.push(r);
                    }
                }
            }
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // M: SimdStore — st1, st2, str Dt/Qt, etc.
        // SIMD data operands expanded to lo+hi
        // =====================================================================
        InsnClass::SimdStore => {
            for op in ops.iter() {
                if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
                    if r.is_simd_lo() {
                        expand_simd_full(&mut uses, r);
                    } else {
                        uses.push(r);
                    }
                }
            }
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // H: StoreExcl — stxr, stlxr, stxp, stlxp
        // DEF=Ws(status reg = ops[0]), USE=ops[1..]
        // =====================================================================
        InsnClass::StoreExcl => {
            if let Some(ws) = first_reg_non_zero(ops) {
                defs.push(ws);
            }
            collect_uses_from(ops, 1, &mut uses);
        }

        // =====================================================================
        // H: AtomicLoadOp — ldadd, ldclr, ldset, ldeor, swp, etc.
        // Layout: <Xs>, <Xt>, [<Xn>]
        // DEF=Xt(ops[1], old mem value), USE=Xs(ops[0])+Xn(ops[2])
        // =====================================================================
        InsnClass::AtomicLoadOp => {
            if let Some(rt) = ops.get(1).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                defs.push(rt);
            }
            if let Some(rs) = ops
                .first()
                .and_then(|o| o.as_reg())
                .filter(|r| !r.is_zero())
            {
                uses.push(rs);
            }
            if let Some(rn) = ops.get(2).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // H: CompareAndSwap — cas, casa, casal, casl
        // Layout: <Ws>, <Wt>, [<Xn>]
        // DEF=Ws(ops[0], RMW), USE=Ws(expected)+Wt(ops[1])+Xn(ops[2])
        // =====================================================================
        InsnClass::CompareAndSwap => {
            if let Some(ws) = ops
                .first()
                .and_then(|o| o.as_reg())
                .filter(|r| !r.is_zero())
            {
                defs.push(ws);
                uses.push(ws);
            }
            if let Some(wt) = ops.get(1).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                uses.push(wt);
            }
            if let Some(rn) = ops.get(2).and_then(|o| o.as_reg()).filter(|r| !r.is_zero()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // I: CondBranchNzcv — b.cond (b.eq, b.ne, etc.)
        // DEF=none, USE=nzcv
        // =====================================================================
        InsnClass::CondBranchNzcv => {
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // I: CondBranchReg — cbz, cbnz, tbz, tbnz
        // DEF=none, USE=Rt
        // =====================================================================
        InsnClass::CondBranchReg => {
            if let Some(rt) = first_reg_non_zero(ops) {
                uses.push(rt);
            }
        }

        // =====================================================================
        // J: Branch — b (unconditional)
        // No DEF/USE
        // =====================================================================
        InsnClass::Branch => {}

        // =====================================================================
        // J: BranchLink — bl
        // DEF=x30 (link register)
        // =====================================================================
        InsnClass::BranchLink => {
            defs.push(RegId::X30);
        }

        // =====================================================================
        // K: BranchReg — br
        // USE=Rn (target register)
        // =====================================================================
        InsnClass::BranchReg => {
            if let Some(rn) = first_reg_non_zero(ops) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // K: BranchLinkReg — blr
        // DEF=x30, USE=Rn
        // =====================================================================
        InsnClass::BranchLinkReg => {
            defs.push(RegId::X30);
            if let Some(rn) = first_reg_non_zero(ops) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // K: Return — ret
        // USE=x30 (implicit)
        // =====================================================================
        InsnClass::Return => {
            uses.push(RegId::X30);
        }

        // =====================================================================
        // Nop / Svc — no DEF/USE
        // =====================================================================
        InsnClass::Nop => {}

        // svc 的寄存器副作用从 trace 的 => 箭头数据推断
        InsnClass::Svc => {
            if let Some(ref post) = line.post_arrow_regs {
                for &(reg, _) in post.iter() {
                    if !reg.is_zero() {
                        defs.push(reg);
                    }
                }
            }
        }

        // =====================================================================
        // L2: SysRegRead — mrs Rd, sysreg
        // DEF=Rd
        // =====================================================================
        InsnClass::SysRegRead => {
            if let Some(rd) = ops.first().and_then(|o| o.as_reg()) {
                defs.push(rd);
            }
        }

        // =====================================================================
        // L2: SysRegNzcvRead — mrs Rd, nzcv
        // DEF=Rd, USE=nzcv
        // =====================================================================
        InsnClass::SysRegNzcvRead => {
            if let Some(rd) = ops.first().and_then(|o| o.as_reg()) {
                defs.push(rd);
            }
            uses.push(RegId::NZCV);
        }

        // =====================================================================
        // L2: SysRegWrite — msr sysreg, Rn
        // USE=Rn (first register operand)
        // =====================================================================
        InsnClass::SysRegWrite => {
            if let Some(rn) = ops.first().and_then(|o| o.as_reg()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // L2: SysRegNzcvWrite — msr nzcv, Rn
        // DEF=nzcv, USE=Rn
        // =====================================================================
        InsnClass::SysRegNzcvWrite => {
            defs.push(RegId::NZCV);
            if let Some(rn) = ops.first().and_then(|o| o.as_reg()) {
                uses.push(rn);
            }
        }

        // =====================================================================
        // M: SimdLoad — ld1 full, ld2, ldr Dt/Qt, etc.
        // DEF=Vt [+ base if writeback], USE=base registers
        // =====================================================================
        InsnClass::SimdLoad => {
            // base_reg 之前的操作数全部作为 DEF（支持多寄存器 ld1 {v0, v1, ...}）
            // 当 base_reg 未设置时，回退到旧行为：仅 ops[0] 为 DEF
            if let Some(base) = line.base_reg {
                for op in ops.iter() {
                    if let Some(r) = op.as_reg() {
                        if r == base {
                            break;
                        }
                        expand_simd_full(&mut defs, r);
                    }
                }
                // base_reg 作为 USE
                uses.push(base);
            } else {
                // 回退：无 base_reg 时，仅第一个寄存器为 DEF，其余为 USE
                if let Some(vt) = ops.first().and_then(|o| o.as_reg()) {
                    expand_simd_full(&mut defs, vt);
                }
                collect_uses_from(ops, 1, &mut uses);
            }
            // writeback: base_reg 也是 DEF
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }

        // =====================================================================
        // M: SimdLaneLoad — ld1 lane load (read-modify-write)
        // DEF=Vt [+ base if writeback], USE=Vt(old) + base + mem
        // =====================================================================
        InsnClass::SimdLaneLoad => {
            if let Some(vt) = ops.first().and_then(|o| o.as_reg()) {
                if let (Some(lane_idx), Some(ew)) = (line.lane_index, line.lane_elem_width) {
                    let target = simd_lane_reg(vt, lane_idx, ew);
                    defs.push(target);
                    uses.push(target); // old value of target lane (RMW)
                } else {
                    // Fallback: conservative full register RMW
                    expand_simd_full(&mut defs, vt);
                    expand_simd_full(&mut uses, vt);
                }
            }
            collect_uses_from(ops, 1, &mut uses);
            if line.writeback {
                if let Some(base) = line.base_reg {
                    defs.push(base);
                }
            }
        }
    }

    (defs, uses)
}

/// Extract the first operand's RegId, filtering out xzr.
fn first_reg_non_zero(ops: &[Operand]) -> Option<RegId> {
    ops.first()
        .and_then(|o| o.as_reg())
        .filter(|r| !r.is_zero())
}

/// Collect register USEs from ops[start..], filtering out xzr and immediates.
fn collect_uses_from(ops: &[Operand], start: usize, uses: &mut SmallVec<[RegId; 4]>) {
    for op in ops.iter().skip(start) {
        if let Some(r) = op.as_reg().filter(|r| !r.is_zero()) {
            uses.push(r);
        }
    }
}

// 测试体积大（815 行）：通过 include! 保持字节级原样，避免转写误差。
#[cfg(test)]
mod tests {
    include!("tests.rs");
}
