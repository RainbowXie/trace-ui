    use super::*;
    use crate::insn_class::InsnClass;
    use crate::types::*;

    /// Helper to build a ParsedLine from a slice of Operands.
    fn make_line(ops: &[Operand]) -> ParsedLine {
        ParsedLine {
            mnemonic: Mnemonic::default(),
            operands: ops.iter().cloned().collect(),
            mem_op: None,
            has_arrow: true,
            arrow_pos: None,

            base_reg: None,
            writeback: false,
            lane_index: None,
            lane_elem_width: None,
            pre_arrow_regs: None,
            post_arrow_regs: None,
        }
    }

    /// Helper to build a ParsedLine with writeback and base_reg set.
    fn make_line_wb(ops: &[Operand], base: RegId) -> ParsedLine {
        ParsedLine {
            mnemonic: Mnemonic::default(),
            operands: ops.iter().cloned().collect(),
            mem_op: None,
            has_arrow: true,
            arrow_pos: None,

            base_reg: Some(base),
            writeback: true,
            lane_index: None,
            lane_elem_width: None,
            pre_arrow_regs: None,
            post_arrow_regs: None,
        }
    }

    // =========================================================================
    // C: Move
    // =========================================================================

    #[test]
    fn test_move_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Reg(RegId::X9)]);
        let (defs, uses) = determine_def_use(InsnClass::Move, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X9]);
    }

    #[test]
    fn test_move_xzr_def_skipped() {
        let line = make_line(&[Operand::Reg(RegId::XZR), Operand::Reg(RegId::X9)]);
        let (defs, uses) = determine_def_use(InsnClass::Move, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X9]);
    }

    #[test]
    fn test_move_imm_source() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Imm(0x1234)]);
        let (defs, uses) = determine_def_use(InsnClass::Move, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert!(uses.is_empty());
    }

    // =========================================================================
    // A: AluReg
    // =========================================================================

    #[test]
    fn test_alu_reg_def_use() {
        let line = make_line(&[
            Operand::Reg(RegId::X8),
            Operand::Reg(RegId::X9),
            Operand::Reg(RegId::X10),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X9, RegId::X10]);
    }

    #[test]
    fn test_alu_reg_with_imm() {
        let line = make_line(&[
            Operand::Reg(RegId::X8),
            Operand::Reg(RegId::X9),
            Operand::Imm(5),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X9]);
    }

    // =========================================================================
    // B: Multiply
    // =========================================================================

    #[test]
    fn test_multiply_madd() {
        // madd Xd, Xn, Xm, Xa
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
            Operand::Reg(RegId::X3),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::Multiply, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::X3]);
    }

    // =========================================================================
    // E: FlagSet
    // =========================================================================

    #[test]
    fn test_flag_set_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Reg(RegId::X9)]);
        let (defs, uses) = determine_def_use(InsnClass::FlagSet, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X8, RegId::X9]);
    }

    #[test]
    fn test_flag_set_cmp_imm() {
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Imm(0)]);
        let (defs, uses) = determine_def_use(InsnClass::FlagSet, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    // =========================================================================
    // E: CondFlagSet
    // =========================================================================

    #[test]
    fn test_cond_flag_set() {
        // ccmp Xn, Xm, #nzcv, cond
        let line = make_line(&[
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
            Operand::Imm(0),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::CondFlagSet, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        // nzcv (implicit) + X1 + X2
        assert!(uses.contains(&RegId::NZCV));
        assert!(uses.contains(&RegId::X1));
        assert!(uses.contains(&RegId::X2));
    }

    // =========================================================================
    // F: AluFlags
    // =========================================================================

    #[test]
    fn test_alu_flags() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluFlags, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2]);
    }

    // =========================================================================
    // F: FlagUse
    // =========================================================================

    #[test]
    fn test_flag_use_csel() {
        // csel Xd, Xn, Xm, cond
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::FlagUse, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::NZCV]);
    }

    // =========================================================================
    // F: AluCarry
    // =========================================================================

    #[test]
    fn test_alu_carry() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluCarry, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::NZCV]);
    }

    // =========================================================================
    // F: AluCarryFlags
    // =========================================================================

    #[test]
    fn test_alu_carry_flags() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluCarryFlags, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X2, RegId::NZCV]);
    }

    // =========================================================================
    // D: ScalarRMW
    // =========================================================================

    #[test]
    fn test_scalar_rmw() {
        // movk X8, #0x1234
        let line = make_line(&[Operand::Reg(RegId::X8), Operand::Imm(0x1234)]);
        let (defs, uses) = determine_def_use(InsnClass::ScalarRMW, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        // X8 old value is a USE
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_scalar_rmw_bfi() {
        // bfi Xd, Xn, #lsb, #width
        let line = make_line(&[
            Operand::Reg(RegId::X8),
            Operand::Reg(RegId::X9),
            Operand::Imm(4),
            Operand::Imm(8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::ScalarRMW, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X8, RegId::X9]); // X8 old + X9 source
    }

    // =========================================================================
    // G: LoadReg
    // =========================================================================

    #[test]
    fn test_load_reg_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::LoadReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_load_reg_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::LoadReg, &line);
        // DEF: X0 (loaded value) + X8 (writeback)
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    // =========================================================================
    // G: LoadPair
    // =========================================================================

    #[test]
    fn test_load_pair() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::LoadPair, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X1]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_load_pair_writeback() {
        let line = make_line_wb(
            &[
                Operand::Reg(RegId::X0),
                Operand::Reg(RegId::X1),
                Operand::Reg(RegId::X8),
            ],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::LoadPair, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X1, RegId::X8]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    // =========================================================================
    // H: StoreReg
    // =========================================================================

    #[test]
    fn test_store_reg_def_use() {
        let line = make_line(&[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::StoreReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X8]);
    }

    #[test]
    fn test_store_reg_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::X0), Operand::Reg(RegId::X8)],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::StoreReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]); // writeback
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X8]);
    }

    // =========================================================================
    // H: StorePair
    // =========================================================================

    #[test]
    fn test_store_pair() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::X8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::StorePair, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X1, RegId::X8]);
    }

    // =========================================================================
    // H: StoreExcl
    // =========================================================================

    #[test]
    fn test_store_excl() {
        // stxr Ws, Xt, [Xn]
        let line = make_line(&[
            Operand::Reg(RegId::X0), // Ws status
            Operand::Reg(RegId::X1), // Xt data
            Operand::Reg(RegId::X8), // Xn base
        ]);
        let (defs, uses) = determine_def_use(InsnClass::StoreExcl, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X8]);
    }

    // =========================================================================
    // I: CondBranchNzcv
    // =========================================================================

    #[test]
    fn test_cond_branch_nzcv() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::CondBranchNzcv, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::NZCV]);
    }

    // =========================================================================
    // I: CondBranchReg
    // =========================================================================

    #[test]
    fn test_cond_branch_reg() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::CondBranchReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0]);
    }

    // =========================================================================
    // J: Branch
    // =========================================================================

    #[test]
    fn test_branch_no_def_use() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::Branch, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty());
    }

    // =========================================================================
    // J: BranchLink
    // =========================================================================

    #[test]
    fn test_branch_link_implicit_x30() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::BranchLink, &line);
        assert_eq!(defs.as_slice(), &[RegId::X30]);
        assert!(uses.is_empty());
    }

    // =========================================================================
    // K: BranchReg
    // =========================================================================

    #[test]
    fn test_branch_reg() {
        let line = make_line(&[Operand::Reg(RegId::X16)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X16]);
    }

    // =========================================================================
    // K: BranchLinkReg
    // =========================================================================

    #[test]
    fn test_branch_link_reg() {
        let line = make_line(&[Operand::Reg(RegId::X16)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchLinkReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X30]);
        assert_eq!(uses.as_slice(), &[RegId::X16]);
    }

    // =========================================================================
    // K: Return
    // =========================================================================

    #[test]
    fn test_return_implicit_x30() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::Return, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X30]);
    }

    // =========================================================================
    // Nop / Svc
    // =========================================================================

    #[test]
    fn test_nop_no_def_use() {
        let line = make_line(&[]);
        let (defs, uses) = determine_def_use(InsnClass::Nop, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty());
    }

    #[test]
    fn test_svc_def_from_arrow() {
        let line = ParsedLine {
            mnemonic: Mnemonic::new("svc"),
            operands: smallvec::smallvec![Operand::Imm(0)],
            post_arrow_regs: Some(Box::new(smallvec::smallvec![
                (RegId::X0, 0),
                (RegId::X30, 0x40001234),
            ])),
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::Svc, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0, RegId::X30]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_svc_no_arrow_no_def() {
        let line = ParsedLine {
            mnemonic: Mnemonic::new("svc"),
            operands: smallvec::smallvec![Operand::Imm(0)],
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::Svc, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty());
    }

    #[test]
    fn test_svc_xzr_filtered() {
        let line = ParsedLine {
            mnemonic: Mnemonic::new("svc"),
            operands: smallvec::smallvec![Operand::Imm(0)],
            post_arrow_regs: Some(Box::new(smallvec::smallvec![
                (RegId::XZR, 0),
                (RegId::X0, 42),
            ])),
            ..Default::default()
        };
        let (defs, _uses) = determine_def_use(InsnClass::Svc, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
    }

    // =========================================================================
    // L2: System registers
    // =========================================================================

    #[test]
    fn test_sys_reg_read() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegRead, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_sys_reg_nzcv_read() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegNzcvRead, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::NZCV]);
    }

    #[test]
    fn test_sys_reg_write() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegWrite, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X0]);
    }

    #[test]
    fn test_sys_reg_nzcv_write() {
        let line = make_line(&[Operand::Reg(RegId::X0)]);
        let (defs, uses) = determine_def_use(InsnClass::SysRegNzcvWrite, &line);
        assert_eq!(defs.as_slice(), &[RegId::NZCV]);
        assert_eq!(uses.as_slice(), &[RegId::X0]);
    }

    // =========================================================================
    // M: SIMD
    // =========================================================================

    #[test]
    fn test_simd_arith() {
        let line = make_line(&[
            Operand::Reg(RegId::V0),
            Operand::Reg(RegId::V1),
            Operand::Reg(RegId::V2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::SimdArith, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI]);
        assert_eq!(
            uses.as_slice(),
            &[RegId::V1, RegId::V1_HI, RegId::V2, RegId::V2_HI]
        );
    }

    #[test]
    fn test_simd_rmw() {
        // bsl Vd, Vn, Vm — full 128-bit RMW (no lane info)
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::V1)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdRMW, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI]);
        assert_eq!(
            uses.as_slice(),
            &[RegId::V0, RegId::V0_HI, RegId::V1, RegId::V1_HI]
        ); // V0 lo+hi old + V1 lo+hi source
    }

    #[test]
    fn test_simd_move() {
        // movi Vd.4S, #imm
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Imm(0)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdMove, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI]);
        assert!(uses.is_empty());
    }

    #[test]
    fn test_simd_load() {
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI]);
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_simd_load_writeback() {
        // ldr d0, [x20], #8 — post-index writeback
        let line = make_line_wb(
            &[Operand::Reg(RegId::V0), Operand::Reg(RegId::X20)],
            RegId::X20,
        );
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI, RegId::X20]); // V0 lo+hi + writeback
        assert_eq!(uses.as_slice(), &[RegId::X20]);
    }

    #[test]
    fn test_simd_load_multi_register() {
        // ld1 {v0, v1}, [x0]  → DEF=v0,v1  USE=x0
        let line = ParsedLine {
            mnemonic: Mnemonic::new("ld1"),
            operands: smallvec::smallvec![
                Operand::Reg(RegId::V0),
                Operand::Reg(RegId::V1),
                Operand::Reg(RegId::X0),
            ],
            base_reg: Some(RegId::X0),
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert!(defs.contains(&RegId::V0), "v0 should be DEF");
        assert!(defs.contains(&RegId::V0_HI), "v0_hi should be DEF");
        assert!(defs.contains(&RegId::V1), "v1 should be DEF");
        assert!(defs.contains(&RegId::V1_HI), "v1_hi should be DEF");
        assert!(
            !defs.contains(&RegId::X0),
            "x0 should not be DEF (no writeback)"
        );
        assert!(uses.contains(&RegId::X0), "x0 should be USE");
        assert!(!uses.contains(&RegId::V0), "v0 should not be USE");
        assert!(!uses.contains(&RegId::V1), "v1 should not be USE");
    }

    #[test]
    fn test_simd_load_multi_register_writeback() {
        // ld1 {v0, v1}, [x0], #32  → DEF=v0,v1,x0  USE=x0
        let line = ParsedLine {
            mnemonic: Mnemonic::new("ld1"),
            operands: smallvec::smallvec![
                Operand::Reg(RegId::V0),
                Operand::Reg(RegId::V1),
                Operand::Reg(RegId::X0),
            ],
            base_reg: Some(RegId::X0),
            writeback: true,
            ..Default::default()
        };
        let (defs, uses) = determine_def_use(InsnClass::SimdLoad, &line);
        assert!(defs.contains(&RegId::V0), "v0 should be DEF");
        assert!(defs.contains(&RegId::V0_HI), "v0_hi should be DEF");
        assert!(defs.contains(&RegId::V1), "v1 should be DEF");
        assert!(defs.contains(&RegId::V1_HI), "v1_hi should be DEF");
        assert!(defs.contains(&RegId::X0), "x0 should be DEF (writeback)");
        assert!(uses.contains(&RegId::X0), "x0 should be USE");
    }

    #[test]
    fn test_simd_lane_load() {
        // No lane_index/lane_elem_width → fallback to conservative full RMW
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdLaneLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI]);
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::V0_HI, RegId::X8]); // V0 lo+hi old + X8 base
    }

    #[test]
    fn test_simd_lane_load_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::V0), Operand::Reg(RegId::X9)],
            RegId::X9,
        );
        let (defs, uses) = determine_def_use(InsnClass::SimdLaneLoad, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0, RegId::V0_HI, RegId::X9]); // V0 lo+hi + writeback
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::V0_HI, RegId::X9]); // V0 lo+hi old + X9 base
    }

    #[test]
    fn test_simd_store() {
        let line = make_line(&[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::SimdStore, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::V0_HI, RegId::X8]);
    }

    #[test]
    fn test_simd_store_writeback() {
        let line = make_line_wb(
            &[Operand::Reg(RegId::V0), Operand::Reg(RegId::X8)],
            RegId::X8,
        );
        let (defs, uses) = determine_def_use(InsnClass::SimdStore, &line);
        assert_eq!(defs.as_slice(), &[RegId::X8]); // writeback
        assert_eq!(uses.as_slice(), &[RegId::V0, RegId::V0_HI, RegId::X8]);
    }

    // =========================================================================
    // N: FloatArith
    // =========================================================================

    #[test]
    fn test_float_arith() {
        let line = make_line(&[
            Operand::Reg(RegId::V0),
            Operand::Reg(RegId::V1),
            Operand::Reg(RegId::V2),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::FloatArith, &line);
        assert_eq!(defs.as_slice(), &[RegId::V0]);
        assert_eq!(uses.as_slice(), &[RegId::V1, RegId::V2]);
    }

    // =========================================================================
    // O: Bitfield
    // =========================================================================

    #[test]
    fn test_bitfield() {
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::X1),
            Operand::Imm(4),
            Operand::Imm(8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::Bitfield, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1]);
    }

    // =========================================================================
    // P: Extend
    // =========================================================================

    #[test]
    fn test_extend() {
        let line = make_line(&[Operand::Reg(RegId::X0), Operand::Reg(RegId::X1)]);
        let (defs, uses) = determine_def_use(InsnClass::Extend, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1]);
    }

    // =========================================================================
    // Edge cases: xzr filtering
    // =========================================================================

    #[test]
    fn test_xzr_use_filtered() {
        // add X0, XZR, X1 — xzr should not appear in uses
        let line = make_line(&[
            Operand::Reg(RegId::X0),
            Operand::Reg(RegId::XZR),
            Operand::Reg(RegId::X1),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AluReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X1]);
    }

    #[test]
    fn test_store_xzr_source() {
        // str XZR, [X8] — xzr should not appear in uses
        let line = make_line(&[Operand::Reg(RegId::XZR), Operand::Reg(RegId::X8)]);
        let (defs, uses) = determine_def_use(InsnClass::StoreReg, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X8]);
    }

    #[test]
    fn test_branch_reg_filters_xzr() {
        let line = make_line(&[Operand::Reg(RegId::XZR)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchReg, &line);
        assert!(defs.is_empty());
        assert!(uses.is_empty(), "br xzr should not USE xzr");
    }

    #[test]
    fn test_branch_link_reg_filters_xzr() {
        let line = make_line(&[Operand::Reg(RegId::XZR)]);
        let (defs, uses) = determine_def_use(InsnClass::BranchLinkReg, &line);
        assert_eq!(defs.as_slice(), &[RegId::X30]);
        assert!(uses.is_empty(), "blr xzr should not USE xzr");
    }

    // =========================================================================
    // H: AtomicLoadOp
    // =========================================================================

    #[test]
    fn test_atomic_load_op() {
        // ldadd Xs, Xt, [Xn]: DEF=Xt, USE=Xs+Xn
        let line = make_line(&[
            Operand::Reg(RegId::X1), // Xs
            Operand::Reg(RegId::X2), // Xt
            Operand::Reg(RegId::X8), // Xn
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AtomicLoadOp, &line);
        assert_eq!(defs.as_slice(), &[RegId::X2]);
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X8]);
    }

    #[test]
    fn test_atomic_load_op_xzr_dest() {
        let line = make_line(&[
            Operand::Reg(RegId::X1),
            Operand::Reg(RegId::XZR),
            Operand::Reg(RegId::X8),
        ]);
        let (defs, uses) = determine_def_use(InsnClass::AtomicLoadOp, &line);
        assert!(defs.is_empty());
        assert_eq!(uses.as_slice(), &[RegId::X1, RegId::X8]);
    }

    // =========================================================================
    // H: CompareAndSwap
    // =========================================================================

    #[test]
    fn test_compare_and_swap() {
        let line = make_line(&[
            Operand::Reg(RegId::X0), // Ws
            Operand::Reg(RegId::X1), // Wt
            Operand::Reg(RegId::X8), // Xn
        ]);
        let (defs, uses) = determine_def_use(InsnClass::CompareAndSwap, &line);
        assert_eq!(defs.as_slice(), &[RegId::X0]);
        assert_eq!(uses.as_slice(), &[RegId::X0, RegId::X1, RegId::X8]);
    }
