    use super::*;
    use crate::types::RegId;

    const INSN_CLASS_COUNT: usize = 42;

    const ALL_CLASSES: [InsnClass; INSN_CLASS_COUNT] = [
        InsnClass::AluReg,          // 0
        InsnClass::AluImm,          // 1
        InsnClass::AluShift,        // 2
        InsnClass::Multiply,        // 3
        InsnClass::Move,            // 4
        InsnClass::ScalarRMW,       // 5
        InsnClass::FlagSet,         // 6
        InsnClass::CondFlagSet,     // 7
        InsnClass::AluFlags,        // 8
        InsnClass::FlagUse,         // 9
        InsnClass::AluCarry,        // 10
        InsnClass::AluCarryFlags,   // 11
        InsnClass::LoadReg,         // 12
        InsnClass::LoadPair,        // 13
        InsnClass::StoreReg,        // 14
        InsnClass::StorePair,       // 15
        InsnClass::StoreExcl,       // 16
        InsnClass::AtomicLoadOp,    // 17
        InsnClass::CompareAndSwap,  // 18
        InsnClass::CondBranchNzcv,  // 19
        InsnClass::CondBranchReg,   // 20
        InsnClass::Branch,          // 21
        InsnClass::BranchLink,      // 22
        InsnClass::BranchReg,       // 23
        InsnClass::BranchLinkReg,   // 24
        InsnClass::Return,          // 25
        InsnClass::Nop,             // 26
        InsnClass::Svc,             // 27
        InsnClass::SysRegRead,      // 28
        InsnClass::SysRegNzcvRead,  // 29
        InsnClass::SysRegWrite,     // 30
        InsnClass::SysRegNzcvWrite, // 31
        InsnClass::SimdArith,       // 32
        InsnClass::SimdRMW,         // 33
        InsnClass::SimdMove,        // 34
        InsnClass::SimdLoad,        // 35
        InsnClass::SimdLaneLoad,    // 36
        InsnClass::SimdStore,       // 37
        InsnClass::SimdMisc,        // 38
        InsnClass::FloatArith,      // 39
        InsnClass::Bitfield,        // 40
        InsnClass::Extend,          // 41
    ];

    #[test]
    fn test_classify_move() {
        assert_eq!(classify("mov", None), InsnClass::Move);
        assert_eq!(classify("movz", None), InsnClass::Move);
        assert_eq!(classify("movn", None), InsnClass::Move);
        assert_eq!(classify("adrp", None), InsnClass::Move);
        assert_eq!(classify("adr", None), InsnClass::Move);
        assert_eq!(classify("mvn", None), InsnClass::Move);
    }

    #[test]
    fn test_classify_alu_reg_scalar() {
        assert_eq!(classify("add", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("sub", Some(RegId::X8)), InsnClass::AluReg);
        assert_eq!(classify("eor", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("and", Some(RegId::X1)), InsnClass::AluReg);
        assert_eq!(classify("orr", Some(RegId::X2)), InsnClass::AluReg);
        assert_eq!(classify("bic", Some(RegId::X3)), InsnClass::AluReg);
        assert_eq!(classify("orn", Some(RegId::X4)), InsnClass::AluReg);
        assert_eq!(classify("eon", Some(RegId::X5)), InsnClass::AluReg);
    }

    #[test]
    fn test_classify_alu_reg_capstone_aliases() {
        // Capstone aliases lsl/lsr/asr/ror -> AluReg
        assert_eq!(classify("lsl", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("lsr", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("asr", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("ror", Some(RegId::X0)), InsnClass::AluReg);
    }

    #[test]
    fn test_classify_alu_vector_disambiguation() {
        // Same mnemonic "add" with vector first_reg -> SimdArith
        assert_eq!(classify("add", Some(RegId::V0)), InsnClass::SimdArith);
        assert_eq!(classify("sub", Some(RegId::V1)), InsnClass::SimdArith);
        assert_eq!(classify("eor", Some(RegId::V2)), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_flag_set() {
        assert_eq!(classify("cmp", None), InsnClass::FlagSet);
        assert_eq!(classify("cmn", None), InsnClass::FlagSet);
        assert_eq!(classify("tst", None), InsnClass::FlagSet);
        assert_eq!(classify("fcmp", None), InsnClass::FlagSet);
        assert_eq!(classify("fcmpe", None), InsnClass::FlagSet);
    }

    #[test]
    fn test_classify_alu_flags() {
        assert_eq!(classify("adds", None), InsnClass::AluFlags);
        assert_eq!(classify("subs", None), InsnClass::AluFlags);
        assert_eq!(classify("ands", None), InsnClass::AluFlags);
        assert_eq!(classify("bics", None), InsnClass::AluFlags);
        assert_eq!(classify("negs", None), InsnClass::AluFlags);
    }

    #[test]
    fn test_classify_flag_use() {
        assert_eq!(classify("csel", None), InsnClass::FlagUse);
        assert_eq!(classify("csinc", None), InsnClass::FlagUse);
        assert_eq!(classify("csinv", None), InsnClass::FlagUse);
        assert_eq!(classify("csneg", None), InsnClass::FlagUse);
        assert_eq!(classify("fcsel", None), InsnClass::FlagUse);
        assert_eq!(classify("cinc", None), InsnClass::FlagUse);
        assert_eq!(classify("cset", None), InsnClass::FlagUse);
        assert_eq!(classify("csetm", None), InsnClass::FlagUse);
    }

    #[test]
    fn test_classify_alu_carry() {
        assert_eq!(classify("adc", None), InsnClass::AluCarry);
        assert_eq!(classify("sbc", None), InsnClass::AluCarry);
        assert_eq!(classify("ngc", None), InsnClass::AluCarry);
    }

    #[test]
    fn test_classify_alu_carry_flags() {
        assert_eq!(classify("adcs", None), InsnClass::AluCarryFlags);
        assert_eq!(classify("sbcs", None), InsnClass::AluCarryFlags);
        assert_eq!(classify("ngcs", None), InsnClass::AluCarryFlags);
    }

    #[test]
    fn test_classify_cond_flag_set() {
        assert_eq!(classify("ccmp", None), InsnClass::CondFlagSet);
        assert_eq!(classify("ccmn", None), InsnClass::CondFlagSet);
        assert_eq!(classify("cfinv", None), InsnClass::CondFlagSet);
    }

    #[test]
    fn test_classify_scalar_rmw() {
        assert_eq!(classify("movk", None), InsnClass::ScalarRMW);
        assert_eq!(classify("bfi", None), InsnClass::ScalarRMW);
        assert_eq!(classify("bfxil", None), InsnClass::ScalarRMW);
        assert_eq!(classify("bfc", None), InsnClass::ScalarRMW);
    }

    #[test]
    fn test_classify_load_reg() {
        assert_eq!(classify("ldr", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldrb", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldrh", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldrsw", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldar", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldaxr", Some(RegId::X0)), InsnClass::LoadReg);
    }

    #[test]
    fn test_classify_load_pair() {
        assert_eq!(classify("ldp", Some(RegId::X0)), InsnClass::LoadPair);
        assert_eq!(classify("ldnp", Some(RegId::X0)), InsnClass::LoadPair);
    }

    #[test]
    fn test_classify_store_reg() {
        assert_eq!(classify("str", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("strb", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("strh", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("stlr", Some(RegId::X0)), InsnClass::StoreReg);
    }

    #[test]
    fn test_classify_store_pair() {
        assert_eq!(classify("stp", Some(RegId::X0)), InsnClass::StorePair);
        assert_eq!(classify("stnp", Some(RegId::X0)), InsnClass::StorePair);
    }

    #[test]
    fn test_classify_store_excl() {
        assert_eq!(classify("stxr", None), InsnClass::StoreExcl);
        assert_eq!(classify("stlxr", None), InsnClass::StoreExcl);
        assert_eq!(classify("stxp", None), InsnClass::StoreExcl);
        assert_eq!(classify("stlxp", None), InsnClass::StoreExcl);
    }

    #[test]
    fn test_classify_cond_branch_nzcv() {
        assert_eq!(classify("b.eq", None), InsnClass::CondBranchNzcv);
        assert_eq!(classify("b.ne", None), InsnClass::CondBranchNzcv);
        assert_eq!(classify("b.lt", None), InsnClass::CondBranchNzcv);
        assert_eq!(classify("b.ge", None), InsnClass::CondBranchNzcv);
        assert_eq!(classify("b.hi", None), InsnClass::CondBranchNzcv);
        assert_eq!(classify("b.lo", None), InsnClass::CondBranchNzcv);
    }

    #[test]
    fn test_classify_cond_branch_reg() {
        assert_eq!(classify("cbz", None), InsnClass::CondBranchReg);
        assert_eq!(classify("cbnz", None), InsnClass::CondBranchReg);
        assert_eq!(classify("tbz", None), InsnClass::CondBranchReg);
        assert_eq!(classify("tbnz", None), InsnClass::CondBranchReg);
    }

    #[test]
    fn test_classify_branch() {
        assert_eq!(classify("b", None), InsnClass::Branch);
    }

    #[test]
    fn test_classify_branch_link() {
        assert_eq!(classify("bl", None), InsnClass::BranchLink);
    }

    #[test]
    fn test_classify_branch_reg() {
        assert_eq!(classify("br", None), InsnClass::BranchReg);
    }

    #[test]
    fn test_classify_branch_link_reg() {
        assert_eq!(classify("blr", None), InsnClass::BranchLinkReg);
    }

    #[test]
    fn test_classify_return() {
        assert_eq!(classify("ret", None), InsnClass::Return);
    }

    #[test]
    fn test_classify_nop() {
        assert_eq!(classify("nop", None), InsnClass::Nop);
        assert_eq!(classify("hint", None), InsnClass::Nop);
        assert_eq!(classify("prfm", None), InsnClass::Nop);
        assert_eq!(classify("dmb", None), InsnClass::Nop);
        assert_eq!(classify("dsb", None), InsnClass::Nop);
        assert_eq!(classify("isb", None), InsnClass::Nop);
    }

    #[test]
    fn test_classify_svc() {
        assert_eq!(classify("svc", None), InsnClass::Svc);
    }

    #[test]
    fn test_classify_bitfield() {
        assert_eq!(classify("ubfm", None), InsnClass::Bitfield);
        assert_eq!(classify("sbfm", None), InsnClass::Bitfield);
        assert_eq!(classify("ubfx", None), InsnClass::Bitfield);
        assert_eq!(classify("sbfx", None), InsnClass::Bitfield);
        assert_eq!(classify("ubfiz", None), InsnClass::Bitfield);
        assert_eq!(classify("sbfiz", None), InsnClass::Bitfield);
    }

    #[test]
    fn test_classify_extend() {
        assert_eq!(classify("sxtb", None), InsnClass::Extend);
        assert_eq!(classify("sxth", None), InsnClass::Extend);
        assert_eq!(classify("sxtw", None), InsnClass::Extend);
        assert_eq!(classify("uxtb", None), InsnClass::Extend);
        assert_eq!(classify("uxth", None), InsnClass::Extend);
    }

    #[test]
    fn test_classify_multiply_scalar() {
        assert_eq!(classify("mul", Some(RegId::X0)), InsnClass::Multiply);
        assert_eq!(classify("madd", Some(RegId::X0)), InsnClass::Multiply);
        assert_eq!(classify("umull", Some(RegId::X0)), InsnClass::Multiply);
        assert_eq!(classify("smull", Some(RegId::X0)), InsnClass::Multiply);
        assert_eq!(classify("umulh", Some(RegId::X0)), InsnClass::Multiply);
        assert_eq!(classify("smulh", Some(RegId::X0)), InsnClass::Multiply);
    }

    #[test]
    fn test_classify_simd_arith() {
        assert_eq!(classify("ushr", None), InsnClass::SimdArith);
        assert_eq!(classify("shl", None), InsnClass::SimdArith);
        assert_eq!(classify("cnt", None), InsnClass::SimdArith);
        assert_eq!(classify("xtn", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_simd_rmw() {
        assert_eq!(classify("ins", None), InsnClass::SimdRMW);
        assert_eq!(classify("bsl", None), InsnClass::SimdRMW);
        assert_eq!(classify("bit", None), InsnClass::SimdRMW);
        assert_eq!(classify("bif", None), InsnClass::SimdRMW);
    }

    #[test]
    fn test_classify_simd_move() {
        assert_eq!(classify("movi", None), InsnClass::SimdMove);
        assert_eq!(classify("mvni", None), InsnClass::SimdMove);
        assert_eq!(classify("dup", None), InsnClass::SimdMove);
        assert_eq!(classify("umov", None), InsnClass::SimdMove);
    }

    #[test]
    fn test_classify_simd_misc() {
        assert_eq!(classify("ext", None), InsnClass::SimdMisc);
        assert_eq!(classify("zip1", None), InsnClass::SimdMisc);
        assert_eq!(classify("zip2", None), InsnClass::SimdMisc);
        assert_eq!(classify("tbl", None), InsnClass::SimdMisc);
        assert_eq!(classify("rev64", None), InsnClass::SimdMisc);
    }

    #[test]
    fn test_classify_simd_load_store() {
        assert_eq!(classify("ld1", None), InsnClass::SimdLoad);
        assert_eq!(classify("st1", None), InsnClass::SimdStore);
        assert_eq!(classify("ld1r", None), InsnClass::SimdLoad);
    }

    #[test]
    fn test_classify_vector_ldp_stp_as_pair() {
        // Vector ldp/stp should be LoadPair/StorePair (same as scalar),
        // NOT SimdLoad/SimdStore — pair instructions need dual-register
        // DEF/USE and double memory width.
        assert_eq!(classify("ldp", Some(RegId::V0)), InsnClass::LoadPair);
        assert_eq!(classify("ldnp", Some(RegId::V0)), InsnClass::LoadPair);
        assert_eq!(classify("stp", Some(RegId::V0)), InsnClass::StorePair);
        assert_eq!(classify("stnp", Some(RegId::V0)), InsnClass::StorePair);
    }

    #[test]
    fn test_classify_vector_ldr_str() {
        assert_eq!(classify("ldr", Some(RegId::V0)), InsnClass::SimdLoad);
        assert_eq!(classify("str", Some(RegId::V0)), InsnClass::SimdStore);
    }

    #[test]
    fn test_classify_sys_reg() {
        assert_eq!(classify("mrs", None), InsnClass::SysRegRead);
        assert_eq!(classify("msr", None), InsnClass::SysRegWrite);
    }

    #[test]
    fn test_classify_fmov_scalar() {
        // fmov with scalar dest -> Move
        assert_eq!(classify("fmov", Some(RegId::X0)), InsnClass::Move);
    }

    #[test]
    fn test_classify_fmov_vector() {
        // fmov with vector dest -> FloatArith
        assert_eq!(classify("fmov", Some(RegId::V0)), InsnClass::FloatArith);
    }

    #[test]
    fn test_classify_unknown_defaults_to_nop() {
        assert_eq!(classify("unknown_insn", None), InsnClass::Nop);
        assert_eq!(classify("xyzzy", None), InsnClass::Nop);
    }

    #[test]
    fn test_insn_class_as_index() {
        assert_eq!(InsnClass::AluReg as u8, 0);
        assert_eq!(InsnClass::Extend as u8, (INSN_CLASS_COUNT - 1) as u8);
    }

    #[test]
    fn test_insn_class_count_matches_variants() {
        let last_index = InsnClass::Extend as usize;
        assert_eq!(last_index + 1, INSN_CLASS_COUNT);
    }

    #[test]
    fn test_classify_previously_unmapped() {
        // stur/ldur vector forms
        assert_eq!(classify("stur", Some(RegId::V0)), InsnClass::SimdStore);
        assert_eq!(classify("ldur", Some(RegId::V0)), InsnClass::SimdLoad);

        // ushl, uaddlv → SimdArith
        assert_eq!(classify("ushl", None), InsnClass::SimdArith);
        assert_eq!(classify("uaddlv", None), InsnClass::SimdArith);

        // extr, udiv, sdiv → AluReg (scalar)
        assert_eq!(classify("extr", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("udiv", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("sdiv", Some(RegId::X0)), InsnClass::AluReg);

        // fcvtpu → FloatArith
        assert_eq!(classify("fcvtpu", None), InsnClass::FloatArith);
    }

    #[test]
    fn test_scalar_stur_ldur_unaffected() {
        // Scalar stur/ldur should still map to StoreReg/LoadReg
        assert_eq!(classify("stur", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("ldur", Some(RegId::X0)), InsnClass::LoadReg);
    }

    #[test]
    fn test_classify_and_refine_simd_lane_load() {
        use crate::types::*;
        let line = ParsedLine {
            mnemonic: Mnemonic::new("ld1"),
            operands: smallvec::smallvec![Operand::Reg(RegId::V0)],
            lane_index: Some(3),
            ..Default::default()
        };
        let class = super::classify_and_refine(&line);
        assert_eq!(class, InsnClass::SimdLaneLoad);
    }

    #[test]
    fn test_classify_and_refine_sysreg_nzcv() {
        use crate::types::*;
        let line = ParsedLine {
            mnemonic: Mnemonic::new("mrs"),
            operands: smallvec::smallvec![Operand::Reg(RegId::X0), Operand::Reg(RegId::NZCV)],
            ..Default::default()
        };
        let class = super::classify_and_refine(&line);
        assert_eq!(class, InsnClass::SysRegNzcvRead);
    }

    #[test]
    fn test_classify_and_refine_no_refinement() {
        use crate::types::*;
        let line = ParsedLine {
            mnemonic: Mnemonic::new("add"),
            operands: smallvec::smallvec![
                Operand::Reg(RegId::X0),
                Operand::Reg(RegId::X1),
                Operand::Reg(RegId::X2)
            ],
            ..Default::default()
        };
        let class = super::classify_and_refine(&line);
        assert_eq!(class, InsnClass::AluReg);
    }

    #[test]
    fn test_all_classes_correctness() {
        for (i, &class) in ALL_CLASSES.iter().enumerate() {
            assert_eq!(
                class as u8 as usize, i,
                "ALL_CLASSES[{}] = {:?} has wrong u8 value",
                i, class
            );
        }
    }

    // =========================================================================
    // P0: Crypto + CRC instruction classification tests
    // =========================================================================

    #[test]
    fn test_classify_aes() {
        assert_eq!(classify("aese", None), InsnClass::SimdRMW);
        assert_eq!(classify("aesd", None), InsnClass::SimdRMW);
        assert_eq!(classify("aesmc", None), InsnClass::SimdArith);
        assert_eq!(classify("aesimc", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_sha1() {
        assert_eq!(classify("sha1c", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha1m", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha1p", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha1su0", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha1su1", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha1h", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_sha256() {
        assert_eq!(classify("sha256h", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha256h2", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha256su0", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha256su1", None), InsnClass::SimdRMW);
    }

    #[test]
    fn test_classify_sha512_sha3() {
        assert_eq!(classify("sha512h", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha512h2", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha512su0", None), InsnClass::SimdRMW);
        assert_eq!(classify("sha512su1", None), InsnClass::SimdRMW);
        assert_eq!(classify("eor3", None), InsnClass::SimdArith);
        assert_eq!(classify("rax1", None), InsnClass::SimdArith);
        assert_eq!(classify("xar", None), InsnClass::SimdArith);
        assert_eq!(classify("bcax", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_sm3() {
        assert_eq!(classify("sm3ss1", None), InsnClass::SimdArith);
        assert_eq!(classify("sm3tt1a", None), InsnClass::SimdRMW);
        assert_eq!(classify("sm3tt1b", None), InsnClass::SimdRMW);
        assert_eq!(classify("sm3tt2a", None), InsnClass::SimdRMW);
        assert_eq!(classify("sm3tt2b", None), InsnClass::SimdRMW);
        assert_eq!(classify("sm3partw1", None), InsnClass::SimdRMW);
        assert_eq!(classify("sm3partw2", None), InsnClass::SimdRMW);
    }

    #[test]
    fn test_classify_sm4() {
        assert_eq!(classify("sm4e", None), InsnClass::SimdRMW);
        assert_eq!(classify("sm4ekey", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_crc32() {
        assert_eq!(classify("crc32b", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32h", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32w", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32x", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32cb", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32ch", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32cw", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("crc32cx", Some(RegId::X0)), InsnClass::AluReg);
    }

    #[test]
    fn test_classify_neg_abs_disambiguation() {
        assert_eq!(classify("neg", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("abs", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("neg", Some(RegId::V0)), InsnClass::SimdArith);
        assert_eq!(classify("abs", Some(RegId::V0)), InsnClass::SimdArith);
        assert_eq!(classify("neg", None), InsnClass::AluReg);
    }

    #[test]
    fn test_classify_fcvt_scvtf_disambiguation() {
        assert_eq!(classify("fcvtzs", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("fcvtzu", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("scvtf", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("ucvtf", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("fcvtzs", Some(RegId::V0)), InsnClass::SimdArith);
        assert_eq!(classify("scvtf", Some(RegId::V0)), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_load_store_unprivileged() {
        assert_eq!(classify("ldtr", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldtrsb", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("ldtrsh", Some(RegId::X0)), InsnClass::LoadReg);
        assert_eq!(classify("sttr", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("sttrb", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("sttrh", Some(RegId::X0)), InsnClass::StoreReg);
    }

    #[test]
    fn test_classify_exclusive_pair_load() {
        assert_eq!(classify("ldaxp", Some(RegId::X0)), InsnClass::LoadPair);
        assert_eq!(classify("ldxp", Some(RegId::X0)), InsnClass::LoadPair);
    }

    #[test]
    fn test_classify_fccmp() {
        assert_eq!(classify("fccmp", None), InsnClass::CondFlagSet);
        assert_eq!(classify("fccmpe", None), InsnClass::CondFlagSet);
    }

    #[test]
    fn test_classify_system_nops() {
        assert_eq!(classify("prfum", None), InsnClass::Nop);
        assert_eq!(classify("dc", None), InsnClass::Nop);
        assert_eq!(classify("ic", None), InsnClass::Nop);
        assert_eq!(classify("tlbi", None), InsnClass::Nop);
        assert_eq!(classify("at", None), InsnClass::Nop);
    }

    #[test]
    fn test_classify_simd_compare() {
        assert_eq!(classify("cmeq", None), InsnClass::SimdArith);
        assert_eq!(classify("cmgt", None), InsnClass::SimdArith);
        assert_eq!(classify("cmtst", None), InsnClass::SimdArith);
        assert_eq!(classify("fcmeq", None), InsnClass::SimdArith);
        assert_eq!(classify("facgt", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_simd_saturating() {
        assert_eq!(classify("sqadd", None), InsnClass::SimdArith);
        assert_eq!(classify("uqsub", None), InsnClass::SimdArith);
        assert_eq!(classify("sqabs", None), InsnClass::SimdArith);
        assert_eq!(classify("sqshlu", None), InsnClass::SimdArith);
        assert_eq!(classify("sqrshrn2", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_simd_reduce() {
        assert_eq!(classify("sminv", None), InsnClass::SimdArith);
        assert_eq!(classify("umaxv", None), InsnClass::SimdArith);
        assert_eq!(classify("saddlv", None), InsnClass::SimdArith);
        assert_eq!(classify("sminp", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_simd_accumulate_rmw() {
        assert_eq!(classify("saba", None), InsnClass::SimdRMW);
        assert_eq!(classify("uaba", None), InsnClass::SimdRMW);
        assert_eq!(classify("sadalp", None), InsnClass::SimdRMW);
        assert_eq!(classify("usqadd", None), InsnClass::SimdRMW);
        assert_eq!(classify("sli", None), InsnClass::SimdRMW);
        assert_eq!(classify("sri", None), InsnClass::SimdRMW);
    }

    #[test]
    fn test_classify_float_convert_round() {
        assert_eq!(classify("fcvtas", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("fcvtmu", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("frinti", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("frint64z", Some(RegId::X0)), InsnClass::FloatArith);
    }

    #[test]
    fn test_classify_float_minmax() {
        assert_eq!(classify("fmax", Some(RegId::X0)), InsnClass::FloatArith);
        assert_eq!(classify("fminnm", Some(RegId::X0)), InsnClass::FloatArith);
    }

    #[test]
    fn test_classify_simd_float_vector() {
        assert_eq!(classify("faddp", None), InsnClass::SimdArith);
        assert_eq!(classify("fmaxv", None), InsnClass::SimdArith);
        assert_eq!(classify("frecpe", None), InsnClass::SimdArith);
        assert_eq!(classify("fcvtxn", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_simd_float_rmw() {
        assert_eq!(classify("fmla", None), InsnClass::SimdRMW);
        assert_eq!(classify("fmls", None), InsnClass::SimdRMW);
    }

    #[test]
    fn test_classify_float_scalar_vector_disambiguation() {
        // Scalar fadd → FloatArith
        assert_eq!(classify("fadd", Some(RegId::X0)), InsnClass::FloatArith);
        // Vector fadd → SimdArith
        assert_eq!(classify("fadd", Some(RegId::V0)), InsnClass::SimdArith);
        assert_eq!(classify("fsub", Some(RegId::V0)), InsnClass::SimdArith);
        assert_eq!(classify("fmul", Some(RegId::V0)), InsnClass::SimdArith);
    }

    // =========================================================================
    // PAC (ARMv8.3-PAuth) instruction classification tests
    // =========================================================================

    #[test]
    fn test_classify_pac_alu() {
        assert_eq!(classify("pacia", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("autib", Some(RegId::X0)), InsnClass::AluReg);
        assert_eq!(classify("xpaci", Some(RegId::X0)), InsnClass::AluReg);
    }

    #[test]
    fn test_classify_pac_hint_nop() {
        assert_eq!(classify("paciasp", None), InsnClass::Nop);
        assert_eq!(classify("autiasp", None), InsnClass::Nop);
        assert_eq!(classify("xpaclri", None), InsnClass::Nop);
    }

    #[test]
    fn test_classify_pac_branch() {
        assert_eq!(classify("braa", Some(RegId::X0)), InsnClass::BranchReg);
        assert_eq!(classify("blraa", Some(RegId::X0)), InsnClass::BranchLinkReg);
        assert_eq!(classify("retaa", None), InsnClass::Return);
    }

    // =========================================================================
    // LSE Atomics (ARMv8.1-Atomics) classification tests
    // =========================================================================

    #[test]
    fn test_classify_lse_atomic_load_op() {
        assert_eq!(classify("ldadd", Some(RegId::X0)), InsnClass::AtomicLoadOp);
        assert_eq!(
            classify("ldaddal", Some(RegId::X0)),
            InsnClass::AtomicLoadOp
        );
        assert_eq!(classify("ldclrb", Some(RegId::X0)), InsnClass::AtomicLoadOp);
        assert_eq!(
            classify("ldsetah", Some(RegId::X0)),
            InsnClass::AtomicLoadOp
        );
        assert_eq!(classify("swp", Some(RegId::X0)), InsnClass::AtomicLoadOp);
        assert_eq!(classify("swpalb", Some(RegId::X0)), InsnClass::AtomicLoadOp);
    }

    #[test]
    fn test_classify_lse_atomic_store() {
        assert_eq!(classify("stadd", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("stclrl", Some(RegId::X0)), InsnClass::StoreReg);
        assert_eq!(classify("stuminh", Some(RegId::X0)), InsnClass::StoreReg);
    }

    #[test]
    fn test_classify_lse_cas() {
        assert_eq!(classify("cas", Some(RegId::X0)), InsnClass::CompareAndSwap);
        assert_eq!(
            classify("casal", Some(RegId::X0)),
            InsnClass::CompareAndSwap
        );
        assert_eq!(classify("casb", Some(RegId::X0)), InsnClass::CompareAndSwap);
        assert_eq!(
            classify("casalh", Some(RegId::X0)),
            InsnClass::CompareAndSwap
        );
    }

    #[test]
    fn test_classify_lse_casp_nop() {
        assert_eq!(classify("casp", None), InsnClass::Nop);
        assert_eq!(classify("caspal", None), InsnClass::Nop);
    }

    // =========================================================================
    // P2: addv, pmul, hint-encoded instructions
    // =========================================================================

    #[test]
    fn test_classify_addv_pmul() {
        assert_eq!(classify("addv", None), InsnClass::SimdArith);
        assert_eq!(classify("pmul", None), InsnClass::SimdArith);
    }

    #[test]
    fn test_classify_hint_mnemonics() {
        let hint_mnemonics = [
            "yield", "wfe", "wfi", "sev", "sevl", "csdb", "esb", "psb", "tsb", "dgh", "bti", "sb",
            "ssbb", "pssbb",
        ];
        for mnemonic in hint_mnemonics {
            assert_eq!(classify(mnemonic, None), InsnClass::Nop, "{mnemonic}");
        }
    }

    #[test]
    fn test_refine_fmov_lane_to_simd_rmw() {
        use crate::types::{Mnemonic, Operand, ParsedLine};

        // fmov v0.d[1], x0 — lane 写入，精化为 SimdRMW
        let lane_write = ParsedLine {
            mnemonic: Mnemonic::new("fmov"),
            operands: smallvec::smallvec![Operand::RegLane(RegId::V0, 1), Operand::Reg(RegId::X0),],
            lane_index: Some(1),
            ..Default::default()
        };
        assert_eq!(classify_and_refine(&lane_write), InsnClass::SimdRMW);

        // fmov d0, x0 — 标量浮点搬移，保持 FloatArith
        let scalar = ParsedLine {
            mnemonic: Mnemonic::new("fmov"),
            operands: smallvec::smallvec![
                Operand::Reg(RegId::V0), // d0 归一化为 v0
                Operand::Reg(RegId::X0),
            ],
            lane_index: None,
            ..Default::default()
        };
        assert_eq!(classify_and_refine(&scalar), InsnClass::FloatArith);
    }

    #[test]
    fn test_is_known_nop() {
        assert!(is_known_nop("nop"));
        assert!(is_known_nop("dmb"));
        assert!(is_known_nop("yield"));
        assert!(is_known_nop("casp"));
        assert!(!is_known_nop("unknown_insn"));
        assert!(!is_known_nop("xar"));
    }
