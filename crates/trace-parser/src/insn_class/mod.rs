use crate::types::{Operand, RegId};

/// 共享 NOP/系统指令助记符列表的宏。
/// classify() 和 is_known_nop() 共用此列表以避免手动同步。
macro_rules! nop_mnemonics {
    ($mnemonic:expr) => {
        matches!(
            $mnemonic,
            "nop" | "hint" | "prfm" | "prfum" | "dmb" | "dsb" | "isb" | "clrex"
                | "dc" | "ic" | "tlbi" | "at"
                // hint 编码指令（反汇编器可能展开为独立助记符）
                | "yield" | "wfe" | "wfi" | "sev" | "sevl"
                | "csdb" | "esb" | "psb" | "tsb" | "dgh"
                | "bti" | "sb" | "ssbb" | "pssbb"
                // CASP (pair CAS, extremely rare)
                | "casp" | "caspa" | "caspal" | "caspl"
                // PAC hint forms（无寄存器副作用，编码为 hint 指令）
                | "pacia1716" | "pacib1716" | "paciaz" | "pacibz" | "paciasp" | "pacibsp"
                | "autia1716" | "autib1716" | "autiasp" | "autibsp" | "autiaz" | "autibz"
                | "xpaclri"
        )
    };
}

/// Instruction semantic classification (all 35 variants from design doc v9).
///
/// Each variant maps to a unique DEF/USE pattern in `determine_def_use()`,
/// eliminating the need for mnemonic-level switching in the slicer.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum InsnClass {
    // A: Arithmetic/Logic/Shift — DEF=Rd, USE=Rn,Rm
    AluReg,
    AluImm,
    AluShift,

    // B: Multiply — DEF=Rd, USE=Rn,Rm[,Ra]
    Multiply,

    // C: Data move — DEF=Rd, USE=Rn (or imm)
    Move,

    // D: Scalar read-modify-write — DEF=Rd, USE=Rd(old)+sources
    //    (movk, bfi, bfxil, bfc)
    ScalarRMW,

    // E: Flags — pure flag write
    //    cmp, cmn, tst, fcmp, fcmpe: DEF=nzcv, USE=operands
    FlagSet,
    //    ccmp, ccmn, cfinv: DEF=nzcv, USE=nzcv+operands
    CondFlagSet,

    // F: ALU+Flags
    //    adds, subs, ands, bics, negs: DEF=Rd+nzcv, USE=sources
    AluFlags,
    //    csel, csinc, csinv, csneg, fcsel: DEF=Rd, USE=sources+nzcv
    FlagUse,
    //    adc, sbc: DEF=Rd, USE=sources+nzcv
    AluCarry,
    //    adcs, sbcs: DEF=Rd+nzcv, USE=sources+nzcv
    AluCarryFlags,

    // G: Load
    //    ldr, ldrb, ldrh, ldrsw, etc.: DEF=Rt[+base if writeback], USE=base+mem
    LoadReg,
    //    ldp, ldpsw: DEF=Rt1+Rt2[+base if writeback], USE=base+mem
    LoadPair,

    // H: Store
    //    str, strb, strh, stlr, etc.: DEF=[base if writeback], USE=Rt+base
    StoreReg,
    //    stp: DEF=[base if writeback], USE=Rt1+Rt2+base
    StorePair,
    //    stxr, stlxr, stxp, stlxp: DEF=Ws(status), USE=Rt+Rn
    StoreExcl,
    //    ldadd, ldclr, ldset, ldeor, swp, etc.: DEF=Rt(old mem val), USE=Rs(operand)+Rn(addr)
    AtomicLoadOp,
    //    cas, casa, casal, casl: DEF=Ws(old mem val, RMW), USE=Ws(expected)+Wt(new)+Xn(addr)
    CompareAndSwap,

    // I: Conditional branch
    //    b.cond: USE=nzcv
    CondBranchNzcv,
    //    cbz, cbnz, tbz, tbnz: USE=Rt
    CondBranchReg,

    // J: Unconditional branch
    //    b: no DEF/USE
    Branch,
    //    bl: DEF=x30
    BranchLink,

    // K: Indirect branch
    //    br: USE=Rn
    BranchReg,
    //    blr: DEF=x30, USE=Rn
    BranchLinkReg,
    //    ret: USE=x30
    Return,

    // NOP/System
    Nop,
    Svc,

    // L2: System register access
    //    mrs Rd, sysreg: DEF=Rd
    SysRegRead,
    //    mrs Rd, nzcv: DEF=Rd, USE=nzcv
    SysRegNzcvRead,
    //    msr sysreg, Rn: USE=Rn
    SysRegWrite,
    //    msr nzcv, Rn: DEF=nzcv, USE=Rn
    SysRegNzcvWrite,

    // M: SIMD/NEON
    //    Standard SIMD arithmetic: DEF=Vd, USE=Vn[,Vm]
    SimdArith,
    //    SIMD read-modify-write (ins, bsl, bit, bif, mla, mls, fmov Vd.D[1]):
    //    DEF=Vd, USE=Vd(old)+sources
    SimdRMW,
    //    SIMD pure move (movi, mvni, dup, umov, fmov Dd):
    //    DEF=Vd, USE=sources
    SimdMove,
    //    SIMD load (ld1 full): DEF=Vt, USE=Rn+mem
    SimdLoad,
    //    SIMD lane load (ld1 lane): DEF=Vt, USE=Vt(old)+Rn+mem
    SimdLaneLoad,
    //    SIMD store (st1): USE=Vt+Rn
    SimdStore,
    //    SIMD misc (rev, ext, trn, zip, uzp, tbl, tbx):
    //    DEF=Vd, USE=sources
    SimdMisc,

    // N: Float arithmetic — DEF=Fd, USE=Fn[,Fm]
    FloatArith,

    // O: Bitfield — DEF=Rd, USE=Rn
    Bitfield,

    // P: Extend — DEF=Rd, USE=Rn
    Extend,
}

/// Map mnemonic + first operand register type to InsnClass.
///
/// `first_reg`: the RegId of the first operand (for scalar/vector disambiguation).
/// Pass `None` if the instruction has no register operands.
///
/// Step 1 maps the core types needed for the slicer MVP.
/// Unknown mnemonics default to `Nop` (safe: no DEF/USE, instruction is ignored by slicer).
pub fn classify(mnemonic: &str, first_reg: Option<RegId>) -> InsnClass {
    // b.cond series: b.eq, b.ne, b.lt, b.ge, b.hi, b.lo, etc.
    if mnemonic.starts_with("b.") {
        return InsnClass::CondBranchNzcv;
    }

    // Helper: is the first operand a scalar (x/w) register?
    // RegId 0..=32 covers x0-x30, sp(31), xzr(32)
    let is_scalar = first_reg.is_none_or(|r| r.0 <= 32);

    match mnemonic {
        // === C: Data move ===
        "mov" | "movz" | "movn" | "adrp" | "adr" | "mvn" => InsnClass::Move,
        "fmov" if is_scalar => InsnClass::Move,

        // === A: ALU (scalar) ===
        "add" | "sub" | "and" | "orr" | "eor" | "bic" | "orn" | "eon" | "lsl" | "lsr" | "asr"
        | "ror" | "rev" | "rev16" | "rev32" | "clz" | "cls" | "rbit" | "extr" | "udiv" | "sdiv"
            if is_scalar =>
        {
            InsnClass::AluReg
        }
        "neg" | "abs" if is_scalar => InsnClass::AluReg,

        // === E: Flag set (pure flag write) ===
        "cmp" | "cmn" | "tst" | "fcmp" | "fcmpe" => InsnClass::FlagSet,

        // === F: ALU + Flags ===
        "adds" | "subs" | "ands" | "bics" | "negs" => InsnClass::AluFlags,

        // === F: Flag use (conditional select) ===
        "csel" | "csinc" | "csinv" | "csneg" | "fcsel" | "cinc" | "cinv" | "cneg" | "cset"
        | "csetm" => InsnClass::FlagUse,

        // === F: ALU with carry ===
        "adc" | "sbc" | "ngc" => InsnClass::AluCarry,
        "adcs" | "sbcs" | "ngcs" => InsnClass::AluCarryFlags,

        // === E: Conditional flag set ===
        "ccmp" | "ccmn" | "cfinv" | "fccmp" | "fccmpe" => InsnClass::CondFlagSet,

        // === D: Scalar read-modify-write ===
        "movk" | "bfi" | "bfxil" | "bfc" => InsnClass::ScalarRMW,

        // === O: Bitfield ===
        "ubfm" | "sbfm" | "ubfx" | "sbfx" | "ubfiz" | "sbfiz" => InsnClass::Bitfield,

        // === P: Extend ===
        "sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" => InsnClass::Extend,

        // === B: Multiply (scalar) ===
        "mul" | "madd" | "msub" | "mneg" | "umull" | "smull" | "umaddl" | "smaddl" | "umsubl"
        | "smsubl" | "umulh" | "smulh" | "umnegl" | "smnegl"
            if is_scalar =>
        {
            InsnClass::Multiply
        }

        // === G: Load (scalar) ===
        "ldr" | "ldrb" | "ldrh" | "ldrsw" | "ldrsh" | "ldrsb" | "ldar" | "ldarb" | "ldarh"
        | "ldaxr" | "ldaxrb" | "ldaxrh" | "ldxr" | "ldxrb" | "ldxrh" | "ldur" | "ldurb"
        | "ldurh" | "ldursw" | "ldursb" | "ldursh" | "ldtrb" | "ldtrh" | "ldtrsw" | "ldtr"
        | "ldtrsb" | "ldtrsh"
            if is_scalar =>
        {
            InsnClass::LoadReg
        }

        // === G: Load pair (scalar + vector — both need dual-register DEF) ===
        "ldp" | "ldpsw" | "ldnp" => InsnClass::LoadPair,

        // === G: Exclusive pair load ===
        "ldaxp" | "ldxp" => InsnClass::LoadPair,

        // === H: Store (scalar) ===
        "str" | "strb" | "strh" | "stlr" | "stlrb" | "stlrh" | "stur" | "sturb" | "sturh"
        | "sttr" | "sttrb" | "sttrh"
            if is_scalar =>
        {
            InsnClass::StoreReg
        }

        // === H: Store pair (scalar + vector — both need dual-register USE) ===
        "stp" | "stnp" => InsnClass::StorePair,

        // === H: Store exclusive ===
        "stxr" | "stlxr" | "stxrb" | "stlxrb" | "stxrh" | "stlxrh" | "stxp" | "stlxp" => {
            InsnClass::StoreExcl
        }

        // === I: Conditional branch (register-tested) ===
        "cbz" | "cbnz" | "tbz" | "tbnz" => InsnClass::CondBranchReg,

        // === J: Unconditional branch ===
        "b" => InsnClass::Branch,
        "bl" => InsnClass::BranchLink,

        // === K: Indirect branch ===
        "br" => InsnClass::BranchReg,
        "blr" => InsnClass::BranchLinkReg,
        "ret" => InsnClass::Return,

        // === NOP/System ===
        m if nop_mnemonics!(m) => InsnClass::Nop,
        "svc" => InsnClass::Svc,

        // === L2: System registers ===
        // classify() returns the generic form; caller refines via operand text
        // to distinguish nzcv variants (SysRegNzcvRead / SysRegNzcvWrite)
        "mrs" => InsnClass::SysRegRead,
        "msr" => InsnClass::SysRegWrite,

        // === M: SIMD arithmetic (vector first_reg, or unconditionally vector) ===
        "add" | "sub" | "and" | "orr" | "eor" | "bic" | "orn" | "eon" if !is_scalar => {
            InsnClass::SimdArith
        }

        "mul" | "umull" | "smull" | "pmull" if !is_scalar => InsnClass::SimdArith,

        "neg" | "abs" if !is_scalar => InsnClass::SimdArith,

        // Unconditionally SIMD (no scalar form or already handled above)
        "ushr" | "sshr" | "shl" | "usra" | "ssra" | "urshr" | "srshr" | "ursra" | "srsra"
        | "uqshl" | "sqshl" | "uqrshl" | "sqrshl" | "addp" | "uaddlp" | "saddlp" | "umin"
        | "smin" | "umax" | "smax" | "uaddl" | "saddl" | "uaddl2" | "saddl2" | "uaddw"
        | "saddw" | "uaddw2" | "saddw2" | "usubl" | "ssubl" | "usubl2" | "ssubl2" | "usubw"
        | "ssubw" | "usubw2" | "ssubw2" | "uabdl" | "sabdl" | "uabdl2" | "sabdl2" | "uabal"
        | "sabal" | "uabal2" | "sabal2" | "umlal" | "smlal" | "umlal2" | "smlal2" | "umlsl"
        | "smlsl" | "umlsl2" | "smlsl2" | "pmull2" | "ushll" | "sshll" | "ushll2" | "sshll2"
        | "shrn" | "shrn2" | "rshrn" | "rshrn2" | "uqxtn" | "sqxtn" | "sqxtun" | "uqxtn2"
        | "sqxtn2" | "sqxtun2" | "cnt" | "not" | "xtn" | "xtn2" | "fcvtl" | "fcvtl2" | "fcvtn"
        | "fcvtn2" | "ushl" | "uaddlv"
        // SIMD compare
        | "cmeq" | "cmge" | "cmgt" | "cmhi" | "cmhs" | "cmle" | "cmlt" | "cmtst"
        // SIMD float compare (vector)
        | "facge" | "facgt" | "fcmeq" | "fcmge" | "fcmgt" | "fcmle" | "fcmlt"
        // Absolute difference
        | "sabd" | "uabd"
        // Narrowing add/sub
        | "addhn" | "addhn2" | "subhn" | "subhn2" | "raddhn" | "raddhn2" | "rsubhn" | "rsubhn2"
        // Saturating arithmetic
        | "sqadd" | "uqadd" | "sqsub" | "uqsub" | "sqneg" | "sqabs"
        // Pairwise min/max
        | "sminp" | "uminp" | "smaxp" | "umaxp"
        // 跨 lane 归约
        | "sminv" | "uminv" | "smaxv" | "umaxv" | "saddlv" | "addv"
        // 多项式乘法（非加宽，GCM 相关）
        | "pmul"
        // Saturating shift
        | "sqshlu"
        | "sqrshrn" | "sqrshrn2" | "uqrshrn" | "uqrshrn2" | "sqrshrun" | "sqrshrun2"
        | "sqshrn" | "sqshrn2" | "uqshrn" | "uqshrn2" | "sqshrun" | "sqshrun2"
        // Vector float
        | "faddp" | "fmaxp" | "fminp" | "fmaxnmp" | "fminnmp"
        | "fmaxv" | "fminv" | "fmaxnmv" | "fminnmv"
        | "frecpe" | "frsqrte" | "frecps" | "frsqrts"
        | "fcvtxn" | "fcvtxn2"
            => InsnClass::SimdArith,

        // SIMD read-modify-write
        "ins" | "bsl" | "bit" | "bif" | "mla" | "mls"
        // Absolute difference accumulate (RMW)
        | "saba" | "uaba"
        // Pairwise add accumulate (RMW)
        | "sadalp" | "uadalp" | "suqadd" | "usqadd"
        // Shift-and-insert (RMW, partial bits preserved)
        | "sli" | "sri"
        // Vector float multiply-accumulate (RMW)
        | "fmla" | "fmls"
            => InsnClass::SimdRMW,

        // SIMD move (pure write)
        "movi" | "mvni" | "dup" | "umov" | "smov" => InsnClass::SimdMove,

        // SIMD misc
        "ext" | "trn1" | "trn2" | "zip1" | "zip2" | "uzp1" | "uzp2" | "tbl" | "tbx" | "rev64" => {
            InsnClass::SimdMisc
        }

        // === SIMD load/store ===
        "ld1" | "ld2" | "ld3" | "ld4" | "ld1r" | "ld2r" | "ld3r" | "ld4r" => InsnClass::SimdLoad,

        "st1" | "st2" | "st3" | "st4" => InsnClass::SimdStore,

        // Vector ldr/str/ldur/stur
        "ldr" if !is_scalar => InsnClass::SimdLoad,
        "str" if !is_scalar => InsnClass::SimdStore,
        "ldur" if !is_scalar => InsnClass::SimdLoad,
        "stur" if !is_scalar => InsnClass::SimdStore,

        // === N: Float arithmetic ===
        // Float vector forms (must match before scalar FloatArith)
        "fadd" | "fsub" | "fmul" | "fdiv" | "fabs" | "fneg" | "fsqrt" if !is_scalar => {
            InsnClass::SimdArith
        }

        // Scalar-only float (no vector form exists)
        "fnmul" | "fmadd" | "fmsub" | "fnmadd" | "fnmsub"
        | "frintn" | "frintm" | "frintp" | "frintz" | "frinta"
        | "fcvt" | "fjcvtzs" | "fcvtpu" | "fmov" => InsnClass::FloatArith,

        // Float that also has vector form — scalar only here
        "fadd" | "fsub" | "fmul" | "fdiv" | "fabs" | "fneg" | "fsqrt" if is_scalar => {
            InsnClass::FloatArith
        }

        // Additional scalar float conversions, rounding, min/max
        "fcvtas" | "fcvtau" | "fcvtms" | "fcvtmu" | "fcvtns" | "fcvtnu" | "fcvtps"
        | "frinti" | "frintx" | "frint32x" | "frint32z" | "frint64x" | "frint64z"
        | "fmax" | "fmin" | "fmaxnm" | "fminnm"
        | "frecpx" => InsnClass::FloatArith,

        "fcvtzs" | "fcvtzu" | "scvtf" | "ucvtf" if is_scalar => InsnClass::FloatArith,
        "fcvtzs" | "fcvtzu" | "scvtf" | "ucvtf" if !is_scalar => InsnClass::SimdArith,

        // === P0: Crypto acceleration ===

        // AES: aese/aesd read-modify-write Vd (XOR then SubBytes/InvSubBytes)
        "aese" | "aesd" => InsnClass::SimdRMW,
        // AES: aesmc/aesimc pure column-mix, DEF=Vd only
        "aesmc" | "aesimc" => InsnClass::SimdArith,

        // SHA-1
        "sha1c" | "sha1m" | "sha1p" | "sha1su0" | "sha1su1" => InsnClass::SimdRMW,
        "sha1h" => InsnClass::SimdArith,

        // SHA-256
        "sha256h" | "sha256h2" | "sha256su0" | "sha256su1" => InsnClass::SimdRMW,

        // SHA-512 / SHA-3 (ARMv8.2-SHA)
        "sha512h" | "sha512h2" | "sha512su0" | "sha512su1" => InsnClass::SimdRMW,
        "eor3" | "rax1" | "xar" | "bcax" => InsnClass::SimdArith,

        // SM3 (ARMv8.2-SM3)
        "sm3ss1" => InsnClass::SimdArith,
        "sm3tt1a" | "sm3tt1b" | "sm3tt2a" | "sm3tt2b" | "sm3partw1" | "sm3partw2" => {
            InsnClass::SimdRMW
        }

        // SM4 (ARMv8.2-SM4)
        "sm4e" => InsnClass::SimdRMW,
        "sm4ekey" => InsnClass::SimdArith,

        // CRC32 (ARMv8.0-CRC): scalar ALU, DEF=Wd, USE=Wn+Rm
        "crc32b" | "crc32h" | "crc32w" | "crc32x" | "crc32cb" | "crc32ch" | "crc32cw"
        | "crc32cx" => InsnClass::AluReg,

        // === PAC (ARMv8.3-PAuth) ===

        // PAC sign/authenticate/strip: DEF=Rd, USE=Rd+Rn (same as ALU)
        "pacia" | "pacib" | "pacda" | "pacdb"
        | "autia" | "autib" | "autda" | "autdb"
        | "xpaci" | "xpacd" => InsnClass::AluReg,

        // PAC hint forms (encoded as hint instructions, no register effect)
        "pacia1716" | "pacib1716" | "paciaz" | "pacibz" | "paciasp" | "pacibsp"
        | "autia1716" | "autib1716" | "autiasp" | "autibsp" | "autiaz" | "autibz"
        | "xpaclri" => InsnClass::Nop,

        // PAC authenticated branches
        "braa" | "brab" | "braaz" | "brabz" => InsnClass::BranchReg,

        // PAC authenticated calls
        "blraa" | "blrab" | "blraaz" | "blrabz" => InsnClass::BranchLinkReg,

        // PAC authenticated returns
        "retaa" | "retab" => InsnClass::Return,

        // === LSE Atomics (ARMv8.1-Atomics) ===

        // Atomic load-operate (return old value)
        "ldadd" | "ldadda" | "ldaddal" | "ldaddl"
        | "ldaddb" | "ldaddab" | "ldaddalb" | "ldaddlb"
        | "ldaddh" | "ldaddah" | "ldaddalh" | "ldaddlh"
        | "ldclr" | "ldclra" | "ldclral" | "ldclrl"
        | "ldclrb" | "ldclrab" | "ldclralb" | "ldclrlb"
        | "ldclrh" | "ldclrah" | "ldclralh" | "ldclrlh"
        | "ldeor" | "ldeora" | "ldeoral" | "ldeorl"
        | "ldeorb" | "ldeorab" | "ldeoralb" | "ldeorlb"
        | "ldeorh" | "ldeorah" | "ldeoralh" | "ldeorlh"
        | "ldset" | "ldseta" | "ldsetal" | "ldsetl"
        | "ldsetb" | "ldsetab" | "ldsetalb" | "ldsetlb"
        | "ldseth" | "ldsetah" | "ldsetalh" | "ldsetlh"
        | "ldsmax" | "ldsmaxa" | "ldsmaxal" | "ldsmaxl"
        | "ldsmaxb" | "ldsmaxab" | "ldsmaxalb" | "ldsmaxlb"
        | "ldsmaxh" | "ldsmaxah" | "ldsmaxalh" | "ldsmaxlh"
        | "ldsmin" | "ldsmina" | "ldsminal" | "ldsminl"
        | "ldsminb" | "ldsminab" | "ldsminalb" | "ldsminlb"
        | "ldsminh" | "ldsminah" | "ldsminalh" | "ldsminlh"
        | "ldumax" | "ldumaxa" | "ldumaxal" | "ldumaxl"
        | "ldumaxb" | "ldumaxab" | "ldumaxalb" | "ldumaxlb"
        | "ldumaxh" | "ldumaxah" | "ldumaxalh" | "ldumaxlh"
        | "ldumin" | "ldumina" | "lduminal" | "lduminl"
        | "lduminb" | "lduminab" | "lduminalb" | "lduminlb"
        | "lduminh" | "lduminah" | "lduminalh" | "lduminlh"
        | "swp" | "swpa" | "swpal" | "swpl"
        | "swpb" | "swpab" | "swpalb" | "swplb"
        | "swph" | "swpah" | "swpalh" | "swplh" => InsnClass::AtomicLoadOp,

        // Atomic store-operate (no return, Rt=xzr implicit)
        "stadd" | "staddl" | "staddb" | "staddlb" | "staddh" | "staddlh"
        | "stclr" | "stclrl" | "stclrb" | "stclrlb" | "stclrh" | "stclrlh"
        | "steor" | "steorl" | "steorb" | "steorlb" | "steorh" | "steorlh"
        | "stset" | "stsetl" | "stsetb" | "stsetlb" | "stseth" | "stsetlh"
        | "stsmax" | "stsmaxl" | "stsmaxb" | "stsmaxlb" | "stsmaxh" | "stsmaxlh"
        | "stsmin" | "stsminl" | "stsminb" | "stsminlb" | "stsminh" | "stsminlh"
        | "stumax" | "stumaxl" | "stumaxb" | "stumaxlb" | "stumaxh" | "stumaxlh"
        | "stumin" | "stuminl" | "stuminb" | "stuminlb" | "stuminh" | "stuminlh" => {
            InsnClass::StoreReg
        }

        // Compare-and-Swap
        "cas" | "casa" | "casal" | "casl"
        | "casb" | "casab" | "casalb" | "caslb"
        | "cash" | "casah" | "casalh" | "caslh" => InsnClass::CompareAndSwap,

        // Default: unknown mnemonic -> Nop (safe fallback: no DEF/USE)
        _ => InsnClass::Nop,
    }
}

/// 判断助记符是否为已知的 NOP/系统指令（非未知回退）。
///
/// 用于区分 classify() 返回 Nop 时，是"已知无副作用指令"还是"未知助记符回退"。
pub fn is_known_nop(mnemonic: &str) -> bool {
    nop_mnemonics!(mnemonic)
}

/// 检查操作数中是否包含 NZCV 寄存器
fn has_nzcv_operand(ops: &[Operand]) -> bool {
    ops.iter()
        .any(|o| matches!(o, Operand::Reg(r) if *r == RegId::NZCV))
}

/// 分类 + 精化：classify 后自动应用 post-classify 调整。
///
/// 调用方不再需要手动执行 SimdLoad→SimdLaneLoad、SysReg→SysRegNzcv 等精化。
pub fn classify_and_refine(line: &super::types::ParsedLine) -> InsnClass {
    let first_reg = line
        .operands
        .first()
        .and_then(|o: &super::types::Operand| o.as_reg());
    let class = classify(line.mnemonic.as_str(), first_reg);
    match class {
        InsnClass::SimdLoad if line.lane_index.is_some() => InsnClass::SimdLaneLoad,
        // fmov Vd.D[1], Xn — lane 写入是读改写（需要 Vd 旧值）
        InsnClass::FloatArith if line.lane_index.is_some() => InsnClass::SimdRMW,
        InsnClass::SysRegRead if has_nzcv_operand(&line.operands) => InsnClass::SysRegNzcvRead,
        InsnClass::SysRegWrite if has_nzcv_operand(&line.operands) => InsnClass::SysRegNzcvWrite,
        other => other,
    }
}

// 测试体积大（767 行）：通过 include! 保持字节级原样，避免转写误差。
#[cfg(test)]
mod tests {
    include!("tests.rs");
}
