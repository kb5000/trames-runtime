// SPDX-License-Identifier: GPL-3.0-or-later
use super::{FloatOp, VectorFloatOp};
use std::arch::aarch64::uint8x16_t;
use std::arch::asm;

pub(super) fn save() -> (u64, u64) {
    let (control, status);
    // SAFETY: unprivileged FP control/status registers; no memory is accessed.
    unsafe {
        asm!("mrs {c}, fpcr", "mrs {s}, fpsr", c=out(reg) control, s=out(reg) status, options(nostack, preserves_flags));
    }
    (control, status)
}
pub(super) fn restore(saved: (u64, u64)) {
    unsafe {
        asm!("msr fpcr, {c}", "msr fpsr, {s}", c=in(reg) saved.0, s=in(reg) saved.1, options(nostack, preserves_flags));
    }
}
pub(super) fn control(value: u32) {
    // Traps stay masked; supported guest rounding/flush controls are cheap to
    // install once per execution slice, rather than around every operation.
    unsafe {
        asm!("msr fpcr, {value}", value=in(reg) (value & 0x07c80000) as u64, options(nostack, preserves_flags));
    }
}
pub(super) fn set_status(value: u32) {
    unsafe {
        asm!("msr fpsr, {value}", value=in(reg) (value & 0x0800009f) as u64, options(nostack, preserves_flags));
    }
}
pub(super) fn status() -> u32 {
    let value: u64;
    unsafe {
        asm!("mrs {value}, fpsr", value=out(reg) value, options(nostack, preserves_flags));
    }
    value as u32 & 0x0800009f
}

pub(super) fn scalar(bits: u32, op: FloatOp, a: u64, b: u64, c: u64) -> Option<u64> {
    macro_rules! compute {
        ($ty:ty, $reg:literal) => {{
            let mut left = <$ty>::from_bits(a as _);
            let right = <$ty>::from_bits(b as _);
            let addend = <$ty>::from_bits(c as _);
            macro_rules! binary { ($instruction:literal) => {
                unsafe { asm!(concat!($instruction, " {a:", $reg, "}, {a:", $reg, "}, {b:", $reg, "}"),
                    a=inout(vreg) left, b=in(vreg) right, options(nostack, preserves_flags)); }
            }; }
            match op {
                FloatOp::Add => binary!("fadd"),
                FloatOp::Sub => binary!("fsub"),
                FloatOp::Mul => binary!("fmul"),
                FloatOp::Div => binary!("fdiv"),
                FloatOp::Min => binary!("fmin"),
                FloatOp::Max => binary!("fmax"),
                FloatOp::MinNumber => binary!("fminnm"),
                FloatOp::MaxNumber => binary!("fmaxnm"),
                FloatOp::MultiplyExtended => binary!("fmulx"),
                FloatOp::NegatedMul => binary!("fnmul"),
                FloatOp::Abs => unsafe { asm!(concat!("fabs {a:", $reg, "}, {a:", $reg, "}"), a=inout(vreg) left, options(nostack, preserves_flags)); },
                FloatOp::Neg => unsafe { asm!(concat!("fneg {a:", $reg, "}, {a:", $reg, "}"), a=inout(vreg) left, options(nostack, preserves_flags)); },
                FloatOp::ReciprocalEstimate => unsafe { asm!(concat!("frecpe {a:", $reg, "}, {a:", $reg, "}"), a=inout(vreg) left, options(nostack, preserves_flags)); },
                FloatOp::ReciprocalSqrtEstimate => unsafe { asm!(concat!("frsqrte {a:", $reg, "}, {a:", $reg, "}"), a=inout(vreg) left, options(nostack, preserves_flags)); },
                FloatOp::ReciprocalStep => binary!("frecps"),
                FloatOp::ReciprocalSqrtStep => binary!("frsqrts"),
                FloatOp::Sqrt => unsafe { asm!(concat!("fsqrt {a:", $reg, "}, {a:", $reg, "}"), a=inout(vreg) left, options(nostack, preserves_flags)); },
                FloatOp::Fma => unsafe { asm!(concat!("fmadd {a:", $reg, "}, {a:", $reg, "}, {b:", $reg, "}, {c:", $reg, "}"),
                    a=inout(vreg) left, b=in(vreg) right, c=in(vreg) addend, options(nostack, preserves_flags)); },
            }
            Some(left.to_bits() as u64)
        }};
    }
    match bits {
        16 if std::arch::is_aarch64_feature_detected!("fp16") => {
            // SAFETY: runtime detection precedes the statically compiled FP16 helper.
            Some(unsafe { scalar_half(op, a, b, c) })
        }
        32 => compute!(f32, "s"),
        64 => compute!(f64, "d"),
        _ => None,
    }
}

pub(super) fn vector_float(
    bits: u32,
    wide: bool,
    op: VectorFloatOp,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    // SAFETY: all bit patterns are valid SIMD values; these are value casts,
    // never guest-address translations or pointer dereferences.
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    let b: uint8x16_t = unsafe { std::mem::transmute(b) };
    let c: uint8x16_t = unsafe { std::mem::transmute(c) };
    macro_rules! compute { ($lanes:literal) => {{
        let mut result = a;
        macro_rules! binary { ($instruction:literal) => {
            unsafe { asm!(concat!($instruction, " {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes),
                a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); }
        }; }
        match op {
            VectorFloatOp::Add => binary!("fadd"), VectorFloatOp::Sub => binary!("fsub"),
            VectorFloatOp::Mul => binary!("fmul"), VectorFloatOp::Div => binary!("fdiv"),
            VectorFloatOp::Min => binary!("fmin"),
            VectorFloatOp::Max => binary!("fmax"),
            VectorFloatOp::MinNumber => binary!("fminnm"),
            VectorFloatOp::MaxNumber => binary!("fmaxnm"),
            VectorFloatOp::MultiplyExtended => binary!("fmulx"),
            VectorFloatOp::AbsoluteDifference => binary!("fabd"),
            VectorFloatOp::Equal => binary!("fcmeq"),
            VectorFloatOp::Greater => binary!("fcmgt"),
            VectorFloatOp::GreaterEqual => binary!("fcmge"),
            VectorFloatOp::AbsoluteGreater => binary!("facgt"),
            VectorFloatOp::AbsoluteGreaterEqual => binary!("facge"),
            VectorFloatOp::PairAdd => binary!("faddp"),
            VectorFloatOp::PairMin => binary!("fminp"),
            VectorFloatOp::PairMax => binary!("fmaxp"),
            VectorFloatOp::PairMinNumber => binary!("fminnmp"),
            VectorFloatOp::PairMaxNumber => binary!("fmaxnmp"),
            VectorFloatOp::Abs => unsafe { asm!(concat!("fabs {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::Neg => unsafe { asm!(concat!("fneg {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::ReciprocalEstimate => unsafe { asm!(concat!("frecpe {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::ReciprocalSqrtEstimate => unsafe { asm!(concat!("frsqrte {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundNearest => unsafe { asm!(concat!("frintn {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundPositive => unsafe { asm!(concat!("frintp {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundNegative => unsafe { asm!(concat!("frintm {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundZero => unsafe { asm!(concat!("frintz {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundAway => unsafe { asm!(concat!("frinta {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundCurrent => unsafe { asm!(concat!("frinti {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundExact => unsafe { asm!(concat!("frintx {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::SignedToFloat => unsafe { asm!(concat!("scvtf {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::UnsignedToFloat => unsafe { asm!(concat!("ucvtf {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedZero => unsafe { asm!(concat!("fcvtzs {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedZero => unsafe { asm!(concat!("fcvtzu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedNearest => unsafe { asm!(concat!("fcvtns {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedNearest => unsafe { asm!(concat!("fcvtnu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedPositive => unsafe { asm!(concat!("fcvtps {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedPositive => unsafe { asm!(concat!("fcvtpu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedNegative => unsafe { asm!(concat!("fcvtms {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedNegative => unsafe { asm!(concat!("fcvtmu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedAway => unsafe { asm!(concat!("fcvtas {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedAway => unsafe { asm!(concat!("fcvtau {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::ReciprocalStep => binary!("frecps"),
            VectorFloatOp::ReciprocalSqrtStep => binary!("frsqrts"),
            VectorFloatOp::Sqrt => unsafe { asm!(concat!("fsqrt {a:v}.", $lanes, ", {a:v}.", $lanes),
                a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::MultiplyAdd | VectorFloatOp::MultiplySub => {
                result = c;
                match op {
                    VectorFloatOp::MultiplyAdd => unsafe { asm!(concat!("fmla {c:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); },
                    _ => unsafe { asm!(concat!("fmls {c:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); },
                }
            }
        }
        Some(unsafe { std::mem::transmute::<uint8x16_t, u128>(result) })
    }}; }
    match (bits, wide) {
        (16, _) if std::arch::is_aarch64_feature_detected!("fp16") => {
            Some(unsafe { vector_half(wide, op, a, b, c) })
        }
        (32, false) => compute!("2s"),
        (32, true) => compute!("4s"),
        (64, true) => compute!("2d"),
        _ => None,
    }
}

#[target_feature(enable = "fp16")]
unsafe fn scalar_half(op: FloatOp, a: u64, b: u64, c: u64) -> u64 {
    // f32 is only a bit carrier here. The h register view reads/writes its low
    // sixteen bits; no promotion, emulated arithmetic or double rounding.
    let mut a = f32::from_bits(a as u16 as u32);
    let b = f32::from_bits(b as u16 as u32);
    let c = f32::from_bits(c as u16 as u32);
    macro_rules! binary { ($i:literal) => {
        unsafe { asm!(concat!($i, " {a:h}, {a:h}, {b:h}"), a=inout(vreg) a,
            b=in(vreg) b, options(nostack, preserves_flags)); }
    }; }
    match op {
        FloatOp::Add => binary!("fadd"),
        FloatOp::Sub => binary!("fsub"),
        FloatOp::Mul => binary!("fmul"),
        FloatOp::Div => binary!("fdiv"),
        FloatOp::Min => binary!("fmin"),
        FloatOp::Max => binary!("fmax"),
        FloatOp::MinNumber => binary!("fminnm"),
        FloatOp::MaxNumber => binary!("fmaxnm"),
        FloatOp::MultiplyExtended => binary!("fmulx"),
        FloatOp::NegatedMul => binary!("fnmul"),
        FloatOp::Abs => unsafe {
            asm!("fabs {a:h}, {a:h}", a=inout(vreg) a, options(nostack, preserves_flags));
        },
        FloatOp::Neg => unsafe {
            asm!("fneg {a:h}, {a:h}", a=inout(vreg) a, options(nostack, preserves_flags));
        },
        FloatOp::ReciprocalEstimate => unsafe {
            asm!("frecpe {a:h}, {a:h}", a=inout(vreg) a, options(nostack, preserves_flags));
        },
        FloatOp::ReciprocalSqrtEstimate => unsafe {
            asm!("frsqrte {a:h}, {a:h}", a=inout(vreg) a, options(nostack, preserves_flags));
        },
        FloatOp::ReciprocalStep => binary!("frecps"),
        FloatOp::ReciprocalSqrtStep => binary!("frsqrts"),
        FloatOp::Sqrt => unsafe {
            asm!("fsqrt {a:h}, {a:h}", a=inout(vreg) a, options(nostack, preserves_flags));
        },
        FloatOp::Fma => unsafe {
            asm!("fmadd {a:h}, {a:h}, {b:h}, {c:h}", a=inout(vreg) a,
            b=in(vreg) b, c=in(vreg) c, options(nostack, preserves_flags));
        },
    }
    (a.to_bits() & 0xffff) as u64
}

#[target_feature(enable = "fp16")]
unsafe fn vector_half(
    wide: bool,
    op: VectorFloatOp,
    a: uint8x16_t,
    b: uint8x16_t,
    c: uint8x16_t,
) -> u128 {
    macro_rules! compute { ($lanes:literal) => {{
        let mut result = a;
        macro_rules! binary { ($i:literal) => {
            unsafe { asm!(concat!($i, " {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes),
                a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); }
        }; }
        match op {
            VectorFloatOp::Add => binary!("fadd"), VectorFloatOp::Sub => binary!("fsub"),
            VectorFloatOp::Mul => binary!("fmul"), VectorFloatOp::Div => binary!("fdiv"),
            VectorFloatOp::Min => binary!("fmin"),
            VectorFloatOp::Max => binary!("fmax"),
            VectorFloatOp::MinNumber => binary!("fminnm"),
            VectorFloatOp::MaxNumber => binary!("fmaxnm"),
            VectorFloatOp::MultiplyExtended => binary!("fmulx"),
            VectorFloatOp::AbsoluteDifference => binary!("fabd"),
            VectorFloatOp::Equal => binary!("fcmeq"),
            VectorFloatOp::Greater => binary!("fcmgt"),
            VectorFloatOp::GreaterEqual => binary!("fcmge"),
            VectorFloatOp::AbsoluteGreater => binary!("facgt"),
            VectorFloatOp::AbsoluteGreaterEqual => binary!("facge"),
            VectorFloatOp::PairAdd => binary!("faddp"),
            VectorFloatOp::PairMin => binary!("fminp"),
            VectorFloatOp::PairMax => binary!("fmaxp"),
            VectorFloatOp::PairMinNumber => binary!("fminnmp"),
            VectorFloatOp::PairMaxNumber => binary!("fmaxnmp"),
            VectorFloatOp::Abs => unsafe { asm!(concat!("fabs {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::Neg => unsafe { asm!(concat!("fneg {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::ReciprocalEstimate => unsafe { asm!(concat!("frecpe {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::ReciprocalSqrtEstimate => unsafe { asm!(concat!("frsqrte {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundNearest => unsafe { asm!(concat!("frintn {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundPositive => unsafe { asm!(concat!("frintp {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundNegative => unsafe { asm!(concat!("frintm {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundZero => unsafe { asm!(concat!("frintz {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundAway => unsafe { asm!(concat!("frinta {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundCurrent => unsafe { asm!(concat!("frinti {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::RoundExact => unsafe { asm!(concat!("frintx {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::SignedToFloat => unsafe { asm!(concat!("scvtf {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::UnsignedToFloat => unsafe { asm!(concat!("ucvtf {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedZero => unsafe { asm!(concat!("fcvtzs {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedZero => unsafe { asm!(concat!("fcvtzu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedNearest => unsafe { asm!(concat!("fcvtns {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedNearest => unsafe { asm!(concat!("fcvtnu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedPositive => unsafe { asm!(concat!("fcvtps {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedPositive => unsafe { asm!(concat!("fcvtpu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedNegative => unsafe { asm!(concat!("fcvtms {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedNegative => unsafe { asm!(concat!("fcvtmu {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToSignedAway => unsafe { asm!(concat!("fcvtas {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::FloatToUnsignedAway => unsafe { asm!(concat!("fcvtau {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::ReciprocalStep => binary!("frecps"), VectorFloatOp::ReciprocalSqrtStep => binary!("frsqrts"),
            VectorFloatOp::Sqrt => unsafe { asm!(concat!("fsqrt {a:v}.", $lanes, ", {a:v}.", $lanes),
                a=inout(vreg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::MultiplyAdd | VectorFloatOp::MultiplySub => {
                result = c;
                match op {
                    VectorFloatOp::MultiplyAdd => unsafe { asm!(concat!("fmla {c:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); },
                    _ => unsafe { asm!(concat!("fmls {c:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); },
                }
            }
        }
        unsafe { std::mem::transmute::<uint8x16_t, u128>(result) }
    }}; }
    if wide {
        compute!("8h")
    } else {
        compute!("4h")
    }
}

// Same-width AdvSIMD operations: static opcodes, no guest code execution.
pub(super) fn vector_integer(
    bits: u32,
    wide: bool,
    op: super::IntegerOp,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    use super::IntegerOp as I;
    if bits == 64
        && !matches!(
            op,
            I::InsertIfFalse
                | I::ReverseBits
                | I::UnsignedSaturatingAdd
                | I::UnsignedSaturatingSub
                | I::SignedRoundingSaturatingShift
                | I::BitClear
                | I::Select
                | I::Abs
                | I::Sub
                | I::Test
                | I::UnsignedGreater
                | I::UnsignedRoundingSaturatingShift
                | I::Not
                | I::InsertIfTrue
                | I::UnsignedGreaterEqual
                | I::SignedShift
                | I::Neg
                | I::SignedGreater
                | I::Equal
                | I::OrNot
                | I::SaturatingAbs
                | I::SignedSaturatingSub
                | I::And
                | I::UnsignedShift
                | I::UnsignedSaturatingShift
                | I::Or
                | I::UnsignedRoundingShift
                | I::Xor
                | I::SignedGreaterEqual
                | I::SignedSaturatingAdd
                | I::PairAdd
                | I::SaturatingNeg
                | I::Add
                | I::SignedSaturatingShift
                | I::SignedRoundingShift
                | I::Popcount
        )
    {
        return None;
    }
    if matches!(
        op,
        I::SaturatingMultiplyHigh | I::RoundingSaturatingMultiplyHigh
    ) && !matches!(bits, 16 | 32)
    {
        return None;
    }
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    let b: uint8x16_t = unsafe { std::mem::transmute(b) };
    let c: uint8x16_t = unsafe { std::mem::transmute(c) };
    macro_rules! compute { ($lanes:literal, $bytes:literal, $small:literal, $high:literal) => {{
        let mut result = a;
        match op {
            I::Add => { unsafe { asm!(concat!("add {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Sub => { unsafe { asm!(concat!("sub {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::PairAdd => { unsafe { asm!(concat!("addp {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Equal => { unsafe { asm!(concat!("cmeq {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Test => { unsafe { asm!(concat!("cmtst {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedGreater => { unsafe { asm!(concat!("cmgt {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedGreaterEqual => { unsafe { asm!(concat!("cmge {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedGreater => { unsafe { asm!(concat!("cmhi {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedGreaterEqual => { unsafe { asm!(concat!("cmhs {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Mul => { unsafe { asm!(concat!("mul {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::MultiplyAdd => { result = c; unsafe { asm!(concat!("mla {c:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::MultiplySub => { result = c; unsafe { asm!(concat!("mls {c:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedMax => { unsafe { asm!(concat!("smax {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedMin => { unsafe { asm!(concat!("smin {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedMax => { unsafe { asm!(concat!("umax {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedMin => { unsafe { asm!(concat!("umin {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedHalvingAdd => { unsafe { asm!(concat!("shadd {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedHalvingAdd => { unsafe { asm!(concat!("uhadd {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedHalvingSub => { unsafe { asm!(concat!("shsub {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedHalvingSub => { unsafe { asm!(concat!("uhsub {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedRoundingHalvingAdd => { unsafe { asm!(concat!("srhadd {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedRoundingHalvingAdd => { unsafe { asm!(concat!("urhadd {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedSaturatingAdd => { unsafe { asm!(concat!("sqadd {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedSaturatingAdd => { unsafe { asm!(concat!("uqadd {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedSaturatingSub => { unsafe { asm!(concat!("sqsub {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedSaturatingSub => { unsafe { asm!(concat!("uqsub {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedAbsoluteDifference => { unsafe { asm!(concat!("sabd {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedAbsoluteDifference => { unsafe { asm!(concat!("uabd {a:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedAbsoluteDifferenceAccumulate => { result = c; unsafe { asm!(concat!("saba {c:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedAbsoluteDifferenceAccumulate => { result = c; unsafe { asm!(concat!("uaba {c:v}.", $small, ", {a:v}.", $small, ", {b:v}.", $small), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedShift => { unsafe { asm!(concat!("sshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedShift => { unsafe { asm!(concat!("ushl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedRoundingShift => { unsafe { asm!(concat!("srshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedRoundingShift => { unsafe { asm!(concat!("urshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedSaturatingShift => { unsafe { asm!(concat!("sqshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedSaturatingShift => { unsafe { asm!(concat!("uqshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SignedRoundingSaturatingShift => { unsafe { asm!(concat!("sqrshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::UnsignedRoundingSaturatingShift => { unsafe { asm!(concat!("uqrshl {a:v}.", $lanes, ", {a:v}.", $lanes, ", {b:v}.", $lanes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::SaturatingMultiplyHigh => { unsafe { asm!(concat!("sqdmulh {a:v}.", $high, ", {a:v}.", $high, ", {b:v}.", $high), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::RoundingSaturatingMultiplyHigh => { unsafe { asm!(concat!("sqrdmulh {a:v}.", $high, ", {a:v}.", $high, ", {b:v}.", $high), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Abs => { unsafe { asm!(concat!("abs {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::Neg => { unsafe { asm!(concat!("neg {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::SaturatingAbs => { unsafe { asm!(concat!("sqabs {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::SaturatingNeg => { unsafe { asm!(concat!("sqneg {a:v}.", $lanes, ", {a:v}.", $lanes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::LeadingZeros => { unsafe { asm!(concat!("clz {a:v}.", $small, ", {a:v}.", $small), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::LeadingSign => { unsafe { asm!(concat!("cls {a:v}.", $small, ", {a:v}.", $small), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::Popcount => { unsafe { asm!(concat!("cnt {a:v}.", $bytes, ", {a:v}.", $bytes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::ReverseBits => { unsafe { asm!(concat!("rbit {a:v}.", $bytes, ", {a:v}.", $bytes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::Not => { unsafe { asm!(concat!("not {a:v}.", $bytes, ", {a:v}.", $bytes), a=inout(vreg) result, options(nostack, preserves_flags)); } },
            I::And => { unsafe { asm!(concat!("and {a:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Or => { unsafe { asm!(concat!("orr {a:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Xor => { unsafe { asm!(concat!("eor {a:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::BitClear => { unsafe { asm!(concat!("bic {a:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::OrNot => { unsafe { asm!(concat!("orn {a:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), a=inout(vreg) result, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::Select => { result = c; unsafe { asm!(concat!("bsl {c:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::InsertIfTrue => { result = c; unsafe { asm!(concat!("bit {c:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
            I::InsertIfFalse => { result = c; unsafe { asm!(concat!("bif {c:v}.", $bytes, ", {a:v}.", $bytes, ", {b:v}.", $bytes), c=inout(vreg) result, a=in(vreg) a, b=in(vreg) b, options(nostack, preserves_flags)); } },
        }
        Some(unsafe { std::mem::transmute::<uint8x16_t, u128>(result) })
    }}; }
    match (bits, wide) {
        (8, false) => compute!("8b", "8b", "8b", "4h"),
        (8, true) => compute!("16b", "16b", "16b", "8h"),
        (16, false) => compute!("4h", "8b", "4h", "4h"),
        (16, true) => compute!("8h", "16b", "8h", "8h"),
        (32, false) => compute!("2s", "8b", "2s", "2s"),
        (32, true) => compute!("4s", "16b", "4s", "4s"),
        (64, true) => compute!("2d", "16b", "4s", "4s"),
        _ => None,
    }
}

pub(super) fn crypto(op: super::CryptoOp, d: u128, n: u128, m: u128) -> Option<u128> {
    use super::CryptoOp as C;
    if matches!(
        op,
        C::AesEncrypt | C::AesDecrypt | C::AesMix | C::AesInverseMix
    ) {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return None;
        }
        Some(unsafe { aes(op, d, n) })
    } else {
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            return None;
        }
        Some(unsafe { sha(op, d, n, m) })
    }
}
#[target_feature(enable = "aes")]
unsafe fn aes(op: super::CryptoOp, d: u128, n: u128) -> u128 {
    use super::CryptoOp as C;
    let mut d: uint8x16_t = unsafe { std::mem::transmute(d) };
    let n: uint8x16_t = unsafe { std::mem::transmute(n) };
    match op {
        C::AesEncrypt => unsafe {
            asm!("aese {d:v}.16b, {n:v}.16b", d=inout(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::AesDecrypt => unsafe {
            asm!("aesd {d:v}.16b, {n:v}.16b", d=inout(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::AesMix => unsafe {
            asm!("aesmc {d:v}.16b, {n:v}.16b", d=out(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::AesInverseMix => unsafe {
            asm!("aesimc {d:v}.16b, {n:v}.16b", d=out(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        _ => unreachable!(),
    }
    unsafe { std::mem::transmute::<uint8x16_t, u128>(d) }
}
#[target_feature(enable = "sha2")]
unsafe fn sha(op: super::CryptoOp, d: u128, n: u128, m: u128) -> u128 {
    use super::CryptoOp as C;
    let mut d: uint8x16_t = unsafe { std::mem::transmute(d) };
    let n: uint8x16_t = unsafe { std::mem::transmute(n) };
    let m: uint8x16_t = unsafe { std::mem::transmute(m) };
    match op {
        C::Sha1Hash => unsafe {
            asm!("sha1h {d:s}, {n:s}", d=out(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::Sha1Choose => unsafe {
            asm!("sha1c {d:q}, {n:s}, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha1Parity => unsafe {
            asm!("sha1p {d:q}, {n:s}, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha1Majority => unsafe {
            asm!("sha1m {d:q}, {n:s}, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha1Schedule0 => unsafe {
            asm!("sha1su0 {d:v}.4s, {n:v}.4s, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha1Schedule1 => unsafe {
            asm!("sha1su1 {d:v}.4s, {n:v}.4s", d=inout(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::Sha256Hash => unsafe {
            asm!("sha256h {d:q}, {n:q}, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha256Hash2 => unsafe {
            asm!("sha256h2 {d:q}, {n:q}, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha256Schedule0 => unsafe {
            asm!("sha256su0 {d:v}.4s, {n:v}.4s", d=inout(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::Sha256Schedule1 => unsafe {
            asm!("sha256su1 {d:v}.4s, {n:v}.4s, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        _ => unreachable!(),
    }
    unsafe { std::mem::transmute::<uint8x16_t, u128>(d) }
}

pub(super) fn polynomial_product(bits: u32, a: u64, b: u64) -> Option<u128> {
    if bits != 64 || !std::arch::is_aarch64_feature_detected!("pmull") {
        return None;
    }
    Some(unsafe { polynomial64(a, b) })
}
#[target_feature(enable = "aes")]
unsafe fn polynomial64(a: u64, b: u64) -> u128 {
    let a: uint8x16_t = unsafe { std::mem::transmute(a as u128) };
    let b: uint8x16_t = unsafe { std::mem::transmute(b as u128) };
    let result: uint8x16_t;
    unsafe {
        asm!("pmull {d:v}.1q, {a:v}.1d, {b:v}.1d", d=out(vreg) result, a=in(vreg) a,
        b=in(vreg) b, options(nostack, preserves_flags));
    }
    unsafe { std::mem::transmute::<uint8x16_t, u128>(result) }
}

pub(super) fn convert(from: u32, to: u32, value: u64) -> Option<u64> {
    macro_rules! convert { ($input:ty, $output:ty, $src:literal, $dst:literal) => {{
        let input = <$input>::from_bits(value as _);
        let output: $output;
        unsafe { asm!(concat!("fcvt {d:", $dst, "}, {s:", $src, "}"), d=out(vreg) output,
            s=in(vreg) input, options(nostack, preserves_flags)); }
        Some(output.to_bits() as u64 & if to == 16 { 0xffff } else { u64::MAX })
    }}; }
    match (from, to) {
        (16, 32) => convert!(f32, f32, "h", "s"),
        (16, 64) => convert!(f32, f64, "h", "d"),
        (32, 16) => convert!(f32, f32, "s", "h"),
        (64, 16) => convert!(f64, f32, "d", "h"),
        (32, 64) => convert!(f32, f64, "s", "d"),
        (64, 32) => convert!(f64, f32, "d", "s"),
        _ => None,
    }
}

pub(super) fn convert_odd(value: u64) -> Option<u32> {
    let input = f64::from_bits(value);
    let output: f32;
    unsafe {
        asm!("fcvtxn {d:s}, {s:d}", d=out(vreg) output, s=in(vreg) input, options(nostack, preserves_flags));
    }
    Some(output.to_bits())
}

pub(super) fn crc(bytes: u32, castagnoli: bool, checksum: u32, data: u64) -> Option<u32> {
    if !matches!(bytes, 1 | 2 | 4 | 8) || !std::arch::is_aarch64_feature_detected!("crc") {
        return None;
    }
    Some(unsafe { crc_native(bytes, castagnoli, checksum, data) })
}
#[target_feature(enable = "crc")]
unsafe fn crc_native(bytes: u32, castagnoli: bool, mut checksum: u32, data: u64) -> u32 {
    macro_rules! compute { ($i:literal, $data:literal) => {
        unsafe { asm!(concat!($i, " {c:w}, {c:w}, {d:", $data, "}"), c=inout(reg) checksum,
            d=in(reg) data, options(nostack, preserves_flags)); }
    }; }
    match (bytes, castagnoli) {
        (1, false) => compute!("crc32b", "w"),
        (2, false) => compute!("crc32h", "w"),
        (4, false) => compute!("crc32w", "w"),
        (8, false) => compute!("crc32x", "x"),
        (1, true) => compute!("crc32cb", "w"),
        (2, true) => compute!("crc32ch", "w"),
        (4, true) => compute!("crc32cw", "w"),
        (8, true) => compute!("crc32cx", "x"),
        _ => unreachable!(),
    }
    checksum
}

pub(super) fn crypto_extended(
    op: super::ExtendedCryptoOp,
    d: u128,
    n: u128,
    m: u128,
    a: u128,
    immediate: u32,
) -> Option<u128> {
    use super::ExtendedCryptoOp as C;
    let sm = matches!(
        op,
        C::Sm3Ss1
            | C::Sm3Tt1A
            | C::Sm3Tt1B
            | C::Sm3Tt2A
            | C::Sm3Tt2B
            | C::Sm3Schedule1
            | C::Sm3Schedule2
            | C::Sm4Encrypt
            | C::Sm4Schedule
    );
    if sm {
        if !std::arch::is_aarch64_feature_detected!("sm4") {
            return None;
        }
        unsafe { native_sm(op, d, n, m, a, immediate) }
    } else {
        if !std::arch::is_aarch64_feature_detected!("sha3") {
            return None;
        }
        unsafe { native_sha3(op, d, n, m, a, immediate) }
    }
}

#[target_feature(enable = "sha3")]
unsafe fn native_sha3(
    op: super::ExtendedCryptoOp,
    d: u128,
    n: u128,
    m: u128,
    a: u128,
    immediate: u32,
) -> Option<u128> {
    use super::ExtendedCryptoOp as C;
    let mut d: uint8x16_t = unsafe { std::mem::transmute(d) };
    let n: uint8x16_t = unsafe { std::mem::transmute(n) };
    let m: uint8x16_t = unsafe { std::mem::transmute(m) };
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    match op {
        C::Sha512Hash => unsafe {
            asm!("sha512h {d:q}, {n:q}, {m:v}.2d", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha512Hash2 => unsafe {
            asm!("sha512h2 {d:q}, {n:q}, {m:v}.2d", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sha512Schedule0 => unsafe {
            asm!("sha512su0 {d:v}.2d, {n:v}.2d", d=inout(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::Sha512Schedule1 => unsafe {
            asm!("sha512su1 {d:v}.2d, {n:v}.2d, {m:v}.2d", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Eor3 => unsafe {
            asm!("eor3 {d:v}.16b, {n:v}.16b, {m:v}.16b, {a:v}.16b", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, a=in(vreg) a, options(nostack, preserves_flags));
        },
        C::Bcax => unsafe {
            asm!("bcax {d:v}.16b, {n:v}.16b, {m:v}.16b, {a:v}.16b", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, a=in(vreg) a, options(nostack, preserves_flags));
        },
        C::Rax1 => unsafe {
            asm!("rax1 {d:v}.2d, {n:v}.2d, {m:v}.2d", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Xar => match immediate {
            0 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #0", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            1 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #1", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            2 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #2", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            3 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #3", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            4 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #4", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            5 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #5", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            6 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #6", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            7 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #7", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            8 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #8", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            9 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #9", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            10 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #10", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            11 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #11", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            12 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #12", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            13 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #13", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            14 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #14", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            15 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #15", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            16 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #16", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            17 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #17", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            18 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #18", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            19 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #19", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            20 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #20", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            21 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #21", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            22 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #22", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            23 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #23", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            24 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #24", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            25 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #25", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            26 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #26", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            27 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #27", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            28 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #28", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            29 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #29", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            30 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #30", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            31 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #31", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            32 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #32", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            33 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #33", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            34 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #34", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            35 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #35", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            36 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #36", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            37 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #37", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            38 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #38", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            39 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #39", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            40 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #40", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            41 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #41", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            42 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #42", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            43 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #43", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            44 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #44", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            45 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #45", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            46 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #46", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            47 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #47", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            48 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #48", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            49 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #49", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            50 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #50", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            51 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #51", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            52 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #52", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            53 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #53", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            54 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #54", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            55 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #55", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            56 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #56", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            57 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #57", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            58 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #58", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            59 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #59", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            60 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #60", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            61 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #61", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            62 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #62", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            63 => unsafe {
                asm!("xar {d:v}.2d, {n:v}.2d, {m:v}.2d, #63", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            _ => return None,
        },
        _ => return None,
    }
    Some(unsafe { std::mem::transmute::<uint8x16_t, u128>(d) })
}

#[target_feature(enable = "sm4")]
unsafe fn native_sm(
    op: super::ExtendedCryptoOp,
    d: u128,
    n: u128,
    m: u128,
    a: u128,
    immediate: u32,
) -> Option<u128> {
    use super::ExtendedCryptoOp as C;
    let mut d: uint8x16_t = unsafe { std::mem::transmute(d) };
    let n: uint8x16_t = unsafe { std::mem::transmute(n) };
    let m: uint8x16_t = unsafe { std::mem::transmute(m) };
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    match op {
        C::Sm3Ss1 => unsafe {
            asm!("sm3ss1 {d:v}.4s, {n:v}.4s, {m:v}.4s, {a:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, a=in(vreg) a, options(nostack, preserves_flags));
        },
        C::Sm3Schedule1 => unsafe {
            asm!("sm3partw1 {d:v}.4s, {n:v}.4s, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sm3Schedule2 => unsafe {
            asm!("sm3partw2 {d:v}.4s, {n:v}.4s, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sm4Encrypt => unsafe {
            asm!("sm4e {d:v}.4s, {n:v}.4s", d=inout(vreg) d, n=in(vreg) n, options(nostack, preserves_flags));
        },
        C::Sm4Schedule => unsafe {
            asm!("sm4ekey {d:v}.4s, {n:v}.4s, {m:v}.4s", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
        },
        C::Sm3Tt1A => match immediate {
            0 => unsafe {
                asm!("sm3tt1a {d:v}.4s, {n:v}.4s, {m:v}.s[0]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            1 => unsafe {
                asm!("sm3tt1a {d:v}.4s, {n:v}.4s, {m:v}.s[1]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            2 => unsafe {
                asm!("sm3tt1a {d:v}.4s, {n:v}.4s, {m:v}.s[2]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            3 => unsafe {
                asm!("sm3tt1a {d:v}.4s, {n:v}.4s, {m:v}.s[3]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            _ => return None,
        },
        C::Sm3Tt1B => match immediate {
            0 => unsafe {
                asm!("sm3tt1b {d:v}.4s, {n:v}.4s, {m:v}.s[0]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            1 => unsafe {
                asm!("sm3tt1b {d:v}.4s, {n:v}.4s, {m:v}.s[1]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            2 => unsafe {
                asm!("sm3tt1b {d:v}.4s, {n:v}.4s, {m:v}.s[2]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            3 => unsafe {
                asm!("sm3tt1b {d:v}.4s, {n:v}.4s, {m:v}.s[3]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            _ => return None,
        },
        C::Sm3Tt2A => match immediate {
            0 => unsafe {
                asm!("sm3tt2a {d:v}.4s, {n:v}.4s, {m:v}.s[0]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            1 => unsafe {
                asm!("sm3tt2a {d:v}.4s, {n:v}.4s, {m:v}.s[1]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            2 => unsafe {
                asm!("sm3tt2a {d:v}.4s, {n:v}.4s, {m:v}.s[2]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            3 => unsafe {
                asm!("sm3tt2a {d:v}.4s, {n:v}.4s, {m:v}.s[3]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            _ => return None,
        },
        C::Sm3Tt2B => match immediate {
            0 => unsafe {
                asm!("sm3tt2b {d:v}.4s, {n:v}.4s, {m:v}.s[0]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            1 => unsafe {
                asm!("sm3tt2b {d:v}.4s, {n:v}.4s, {m:v}.s[1]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            2 => unsafe {
                asm!("sm3tt2b {d:v}.4s, {n:v}.4s, {m:v}.s[2]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            3 => unsafe {
                asm!("sm3tt2b {d:v}.4s, {n:v}.4s, {m:v}.s[3]", d=inout(vreg) d, n=in(vreg) n, m=in(vreg) m, options(nostack, preserves_flags));
            },
            _ => return None,
        },
        _ => return None,
    }
    Some(unsafe { std::mem::transmute::<uint8x16_t, u128>(d) })
}

pub(super) fn bfloat(op: super::BFloatOp, wide: bool, a: u128, b: u128, c: u128) -> Option<u128> {
    if !std::arch::is_aarch64_feature_detected!("bf16") {
        return None;
    }
    Some(unsafe { native_bfloat(op, wide, a, b, c) })
}
#[target_feature(enable = "bf16")]
unsafe fn native_bfloat(op: super::BFloatOp, wide: bool, a: u128, b: u128, c: u128) -> u128 {
    use super::BFloatOp as B;
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    let b: uint8x16_t = unsafe { std::mem::transmute(b) };
    let mut c: uint8x16_t = unsafe { std::mem::transmute(c) };
    match op {
        B::ConvertScalar => unsafe {
            asm!("bfcvt {c:h}, {a:s}",c=out(vreg)c,a=in(vreg)a,options(nostack,preserves_flags));
        },
        B::ConvertVector => {
            if wide {
                unsafe {
                    asm!("bfcvtn2 {c:v}.8h, {a:v}.4s",c=inout(vreg)c,a=in(vreg)a,options(nostack,preserves_flags));
                }
            } else {
                unsafe {
                    asm!("bfcvtn {c:v}.4h, {a:v}.4s",c=out(vreg)c,a=in(vreg)a,options(nostack,preserves_flags));
                }
            }
        }
        B::Dot => {
            if wide {
                unsafe {
                    asm!("bfdot {c:v}.4s, {a:v}.8h, {b:v}.8h",c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));
                }
            } else {
                unsafe {
                    asm!("bfdot {c:v}.2s, {a:v}.4h, {b:v}.4h",c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));
                }
            }
        }
        B::Matrix => unsafe {
            asm!("bfmmla {c:v}.4s, {a:v}.8h, {b:v}.8h",c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));
        },
        B::MultiplyLong => {
            if wide {
                unsafe {
                    asm!("bfmlalt {c:v}.4s, {a:v}.8h, {b:v}.8h",c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));
                }
            } else {
                unsafe {
                    asm!("bfmlalb {c:v}.4s, {a:v}.8h, {b:v}.8h",c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));
                }
            }
        }
    }
    unsafe { std::mem::transmute::<uint8x16_t, u128>(c) }
}

pub(super) fn multiply_long(
    wide: bool,
    upper: bool,
    subtract: bool,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    if !std::arch::is_aarch64_feature_detected!("fhm") {
        return None;
    }
    Some(unsafe { native_multiply_long(wide, upper, subtract, a, b, c) })
}
#[target_feature(enable = "fhm")]
unsafe fn native_multiply_long(
    wide: bool,
    upper: bool,
    subtract: bool,
    a: u128,
    b: u128,
    c: u128,
) -> u128 {
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    let b: uint8x16_t = unsafe { std::mem::transmute(b) };
    let mut c: uint8x16_t = unsafe { std::mem::transmute(c) };
    macro_rules! compute{($i:literal,$dst:literal,$src:literal)=>{unsafe{asm!(concat!($i," {c:v}.",$dst,", {a:v}.",$src,", {b:v}.",$src),c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));}};}
    match (wide, upper, subtract) {
        (false, false, false) => compute!("fmlal", "2s", "2h"),
        (true, false, false) => compute!("fmlal", "4s", "4h"),
        (false, true, false) => compute!("fmlal2", "2s", "2h"),
        (true, true, false) => compute!("fmlal2", "4s", "4h"),
        (false, false, true) => compute!("fmlsl", "2s", "2h"),
        (true, false, true) => compute!("fmlsl", "4s", "4h"),
        (false, true, true) => compute!("fmlsl2", "2s", "2h"),
        (true, true, true) => compute!("fmlsl2", "4s", "4h"),
    }
    unsafe { std::mem::transmute::<uint8x16_t, u128>(c) }
}

pub(super) fn complex(
    bits: u32,
    wide: bool,
    multiply: bool,
    rotation: u32,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    if !std::arch::is_aarch64_feature_detected!("fcma")
        || bits == 16 && !std::arch::is_aarch64_feature_detected!("fp16")
    {
        return None;
    }
    unsafe { native_complex(bits, wide, multiply, rotation, a, b, c) }
}
#[target_feature(enable = "fcma,fp16")]
unsafe fn native_complex(
    bits: u32,
    wide: bool,
    multiply: bool,
    rotation: u32,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    let a: uint8x16_t = unsafe { std::mem::transmute(a) };
    let b: uint8x16_t = unsafe { std::mem::transmute(b) };
    let mut c: uint8x16_t = unsafe { std::mem::transmute(c) };
    macro_rules! compute{($arr:literal)=>{{
        if multiply{
            macro_rules! fma{($angle:literal)=>{unsafe{asm!(concat!("fcmla {c:v}.",$arr,", {a:v}.",$arr,", {b:v}.",$arr,", #",$angle),c=inout(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));}};}
            match rotation{0=>fma!("0"),1=>fma!("90"),2=>fma!("180"),3=>fma!("270"),_=>return None,}
        }else{
            match rotation{
                1=>unsafe{asm!(concat!("fcadd {c:v}.",$arr,", {a:v}.",$arr,", {b:v}.",$arr,", #90"),c=out(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));},
                3=>unsafe{asm!(concat!("fcadd {c:v}.",$arr,", {a:v}.",$arr,", {b:v}.",$arr,", #270"),c=out(vreg)c,a=in(vreg)a,b=in(vreg)b,options(nostack,preserves_flags));},
                _=>return None,
            }
        }
    }};}
    match (bits, wide) {
        (16, false) => compute!("4h"),
        (16, true) => compute!("8h"),
        (32, false) => compute!("2s"),
        (32, true) => compute!("4s"),
        (64, true) => compute!("2d"),
        _ => return None,
    }
    Some(unsafe { std::mem::transmute::<uint8x16_t, u128>(c) })
}
