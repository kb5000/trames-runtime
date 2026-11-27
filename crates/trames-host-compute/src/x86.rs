// SPDX-License-Identifier: GPL-3.0-or-later
use super::{FloatOp, VectorFloatOp};
use std::arch::asm;
use std::arch::x86_64::__m128i;

fn read() -> u32 {
    let mut value = 0u32;
    // SAFETY: the pointer refers to one live, aligned u32 local. It never
    // references guest memory. SSE2 is part of the x86_64 baseline.
    unsafe {
        asm!("stmxcsr [{p}]", p=in(reg) &mut value, options(nostack, preserves_flags));
    }
    value
}
fn write(value: u32) {
    unsafe {
        asm!("ldmxcsr [{p}]", p=in(reg) &value, options(nostack, preserves_flags));
    }
}
pub(super) fn save() -> (u64, u64) {
    (read() as u64, 0)
}
pub(super) fn restore(saved: (u64, u64)) {
    write(saved.0 as u32);
}
pub(super) fn control(value: u32) {
    let mode = (value >> 22) & 3;
    let rounding = ((mode & 1) << 1) | ((mode & 2) >> 1);
    let flush = if value & (1 << 24) != 0 {
        (1 << 15) | (1 << 6)
    } else {
        0
    };
    write((read() & 63) | 0x1f80 | rounding << 13 | flush);
}
pub(super) fn set_status(value: u32) {
    let flags = (value & 1) | ((value >> 6) & 2) | ((value & 14) << 1) | ((value & 16) << 1);
    write((read() & !63) | flags);
}
pub(super) fn status() -> u32 {
    let value = read();
    (value & 1) | ((value & 2) << 6) | ((value & 28) >> 1) | ((value & 32) >> 1)
}
pub(super) fn scalar(bits: u32, op: FloatOp, a: u64, b: u64, c: u64) -> Option<u64> {
    macro_rules! compute {
        ($ty:ty, $suffix:literal) => {{
            let mut left = <$ty>::from_bits(a as _);
            let right = <$ty>::from_bits(b as _);
            let addend = match op {
                FloatOp::ReciprocalStep => 2.0 as $ty,
                FloatOp::ReciprocalSqrtStep => 3.0 as $ty,
                _ => <$ty>::from_bits(c as _),
            };
            macro_rules! binary { ($instruction:literal) => {
                unsafe { asm!(concat!($instruction, $suffix, " {a}, {b}"), a=inout(xmm_reg) left,
                    b=in(xmm_reg) right, options(nostack, preserves_flags)); }
            }; }
            match op {
                FloatOp::Add => binary!("add"),
                FloatOp::Sub => binary!("sub"),
                FloatOp::Mul => binary!("mul"),
                FloatOp::Div => binary!("div"),
                FloatOp::Min | FloatOp::Max | FloatOp::MinNumber | FloatOp::MaxNumber | FloatOp::MultiplyExtended | FloatOp::NegatedMul | FloatOp::Abs | FloatOp::Neg | FloatOp::ReciprocalEstimate | FloatOp::ReciprocalSqrtEstimate => return None,
                FloatOp::Sqrt => unsafe { asm!(concat!("sqrt", $suffix, " {a}, {a}"), a=inout(xmm_reg) left, options(nostack, preserves_flags)); },
                FloatOp::Fma | FloatOp::ReciprocalStep | FloatOp::ReciprocalSqrtStep => {
                    if !std::arch::is_x86_feature_detected!("fma") { return None; }
                    if !matches!(op, FloatOp::Fma) {
                        if (left.is_infinite() && right == 0.0) || (right.is_infinite() && left == 0.0) {
                            return Some((if matches!(op, FloatOp::ReciprocalStep) { 2.0 as $ty } else { 1.5 as $ty }).to_bits() as u64);
                        }
                        left = -left;
                    }
                    // SAFETY: the hardware feature was checked before executing
                    // the statically compiled FMA instruction.
                    unsafe { asm!(concat!("vfmadd213", $suffix, " {a}, {b}, {c}"), a=inout(xmm_reg) left,
                        b=in(xmm_reg) right, c=in(xmm_reg) addend, options(nostack, preserves_flags)); }
                    if matches!(op, FloatOp::ReciprocalSqrtStep) {
                        let half = 0.5 as $ty;
                        unsafe { asm!(concat!("mul", $suffix, " {a}, {b}"), a=inout(xmm_reg) left,
                            b=in(xmm_reg) half, options(nostack, preserves_flags)); }
                    }
                }
            }
            Some(left.to_bits() as u64)
        }};
    }
    match bits {
        16 if std::arch::is_x86_feature_detected!("f16c") => unsafe { scalar_half(op, a, b, c) },
        32 => compute!(f32, "ss"),
        64 => compute!(f64, "sd"),
        _ => None,
    }
}

pub(super) fn vector_float(
    bits: u32,
    wide: bool,
    op: VectorFloatOp,
    mut a: u128,
    mut b: u128,
    mut c: u128,
) -> Option<u128> {
    if bits == 16 && std::arch::is_x86_feature_detected!("f16c") {
        return unsafe { vector_half(wide, op, a, b, c) };
    }
    if matches!(
        op,
        VectorFloatOp::ReciprocalStep | VectorFloatOp::ReciprocalSqrtStep
    ) {
        return None;
    }
    if !matches!((bits, wide), (32, false) | (32, true) | (64, true)) {
        return None;
    }
    if !wide {
        a &= u64::MAX as u128;
        b &= u64::MAX as u128;
        c &= u64::MAX as u128;
        if matches!(op, VectorFloatOp::Div) {
            // Inactive upper lanes must not cause a synthetic 0/0 exception.
            b |= (1.0f32.to_bits() as u128) << 64 | (1.0f32.to_bits() as u128) << 96;
        }
    }
    let a: __m128i = unsafe { std::mem::transmute(a) };
    let b: __m128i = unsafe { std::mem::transmute(b) };
    let c: __m128i = unsafe { std::mem::transmute(c) };
    macro_rules! compute { ($suffix:literal) => {{
        let mut result = a;
        macro_rules! binary { ($instruction:literal) => {
            unsafe { asm!(concat!($instruction, $suffix, " {a}, {b}"), a=inout(xmm_reg) result,
                b=in(xmm_reg) b, options(nostack, preserves_flags)); }
        }; }
        match op {
            VectorFloatOp::Add => binary!("add"), VectorFloatOp::Sub => binary!("sub"),
            VectorFloatOp::Mul => binary!("mul"), VectorFloatOp::Div => binary!("div"),
            VectorFloatOp::ReciprocalStep | VectorFloatOp::ReciprocalSqrtStep => unreachable!(),
            VectorFloatOp::Min | VectorFloatOp::Max | VectorFloatOp::MinNumber | VectorFloatOp::MaxNumber | VectorFloatOp::MultiplyExtended | VectorFloatOp::AbsoluteDifference | VectorFloatOp::Equal | VectorFloatOp::Greater | VectorFloatOp::GreaterEqual | VectorFloatOp::AbsoluteGreater | VectorFloatOp::AbsoluteGreaterEqual | VectorFloatOp::PairAdd | VectorFloatOp::PairMin | VectorFloatOp::PairMax | VectorFloatOp::PairMinNumber | VectorFloatOp::PairMaxNumber | VectorFloatOp::Abs | VectorFloatOp::Neg | VectorFloatOp::ReciprocalEstimate | VectorFloatOp::ReciprocalSqrtEstimate | VectorFloatOp::RoundNearest | VectorFloatOp::RoundPositive | VectorFloatOp::RoundNegative | VectorFloatOp::RoundZero | VectorFloatOp::RoundAway | VectorFloatOp::RoundCurrent | VectorFloatOp::RoundExact | VectorFloatOp::SignedToFloat | VectorFloatOp::UnsignedToFloat | VectorFloatOp::FloatToSignedZero | VectorFloatOp::FloatToUnsignedZero | VectorFloatOp::FloatToSignedNearest | VectorFloatOp::FloatToUnsignedNearest | VectorFloatOp::FloatToSignedPositive | VectorFloatOp::FloatToUnsignedPositive | VectorFloatOp::FloatToSignedNegative | VectorFloatOp::FloatToUnsignedNegative | VectorFloatOp::FloatToSignedAway | VectorFloatOp::FloatToUnsignedAway => return None,
            VectorFloatOp::Sqrt => unsafe { asm!(concat!("sqrt", $suffix, " {a}, {a}"),
                a=inout(xmm_reg) result, options(nostack, preserves_flags)); },
            VectorFloatOp::MultiplyAdd | VectorFloatOp::MultiplySub => {
                if !std::arch::is_x86_feature_detected!("fma") { return None; }
                result = c;
                match op {
                    VectorFloatOp::MultiplyAdd => unsafe { asm!(concat!("vfmadd231", $suffix, " {c}, {a}, {b}"), c=inout(xmm_reg) result, a=in(xmm_reg) a, b=in(xmm_reg) b, options(nostack, preserves_flags)); },
                    _ => unsafe { asm!(concat!("vfnmadd231", $suffix, " {c}, {a}, {b}"), c=inout(xmm_reg) result, a=in(xmm_reg) a, b=in(xmm_reg) b, options(nostack, preserves_flags)); },
                }
            }
        }
        let result: u128 = unsafe { std::mem::transmute(result) };
        Some(if wide { result } else { result & u64::MAX as u128 })
    }}; }
    if bits == 32 {
        compute!("ps")
    } else {
        compute!("pd")
    }
}

// CI hosts with F16C promote/round using hardware conversion, with native
// binary32 arithmetic between them. Device ARM64 executes actual FP16 instead.
#[target_feature(enable = "f16c")]
unsafe fn scalar_half(op: FloatOp, a: u64, b: u64, c: u64) -> Option<u64> {
    use std::arch::x86_64::{_mm_cvtph_ps, _mm_cvtps_ph};
    let promote = |raw: u64| {
        let value: __m128i = unsafe { std::mem::transmute(raw as u16 as u128) };
        let value = _mm_cvtph_ps(value);
        let raw: [u32; 4] = unsafe { std::mem::transmute(value) };
        raw[0] as u64
    };
    let result = scalar(32, op, promote(a), promote(b), promote(c))?;
    let value = unsafe { std::mem::transmute::<u128, std::arch::x86_64::__m128>(result as u128) };
    let value = _mm_cvtps_ph::<4>(value);
    let raw: u128 = unsafe { std::mem::transmute(value) };
    Some((raw & 0xffff) as u64)
}

#[target_feature(enable = "f16c")]
unsafe fn vector_half(wide: bool, op: VectorFloatOp, a: u128, b: u128, c: u128) -> Option<u128> {
    use std::arch::x86_64::{_mm_cvtph_ps, _mm_cvtps_ph};
    let mut result = 0;
    for offset in [0, 64].into_iter().take(if wide { 2 } else { 1 }) {
        let promote = |raw: u128| {
            let value =
                unsafe { std::mem::transmute::<u128, __m128i>((raw >> offset) & u64::MAX as u128) };
            unsafe { std::mem::transmute::<std::arch::x86_64::__m128, u128>(_mm_cvtph_ps(value)) }
        };
        let value = vector_float(32, true, op, promote(a), promote(b), promote(c))?;
        let value = unsafe { std::mem::transmute::<u128, std::arch::x86_64::__m128>(value) };
        let value = _mm_cvtps_ph::<4>(value);
        let raw: u128 = unsafe { std::mem::transmute(value) };
        result |= (raw & u64::MAX as u128) << offset;
    }
    Some(result)
}

pub(super) fn vector_integer(
    bits: u32,
    wide: bool,
    op: super::IntegerOp,
    a: u128,
    b: u128,
    _: u128,
) -> Option<u128> {
    use super::IntegerOp as I;
    let mut a: __m128i = unsafe { std::mem::transmute(a) };
    let b: __m128i = unsafe { std::mem::transmute(b) };
    macro_rules! compute { ($i:expr) => {
        unsafe { asm!(concat!($i, " {a}, {b}"), a=inout(xmm_reg) a, b=in(xmm_reg) b,
            options(nostack, preserves_flags)); }
    }; }
    macro_rules! lanes {
        ($i:literal) => {
            match bits {
                8 => compute!(concat!($i, "b")),
                16 => compute!(concat!($i, "w")),
                32 => compute!(concat!($i, "d")),
                64 => compute!(concat!($i, "q")),
                _ => return None,
            }
        };
    }
    match op {
        I::Add => lanes!("padd"),
        I::Sub => lanes!("psub"),
        I::And => compute!("pand"),
        I::Or => compute!("por"),
        I::Xor => compute!("pxor"),
        I::Equal => match bits {
            8 => compute!("pcmpeqb"),
            16 => compute!("pcmpeqw"),
            32 => compute!("pcmpeqd"),
            64 if std::arch::is_x86_feature_detected!("sse4.1") => compute!("pcmpeqq"),
            _ => return None,
        },
        I::Mul => match bits {
            16 => compute!("pmullw"),
            32 if std::arch::is_x86_feature_detected!("sse4.1") => compute!("pmulld"),
            _ => return None,
        },
        _ => return None,
    }
    let value: u128 = unsafe { std::mem::transmute(a) };
    Some(if wide {
        value
    } else {
        value & u64::MAX as u128
    })
}

pub(super) fn crypto(op: super::CryptoOp, d: u128, n: u128, _: u128) -> Option<u128> {
    use super::CryptoOp as C;
    if !std::arch::is_x86_feature_detected!("aes") {
        return None;
    }
    let mut result: __m128i = unsafe { std::mem::transmute(n) };
    let zero: __m128i = unsafe { std::mem::transmute(0u128) };
    match op {
        C::AesEncrypt | C::AesDecrypt => {
            result = unsafe { std::mem::transmute::<u128, __m128i>(d ^ n) };
            if matches!(op, C::AesEncrypt) {
                unsafe {
                    asm!("aesenclast {d}, {z}", d=inout(xmm_reg) result, z=in(xmm_reg) zero, options(nostack, preserves_flags));
                }
            } else {
                unsafe {
                    asm!("aesdeclast {d}, {z}", d=inout(xmm_reg) result, z=in(xmm_reg) zero, options(nostack, preserves_flags));
                }
            }
        }
        C::AesMix => unsafe {
            asm!("aesdeclast {d}, {z}", "aesenc {d}, {z}", d=inout(xmm_reg) result, z=in(xmm_reg) zero, options(nostack, preserves_flags));
        },
        C::AesInverseMix => unsafe {
            asm!("aesimc {d}, {d}", d=inout(xmm_reg) result, options(nostack, preserves_flags));
        },
        _ => return None,
    }
    Some(unsafe { std::mem::transmute::<__m128i, u128>(result) })
}

pub(super) fn polynomial_product(bits: u32, a: u64, b: u64) -> Option<u128> {
    if bits != 64 || !std::arch::is_x86_feature_detected!("pclmulqdq") {
        return None;
    }
    let mut a: __m128i = unsafe { std::mem::transmute(a as u128) };
    let b: __m128i = unsafe { std::mem::transmute(b as u128) };
    unsafe {
        asm!("pclmulqdq {a}, {b}, 0", a=inout(xmm_reg) a, b=in(xmm_reg) b, options(nostack, preserves_flags));
    }
    Some(unsafe { std::mem::transmute::<__m128i, u128>(a) })
}

pub(super) fn convert(from: u32, to: u32, value: u64) -> Option<u64> {
    match (from, to) {
        (32, 64) => {
            let a = f32::from_bits(value as u32);
            let result: f64;
            unsafe {
                asm!("cvtss2sd {d}, {a}", d=out(xmm_reg) result, a=in(xmm_reg) a, options(nostack, preserves_flags));
            }
            Some(result.to_bits())
        }
        (64, 32) => {
            let a = f64::from_bits(value);
            let result: f32;
            unsafe {
                asm!("cvtsd2ss {d}, {a}", d=out(xmm_reg) result, a=in(xmm_reg) a, options(nostack, preserves_flags));
            }
            Some(result.to_bits() as u64)
        }
        // Alternative half and the various conversion flush rules stay with
        // the format fallback on CI; ARM64 uses the actual FCVT instruction.
        _ => None,
    }
}

pub(super) fn convert_odd(_: u64) -> Option<u32> {
    None
}

pub(super) fn crc(bytes: u32, castagnoli: bool, checksum: u32, data: u64) -> Option<u32> {
    if !castagnoli || !std::arch::is_x86_feature_detected!("sse4.2") {
        return None;
    }
    let mut result = checksum as u64;
    match bytes {
        1 => unsafe {
            asm!("crc32 {c:e}, {d}", c=inout(reg) result, d=in(reg_byte) data as u8, options(nostack, preserves_flags));
        },
        2 => unsafe {
            asm!("crc32 {c:e}, {d:x}", c=inout(reg) result, d=in(reg) data, options(nostack, preserves_flags));
        },
        4 => unsafe {
            asm!("crc32 {c:e}, {d:e}", c=inout(reg) result, d=in(reg) data, options(nostack, preserves_flags));
        },
        8 => unsafe {
            asm!("crc32 {c}, {d}", c=inout(reg) result, d=in(reg) data, options(nostack, preserves_flags));
        },
        _ => return None,
    }
    Some(result as u32)
}

pub(super) fn crypto_extended(
    _: super::ExtendedCryptoOp,
    _: u128,
    _: u128,
    _: u128,
    _: u128,
    _: u32,
) -> Option<u128> {
    None
}

pub(super) fn bfloat(_: super::BFloatOp, _: bool, _: u128, _: u128, _: u128) -> Option<u128> {
    None
}
pub(super) fn multiply_long(_: bool, _: bool, _: bool, _: u128, _: u128, _: u128) -> Option<u128> {
    None
}
pub(super) fn complex(_: u32, _: bool, _: bool, _: u32, _: u128, _: u128, _: u128) -> Option<u128> {
    None
}
