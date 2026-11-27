// SPDX-License-Identifier: GPL-3.0-or-later
//! Statically compiled host arithmetic. This is a compute helper, not an
//! execution backend. No guest pointers, executable allocations or code emission.
use std::{marker::PhantomData, rc::Rc};

#[derive(Clone, Copy, Debug)]
pub enum FloatOp {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
    Fma,
    ReciprocalStep,
    ReciprocalSqrtStep,
    Min,
    Max,
    MinNumber,
    MaxNumber,
    MultiplyExtended,
    NegatedMul,
    Abs,
    Neg,
    ReciprocalEstimate,
    ReciprocalSqrtEstimate,
}
#[derive(Clone, Copy, Debug)]
pub enum VectorFloatOp {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
    MultiplyAdd,
    MultiplySub,
    ReciprocalStep,
    ReciprocalSqrtStep,
    Min,
    Max,
    MinNumber,
    MaxNumber,
    MultiplyExtended,
    AbsoluteDifference,
    Equal,
    Greater,
    GreaterEqual,
    AbsoluteGreater,
    AbsoluteGreaterEqual,
    PairAdd,
    PairMin,
    PairMax,
    PairMinNumber,
    PairMaxNumber,
    Abs,
    Neg,
    ReciprocalEstimate,
    ReciprocalSqrtEstimate,
    RoundNearest,
    RoundPositive,
    RoundNegative,
    RoundZero,
    RoundAway,
    RoundCurrent,
    RoundExact,
    SignedToFloat,
    UnsignedToFloat,
    FloatToSignedZero,
    FloatToUnsignedZero,
    FloatToSignedNearest,
    FloatToUnsignedNearest,
    FloatToSignedPositive,
    FloatToUnsignedPositive,
    FloatToSignedNegative,
    FloatToUnsignedNegative,
    FloatToSignedAway,
    FloatToUnsignedAway,
}

#[derive(Clone, Copy, Debug)]
pub enum IntegerOp {
    Add,
    Sub,
    PairAdd,
    Equal,
    Test,
    SignedGreater,
    SignedGreaterEqual,
    UnsignedGreater,
    UnsignedGreaterEqual,
    Mul,
    MultiplyAdd,
    MultiplySub,
    SignedMax,
    SignedMin,
    UnsignedMax,
    UnsignedMin,
    SignedHalvingAdd,
    UnsignedHalvingAdd,
    SignedHalvingSub,
    UnsignedHalvingSub,
    SignedRoundingHalvingAdd,
    UnsignedRoundingHalvingAdd,
    SignedSaturatingAdd,
    UnsignedSaturatingAdd,
    SignedSaturatingSub,
    UnsignedSaturatingSub,
    SignedAbsoluteDifference,
    UnsignedAbsoluteDifference,
    SignedAbsoluteDifferenceAccumulate,
    UnsignedAbsoluteDifferenceAccumulate,
    SignedShift,
    UnsignedShift,
    SignedRoundingShift,
    UnsignedRoundingShift,
    SignedSaturatingShift,
    UnsignedSaturatingShift,
    SignedRoundingSaturatingShift,
    UnsignedRoundingSaturatingShift,
    SaturatingMultiplyHigh,
    RoundingSaturatingMultiplyHigh,
    Abs,
    Neg,
    SaturatingAbs,
    SaturatingNeg,
    LeadingZeros,
    LeadingSign,
    Popcount,
    ReverseBits,
    Not,
    And,
    Or,
    Xor,
    BitClear,
    OrNot,
    Select,
    InsertIfTrue,
    InsertIfFalse,
}

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "aarch64")]
use arm as host;
#[cfg(target_arch = "x86_64")]
use x86 as host;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!(
    "Trames runs ARM64 guests; native compute supports ARM64 devices and x86_64 test hosts"
);

/// A thread-local floating-point scope. It restores the caller's control and
/// status on normal return, error and unwinding, and cannot cross threads.
pub struct Scope {
    saved: (u64, u64),
    _thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub fn new(control: u32, status: u32) -> Self {
        let saved = host::save();
        set_control(control);
        set_status(status);
        Self {
            saved,
            _thread: PhantomData,
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        host::restore(self.saved);
    }
}
pub fn set_control(value: u32) {
    host::control(value);
}
pub fn set_status(value: u32) {
    host::set_status(value);
}
pub fn status() -> u32 {
    host::status()
}
#[inline]
pub fn scalar(bits: u32, op: FloatOp, a: u64, b: u64, c: u64) -> Option<u64> {
    host::scalar(bits, op, a, b, c)
}
#[inline]
pub fn vector_float(
    bits: u32,
    wide: bool,
    op: VectorFloatOp,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    host::vector_float(bits, wide, op, a, b, c)
}

#[inline]
pub fn vector_integer(
    bits: u32,
    wide: bool,
    op: IntegerOp,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    host::vector_integer(bits, wide, op, a, b, c)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_scopes_keep_each_threads_status_and_rounding() {
        let gate = std::sync::Arc::new(std::sync::Barrier::new(4));
        let workers: Vec<_> = (0..4)
            .map(|index| {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    let before = host::save();
                    for _ in 0..100 {
                        {
                            let _scope =
                                Scope::new(index << 22, if index % 2 == 0 { 0 } else { 2 });
                            let own = host::save();
                            gate.wait();
                            assert_eq!(host::save(), own);
                            assert_eq!(status() & 2, if index % 2 == 0 { 0 } else { 2 });
                            let value = scalar(64, FloatOp::Add, 2f64.to_bits(), 3f64.to_bits(), 0)
                                .unwrap();
                            assert_eq!(value, 5f64.to_bits());
                            gate.wait();
                        }
                        assert_eq!(host::save(), before);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn scope_restores_control_and_status_on_unwind() {
        let before = host::save();
        {
            let _caller = Scope::new(2 << 22, 2);
            let caller = host::save();
            let result = std::panic::catch_unwind(|| {
                let _guest = Scope::new(1 << 22, 0);
                scalar(64, FloatOp::Div, 1.0f64.to_bits(), 0, 0).unwrap();
                assert_ne!(status() & 2, 0);
                panic!("exercise scope cleanup");
            });
            assert!(result.is_err());
            assert_eq!(host::save(), caller);
            // Updating rounding must preserve the sticky exception flags.
            set_control(0);
            assert_eq!(status() & 2, 2);
            set_status(0);
            assert_eq!(status() & 0x9f, 0);
        }
        assert_eq!(host::save(), before);
    }

    #[test]
    fn scalar_and_packed_arithmetic_are_native() {
        let _scope = Scope::new(0, 0);
        for (op, expected) in [
            (FloatOp::Add, 6.0),
            (FloatOp::Sub, 2.0),
            (FloatOp::Mul, 8.0),
            (FloatOp::Div, 2.0),
            (FloatOp::Sqrt, 2.0),
            (FloatOp::Fma, 9.0),
        ] {
            let output = scalar(
                32,
                op,
                4.0f32.to_bits() as u64,
                2.0f32.to_bits() as u64,
                1.0f32.to_bits() as u64,
            )
            .unwrap();
            assert_eq!(f32::from_bits(output as u32), expected as f32);
            let output =
                scalar(64, op, 4.0f64.to_bits(), 2.0f64.to_bits(), 1.0f64.to_bits()).unwrap();
            assert_eq!(f64::from_bits(output), expected);
        }
        let packed = |v: [f32; 4]| {
            v.into_iter()
                .enumerate()
                .fold(0, |out, (i, x)| out | (x.to_bits() as u128) << (32 * i))
        };
        let a = packed([4.0, 9.0, f32::NAN, f32::INFINITY]);
        let b = packed([2.0, 3.0, 0.0, 0.0]);
        set_status(0);
        assert_eq!(
            vector_float(32, false, VectorFloatOp::Div, a, b, 0).unwrap(),
            packed([2.0, 3.0, 0.0, 0.0])
        );
        assert_eq!(status() & 3, 0, "inactive lanes may not set exceptions");
        assert_eq!(
            vector_float(
                64,
                true,
                VectorFloatOp::MultiplySub,
                4.0f64.to_bits() as u128 | (2.0f64.to_bits() as u128) << 64,
                2.0f64.to_bits() as u128 | (3.0f64.to_bits() as u128) << 64,
                9.0f64.to_bits() as u128 | (7.0f64.to_bits() as u128) << 64
            )
            .unwrap(),
            1.0f64.to_bits() as u128 | (1.0f64.to_bits() as u128) << 64
        );
    }

    #[test]
    fn fp16_bit_carriers_and_refinement_special_values() {
        let _scope = Scope::new(0, 0);
        if let Some(value) = scalar(16, FloatOp::Fma, 0x4400, 0x4000, 0x3c00) {
            assert_eq!(value, 0x4880); // 4 * 2 + 1 = 9
            let a = 0x4400_4400_4400_4400u128;
            let b = 0x4000_4000_4000_4000u128;
            assert_eq!(
                vector_float(16, false, VectorFloatOp::Div, a, b, 0).unwrap(),
                b
            );
        }
        for bits in [32, 64] {
            let inf = if bits == 32 {
                f32::INFINITY.to_bits() as u64
            } else {
                f64::INFINITY.to_bits()
            };
            set_status(0);
            let output = scalar(bits, FloatOp::ReciprocalSqrtStep, inf, 0, 0).unwrap();
            let expected = if bits == 32 {
                1.5f32.to_bits() as u64
            } else {
                1.5f64.to_bits()
            };
            assert_eq!(output, expected);
            assert_eq!(status() & 1, 0);
            let (a, b) = if bits == 32 {
                (2.0f32.to_bits() as u64, 0.5f32.to_bits() as u64)
            } else {
                (2.0f64.to_bits(), 0.5f64.to_bits())
            };
            let expected = if bits == 32 {
                1.0f32.to_bits() as u64
            } else {
                1.0f64.to_bits()
            };
            assert_eq!(
                scalar(bits, FloatOp::ReciprocalSqrtStep, a, b, 0).unwrap(),
                expected
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CryptoOp {
    AesEncrypt,
    AesDecrypt,
    AesMix,
    AesInverseMix,
    Sha1Hash,
    Sha1Choose,
    Sha1Parity,
    Sha1Majority,
    Sha1Schedule0,
    Sha1Schedule1,
    Sha256Hash,
    Sha256Hash2,
    Sha256Schedule0,
    Sha256Schedule1,
}
#[inline]
pub fn crypto(op: CryptoOp, d: u128, n: u128, m: u128) -> Option<u128> {
    host::crypto(op, d, n, m)
}

#[inline]
pub fn polynomial_product(bits: u32, a: u64, b: u64) -> Option<u128> {
    host::polynomial_product(bits, a, b)
}

#[inline]
pub fn convert(from: u32, to: u32, value: u64) -> Option<u64> {
    host::convert(from, to, value)
}

#[inline]
pub fn convert_odd(value: u64) -> Option<u32> {
    host::convert_odd(value)
}

#[inline]
pub fn crc(bytes: u32, castagnoli: bool, checksum: u32, data: u64) -> Option<u32> {
    host::crc(bytes, castagnoli, checksum, data)
}

#[derive(Clone, Copy, Debug)]
pub enum ExtendedCryptoOp {
    Sha512Hash,
    Sha512Hash2,
    Sha512Schedule0,
    Sha512Schedule1,
    Eor3,
    Bcax,
    Rax1,
    Xar,
    Sm3Ss1,
    Sm3Tt1A,
    Sm3Tt1B,
    Sm3Tt2A,
    Sm3Tt2B,
    Sm3Schedule1,
    Sm3Schedule2,
    Sm4Encrypt,
    Sm4Schedule,
}
#[inline]
pub fn crypto_extended(
    op: ExtendedCryptoOp,
    d: u128,
    n: u128,
    m: u128,
    a: u128,
    immediate: u32,
) -> Option<u128> {
    host::crypto_extended(op, d, n, m, a, immediate)
}

#[derive(Clone, Copy, Debug)]
pub enum BFloatOp {
    ConvertScalar,
    ConvertVector,
    Dot,
    Matrix,
    MultiplyLong,
}
#[inline]
pub fn bfloat(op: BFloatOp, wide: bool, a: u128, b: u128, c: u128) -> Option<u128> {
    host::bfloat(op, wide, a, b, c)
}
#[inline]
pub fn multiply_long(
    wide: bool,
    upper: bool,
    subtract: bool,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    host::multiply_long(wide, upper, subtract, a, b, c)
}
#[inline]
pub fn complex(
    bits: u32,
    wide: bool,
    multiply: bool,
    rotation: u32,
    a: u128,
    b: u128,
    c: u128,
) -> Option<u128> {
    host::complex(bits, wide, multiply, rotation, a, b, c)
}
