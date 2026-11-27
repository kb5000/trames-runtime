// SPDX-License-Identifier: GPL-3.0-or-later
//! NZCV is architectural state, but its four bits need not be computed together.
use super::{Cpu, Flags};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    #[default]
    Known,
    Add32,
    Add64,
    Sub32,
    Sub64,
}

#[derive(Default, Clone, Copy, Debug)]
pub(super) struct ConditionFlags {
    left: u64,
    right: u64,
    kind: Kind,
    // N/Z are cheap result predicates and dominate conditional branches. Keep
    // them directly readable; defer C/V rather than adding a mode dispatch to
    // every EQ/NE/MI/PL. Operands are width-masked at the producer.
    n: bool,
    z: bool,
}

impl ConditionFlags {
    #[inline]
    pub(super) fn set(&mut self, value: u32) {
        self.left = (value & 15) as u64;
        self.kind = Kind::Known;
        self.n = value & 8 != 0;
        self.z = value & 4 != 0;
    }

    #[inline(always)]
    pub(super) fn arithmetic(&mut self, a: u64, b: u64, result: u64, sub: bool, wide: bool) {
        self.left = a;
        self.right = b;
        self.kind = match (sub, wide) {
            (false, false) => Kind::Add32,
            (false, true) => Kind::Add64,
            (true, false) => Kind::Sub32,
            (true, true) => Kind::Sub64,
        };
        self.n = result & (1 << if wide { 63 } else { 31 }) != 0;
        self.z = result == 0;
    }

    #[inline(always)]
    pub(super) fn calculate(
        &mut self,
        a: u64,
        b: u64,
        sub: bool,
        set_flags: bool,
        wide: bool,
    ) -> u64 {
        let mask = super::width_mask(wide);
        let a = a & mask;
        let b = b & mask;
        let result = if sub {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        } & mask;
        if set_flags {
            self.arithmetic(a, b, result, sub, wide);
        }
        result
    }

    #[inline(always)]
    pub(super) fn carry(&self) -> bool {
        match self.kind {
            Kind::Known => self.left & 2 != 0,
            Kind::Add32 => self.left + self.right > u32::MAX as u64,
            Kind::Add64 => self.left.wrapping_add(self.right) < self.left,
            Kind::Sub32 | Kind::Sub64 => self.left >= self.right,
        }
    }

    #[inline(always)]
    fn overflow(&self) -> bool {
        if self.kind == Kind::Known {
            return self.left & 1 != 0;
        }
        let sub = matches!(self.kind, Kind::Sub32 | Kind::Sub64);
        let wide = matches!(self.kind, Kind::Add64 | Kind::Sub64);
        let result = if sub {
            self.left.wrapping_sub(self.right)
        } else {
            self.left.wrapping_add(self.right)
        };
        let different = self.left ^ self.right;
        let signs = if sub { different } else { !different };
        signs & (self.left ^ result) & (1 << if wide { 63 } else { 31 }) != 0
    }

    #[inline(always)]
    fn signed_ge(&self) -> bool {
        match self.kind {
            Kind::Sub32 => (self.left as u32 as i32) >= (self.right as u32 as i32),
            Kind::Sub64 => (self.left as i64) >= (self.right as i64),
            _ => self.n == self.overflow(),
        }
    }

    #[inline(always)]
    pub(super) fn condition(&self, condition: u32) -> bool {
        let basic = match condition >> 1 {
            0 => self.z,
            1 => self.carry(),
            2 => self.n,
            3 => self.overflow(),
            4 => self.carry() && !self.z,
            5 => self.signed_ge(),
            6 => !self.z && self.signed_ge(),
            7 => return true, // AL and NV inspect no flags.
            _ => unreachable!(),
        };
        basic ^ (condition & 1 != 0)
    }

    fn bits(&self) -> u32 {
        (self.n as u32) << 3
            | (self.z as u32) << 2
            | (self.carry() as u32) << 1
            | self.overflow() as u32
    }
}

impl Cpu {
    /// Read all architectural flags, including deferred arithmetic. Observation
    /// does not discard the operands, so later branches can still compare them.
    pub fn flags(&self) -> Flags {
        let bits = self.nzcv();
        Flags {
            n: bits & 8 != 0,
            z: bits & 4 != 0,
            c: bits & 2 != 0,
            v: bits & 1 != 0,
        }
    }

    pub fn set_flags(&mut self, flags: Flags) {
        self.set_nzcv(
            (flags.n as u32) << 3 | (flags.z as u32) << 2 | (flags.c as u32) << 1 | flags.v as u32,
        );
    }

    /// Replace NZCV with the low four bits. Used by MSR, FP comparisons and
    /// signal restoration; a prior deferred arithmetic operation is discarded.
    #[inline]
    pub fn set_nzcv(&mut self, value: u32) {
        self.condition_flags.set(value);
    }

    pub fn nzcv(&self) -> u32 {
        self.condition_flags.bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conditions(f: Flags) -> [bool; 16] {
        [
            f.z,
            !f.z,
            f.c,
            !f.c,
            f.n,
            !f.n,
            f.v,
            !f.v,
            f.c && !f.z,
            !f.c || f.z,
            f.n == f.v,
            f.n != f.v,
            !f.z && f.n == f.v,
            f.z || f.n != f.v,
            true,
            true,
        ]
    }

    #[test]
    fn deferred_arithmetic_matches_widened_integer_oracle() {
        let edge = [
            0,
            1,
            2,
            0x7fffffff,
            0x80000000,
            0xffffffff,
            0x100000000,
            0x7fffffffffffffff,
            0x8000000000000000,
            u64::MAX,
        ];
        let mut pairs: Vec<_> = edge
            .iter()
            .flat_map(|&a| edge.iter().map(move |&b| (a, b)))
            .collect();
        let mut seed = 0x7fac8912eb390d61u64;
        for _ in 0..4096 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            pairs.push((seed, seed.rotate_left(29)));
        }
        let mut cpu = Cpu::default();
        for (raw_a, raw_b) in pairs {
            for wide in [false, true] {
                let bits = if wide { 64 } else { 32 };
                let mask = (1u128 << bits) - 1;
                let a = raw_a as u128 & mask;
                let b = raw_b as u128 & mask;
                let signed = |value: u128| {
                    if value & (1 << (bits - 1)) != 0 {
                        value as i128 - (1i128 << bits)
                    } else {
                        value as i128
                    }
                };
                for sub in [false, true] {
                    let mathematical = if sub {
                        signed(a) - signed(b)
                    } else {
                        signed(a) + signed(b)
                    };
                    let result = (mathematical as u128 & mask) as u64;
                    let expected = Flags {
                        n: result & (1 << (bits - 1)) != 0,
                        z: result == 0,
                        c: if sub { a >= b } else { a + b > mask },
                        v: !(-(1i128 << (bits - 1))..(1i128 << (bits - 1))).contains(&mathematical),
                    };
                    assert_eq!(cpu.arithmetic(raw_a, raw_b, sub, true, wide), result);
                    for (condition, expected) in conditions(expected).into_iter().enumerate() {
                        assert_eq!(
                            cpu.condition(condition as u32),
                            expected,
                            "{raw_a:x} {raw_b:x} sub={sub} wide={wide} condition={condition}"
                        );
                    }
                    assert_eq!(cpu.flags(), expected);
                    assert_eq!(cpu.condition_flags.carry(), expected.c);
                    // Register reuse and non-S ALU instructions must not change NZCV.
                    cpu.set_x(0, !raw_a);
                    cpu.arithmetic(raw_b, raw_a, !sub, false, !wide);
                    assert_eq!(cpu.flags(), expected);
                }
            }
        }
    }

    #[test]
    fn explicit_writes_replace_pending_state_and_clone_owns_operands() {
        let mut cpu = Cpu::default();
        for bits in 0..16 {
            cpu.arithmetic(1 << 63, 1, true, true, true);
            let saved = cpu.clone();
            cpu.set_nzcv(bits | 0xfffffff0);
            assert_eq!(cpu.nzcv(), bits);
            for (condition, expected) in conditions(cpu.flags()).into_iter().enumerate() {
                assert_eq!(cpu.condition(condition as u32), expected);
            }
            let migrated = std::thread::spawn(move || saved.nzcv()).join().unwrap();
            assert_eq!(migrated, 3); // INT64_MIN - 1: C=V=1, N=Z=0.
        }
    }
}
