// SPDX-License-Identifier: GPL-3.0-or-later
//! Architectural state at kernel/executor boundaries; no decoder or host VM.
#![no_std]

/// The Linux syscall ABI needs registers, not an interpreter or its caches.
/// Calls are statically dispatched and add no work to ordinary guest accesses.
pub trait Registers {
    fn x(&self, index: usize) -> u64;
    fn set_x(&mut self, index: usize, value: u64);
    fn pc(&self) -> u64;
}

/// AArch64 EL0 state shared by execution engines, signals and checkpoints.
/// NZCV uses the architectural PSTATE bit positions, not a decoder's encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Aarch64State {
    pub registers: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u32,
    pub tpidr_el0: u64,
    pub tpidr2_el0: u64,
    pub fpcr: u32,
    pub fpsr: u32,
    pub vectors: [u128; 32],
}
impl Registers for Aarch64State {
    #[inline]
    fn x(&self, index: usize) -> u64 {
        if index == 31 {
            0
        } else {
            self.registers[index]
        }
    }
    #[inline]
    fn set_x(&mut self, index: usize, value: u64) {
        if index != 31 {
            self.registers[index] = value;
        }
    }
    #[inline]
    fn pc(&self) -> u64 {
        self.pc
    }
}

/// Conservative minimum signal stack for this bounded 512-bit SME ABI profile.
pub const SME_SIGNAL_STACK_MIN: u64 = 8192;

/// Optional streaming context. The baseline Aarch64State ABI stays 816 bytes.
/// Registers are packed at the configured VL within fixed-capacity arrays;
/// only engines advertising SME allocate this state, and only after use.
/// This profile supports streaming vectors through 512 bits, without FA64.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SmeState {
    pub vl: u64,
    pub svcr: u64,
    pub z: [u8; 2048],
    pub p: [u8; 128],
    pub za: [u8; 4096],
    pub zt: [u8; 64],
}
impl Default for SmeState {
    fn default() -> Self {
        Self {
            vl: 64,
            svcr: 0,
            z: [0; 2048],
            p: [0; 128],
            za: [0; 4096],
            zt: [0; 64],
        }
    }
}
impl SmeState {
    pub fn valid(&self) -> bool {
        matches!(self.vl, 16 | 32 | 64) && self.svcr & !3 == 0
    }
    /// Linux preserves ZA/ZT across SVC, clears streaming mode, and defines
    /// only the low 128 vector bits on return (held in Aarch64State).
    pub fn syscall(&mut self) {
        self.svcr &= !1;
    }
}

/// Linux's per-thread streaming vector-length policy, separate from registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmeConfig {
    pub vl: u16,
    pub inherit: bool,
    pub on_exec: Option<u16>,
}
impl Default for SmeConfig {
    fn default() -> Self {
        Self {
            vl: 64,
            inherit: false,
            on_exec: None,
        }
    }
}
impl SmeConfig {
    pub fn get(self) -> u64 {
        self.vl as u64 | (u64::from(self.inherit) << 17)
    }
    pub fn set(&mut self, arg: u64, supported: &[u16]) -> Option<u64> {
        let requested = arg & 0xffff;
        if arg & !(0xffff | 1 << 17 | 1 << 18) != 0
            || requested == 0
            || requested > 8192
            || requested % 16 != 0
        {
            return None;
        }
        let minimum = supported.iter().copied().min()?;
        let vl = supported
            .iter()
            .copied()
            .filter(|&vl| vl as u64 <= requested)
            .max()
            .unwrap_or(minimum);
        self.inherit = arg & (1 << 17) != 0;
        self.on_exec = (arg & (1 << 18) != 0).then_some(vl);
        if self.on_exec.is_none() {
            self.vl = vl;
        }
        Some(vl as u64 | (u64::from(self.inherit) << 17))
    }
    pub fn exec(self) -> Self {
        Self {
            vl: self
                .on_exec
                .unwrap_or(if self.inherit { self.vl } else { 64 }),
            inherit: self.inherit,
            on_exec: if self.inherit { self.on_exec } else { None },
        }
    }
}

/// An executor must advertise its actual guest features. Hardware backends may
/// not inherit the interpreter's emulated instruction set in ELF auxv/procfs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    pub hwcap: u64,
    pub hwcap2: u64,
}

/// Hardware execution cannot promise an exact software instruction budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionCount {
    Exact(u64),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    Syscall,
    Yield,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionExit {
    pub reason: ExitReason,
    pub instructions: InstructionCount,
}

#[cfg(test)]
mod sme_tests {
    use super::*;
    #[test]
    fn sme_keeps_the_base_abi_and_rounds_only_to_supported_lengths() {
        assert_eq!(core::mem::size_of::<Aarch64State>(), 816);
        assert_eq!(core::mem::size_of::<SmeState>(), 6352);
        let mut c = SmeConfig::default();
        for requested in [16, 32, 48, 64, 80, 256, 8192] {
            assert_eq!(c.set(requested, &[64]), Some(64));
        }
        for bad in [0, 15, 65, 8208, 64 | (1 << 16), 64 | (1 << 19)] {
            let old = c;
            assert_eq!(c.set(bad, &[64]), None);
            assert_eq!(c, old);
        }
        assert_eq!(c.set(48, &[16, 32, 64]), Some(32));
    }
    #[test]
    fn sme_exec_deferred_length_and_inherit_are_per_thread() {
        let mut c = SmeConfig::default();
        assert_eq!(c.set(32 | (1 << 18), &[16, 32, 64]), Some(32));
        assert_eq!(c.get(), 64);
        assert_eq!(
            c.exec(),
            SmeConfig {
                vl: 32,
                inherit: false,
                on_exec: None
            }
        );
        assert_eq!(c.exec().exec().vl, 64);
        assert_eq!(
            c.set(16 | (1 << 17) | (1 << 18), &[16, 32, 64]),
            Some(16 | (1 << 17))
        );
        assert_eq!(c.get(), 64 | (1 << 17));
        assert_eq!(c.exec().exec().vl, 16);
        assert_eq!(c.set(64, &[64]), Some(64));
        assert_eq!(c.on_exec, None);
    }
}
