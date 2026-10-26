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
