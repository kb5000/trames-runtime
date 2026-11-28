// SPDX-License-Identifier: GPL-3.0-or-later
// Pinned in rust-toolchain.toml: compiler-enforced, bounded-stack dispatch.
#![feature(explicit_tail_calls, rust_preserve_none_cc)]
#![allow(incomplete_features)]
//! AArch64 virtual CPU with a single bounded cached interpreter.
use trames_execution::{Aarch64State, Registers};
use trames_memory::CpuMemory;
/// Capabilities of the virtual CPU, independent of the host.
macro_rules! linux_features {
    (hwcap: $first:ident = $first_bit:literal $(, $name:ident = $bit:literal)*;
     hwcap2: $($name2:ident = $bit2:literal),+) => {
        pub const HWCAP: u64 = (1 << $first_bit) $(| (1 << $bit))*;
        pub const HWCAP2: u64 = 0 $(| (1 << $bit2))+;
        pub const FEATURE_NAMES: &str = concat!(
            stringify!($first) $(, " ", stringify!($name))* $(, " ", stringify!($name2))+
        );
    };
}
// Linux AArch64 ELF hwcap bit numbers. The aux vector and procfs must
// describe the same interpreter, independent of the machine running it.
linux_features! {
    hwcap: fp = 0, asimd = 1, aes = 3, pmull = 4, sha1 = 5, sha2 = 6,
    crc32 = 7, atomics = 8, fphp = 9, asimdhp = 10, asimdrdm = 12,
    jscvt = 13, fcma = 14, lrcpc = 15, sha3 = 17, sm3 = 18, sm4 = 19,
    asimddp = 20, sha512 = 21, asimdfhm = 23, ilrcpc = 26, flagm = 27, sb = 29;
    hwcap2: flagm2 = 7, frint = 8, i8mm = 13, bf16 = 14, dgh = 15,
    rng = 16, cssc = 34, mops = 43
}
mod cached;
mod compatibility;
pub mod counter;
mod crypto;
mod extended;
mod flags;
mod floating;
mod half_vector;
mod load_store;
mod modern_crypto;
mod modern_memory;
mod modern_scalar;
mod soft_float;
mod vector_extensions;
mod vector_extra_float;
mod vector_float;
mod vector_integer;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags {
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

pub use trames_engine::{CpuFault, DecodeStats, SliceOutcome};

/// Host-worker execution resources. Sleeping guest tasks keep architectural
/// state and counters, not a multi-megabyte decoded instruction working set.
/// The existing memory/page identities validate reuse across task/mm changes.
#[derive(Default, Debug)]
pub struct Engine {
    decoded: cached::Cache,
}

#[derive(Default, Clone, Debug)]
pub struct Cpu {
    native_calls: bool,
    vulkan_calls: bool,
    video_calls: bool,
    audio_calls: bool,
    registers: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    condition_flags: flags::ConditionFlags,
    pub tpidr_el0: u64,
    pub tpidr2_el0: u64,
    pub fpcr: u32,
    pub fpsr: u32,
    vectors: [u128; 32],
    exclusive: Reservation,
    decoded: cached::Cache,
    yield_current: bool,
    fault_retired: u64,
}

/// The existing guest reservation, with an explicit inactive-width sentinel so
/// native CLREX can clear it without depending on Rust Option's layout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Reservation {
    address: u64,
    size: u64,
    token: u128,
}
impl Reservation {
    fn get(self) -> Option<(u64, usize, u128)> {
        (self.size != 0).then_some((self.address, self.size as usize, self.token))
    }
    fn take(&mut self) -> Option<(u64, usize, u128)> {
        let value = self.get();
        self.size = 0;
        value
    }
}
impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}
impl PartialEq for Reservation {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}
impl Eq for Reservation {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Continue,
    Syscall,
    /// Typed virtual native call; PC is held until the dispatcher commits.
    NativeCall {
        pc: u64,
        module: u64,
        function: u64,
    },
    /// A bounded long instruction has made progress but has not retired.
    Yield,
}

/// Compile-time offsets from a native GPR pointer carrying the whole CPU's raw
/// provenance. These name existing fields; there is no second register model.
#[derive(Clone, Copy)]
pub enum NativeSystemRegister {
    Tls,
    Tls2,
    Fpcr,
    Fpsr,
}

#[inline]
fn sign_extend(value: u64, bits: u32) -> u64 {
    (((value << (64 - bits)) as i64) >> (64 - bits)) as u64
}
#[inline]
fn width_mask(wide: bool) -> u64 {
    if wide {
        u64::MAX
    } else {
        u32::MAX as u64
    }
}
#[inline]
fn shifted(value: u64, kind: u32, amount: u32, wide: bool) -> u64 {
    let value = value & width_mask(wide);
    (match kind {
        0 => value.wrapping_shl(amount),
        1 => value >> amount,
        2 if wide => ((value as i64) >> amount) as u64,
        2 => ((value as u32 as i32) >> amount) as u32 as u64,
        3 if wide => value.rotate_right(amount),
        3 => (value as u32).rotate_right(amount) as u64,
        _ => unreachable!("two-bit shift"),
    }) & width_mask(wide)
}

impl Cpu {
    /// Materialize architectural state only at an explicit engine boundary.
    /// The normal interpreter slice keeps its deferred flags and decode cache.
    pub fn architectural_state(&self) -> Aarch64State {
        Aarch64State {
            registers: self.registers,
            sp: self.sp,
            pc: self.pc,
            nzcv: self.nzcv() << 28,
            tpidr_el0: self.tpidr_el0,
            tpidr2_el0: self.tpidr2_el0,
            fpcr: self.fpcr,
            fpsr: self.fpsr,
            vectors: self.vectors,
        }
    }
    pub fn restore_architectural_state(&mut self, state: &Aarch64State) {
        self.registers = state.registers;
        self.sp = state.sp;
        self.pc = state.pc;
        self.set_nzcv(state.nzcv >> 28);
        self.tpidr_el0 = state.tpidr_el0;
        self.tpidr2_el0 = state.tpidr2_el0;
        self.fpcr = state.fpcr;
        self.fpsr = state.fpsr;
        self.vectors = state.vectors;
        self.clear_exclusive();
    }
    pub fn set_native_calls(&mut self, enabled: bool) {
        self.native_calls = enabled;
    }
    pub fn set_vulkan_calls(&mut self, enabled: bool) {
        self.vulkan_calls = enabled;
    }
    pub fn native_calls_enabled(&self) -> bool {
        self.native_calls || self.vulkan_calls || self.video_calls || self.audio_calls
    }
    pub fn native_call_target(&self) -> Option<(u64, u64)> {
        let module = self.x(16);
        (self.native_calls
            || self.vulkan_calls && module == 0x0001_0006
            || self.video_calls && module == 0x0001_0007
            || self.audio_calls && module == 0x0001_0008)
            .then(|| (module, self.x(17)))
    }
    pub fn decode_stats(&self) -> DecodeStats {
        self.decoded.stats
    }
    pub fn new(pc: u64, sp: u64) -> Self {
        Self {
            pc,
            sp,
            ..Self::default()
        }
    }
    /// Register 31 denotes ZR here; SP is selected explicitly by instruction semantics.
    #[inline]
    pub fn x(&self, index: usize) -> u64 {
        if index == 31 {
            0
        } else {
            self.registers[index]
        }
    }
    #[inline]
    pub fn set_x(&mut self, index: usize, value: u64) {
        if index != 31 {
            self.registers[index] = value;
        }
    }
    /// Exception entry and virtual CPU migration may clear the local monitor.
    /// Shared reservation domain for interpreted and translated accesses.
    pub fn set_exclusive(&mut self, address: u64, size: usize, token: u128) {
        self.exclusive = Reservation {
            address,
            size: size as u64,
            token,
        };
    }
    pub fn take_exclusive(&mut self, address: u64, size: usize) -> Option<u128> {
        self.exclusive
            .take()
            .filter(|r| r.0 == address && r.1 == size)
            .map(|r| r.2)
    }
    pub fn clear_exclusive(&mut self) {
        self.exclusive.size = 0;
    }
    #[inline]
    fn reg(&self, index: usize, sp: bool) -> u64 {
        if sp && index == 31 {
            self.sp
        } else {
            self.x(index)
        }
    }
    #[inline]
    fn put(&mut self, index: usize, value: u64, wide: bool, sp: bool) {
        let value = value & width_mask(wide);
        if sp && index == 31 {
            self.sp = value;
        } else {
            self.set_x(index, value);
        }
    }
    // The decoder supplies constant flag modes at many call sites. Keep
    // them visible so flag-free ALU operations lose the entire NZCV path.
    #[inline(always)]
    fn arithmetic(&mut self, a: u64, b: u64, sub: bool, set_flags: bool, wide: bool) -> u64 {
        self.condition_flags.calculate(a, b, sub, set_flags, wide)
    }
    #[inline(always)]
    fn condition(&self, condition: u32) -> bool {
        self.condition_flags.condition(condition)
    }

    pub fn step(&mut self, memory: &mut impl CpuMemory) -> Result<Event, CpuFault> {
        let pc = self.pc;
        let memory_fault = |error| CpuFault::Memory { pc, error };
        let ins = memory.fetch_u32(pc).map_err(memory_fault)?;
        let scope = trames_compute::Scope::new(self.fpcr, self.fpsr);
        let result = self.execute_instruction(ins, memory);
        self.fpsr |= trames_compute::status();
        drop(scope);
        result
    }
    fn execute_instruction(
        &mut self,
        ins: u32,
        memory: &mut impl CpuMemory,
    ) -> Result<Event, CpuFault> {
        self.yield_current = false;
        let pc = self.pc;
        let invalid = || CpuFault::Instruction {
            pc,
            instruction: ins,
        };
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let wide = ins >> 31 != 0;
        let mut next = pc.wrapping_add(4);
        let mut event = Event::Continue;
        if ins == 0xd44a8a40 && self.native_call_target().is_some() {
            let (module, function) = self.native_call_target().unwrap();
            next = pc;
            event = Event::NativeCall {
                pc,
                module,
                function,
            };
        } else if matches!(ins & 0xffe0001f, 0xd4200000 | 0xd4400000) {
            return Err(CpuFault::Trap {
                pc,
                instruction: ins,
                signal: if ins & 0xffe0001f == 0xd4200000 { 5 } else { 4 },
                code: 1,
            });
        } else if ins == 0xd503201f { // NOP
        } else if ins & 0xffe0001f == 0xd4000001 {
            // SVC #0; the syscall dispatcher owns guest-visible effects.
            event = Event::Syscall;
        } else if ins & 0x7fe0e000 == 0x1ac04000 {
            // CRC32/CRC32C operate on the little-endian bytes of B/H/W/X.
            let bytes = 1 << ((ins >> 10) & 3);
            if wide != (bytes == 8) {
                return Err(invalid());
            }
            let polynomial = if ins & (1 << 12) != 0 {
                0x82f63b78
            } else {
                0xedb88320
            };
            let native =
                trames_compute::crc(bytes, ins & (1 << 12) != 0, self.x(rn) as u32, self.x(rm));
            let mut crc = self.x(rn) as u32;
            if let Some(value) = native {
                crc = value;
            } else {
                for byte in 0..bytes {
                    crc ^= ((self.x(rm) >> (byte * 8)) & 255) as u32;
                    for _ in 0..8 {
                        crc = (crc >> 1) ^ if crc & 1 != 0 { polynomial } else { 0 };
                    }
                }
            }
            self.set_x(rd, crc as u64);
        } else if ins & 0x1f800000 == 0x12800000 {
            // MOVN/MOVZ/MOVK
            let opc = (ins >> 29) & 3;
            let shift = ((ins >> 21) & 3) * 16;
            if opc == 1 || (!wide && shift >= 32) {
                return Err(invalid());
            }
            let immediate = (((ins >> 5) & 0xffff) as u64) << shift;
            let value = match opc {
                0 => !immediate,
                2 => immediate,
                3 => (self.x(rd) & !(0xffffu64 << shift)) | immediate,
                _ => unreachable!(),
            };
            self.put(rd, value, wide, false);
        } else if ins & 0x1f000000 == 0x10000000 {
            // ADR/ADRP
            let immediate = sign_extend(
                ((((ins >> 5) & 0x7ffff) as u64) << 2) | ((ins >> 29) & 3) as u64,
                21,
            );
            let value = if wide {
                (pc & !4095).wrapping_add(immediate << 12)
            } else {
                pc.wrapping_add(immediate)
            };
            self.set_x(rd, value);
        } else if ins & 0x1f800000 == 0x11000000 {
            // ADD/SUB immediate
            let sub = ins & (1 << 30) != 0;
            let flags = ins & (1 << 29) != 0;
            let immediate =
                (((ins >> 10) & 0xfff) as u64) << if ins & (1 << 22) != 0 { 12 } else { 0 };
            let value = self.arithmetic(self.reg(rn, true), immediate, sub, flags, wide);
            self.put(rd, value, wide, !flags);
        } else if ins & 0x1f200000 == 0x0b000000 {
            // ADD/SUB shifted register
            let kind = (ins >> 22) & 3;
            let amount = (ins >> 10) & 63;
            if kind == 3 || (!wide && amount >= 32) {
                return Err(invalid());
            }
            let sub = ins & (1 << 30) != 0;
            let flags = ins & (1 << 29) != 0;
            let value = self.arithmetic(
                self.x(rn),
                shifted(self.x(rm), kind, amount, wide),
                sub,
                flags,
                wide,
            );
            self.put(rd, value, wide, false);
        } else if ins & 0x1f000000 == 0x0a000000 {
            // AND/ORR/EOR/ANDS shifted register (+ inverted forms)
            let kind = (ins >> 22) & 3;
            let amount = (ins >> 10) & 63;
            if !wide && amount >= 32 {
                return Err(invalid());
            }
            let mut rhs = shifted(self.x(rm), kind, amount, wide);
            if ins & (1 << 21) != 0 {
                rhs = !rhs;
            }
            let opc = (ins >> 29) & 3;
            let value = match opc {
                0 | 3 => self.x(rn) & rhs,
                1 => self.x(rn) | rhs,
                2 => self.x(rn) ^ rhs,
                _ => unreachable!(),
            } & width_mask(wide);
            if opc == 3 {
                self.set_flags(Flags {
                    n: value & (if wide { 1 << 63 } else { 1 << 31 }) != 0,
                    z: value == 0,
                    c: false,
                    v: false,
                });
            }
            self.put(rd, value, wide, false);
        } else if ins & 0x7c000000 == 0x14000000 {
            // B/BL
            if wide {
                self.set_x(30, next);
            }
            next = pc.wrapping_add(sign_extend(((ins & 0x03ffffff) as u64) << 2, 28));
        } else if matches!(ins & 0xfffffc1f, 0xd61f0000 | 0xd63f0000 | 0xd65f0000) {
            // BR/BLR/RET
            let target = self.x(rn);
            if ins & 0xfffffc1f == 0xd63f0000 {
                self.set_x(30, next);
            }
            next = target;
        } else if ins & 0x7e000000 == 0x34000000 {
            // CBZ/CBNZ
            let nonzero = ins & (1 << 24) != 0;
            if (self.x(rd) & width_mask(wide) != 0) == nonzero {
                next = pc.wrapping_add(sign_extend((((ins >> 5) & 0x7ffff) as u64) << 2, 21));
            }
        } else if ins & 0xff000010 == 0x54000000 {
            // B.cond
            if self.condition(ins & 15) {
                next = pc.wrapping_add(sign_extend((((ins >> 5) & 0x7ffff) as u64) << 2, 21));
            }
        } else if let Some(target) = self.execute_extended(ins, memory)? {
            next = target;
        } else {
            return Err(invalid());
        }
        self.pc = next;
        Ok(if std::mem::take(&mut self.yield_current) {
            Event::Yield
        } else {
            event
        })
    }

    /// Completed instructions before the most recent fault, for scheduler
    /// accounting when a signal handler recovers from the failed instruction.
    pub fn fault_retired(&self) -> u64 {
        self.fault_retired
    }
    pub(crate) fn slice_fault(&mut self, error: CpuFault, instructions: u64) -> SliceOutcome {
        self.fault_retired = instructions;
        SliceOutcome::Fault(error)
    }
    /// Borrow only integer registers for a translated native block. Other
    /// architectural state, deferred flags and exclusive reservations stay put.
    pub fn general_registers_mut(&mut self) -> &mut [u64; 31] {
        &mut self.registers
    }
    /// Disjoint existing register banks for a translated FP/SIMD entry. Taking
    /// both at once avoids reborrowing the CPU parent over a live child pointer.
    pub fn native_register_banks_mut(&mut self) -> (&mut [u64; 31], &mut [u128; 32]) {
        (&mut self.registers, &mut self.vectors)
    }
    /// Raw native-entry banks derived directly from one whole-CPU grant, without
    /// creating a narrower register-array reference. Native system instructions
    /// may reach the named fields via `native_system_offset`. Suspend Rust CPU
    /// access until native return; callbacks must refresh both pointers after
    /// their final CPU access. No pointer may outlive the CPU or its entry.
    pub fn native_register_pointers(&mut self) -> (*mut u64, *mut u128) {
        let parent = self as *mut Self;
        unsafe {
            (
                std::ptr::addr_of_mut!((*parent).registers).cast(),
                std::ptr::addr_of_mut!((*parent).vectors).cast(),
            )
        }
    }
    pub const fn native_exclusive_size_offset() -> i64 {
        (std::mem::offset_of!(Self, exclusive) + std::mem::offset_of!(Reservation, size)) as i64
            - std::mem::offset_of!(Self, registers) as i64
    }
    pub const fn native_system_offset(register: NativeSystemRegister) -> i64 {
        let offset = match register {
            NativeSystemRegister::Tls => std::mem::offset_of!(Self, tpidr_el0),
            NativeSystemRegister::Tls2 => std::mem::offset_of!(Self, tpidr2_el0),
            NativeSystemRegister::Fpcr => std::mem::offset_of!(Self, fpcr),
            NativeSystemRegister::Fpsr => std::mem::offset_of!(Self, fpsr),
        };
        offset as i64 - std::mem::offset_of!(Self, registers) as i64
    }
    pub fn run_slice(&mut self, memory: &mut impl CpuMemory, budget: u64) -> SliceOutcome {
        self.run_slice_with_engine(memory, budget, None)
    }
    pub fn run_with_engine(
        &mut self,
        engine: &mut Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome {
        self.run_slice_with_engine(memory, budget, Some(engine))
    }
    fn run_slice_with_engine(
        &mut self,
        memory: &mut impl CpuMemory,
        budget: u64,
        engine: Option<&mut Engine>,
    ) -> SliceOutcome {
        self.fault_retired = 0;
        let scope = trames_compute::Scope::new(self.fpcr, self.fpsr);
        let result = if let Some(engine) = engine {
            self.run_worker_cached(engine, &mut *memory.cpu_slice(), budget)
        } else {
            self.run_cached(&mut *memory.cpu_slice(), budget)
        };
        self.fpsr |= trames_compute::status();
        drop(scope);
        result
    }
    #[cfg(test)]
    fn run_reference(&mut self, memory: &mut impl CpuMemory, budget: u64) -> SliceOutcome {
        for executed in 0..budget {
            match self.step(memory) {
                Ok(Event::Continue) => {}
                Ok(Event::Yield) => {
                    return SliceOutcome::Yield {
                        instructions: executed,
                    }
                }
                Ok(Event::Syscall) => {
                    return SliceOutcome::Syscall {
                        instructions: executed + 1,
                    }
                }
                Ok(Event::NativeCall {
                    pc,
                    module,
                    function,
                }) => {
                    return SliceOutcome::NativeCall {
                        instructions: executed,
                        pc,
                        module,
                        function,
                    }
                }
                Err(e) => return SliceOutcome::Fault(e),
            }
        }
        SliceOutcome::Yield {
            instructions: budget,
        }
    }
}

impl Registers for Cpu {
    #[inline]
    fn x(&self, index: usize) -> u64 {
        Cpu::x(self, index)
    }
    #[inline]
    fn set_x(&mut self, index: usize, value: u64) {
        Cpu::set_x(self, index, value);
    }
    #[inline]
    fn pc(&self) -> u64 {
        self.pc
    }
}

#[cfg(test)]
mod execution_state_tests {
    use super::*;
    use trames_memory::{Memory, Permissions};

    #[test]
    fn architectural_handoff_preserves_deferred_flags_tls_simd_and_resume_pc() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                4096,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        memory
            .write(
                0x1000,
                &[0xab010002u32, 0xba010043]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let mut cpu = Cpu::new(0x1000, 0x4000);
        cpu.set_x(0, u64::MAX);
        cpu.set_x(1, 1);
        cpu.set_vector(31, u128::MAX - 41);
        cpu.fpcr = 0x400000;
        cpu.fpsr = 0x10;
        cpu.tpidr_el0 = 0x8000;
        cpu.tpidr2_el0 = 0x9000;
        cpu.step(&mut memory).unwrap();
        let state = cpu.architectural_state();
        assert_eq!(state.nzcv, 0x60000000);
        assert_eq!(state.pc, 0x1004);
        let mut restored = Cpu::default();
        restored.restore_architectural_state(&state);
        assert_eq!(restored.architectural_state(), state);
        cpu.step(&mut memory).unwrap();
        restored.step(&mut memory).unwrap();
        assert_eq!(restored.x(3), 2);
        assert_eq!(restored.architectural_state(), cpu.architectural_state());
    }
}

#[cfg(test)]
use trames_memory::Memory;
#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn code(words: &[u32]) -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.iter().enumerate() {
            m.write(0x1000 + i as u64 * 4, &word.to_le_bytes()).unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m
    }
    #[test]
    fn zero_register_writes_and_w_register_zero_extension() {
        let mut m = code(&[0xd280003f, 0x12800000, 0xd503201f]); // mov xzr,1; movn w0,0
        let mut c = Cpu {
            pc: 0x1000,
            ..Cpu::default()
        };
        c.set_x(0, u64::MAX);
        c.step(&mut m).unwrap();
        assert_eq!(c.x(31), 0);
        c.step(&mut m).unwrap();
        assert_eq!(c.x(0), u32::MAX as u64);
    }
    #[test]
    fn arithmetic_flags_cover_carry_and_signed_overflow() {
        let mut c = Cpu::default();
        assert_eq!(c.arithmetic(u64::MAX, 1, false, true, true), 0);
        assert!(c.flags().z && c.flags().c && !c.flags().v);
        assert_eq!(c.arithmetic(0x7fffffff, 1, false, true, false), 0x80000000);
        assert!(c.flags().n && c.flags().v && !c.flags().c);
        c.arithmetic(0, 1, true, true, true);
        assert!(!c.flags().c && c.flags().n);
        c.arithmetic(1 << 63, 1, true, true, true);
        assert!(c.flags().v && c.flags().c);
    }
    #[test]
    fn stack_pointer_and_zero_register_have_distinct_semantics() {
        let mut m = code(&[0x910043ff, 0xf10043ff]); // add sp,sp,16; cmp sp,16
        let mut c = Cpu {
            pc: 0x1000,
            ..Cpu::default()
        };
        c.step(&mut m).unwrap();
        assert_eq!(c.sp, 16);
        c.step(&mut m).unwrap();
        assert!(c.flags().z);
        assert_eq!(c.sp, 16);
    }
    #[test]
    fn branches_syscall_and_budget() {
        let mut m = code(&[0x14000000]);
        let mut c = Cpu {
            pc: 0x1000,
            ..Cpu::default()
        };
        assert!(matches!(
            c.run_slice(&mut m, 5),
            SliceOutcome::Yield { instructions: 5 }
        ));
        assert_eq!(c.pc, 0x1000);
        m = code(&[0xd4000001]);
        assert!(matches!(
            c.run_slice(&mut m, 5),
            SliceOutcome::Syscall { instructions: 1 }
        ));
        assert_eq!(c.pc, 0x1004);
    }
    #[test]
    fn invalid_encodings_and_memory_faults_keep_pc() {
        for instruction in [0, 0x52c00000, 0xd4000003, 0x0bc00000] {
            let mut m = code(&[instruction]);
            let mut c = Cpu {
                pc: 0x1000,
                ..Cpu::default()
            };
            assert!(matches!(c.step(&mut m), Err(CpuFault::Instruction { .. })));
            assert_eq!(c.pc, 0x1000);
        }
        let mut m = code(&[0xf9400020]);
        let mut c = Cpu {
            pc: 0x1000,
            ..Cpu::default()
        };
        c.set_x(1, u64::MAX);
        assert!(matches!(c.step(&mut m), Err(CpuFault::Memory { .. })));
        assert_eq!(c.pc, 0x1000);
    }

    #[test]
    fn reserved_new_encodings_have_no_architectural_effects() {
        // Invalid RDM widths, scalar vector-only FADD, odd CASP pair, an
        // unallocated atomic operation and the reserved indexed FP type.
        for instruction in [
            0x6e028420, 0x6ec28420, 0x5e421420, 0x48217c82, 0xf8209022, 0x4f729820,
        ] {
            for cached in [false, true] {
                let mut memory = code(&[instruction]);
                memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
                memory.write(0x2000, &[0x5a; 32]).unwrap();
                let mut cpu = Cpu::new(0x1000, 0x2800);
                for i in 0..31 {
                    cpu.set_x(i, 0x2000);
                }
                for i in 0..32 {
                    cpu.set_vector(i, u128::MAX);
                }
                cpu.set_nzcv(9);
                cpu.fpcr = 0x07c80000;
                cpu.fpsr = 0x9f;
                let before = cpu.clone();
                let revision = memory.revision();
                assert!(
                    matches!(
                        if cached {
                            cpu.run_slice(&mut memory, 1)
                        } else {
                            cpu.run_reference(&mut memory, 1)
                        },
                        SliceOutcome::Fault(CpuFault::Instruction { .. })
                    ),
                    "{instruction:08x} cached={cached}"
                );
                assert_eq!(cpu.registers, before.registers);
                assert_eq!(cpu.vectors, before.vectors);
                assert_eq!(
                    (
                        cpu.pc,
                        cpu.sp,
                        cpu.nzcv(),
                        cpu.fpcr,
                        cpu.fpsr,
                        cpu.exclusive
                    ),
                    (
                        before.pc,
                        before.sp,
                        before.nzcv(),
                        before.fpcr,
                        before.fpsr,
                        before.exclusive
                    )
                );
                assert_eq!(memory.revision(), revision);
            }
        }
    }

    #[test]
    fn failed_atomic_write_preflight_keeps_memory_and_registers() {
        for instruction in [0xf8208022, 0x48207c82] {
            // SWP / CASP
            for cached in [false, true] {
                let mut memory = code(&[instruction]);
                memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
                memory.write(0x2000, &[0xa5; 16]).unwrap();
                memory.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
                let mut cpu = Cpu::new(0x1000, 0x2800);
                for i in 0..31 {
                    cpu.set_x(i, 0x2000);
                }
                let before = cpu.clone();
                let revision = memory.revision();
                assert!(matches!(
                    if cached {
                        cpu.run_slice(&mut memory, 1)
                    } else {
                        cpu.run_reference(&mut memory, 1)
                    },
                    SliceOutcome::Fault(CpuFault::Memory { .. })
                ));
                assert_eq!(cpu.registers, before.registers);
                assert_eq!(cpu.pc, before.pc);
                assert_eq!(memory.revision(), revision);
                let mut contents = [0; 16];
                memory.read(0x2000, &mut contents).unwrap();
                assert_eq!(contents, [0xa5; 16]);
            }
        }
    }

    #[test]
    fn serial_exclusive_store_succeeds_after_an_unrelated_stack_spill() {
        // The original Firefox 142 lock loop spills its desired CAS value
        // between LDAXR and STLXR. The spill must not force every retry to fail.
        let mut memory = code(&[0xc85ffee9, 0xf90023eb, 0xc80afeeb]);
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x4000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x2000, 1u64.to_le_bytes()).unwrap();
        let mut cpu = Cpu::new(0x1000, 0x4000);
        cpu.set_x(23, 0x2000);
        cpu.set_x(11, 2);
        for _ in 0..3 {
            cpu.step(&mut memory).unwrap();
        }
        assert_eq!(cpu.x(9), 1);
        assert_eq!(cpu.x(10), 0);
        assert_eq!(memory.read_u64(0x2000).unwrap(), 2);
        assert_eq!(memory.read_u64(0x4040).unwrap(), 2);
    }

    #[test]
    fn rcpc_load_does_not_create_an_exclusive_reservation() {
        let mut memory = code(&[0xf8bfc020, 0xc8037c24]); // LDAPR X0 / STXR W3,X4
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x2000, &7u64.to_le_bytes()).unwrap();
        let mut cpu = Cpu::new(0x1000, 0x2800);
        cpu.set_x(1, 0x2000);
        cpu.set_x(4, 99);
        cpu.step(&mut memory).unwrap();
        assert_eq!(cpu.x(0), 7);
        cpu.step(&mut memory).unwrap();
        assert_eq!(cpu.x(3), 1);
        assert_eq!(memory.read_u64(0x2000).unwrap(), 7);
    }

    #[test]
    fn virtual_counter_and_cache_maintenance_preserve_guest_state() {
        let mut memory = code(&[0xd53be000, 0xd53be041, 0xd53be042]);
        let mut cpu = Cpu::new(0x1000, 0x2800);
        cpu.step(&mut memory).unwrap();
        cpu.step(&mut memory).unwrap();
        cpu.step(&mut memory).unwrap();
        assert_eq!(cpu.x(0), counter::frequency());
        assert!(cpu.x(2) >= cpu.x(1));
        for instruction in [0xd50b7b21, 0xd50b7a21, 0xd50b7e21, 0xd50b7521] {
            memory = code(&[instruction]);
            memory
                .map(
                    0x2000,
                    PAGE_SIZE,
                    Permissions {
                        read: false,
                        write: false,
                        execute: false,
                    },
                )
                .unwrap();
            cpu = Cpu::new(0x1000, 0x2800);
            cpu.set_x(1, 0x2001);
            let revision = memory.instruction_revision();
            cpu.step(&mut memory).unwrap();
            assert_eq!(memory.instruction_revision(), revision);
            cpu.pc = 0x1000;
            cpu.set_x(1, 0x3000);
            assert!(matches!(
                cpu.step(&mut memory),
                Err(CpuFault::Memory { .. })
            ));
            assert_eq!(cpu.pc, 0x1000);
        }
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn video_opt_in_is_independent_of_vulkan_and_pure_memory() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &0xd44a8a40u32.to_le_bytes()).unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        for module in [0x10001, 0x10006, 0x10007] {
            let mut cpu = Cpu::new(0x1000, 0);
            <Cpu as trames_engine::Cpu>::set_video_calls(&mut cpu, true);
            cpu.set_x(16, module);
            cpu.set_x(17, 1);
            let result = cpu.run_slice(&mut memory, 1);
            assert_eq!(
                matches!(
                    result,
                    SliceOutcome::NativeCall {
                        module: 0x10007,
                        ..
                    }
                ),
                module == 0x10007
            );
        }
    }
    #[test]
    fn audio_opt_in_cannot_enable_other_native_profiles() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &0xd44a8a40u32.to_le_bytes()).unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        for module in [0x10001, 0x10006, 0x10007, 0x10008] {
            let mut cpu = Cpu::new(0x1000, 0);
            <Cpu as trames_engine::Cpu>::set_audio_calls(&mut cpu, true);
            cpu.set_x(16, module);
            cpu.set_x(17, 1);
            assert_eq!(
                matches!(
                    cpu.run_slice(&mut memory, 1),
                    SliceOutcome::NativeCall {
                        module: 0x10008,
                        ..
                    }
                ),
                module == 0x10008
            );
        }
    }
    #[test]
    fn vulkan_opt_in_does_not_activate_the_pure_memory_profile() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &0xd44a8a40u32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut gpu = Cpu::new(0x1000, 0);
        gpu.set_vulkan_calls(true);
        gpu.set_x(16, 0x10006);
        gpu.set_x(17, 1);
        assert!(matches!(
            gpu.run_slice(&mut m, 1),
            SliceOutcome::NativeCall {
                module: 0x10006,
                ..
            }
        ));
        let mut pure = Cpu::new(0x1000, 0);
        pure.set_vulkan_calls(true);
        pure.set_x(16, 0x10001);
        pure.set_x(17, 1);
        assert!(matches!(
            pure.run_slice(&mut m, 1),
            SliceOutcome::Fault(CpuFault::Trap { signal: 4, .. })
        ));
    }
    #[test]
    fn native_exit_gating_pc_and_budget_match_reference() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &0xd503201fu32.to_le_bytes()).unwrap();
        m.write(0x1004, &0xd44a8a40u32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut disabled = Cpu::new(0x1004, 0);
        assert!(matches!(
            disabled.run_slice(&mut m, 1),
            SliceOutcome::Fault(CpuFault::Trap {
                pc: 0x1004,
                signal: 4,
                ..
            })
        ));
        for budget in [0, 1, 2, 3] {
            let mut c = Cpu::new(0x1000, 0);
            c.set_native_calls(true);
            c.set_x(16, 0x10001);
            c.set_x(17, 3);
            let mut reference = c.clone();
            let mut reference_memory = m.clone();
            let a = c.run_slice(&mut m, budget);
            let b = reference.run_reference(&mut reference_memory, budget);
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            assert_eq!(c.pc, reference.pc);
            if budget >= 2 {
                assert!(matches!(
                    a,
                    SliceOutcome::NativeCall {
                        instructions: 1,
                        pc: 0x1004,
                        module: 0x10001,
                        function: 3
                    }
                ));
            }
        }
        let mut c = Cpu::new(0x1004, 0);
        c.set_native_calls(true);
        assert!(matches!(
            c.step(&mut m),
            Ok(Event::NativeCall { pc: 0x1004, .. })
        ));
        assert_eq!(c.pc, 0x1004);
        // Every other HLT and every BRK retains its normal architectural fault.
        m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1004, &0xd4400000u32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert!(matches!(
            c.run_slice(&mut m, 1),
            SliceOutcome::Fault(CpuFault::Trap { signal: 4, .. })
        ));
    }
}

impl trames_engine::Cpu for Cpu {
    type Engine = Engine;
    const FEATURES: trames_execution::Features = trames_execution::Features {
        hwcap: HWCAP,
        hwcap2: HWCAP2,
    };
    const FEATURE_NAMES: &'static str = FEATURE_NAMES;
    fn counter_frequency() -> u64 {
        counter::frequency()
    }
    fn clock_sample() -> Option<trames_engine::ClockSample> {
        counter::sample()
    }
    const EXACT_INSTRUCTIONS: bool = true;
    fn new(pc: u64, sp: u64) -> Self {
        Self::new(pc, sp)
    }
    fn sp(&self) -> u64 {
        self.sp
    }
    fn set_sp(&mut self, value: u64) {
        self.sp = value;
    }
    fn set_pc(&mut self, value: u64) {
        self.pc = value;
    }
    fn set_tls(&mut self, value: u64) {
        self.tpidr_el0 = value;
    }
    fn architectural_state(&self) -> Aarch64State {
        self.architectural_state()
    }
    fn restore_architectural_state(&mut self, state: &Aarch64State) {
        self.restore_architectural_state(state);
    }
    fn set_native_calls(&mut self, enabled: bool) {
        self.set_native_calls(enabled);
    }
    fn set_vulkan_calls(&mut self, enabled: bool) {
        self.set_vulkan_calls(enabled);
    }
    fn set_audio_calls(&mut self, enabled: bool) {
        self.audio_calls = enabled;
    }
    fn set_video_calls(&mut self, enabled: bool) {
        self.video_calls = enabled;
    }
    fn clear_exclusive(&mut self) {
        self.clear_exclusive();
    }
    fn fault_retired(&self) -> u64 {
        self.fault_retired()
    }
    fn decode_stats(&self) -> DecodeStats {
        self.decode_stats()
    }
    fn run(
        &mut self,
        engine: &mut Engine,
        memory: &mut trames_memory::Memory,
        budget: u64,
    ) -> SliceOutcome {
        self.run_with_engine(engine, memory, budget)
    }
    fn run_parallel(
        &mut self,
        engine: &mut Engine,
        memory: &mut trames_memory::parallel::View,
        budget: u64,
    ) -> SliceOutcome {
        self.run_with_engine(engine, memory, budget)
    }
}
