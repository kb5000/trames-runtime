// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-thread restartable sequences on the original task's execution boundary.
//! Guest accesses use CpuMemory; no timer, executor or resource-service thread
//! is created. An unregistered task takes only the relaxed address check.
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering::Relaxed},
    Mutex,
};
use trames_memory::{CpuMemory, ADDRESS_LIMIT};
use trames_vfs::Errno;

pub const FEATURE_SIZE: u64 = 28;
pub const ALIGN: u64 = 32;
const PREEMPT: u32 = 1;
const SIGNAL: u32 = 2;
const MIGRATE: u32 = 4;
const UPDATE: u32 = 8;

#[derive(Clone, Copy)]
struct Registration {
    address: u64,
    length: u32,
    signature: u32,
}

pub struct Rseq {
    address: AtomicU64,
    registration: Mutex<Option<Registration>>,
    pending: AtomicU32,
    cpu: AtomicU32,
}
impl Default for Rseq {
    fn default() -> Self {
        Self {
            address: AtomicU64::new(0),
            registration: Mutex::new(None),
            pending: AtomicU32::new(0),
            cpu: AtomicU32::new(u32::MAX),
        }
    }
}
impl Rseq {
    pub fn call(&self, memory: &mut impl CpuMemory, args: [u64; 6]) -> Result<u64, Errno> {
        let (address, length, flags, signature) =
            (args[0], args[1] as u32, args[2] as u32, args[3] as u32);
        if flags & !1 != 0 {
            return Err(Errno(22));
        }
        let mut registration = self.registration.lock().unwrap();
        if let Some(old) = *registration {
            if old.address != address || old.length != length {
                return Err(Errno(22));
            }
            if old.signature != signature {
                return Err(Errno(1));
            }
            if flags == 0 {
                return Err(Errno(16));
            }
            for (at, value) in [(0, 0), (4, u32::MAX), (20, 0), (24, 0)] {
                memory
                    .write_array(address + at, value.to_le_bytes())
                    .map_err(|_| Errno(14))?;
            }
            *registration = None;
            self.address.store(0, Relaxed);
            self.pending.store(0, Relaxed);
            self.cpu.store(u32::MAX, Relaxed);
            return Ok(0);
        }
        if flags != 0 || length < 32 || address & (ALIGN - 1) != 0 {
            return Err(Errno(22));
        }
        // Like access_ok, registration validates the address range, not page
        // presence. A later notify-resume fault is a synchronous SIGSEGV.
        let untagged = address & 0x00ff_ffff_ffff_ffff;
        if untagged
            .checked_add(u64::from(length))
            .is_none_or(|end| end > ADDRESS_LIMIT)
        {
            return Err(Errno(14));
        }
        if address == 0 {
            return Ok(0);
        }
        *registration = Some(Registration {
            address,
            length,
            signature,
        });
        self.cpu.store(u32::MAX, Relaxed);
        self.pending.store(UPDATE, Relaxed);
        self.address.store(address, Relaxed);
        Ok(0)
    }
    pub fn preempt(&self) {
        if self.address.load(Relaxed) != 0 {
            self.pending.fetch_or(PREEMPT, Relaxed);
        }
    }
    pub fn clear(&self) {
        let mut registration = self.registration.lock().unwrap();
        *registration = None;
        self.address.store(0, Relaxed);
        self.pending.store(0, Relaxed);
        self.cpu.store(u32::MAX, Relaxed);
    }
    pub fn inherit(&self, parent: &Self) {
        let registration = *parent.registration.lock().unwrap();
        *self.registration.lock().unwrap() = registration;
        self.cpu.store(u32::MAX, Relaxed);
        self.pending.store(
            if registration.is_some() {
                PREEMPT | UPDATE
            } else {
                0
            },
            Relaxed,
        );
        self.address.store(
            registration.map_or(0, |registration| registration.address),
            Relaxed,
        );
    }
    /// Return the interrupted PC or its validated abort target. Each execution
    /// slot is one guest CPU; using that slot as mm_cid also gives concurrently
    /// running threads in one mm distinct IDs without another allocator.
    pub fn resume(&self, memory: &mut impl CpuMemory, pc: u64, cpu: u32) -> Result<u64, Errno> {
        self.resume_event(memory, pc, cpu, 0)
    }
    pub fn signal(&self, memory: &mut impl CpuMemory, pc: u64) -> Result<u64, Errno> {
        let cpu = self.cpu.load(Relaxed);
        let cpu = if cpu == u32::MAX { 0 } else { cpu };
        self.resume_event(memory, pc, cpu, SIGNAL)
    }
    fn resume_event(
        &self,
        memory: &mut impl CpuMemory,
        pc: u64,
        cpu: u32,
        event: u32,
    ) -> Result<u64, Errno> {
        if self.address.load(Relaxed) == 0 {
            return Ok(pc);
        }
        let current = self.cpu.load(Relaxed);
        if event == 0 && current == cpu && self.pending.load(Relaxed) == 0 {
            return Ok(pc);
        }
        let Some(registration) = *self.registration.lock().unwrap() else {
            return Ok(pc);
        };
        let migrate = current != u32::MAX && current != cpu;
        let events = self.pending.swap(0, Relaxed) | event | if migrate { MIGRATE } else { 0 };
        // The forced fault path may build a signal frame. Do not repeat this
        // same failed notify before that frame can be delivered.
        let result = Self::fixup(
            memory,
            registration,
            pc,
            events & (PREEMPT | SIGNAL | MIGRATE),
        )?;
        for (at, value) in [(0, cpu), (4, cpu), (20, 0), (24, cpu)] {
            memory
                .write_array(registration.address + at, value.to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        self.cpu.store(cpu, Relaxed);
        Ok(result)
    }
    fn fixup(
        memory: &mut impl CpuMemory,
        registration: Registration,
        pc: u64,
        events: u32,
    ) -> Result<u64, Errno> {
        let pointer = u64::from_le_bytes(
            memory
                .read_array::<8>(registration.address + 8)
                .map_err(|_| Errno(14))?,
        );
        if pointer == 0 {
            return Ok(pc);
        }
        if pointer >= ADDRESS_LIMIT {
            return Err(Errno(22));
        }
        let bytes = memory.read_array::<32>(pointer).map_err(|_| Errno(14))?;
        let word = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let (start, length, abort) = (word(8), word(16), word(24));
        let end = start
            .checked_add(length)
            .filter(|end| *end < ADDRESS_LIMIT)
            .ok_or(Errno(22))?;
        if bytes[..4] != [0; 4]
            || start >= ADDRESS_LIMIT
            || abort >= ADDRESS_LIMIT
            || (start..end).contains(&abort)
        {
            return Err(Errno(22));
        }
        let signature = u32::from_le_bytes(
            memory
                .read_array::<4>(abort.checked_sub(4).ok_or(Errno(14))?)
                .map_err(|_| Errno(14))?,
        );
        if signature != registration.signature {
            return Err(Errno(22));
        }
        if !(start..end).contains(&pc) {
            memory
                .write_array(registration.address + 8, 0u64.to_le_bytes())
                .map_err(|_| Errno(14))?;
            return Ok(pc);
        }
        // Linux rejects deprecated no-restart flags as well as unknown bits.
        let flags = memory
            .read_array::<4>(registration.address + 16)
            .map_err(|_| Errno(14))?;
        if bytes[4..8] != [0; 4] || flags != [0; 4] {
            return Err(Errno(22));
        }
        if events == 0 {
            return Ok(pc);
        }
        memory
            .write_array(registration.address + 8, 0u64.to_le_bytes())
            .map_err(|_| Errno(14))?;
        Ok(abort)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    const TLS: u64 = 0x1000;
    const DESCRIPTOR: u64 = 0x1100;
    const START: u64 = 0x2000;
    const ABORT: u64 = 0x2080;
    const SIGNATURE: u32 = 0xd428bc00;
    fn fixture() -> (Rseq, Memory) {
        let mut memory = Memory::new(PAGE_SIZE as usize * 8);
        memory.map(TLS, PAGE_SIZE * 2, Permissions::RW).unwrap();
        memory
            .write_array(ABORT - 4, SIGNATURE.to_le_bytes())
            .unwrap();
        memory
            .write_array(DESCRIPTOR + 8, START.to_le_bytes())
            .unwrap();
        memory
            .write_array(DESCRIPTOR + 16, 32u64.to_le_bytes())
            .unwrap();
        memory
            .write_array(DESCRIPTOR + 24, ABORT.to_le_bytes())
            .unwrap();
        let rseq = Rseq::default();
        rseq.call(&mut memory, [TLS, 32, 0, SIGNATURE as u64, 0, 0])
            .unwrap();
        assert_eq!(rseq.resume(&mut memory, 0x3000, 2), Ok(0x3000));
        (rseq, memory)
    }
    fn arm(memory: &mut Memory) {
        memory
            .write_array(TLS + 8, DESCRIPTOR.to_le_bytes())
            .unwrap();
    }
    #[test]
    fn preemption_migration_and_signal_abort_before_exposing_the_new_cpu() {
        for event in 0..3 {
            let (rseq, mut memory) = fixture();
            arm(&mut memory);
            let next = if event == 0 {
                rseq.preempt();
                rseq.resume(&mut memory, START + 4, 2)
            } else if event == 1 {
                rseq.resume(&mut memory, START + 4, 3)
            } else {
                rseq.signal(&mut memory, START + 4)
            };
            assert_eq!(next, Ok(ABORT));
            assert_eq!(memory.read_array::<8>(TLS + 8).unwrap(), [0; 8]);
            let cpu = if event == 1 { 3u32 } else { 2u32 };
            assert_eq!(memory.read_array::<4>(TLS).unwrap(), cpu.to_le_bytes());
            assert_eq!(memory.read_array::<4>(TLS + 4).unwrap(), cpu.to_le_bytes());
            assert_eq!(memory.read_array::<4>(TLS + 24).unwrap(), cpu.to_le_bytes());
        }
    }
    #[test]
    fn post_commit_and_uninterrupted_execution_do_not_branch_to_abort() {
        let (rseq, mut memory) = fixture();
        arm(&mut memory);
        assert_eq!(rseq.resume(&mut memory, START + 4, 2), Ok(START + 4));
        assert_ne!(memory.read_array::<8>(TLS + 8).unwrap(), [0; 8]);
        rseq.preempt();
        assert_eq!(rseq.resume(&mut memory, START + 32, 2), Ok(START + 32));
        assert_eq!(memory.read_array::<8>(TLS + 8).unwrap(), [0; 8]);
    }
    #[test]
    fn registration_errno_order_and_failed_unregister_keep_the_original_state() {
        let (rseq, mut memory) = fixture();
        assert_eq!(
            rseq.call(&mut memory, [TLS, 32, 0, SIGNATURE as u64, 0, 0]),
            Err(Errno(16))
        );
        assert_eq!(rseq.call(&mut memory, [TLS, 32, 0, 0, 0, 0]), Err(Errno(1)));
        assert_eq!(
            rseq.call(&mut memory, [TLS + 1, 32, 1, 0, 0, 0]),
            Err(Errno(22))
        );
        assert_eq!(rseq.call(&mut memory, [TLS, 32, 1, 0, 0, 0]), Err(Errno(1)));
        memory.protect(TLS, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(
            rseq.call(&mut memory, [TLS, 32, 1, SIGNATURE as u64, 0, 0]),
            Err(Errno(14))
        );
        memory.protect(TLS, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(
            rseq.call(&mut memory, [TLS, 32, 1, SIGNATURE as u64, 0, 0]),
            Ok(0)
        );
        assert_eq!(
            memory.read_array::<4>(TLS + 4).unwrap(),
            u32::MAX.to_le_bytes()
        );
        assert_eq!(rseq.resume(&mut memory, START, 3), Ok(START));
    }
    #[test]
    fn fork_inherits_a_registration_and_exec_clear_never_writes_the_old_address_space() {
        let (parent, mut memory) = fixture();
        let child = Rseq::default();
        child.inherit(&parent);
        arm(&mut memory);
        assert_eq!(child.resume(&mut memory, START + 4, 1), Ok(ABORT));
        arm(&mut memory);
        parent.clear();
        assert_eq!(parent.resume(&mut memory, START + 4, 0), Ok(START + 4));
        assert_eq!(
            memory.read_array::<8>(TLS + 8).unwrap(),
            DESCRIPTOR.to_le_bytes()
        );
    }
    #[test]
    fn bad_signature_version_flags_and_abort_range_are_detected_before_pc_change() {
        for variant in 0..4 {
            let (rseq, mut memory) = fixture();
            arm(&mut memory);
            match variant {
                0 => memory.write_array(ABORT - 4, 0u32.to_le_bytes()).unwrap(),
                1 => memory.write_array(DESCRIPTOR, 1u32.to_le_bytes()).unwrap(),
                2 => memory.write_array(TLS + 16, 1u32.to_le_bytes()).unwrap(),
                _ => memory
                    .write_array(DESCRIPTOR + 24, (START + 8).to_le_bytes())
                    .unwrap(),
            }
            rseq.preempt();
            assert!(rseq.resume(&mut memory, START + 4, 2).is_err());
        }
    }
}
