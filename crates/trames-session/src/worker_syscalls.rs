// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker syscalls over retained policy and actual shared resource ownership.
//! No VFS/Process Rc crosses the boundary. Only seccomp-allowed calls execute;
//! filter installation, tracing and mutable authority changes still checkpoint.
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trames_engine::Cpu;
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;

pub(super) struct Snapshot {
    pub seccomp: crate::process::seccomp::Seccomp,
    /// getpid, getppid, getuid, geteuid, getgid, getegid, gettid.
    pub identities: [u64; 7],
    pub started: Instant,
    pub processor: u32,
    pub profile: bool,
    pub streams: trames_vfs::FdMask,
    pub files: trames_vfs::FdMask,
    pub fd_flags: trames_vfs::FdFlags,
    pub umask: trames_vfs::Umask,
    pub actions: crate::signal_actions::Actions,
    pub program_break: trames_linux::ProgramBreak,
    pub uts: Option<trames_vfs::UtsAccess>,
    pub direct: trames_linux::DirectSyscalls,
    pub futex: crate::futex::Authority,
}

/// These operations change or inspect this mm's mappings, without changing
/// task/FD/namespace authority. Filtered/traced callers retain the joined path.
pub(super) fn vm_call(number: u32) -> bool {
    matches!(number, 214..=216 | 222 | 226 | 232 | 233)
}

/// These calls can request the coordinator without stopping peer CPUs. The
/// service still admits the actual descriptor kind before doing any effects.
pub(super) fn service_candidate<C: Cpu>(cpu: &C, snapshot: &Snapshot) -> bool {
    match cpu.x(8) as u32 {
        62 | 80 => true,
        63..=66 => {
            let fd = cpu.x(0) as u32;
            fd < trames_vfs::MAX_FDS
                && (snapshot.streams[fd as usize / 64] | snapshot.files[fd as usize / 64])
                    & (1 << (fd % 64))
                    != 0
        }
        67..=70 | 82 | 83 => {
            let fd = cpu.x(0) as u32;
            fd < trames_vfs::MAX_FDS && snapshot.files[fd as usize / 64] & (1 << (fd % 64)) != 0
        }
        _ => false,
    }
}

pub(super) fn clock(
    memory: &mut impl CpuMemory,
    number: u32,
    id: u64,
    address: u64,
    started: Instant,
) -> Result<u64, Errno> {
    // clockid_t is a signed 32-bit Linux ABI argument, including raw SVCs.
    let id = id as u32;
    if !matches!(id, 0 | 1 | 4..=7) {
        return Err(Errno(22));
    }
    if number == 114 && address == 0 {
        return Ok(0);
    }
    memory
        .check(address, 16, Access::Write)
        .map_err(|_| Errno(14))?;
    let (seconds, nanos) = if number == 114 {
        (0, 1)
    } else {
        // Linux 5 is CLOCK_REALTIME_COARSE; 6 is CLOCK_MONOTONIC_COARSE.
        // Both coarse clocks use the same epoch as their high-resolution
        // counterpart. Mixing Unix time with session-monotonic deadlines can
        // turn GLib/Gecko event waits into an effectively endless busy loop.
        let elapsed = if matches!(id, 0 | 5) {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Errno(5))?
        } else {
            started.elapsed()
        };
        (elapsed.as_secs(), elapsed.subsec_nanos() as u64)
    };
    let mut out = [0; 16];
    out[..8].copy_from_slice(&seconds.to_le_bytes());
    out[8..].copy_from_slice(&nanos.to_le_bytes());
    memory.write_array(address, out).map_err(|_| Errno(14))?;
    Ok(0)
}

pub(super) fn futex_wait_parameters(
    memory: &impl CpuMemory,
    a: [u64; 6],
    started: Instant,
) -> Result<(u32, Option<Instant>), Errno> {
    let bitset = a[1] & 127 == 9;
    let bits = if bitset { a[5] as u32 } else { u32::MAX };
    if bits == 0 {
        return Err(Errno(22));
    }
    let deadline = if a[3] == 0 {
        None
    } else {
        let bytes = memory.read_array::<16>(a[3]).map_err(|_| Errno(14))?;
        let sec = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let ns = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
            return Err(Errno(22));
        }
        let mut duration = Duration::new(sec, ns as u32);
        if bitset {
            let now = if a[1] & 256 != 0 {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Errno(5))?
            } else {
                started.elapsed()
            };
            duration = duration.saturating_sub(now);
        } else if a[1] & 256 != 0 {
            return Err(Errno(38));
        }
        Some(Instant::now().checked_add(duration).ok_or(Errno(22))?)
    };
    Ok((bits, deadline))
}

pub(super) fn futex_key(
    memory: &impl CpuMemory,
    vm: u64,
    address: u64,
    private: bool,
) -> Result<crate::futex::Key, Errno> {
    if !private {
        if let Some(key) = memory.shared_futex_key(address).map_err(|_| Errno(14))? {
            return Ok(key);
        }
    }
    Ok((0, vm, address & 0x00ff_ffff_ffff_ffff))
}
pub(super) fn futex_parameters(
    memory: &impl CpuMemory,
    vm: u64,
    a: [u64; 6],
) -> Result<crate::futex::Key, Errno> {
    if a[0] & 3 != 0 || a[1] & !0x1ff != 0 {
        return Err(Errno(22));
    }
    memory.check(a[0], 4, Access::Read).map_err(|_| Errno(14))?;
    futex_key(memory, vm, a[0], a[1] & 128 != 0)
}
/// One ABI/validation implementation for owner and worker queue operations.
pub(super) fn futex_queue(
    table: &crate::futex::Futexes,
    memory: &impl CpuMemory,
    vm: u64,
    a: [u64; 6],
) -> Result<crate::futex::Effect, Errno> {
    let key = futex_parameters(memory, vm, a)?;
    match a[1] & 127 {
        op @ (1 | 10) => {
            let bits = if op == 10 { a[5] as u32 } else { u32::MAX };
            if a[2] > i32::MAX as u64 || bits == 0 {
                return Err(Errno(22));
            }
            Ok(table.wake_local(key, a[2] as u32, bits))
        }
        op @ (3 | 4) => {
            if a[4] & 3 != 0 || a[2] > i32::MAX as u64 || a[3] > i32::MAX as u64 {
                return Err(Errno(22));
            }
            memory.check(a[4], 4, Access::Read).map_err(|_| Errno(14))?;
            let new = futex_key(memory, vm, a[4], a[1] & 128 != 0)?;
            table.requeue(key, new, a[2] as u32, a[3] as u32, || {
                if op == 4
                    && u32::from_le_bytes(memory.read_array::<4>(a[0]).map_err(|_| Errno(14))?)
                        != a[5] as u32
                {
                    return Err(Errno(11));
                }
                Ok(())
            })
        }
        _ => Err(Errno(38)),
    }
}

impl Snapshot {
    fn futex_wait<C: Cpu>(&self, cpu: &C) -> bool {
        cpu.x(8) as u32 == 98 && matches!(cpu.x(1) & 127, 0 | 9)
    }
    pub fn wait<C: Cpu>(
        &self,
        cpu: &C,
        memory: &mut impl CpuMemory,
        pid: u32,
        epoch: &Arc<crate::run_queue::Epoch<C>>,
    ) -> Option<Result<crate::run_queue::WaitState, Errno>> {
        if !self.futex_wait(cpu) {
            return None;
        }
        Some((|| {
            let key = futex_parameters(memory, self.futex.vm, std::array::from_fn(|i| cpu.x(i)))?;
            let (bits, deadline) =
                futex_wait_parameters(memory, std::array::from_fn(|i| cpu.x(i)), self.started)?;
            let wait = self.futex.table.wait_target(
                key,
                pid,
                bits,
                Some({
                    let target = Arc::downgrade(epoch);
                    let target: std::sync::Weak<dyn crate::futex::Wake> = target;
                    target
                }),
                || {
                    let value = u32::from_le_bytes(
                        memory.read_array::<4>(cpu.x(0)).map_err(|_| Errno(14))?,
                    );
                    if value != cpu.x(2) as u32 {
                        return Err(Errno(11));
                    }
                    Ok(())
                },
            )?;
            Ok(crate::run_queue::WaitState { wait, deadline })
        })())
    }
    fn futex_queue<C: Cpu>(&self, cpu: &C) -> bool {
        cpu.x(8) as u32 == 98 && matches!(cpu.x(1) & 127, 1 | 10 | 3 | 4)
    }
    pub fn admit<C: Cpu>(&self, cpu: &C) -> bool {
        if cpu.x(8) as u32 == 25 && cpu.x(1) == 4 && cpu.x(2) as u32 & trames_vfs::O_NOATIME != 0 {
            return false;
        }
        if self.seccomp.mode() == 0 {
            return true;
        }
        // Filtered membership entries use the dedicated worker path, which
        // carries their exact decision through an owner-resource fallback.
        if matches!(cpu.x(8) as u32, 23 | 24 | 57)
            || cpu.x(8) as u32 == 25 && matches!(cpu.x(1), 0 | 1030)
        {
            return false;
        }
        // Unsupported calls go straight to the joined kernel, which evaluates
        // their filter once. In particular, do not run BPF twice for each
        // futex/epoll checkpoint. Ordinary unfiltered calls keep the old path.
        if !matches!(
            cpu.x(8) as u32,
            25 | 113 | 114 | 124 | 166 | 168 | 172..=178
        ) && !(cpu.x(8) as u32 == 29 && cpu.x(1) as u32 == 0x5421)
            && !(matches!(cpu.x(8) as u32, 160..=162) && self.uts.is_some())
            && !(cpu.x(8) as u32 == 32 && (cpu.x(1) as u32 & 4 != 0 || cpu.x(1) as u32 == 8))
            && !(cpu.x(8) as u32 == 134 && cpu.x(1) == 0)
            && !(cpu.x(8) as u32 == 214 && cpu.x(0) == 0)
            && !(cpu.x(8) as u32 == 436 && cpu.x(2) as u32 == 4)
            && !self
                .direct
                .supports_call(cpu.x(8) as u32, std::array::from_fn(|i| cpu.x(i)))
            && !service_candidate(cpu, self)
            && !self.futex_queue(cpu)
            && !self.futex_wait(cpu)
        {
            return false;
        }
        self.seccomp
            .allows(cpu.x(8) as u32, cpu.pc(), std::array::from_fn(|i| cpu.x(i)))
    }
    pub fn invoke<C: Cpu>(&self, cpu: &C, memory: &mut impl CpuMemory) -> Option<u64> {
        if let Some(result) = self
            .direct
            .invoke_membership(cpu.x(8) as u32, std::array::from_fn(|i| cpu.x(i)))
        {
            return Some(result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
        }
        if let Some(result) =
            self.direct
                .invoke_file(cpu.x(8) as u32, std::array::from_fn(|i| cpu.x(i)), memory)
        {
            return Some(result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
        }
        let result = match cpu.x(8) as u32 {
            29 if cpu.x(1) as u32 == 0x5421 => {
                let result = (|| {
                    let flags = self.fd_flags.get(cpu.x(0) as u32)?;
                    if flags & trames_vfs::O_PATH != 0 {
                        return Err(Errno(9));
                    }
                    let bytes = memory.read_array::<4>(cpu.x(2)).map_err(|_| Errno(14))?;
                    self.fd_flags
                        .set_nonblocking(cpu.x(0) as u32, u32::from_le_bytes(bytes) != 0)
                })();
                self.direct.record_fd_control();
                result
            }
            number @ (29 | 62..=66 | 73 | 86 | 87 | 116 | 206 | 207 | 210..=212) => self
                .direct
                .invoke(number, std::array::from_fn(|i| cpu.x(i)), memory)?,
            98 if self.futex_queue(cpu) => futex_queue(
                &self.futex.table,
                memory,
                self.futex.vm,
                std::array::from_fn(|i| cpu.x(i)),
            )
            .map(|effect| {
                self.futex.record(&effect, matches!(cpu.x(1) & 127, 3 | 4));
                effect.total()
            }),
            25 if matches!(cpu.x(1), 1..=4) => {
                if cpu.x(1) == 4 && cpu.x(2) as u32 & trames_vfs::O_NOATIME != 0 {
                    return None;
                }
                let result = self.fd_flags.fcntl(cpu.x(0) as u32, cpu.x(1), cpu.x(2));
                self.direct.record_fd_control();
                result
            }
            436 if cpu.x(2) as u32 == 4 => {
                let result = self
                    .fd_flags
                    .cloexec_range(cpu.x(0) as u32, cpu.x(1) as u32);
                self.direct.record_fd_control();
                result
            }
            134 => self
                .actions
                .query(std::array::from_fn(|i| cpu.x(i)), memory)?,
            number @ 160..=162 => trames_linux::uts_call(
                self.uts.as_ref()?,
                number,
                std::array::from_fn(|i| cpu.x(i)),
                memory,
            ),
            166 => Ok(self.umask.swap(cpu.x(0) as u32) as u64),
            214 if cpu.x(0) == 0 => Ok(self.program_break.get()),
            number @ 172..=178 => Ok(self.identities[(number - 172) as usize]),
            number @ (113 | 114) => clock(memory, number, cpu.x(0), cpu.x(1), self.started),
            168 => (|| {
                let cpu_address = cpu.x(0);
                let node_address = cpu.x(1);
                // As on the coordinator, validate both destinations before
                // either store. Writes use the interpreter's exact view/model.
                for address in [cpu_address, node_address] {
                    if address != 0 {
                        memory
                            .check(address, 4, Access::Write)
                            .map_err(|_| Errno(14))?;
                    }
                }
                if cpu_address != 0 {
                    memory
                        .write_array(cpu_address, self.processor.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if node_address != 0 {
                    memory
                        .write_array(node_address, 0u32.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                Ok(0)
            })(),
            _ => return None,
        };
        Some(result.unwrap_or_else(|error| 0u64.wrapping_sub(error.0 as u64)))
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;

    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn queue_abi_checks_before_effects_and_owner_and_view_share_the_same_implementation() {
        fn check(memory: &impl CpuMemory) {
            let table = crate::futex::Futexes::default();
            let first = table
                .wait((0, 7, 0x1000), 1, 1, || Ok::<_, ()>(()))
                .unwrap();
            let second = table
                .wait((0, 7, 0x1000), 2, 2, || Ok::<_, ()>(()))
                .unwrap();
            for (args, error) in [
                ([0x1001, 132, 1, 1, 0x1004, 0], 22),
                ([0x5000, 0x204, 1, 1, 0x1004, 0], 22),
                ([0x5000, 132, 1, 1, 0x1004, 0], 14),
                ([0x1000, 132, 1, 1, 0x1005, 0], 22),
                ([0x1000, 132, i32::MAX as u64 + 1, 1, 0x1004, 0], 22),
                ([0x1000, 132, 1, i32::MAX as u64 + 1, 0x1004, 0], 22),
                ([0x1000, 132, 1, 1, 0x2000, 1], 14),
                ([0x1000, 132, 1, 1, 0x1004, 1], 11),
                ([0x1000, 138, 1, 0, 0, 0], 22),
                ([0x1000, 2, 0, 0, 0, 0], 38),
            ] {
                assert_eq!(futex_queue(&table, memory, 7, args).unwrap_err().0, error);
                assert!(!first.woken() && !second.woken());
            }
            let result = futex_queue(&table, memory, 7, [0x1000, 4, 1, 1, 0x1004, 0]).unwrap();
            assert_eq!((result.woken, result.moved), (1, 1));
            assert!(first.woken() && !second.woken());
            assert_eq!(table.wake((0, 7, 0x1000), 1, 2), 0);
            assert_eq!(table.wake((0, 7, 0x1004), 1, 2), 1);
        }
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        check(&memory);
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        check(&view);
    }
    #[test]
    fn shared_wait_parser_preserves_absolute_clocks_flags_and_error_order() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let started = Instant::now();
        for op in [137, 393] {
            let (bits, deadline) =
                futex_wait_parameters(&memory, [0x1000, op, 0, 0x1100, 0, 2], started).unwrap();
            assert_eq!(bits, 2);
            assert!(deadline.unwrap() <= Instant::now());
        }
        assert_eq!(
            futex_wait_parameters(&memory, [0, 384, 0, 0x1100, 0, 0], started),
            Err(Errno(38))
        );
        assert_eq!(
            futex_wait_parameters(&memory, [0, 384, 0, 0, 0, 0], started),
            Ok((u32::MAX, None))
        );
        memory
            .write_array(0x1108, 1_000_000_000u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            futex_wait_parameters(&memory, [0, 128, 0, 0x1100, 0, 0], started),
            Err(Errno(22))
        );
        assert_eq!(
            futex_wait_parameters(&memory, [0, 128, 0, 0x1ff8, 0, 0], started),
            Err(Errno(14))
        );
        assert_eq!(
            futex_wait_parameters(&memory, [0, 137, 0, 0x3000, 0, 0], started),
            Err(Errno(22))
        );
    }
    #[test]
    fn private_wakes_claim_waiters_and_preserve_bitsets_and_validation() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x1000, 17u32.to_le_bytes()).unwrap();
        let table = crate::futex::Futexes::default();
        let first = table
            .wait((0, 7, 0x1000), 1, 2, || Ok::<_, ()>(()))
            .unwrap();
        let second = table
            .wait((0, 7, 0x1000), 2, 2, || Ok::<_, ()>(()))
            .unwrap();
        let other_vm = table
            .wait((0, 8, 0x1000), 3, 2, || Ok::<_, ()>(()))
            .unwrap();
        let snapshot = Snapshot {
            seccomp: Default::default(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: Default::default(),
            files: Default::default(),
            fd_flags: Default::default(),
            umask: Default::default(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: crate::futex::Authority::new(table, 7),
        };
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let mut cpu = Cpu::new(0x4004, 0);
        cpu.set_x(8, 98);
        cpu.set_x(0, 0x1004);
        cpu.set_x(1, 129);
        cpu.set_x(2, 1);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        cpu.set_x(0, 0x1000);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(1));
        assert!(first.woken());
        assert!(!second.woken() && !other_vm.woken());
        assert!(snapshot.futex.take_readied());
        cpu.set_x(1, 138);
        cpu.set_x(5, 4);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        cpu.set_x(5, 2);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(1));
        assert!(second.woken() && !other_vm.woken());
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        assert!(snapshot.futex.take_readied());
        cpu.set_x(2, 0);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        cpu.set_x(5, 0);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(22))
        );
        cpu.set_x(1, 129);
        cpu.set_x(0, 0x1005);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(22))
        );
        cpu.set_x(0, 0x2000);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(14))
        );
        cpu.set_x(0, 0x1004);
        cpu.set_x(2, 1 << 31);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(22))
        );
        cpu.set_x(1, 1); // Shared-key wake must use the actual backing key.
        cpu.set_x(2, 1);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        assert_eq!(view.read_array::<4>(0x1000).unwrap(), 17u32.to_le_bytes());
    }
    #[test]
    fn clockid_uses_the_linux_low_32_bit_argument_with_syscall_fallback() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let started = Instant::now();
        assert_eq!(
            clock(&mut memory, 113, 0x1234_0000_0001, 0x1000, started),
            Ok(0)
        );
        assert_eq!(
            clock(&mut memory, 113, u64::MAX, 0x1000, started),
            Err(Errno(22))
        );
    }
    #[test]
    fn coarse_clocks_share_the_epoch_of_their_high_resolution_counterparts() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let snapshot = Snapshot {
            seccomp: Default::default(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: [0; (trames_vfs::MAX_FDS as usize).div_ceil(64)],
            files: [0; (trames_vfs::MAX_FDS as usize).div_ceil(64)],
            fd_flags: Default::default(),
            umask: Default::default(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: Default::default(),
        };
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let mut cpu = Cpu::new(0, 0);
        cpu.set_x(8, 113);
        cpu.set_x(1, 0x1000);
        for id in [0, 5, 1, 4, 6, 7] {
            let before = if matches!(id, 0 | 5) {
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            } else {
                snapshot.started.elapsed()
            };
            cpu.set_x(0, id);
            assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
            let seconds = view.read_u64(0x1000).unwrap();
            let nanos = view.read_u64(0x1008).unwrap();
            assert!(nanos < 1_000_000_000);
            let stamp = std::time::Duration::new(seconds, nanos as u32);
            let after = if matches!(id, 0 | 5) {
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            } else {
                snapshot.started.elapsed()
            };
            assert!(before <= stamp && stamp <= after, "clock {id}: {stamp:?}");
            cpu.set_x(8, 114);
            cpu.set_x(1, 0);
            assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
            cpu.set_x(8, 113);
            cpu.set_x(1, 0x1000);
        }
    }
    #[test]
    fn fd_metadata_controls_and_membership_changes_complete_locally() {
        let mut vfs = trames_vfs::Vfs::default();
        let [fd, _] = vfs
            .pipe(trames_vfs::O_CLOEXEC | trames_vfs::O_NONBLOCK)
            .unwrap();
        let mut snapshot = Snapshot {
            seccomp: Default::default(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: vfs.stream_descriptors(),
            files: vfs.file_descriptors(),
            fd_flags: vfs.fd_flags_snapshot(),
            umask: vfs.umask_capability(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: Default::default(),
        };
        let mut memory = Memory::default();
        let mut cpu = Cpu::new(0, 0);
        cpu.set_x(8, 25);
        cpu.set_x(0, fd as u64);
        cpu.set_x(1, 1);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(1));
        cpu.set_x(1, 3);
        assert_eq!(
            snapshot.invoke(&cpu, &mut memory),
            Some(trames_vfs::O_NONBLOCK as u64)
        );
        cpu.set_x(1, 4);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(0));
        assert_eq!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
        cpu.set_x(1, 2);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(0));
        assert_eq!(vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC, 0);
        cpu.set_x(1, 0);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), None);
        assert!(!service_candidate(&cpu, &snapshot));
        snapshot.direct = trames_linux::DirectSyscalls::default()
            .with_membership(vfs.shared_files())
            .with_lock_context(vfs.record_lock_context(1));
        cpu.set_x(1, 1030);
        cpu.set_x(2, 160);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(160));
        cpu.set_x(0, 160);
        cpu.set_x(1, 1);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(1));
        cpu.set_x(8, 24);
        cpu.set_x(1, 200);
        cpu.set_x(2, 0);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(200));
        cpu.set_x(8, 57);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(0));
        assert_eq!(vfs.flags(160), Err(Errno(9)));
        assert!(vfs.flags(fd).is_ok() && vfs.flags(200).is_ok());
        cpu.set_x(8, 25);
        cpu.set_x(0, u32::MAX as u64);
        cpu.set_x(1, 3);
        assert_eq!(
            snapshot.invoke(&cpu, &mut memory),
            Some(0u64.wrapping_sub(9))
        );
    }

    #[test]
    fn fionbio_uses_shared_status_preserves_append_and_validates_before_effects() {
        let mut vfs = trames_vfs::Vfs::default();
        let [fd, _] = vfs.pipe(trames_vfs::O_CLOEXEC).unwrap();
        vfs.set_status_flags(fd, 0x400).unwrap();
        let alias = vfs.dup(fd, 0, false).unwrap();
        let path = vfs
            .open_at(trames_vfs::AT_FDCWD, b"/", trames_vfs::O_PATH, 0)
            .unwrap();
        let snapshot = Snapshot {
            seccomp: Default::default(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: vfs.stream_descriptors(),
            files: vfs.file_descriptors(),
            fd_flags: vfs.fd_flags_snapshot(),
            umask: vfs.umask_capability(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: Default::default(),
        };
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x1000, 1u32.to_le_bytes()).unwrap();
        let mut cpu = Cpu::new(0, 0);
        cpu.set_x(8, 29);
        cpu.set_x(0, alias as u64);
        cpu.set_x(1, 0x5421);
        cpu.set_x(2, 0x1000);
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(0));
        assert_eq!(
            vfs.flags(fd).unwrap(),
            trames_vfs::O_CLOEXEC | trames_vfs::O_NONBLOCK | 0x400
        );
        cpu.set_x(2, u64::MAX);
        assert_eq!(
            snapshot.invoke(&cpu, &mut memory),
            Some(0u64.wrapping_sub(14))
        );
        assert_ne!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
        cpu.set_x(0, path as u64);
        assert_eq!(
            snapshot.invoke(&cpu, &mut memory),
            Some(0u64.wrapping_sub(9))
        );
        cpu.set_x(0, u32::MAX as u64);
        assert_eq!(
            snapshot.invoke(&cpu, &mut memory),
            Some(0u64.wrapping_sub(9))
        );
        cpu.set_x(0, fd as u64);
        cpu.set_x(2, 0x1000);
        memory.write_array(0x1000, 0u32.to_le_bytes()).unwrap();
        assert_eq!(snapshot.invoke(&cpu, &mut memory), Some(0));
        assert_eq!(vfs.flags(alias).unwrap(), 0x400);
        assert_eq!(snapshot.direct.fd_control_completed(), 5);
    }

    #[test]
    fn clock_and_processor_writes_use_checked_shared_guest_memory() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        memory.write_array(0x1ff8, [0x5a; 8]).unwrap();
        memory.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        let snapshot = Snapshot {
            seccomp: Default::default(),
            identities: [1, 0, 1000, 1001, 2000, 2001, 2],
            started: Instant::now(),
            processor: 3,
            profile: false,
            streams: [0; (trames_vfs::MAX_FDS as usize).div_ceil(64)],
            files: [0; (trames_vfs::MAX_FDS as usize).div_ceil(64)],
            fd_flags: Default::default(),
            umask: Default::default(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: Default::default(),
        };
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let mut cpu = Cpu::new(0, 0);
        cpu.set_x(8, 113);
        cpu.set_x(0, 1);
        cpu.set_x(1, 0x1ff8);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(14))
        );
        assert_eq!(view.read_array::<8>(0x1ff8).unwrap(), [0x5a; 8]);
        cpu.set_x(0, 2);
        cpu.set_x(1, 0);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(22))
        );
        cpu.set_x(8, 114);
        cpu.set_x(0, 1);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        cpu.set_x(1, 0xab00000000001800);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        assert_eq!(
            view.read_array::<16>(0x1800).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
        cpu.set_x(8, 113);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        assert!(view.read_u64(0x1808).unwrap() < 1_000_000_000);
        cpu.set_x(8, 168);
        cpu.set_x(0, 0x1ff8);
        cpu.set_x(1, 0x2000);
        assert_eq!(
            snapshot.invoke(&cpu, &mut view),
            Some(0u64.wrapping_sub(14))
        );
        assert_eq!(view.read_array::<8>(0x1ff8).unwrap(), [0x5a; 8]);
        cpu.set_x(1, 0x1ffc);
        assert_eq!(snapshot.invoke(&cpu, &mut view), Some(0));
        drop(view);
        memory.commit_parallel().unwrap();
        assert_eq!(
            memory.read_array::<8>(0x1ff8).unwrap(),
            [3, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
