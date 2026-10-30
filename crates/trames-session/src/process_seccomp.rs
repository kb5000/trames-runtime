// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest classic-BPF seccomp. Immutable programs run only at syscall entry;
//! filters never reach the host kernel and add no CPU/memory hot-path work.
use super::*;
use std::sync::Arc;

const ALLOW: u32 = 0x7fff_0000;
const KILL_PROCESS: u32 = 0x8000_0000;
const ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
const MAX_INSNS: usize = 4096;
const MAX_PATH: usize = 32768;

#[derive(Clone, Copy)]
struct Instruction {
    code: u16,
    yes: u8,
    no: u8,
    value: u32,
}
struct Filter(Vec<Instruction>);
#[derive(Default, Clone)]
pub(crate) struct Seccomp {
    strict: bool,
    // Immutable across a CPU epoch. Cloning a process/worker snapshot is O(1);
    // installation copies only the small chain of program handles after join.
    filters: Arc<Vec<Arc<Filter>>>,
    #[cfg(all(test, trames_interpreter_conformance))]
    evaluations: Arc<std::sync::atomic::AtomicU64>,
}
/// A single immutable BPF result, bound to its exact architectural entry and
/// filter chain. A deferred denial must not rerun BPF or apply actions locally.
pub(super) struct EntryDecision {
    policy: Seccomp,
    number: u32,
    pc: u64,
    args: [u64; 6],
    value: u32,
}
impl EntryDecision {
    pub(super) fn allowed(&self) -> bool {
        self.value & 0xffff_0000 == ALLOW
    }
    fn value_for(self, policy: &Seccomp, number: u32, pc: u64, args: [u64; 6]) -> Option<u32> {
        (self.number == number
            && self.pc == pc
            && self.args == args
            && self.policy.strict == policy.strict
            && Arc::ptr_eq(&self.policy.filters, &policy.filters))
        .then_some(self.value)
    }
}
impl Seccomp {
    fn push(&mut self, filter: Arc<Filter>) {
        Arc::make_mut(&mut self.filters).push(filter);
    }
    pub fn allows(&self, number: u32, pc: u64, args: [u64; 6]) -> bool {
        self.decision(number, pc, args) & 0xffff_0000 == ALLOW
    }
    pub fn mode(&self) -> u32 {
        if self.strict {
            1
        } else if self.filters.is_empty() {
            0
        } else {
            2
        }
    }
    pub fn count(&self) -> usize {
        self.filters.len()
    }
    fn ancestor_of(&self, other: &Self) -> bool {
        !self.strict
            && self.filters.len() <= other.filters.len()
            && self
                .filters
                .iter()
                .zip(other.filters.iter())
                .all(|(a, b)| Arc::ptr_eq(a, b))
    }
    pub(super) fn entry_decision(&self, number: u32, pc: u64, args: [u64; 6]) -> EntryDecision {
        EntryDecision {
            policy: self.clone(),
            number,
            pc,
            args,
            value: self.decision(number, pc, args),
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn evaluations(&self) -> u64 {
        self.evaluations.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn decision(&self, number: u32, pc: u64, args: [u64; 6]) -> u32 {
        #[cfg(all(test, trames_interpreter_conformance))]
        self.evaluations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.strict {
            return if matches!(number, 63 | 64 | 93 | 139) {
                ALLOW
            } else {
                0
            };
        }
        if self.filters.is_empty() {
            return ALLOW;
        }
        let mut input = [0u32; 16];
        input[0] = number;
        input[1] = ARCH;
        input[2] = pc as u32;
        input[3] = (pc >> 32) as u32;
        for (i, a) in args.into_iter().enumerate() {
            input[4 + i * 2] = a as u32;
            input[5 + i * 2] = (a >> 32) as u32;
        }
        self.filters.iter().rev().fold(ALLOW, |old, filter| {
            let new = filter.run(&input);
            if ((new & 0xffff_0000) as i32) < ((old & 0xffff_0000) as i32) {
                new
            } else {
                old
            }
        })
    }
}
impl Filter {
    fn load(memory: &Memory, address: u64) -> Result<Self, Errno> {
        Linux::check(memory, address, 16, Access::Read)?;
        let mut header = [0; 16];
        memory.read(address, &mut header).map_err(|_| Errno(14))?;
        let n = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
        if n == 0 || n > MAX_INSNS {
            return Err(Errno(22));
        }
        let pointer = u64::from_le_bytes(header[8..16].try_into().unwrap());
        Linux::check(memory, pointer, n * 8, Access::Read)?;
        let mut bytes = vec![0; n * 8];
        memory.read(pointer, &mut bytes).map_err(|_| Errno(14))?;
        let code: Vec<_> = bytes
            .chunks_exact(8)
            .map(|i| Instruction {
                code: u16::from_le_bytes(i[..2].try_into().unwrap()),
                yes: i[2],
                no: i[3],
                value: u32::from_le_bytes(i[4..8].try_into().unwrap()),
            })
            .collect();
        Self::validate(code)
    }
    fn validate(code: Vec<Instruction>) -> Result<Self, Errno> {
        if code.is_empty()
            || code.len() > MAX_INSNS
            || !matches!(code.last().unwrap().code, 0x06 | 0x16)
        {
            return Err(Errno(22));
        }
        let mut initialized = vec![None; code.len()];
        initialized[0] = Some(0u16);
        for (pc, i) in code.iter().enumerate() {
            let mut mask = initialized[pc];
            let mut targets = vec![pc + 1];
            match i.code {
                0x00 | 0x01 | 0x80 | 0x81 | 0x07 | 0x87 => {}
                0x20 if i.value < 64 && i.value.is_multiple_of(4) => {}
                0x60 | 0x61 if i.value < 16 => {
                    if mask.is_some_and(|m| m & (1 << i.value) == 0) {
                        return Err(Errno(22));
                    }
                }
                0x02 | 0x03 if i.value < 16 => {
                    mask = mask.map(|m| m | (1 << i.value));
                }
                0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x4c | 0x44 | 0x54 | 0x5c | 0x6c
                | 0x7c | 0x84 | 0xac | 0xa4 | 0x3c | 0x9c => {}
                0x34 | 0x94 if i.value != 0 => {}
                0x64 | 0x74 if i.value < 32 => {}
                0x05 => {
                    targets = vec![pc
                        .checked_add(i.value as usize)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(Errno(22))?];
                }
                0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                    targets = vec![pc + 1 + i.yes as usize, pc + 1 + i.no as usize];
                }
                0x06 | 0x16 => targets.clear(),
                _ => return Err(Errno(22)),
            }
            for target in targets {
                if target >= code.len() {
                    return Err(Errno(22));
                }
                if let Some(mask) = mask {
                    initialized[target] = Some(initialized[target].map_or(mask, |old| old & mask));
                }
            }
        }
        Ok(Self(code))
    }
    fn run(&self, input: &[u32; 16]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let mut scratch = [0u32; 16];
        while let Some(i) = self.0.get(pc) {
            pc += 1;
            match i.code {
                0x00 => a = i.value,
                0x01 => x = i.value,
                0x20 => a = input[(i.value / 4) as usize],
                0x80 => a = 64,
                0x81 => x = 64,
                0x60 => a = scratch[i.value as usize],
                0x61 => x = scratch[i.value as usize],
                0x02 => scratch[i.value as usize] = a,
                0x03 => scratch[i.value as usize] = x,
                0x07 => x = a,
                0x87 => a = x,
                0x06 => return i.value,
                0x16 => return a,
                0x05 => pc += i.value as usize,
                c if c & 7 == 4 => {
                    let v = if c & 8 != 0 { x } else { i.value };
                    a = match c & 0xf0 {
                        0x00 => a.wrapping_add(v),
                        0x10 => a.wrapping_sub(v),
                        0x20 => a.wrapping_mul(v),
                        0x30 => {
                            if v == 0 {
                                return 0;
                            } else {
                                a / v
                            }
                        }
                        0x40 => a | v,
                        0x50 => a & v,
                        0x60 => a.checked_shl(v).unwrap_or(0),
                        0x70 => a.checked_shr(v).unwrap_or(0),
                        0x80 => a.wrapping_neg(),
                        0x90 => {
                            if v == 0 {
                                return 0;
                            } else {
                                a % v
                            }
                        }
                        0xa0 => a ^ v,
                        _ => return KILL_PROCESS,
                    };
                }
                c if c & 7 == 5 => {
                    let v = if c & 8 != 0 { x } else { i.value };
                    let yes = match c & 0xf0 {
                        0x10 => a == v,
                        0x20 => a > v,
                        0x30 => a >= v,
                        0x40 => a & v != 0,
                        _ => false,
                    };
                    pc += if yes { i.yes } else { i.no } as usize;
                }
                _ => return KILL_PROCESS,
            }
        }
        KILL_PROCESS
    }
}
impl<C: Cpu> Kernel<C> {
    pub(super) fn seccomp(&mut self, p: &mut Process<C>, a: [u64; 6]) -> Result<u64, Errno> {
        match a[0] {
            0 => {
                if a[1] != 0 || a[2] != 0 || p.seccomp.mode() != 0 {
                    return Err(Errno(22));
                }
                p.seccomp.strict = true;
                Ok(0)
            }
            1 => {
                // TSYNC supported. Other installation modes fail explicitly;
                // in particular no fake notification listener FD is returned.
                if a[1] & !1 != 0 || p.seccomp.strict {
                    return Err(Errno(22));
                }
                if !p.linux.vfs.credentials.caps.no_new_privs
                    && !p.linux.vfs.credentials.has_cap(capabilities::SYS_ADMIN)
                {
                    return Err(Errno(13));
                }
                let filter = Arc::new(Filter::load(&p.memory, a[2])?);
                if p.seccomp
                    .filters
                    .iter()
                    .map(|f| f.0.len() + 4)
                    .sum::<usize>()
                    + filter.0.len()
                    > MAX_PATH
                {
                    return Err(Errno(12));
                }
                if a[1] & 1 != 0 {
                    if let Some((&id, _)) = self.processes.iter().find(|(_, t)| {
                        t.tgid == p.tgid
                            && !matches!(t.state, State::Zombie(_))
                            && !t.seccomp.ancestor_of(&p.seccomp)
                    }) {
                        return Ok(p.linux.vfs.visible_pid(id) as u64);
                    }
                }
                p.seccomp.push(filter);
                if a[1] & 1 != 0 {
                    for t in self
                        .processes
                        .values_mut()
                        .filter(|t| t.tgid == p.tgid && !matches!(t.state, State::Zombie(_)))
                    {
                        t.seccomp = p.seccomp.clone();
                        t.linux.vfs.credentials.caps.no_new_privs |=
                            p.linux.vfs.credentials.caps.no_new_privs;
                    }
                }
                Ok(0)
            }
            2 => {
                if a[1] != 0 {
                    return Err(Errno(22));
                }
                let action = read_u32(&p.memory, a[2])?;
                if matches!(
                    action,
                    0 | KILL_PROCESS | 0x0003_0000 | 0x0005_0000 | 0x7ff0_0000 | ALLOW
                ) {
                    Ok(0)
                } else {
                    Err(Errno(95))
                }
            }
            _ => Err(Errno(22)),
        }
    }
    /// True means the syscall was consumed without executing its implementation.
    pub(super) fn filter_syscall(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        args: [u64; 6],
    ) -> bool {
        let decision = p
            .seccomp_entry
            .take()
            .and_then(|entry| entry.value_for(&p.seccomp, number, p.cpu.pc(), args))
            .unwrap_or_else(|| p.seccomp.decision(number, p.cpu.pc(), args));
        match decision & 0xffff_0000 {
            ALLOW => return false,
            0x0005_0000 => {
                p.cpu.set_x(0, error(Errno((decision & 0xffff).min(4095))));
                p.state = State::Ready;
            }
            0x7ff0_0000 | 0x7fc0_0000 => {
                p.cpu.set_x(0, error(Errno(38)));
                p.state = State::Ready;
            }
            0x0003_0000 => {
                // force_sig_seccomp cannot be suppressed by ignoring or
                // blocking SIGSYS; Linux forces its fatal default action.
                if p.signals.mask & (1u64 << 30) != 0 || p.signals.actions.get(31).handler == 1 {
                    self.exit(pid, p, 31);
                    return true;
                }
                // ARM64 syscall_rollback restores the original x0 argument.
                // The syscall number lives in x8 and siginfo; replacing x0
                // would corrupt the arguments inspected by a SIGSYS broker.
                p.state = State::Ready;
                p.signals.pending.discard(31);
                let _ = p.signals.pending.enqueue(
                    31,
                    Info {
                        sender: decision & 0xffff,
                        uid: ARCH,
                        status: number as i32,
                        code: 1,
                        timer: None,
                        fault: Some(p.cpu.pc()),
                    },
                );
                if self.deliver(pid, p).is_err() {
                    self.exit(pid, p, 31);
                }
            }
            0 => self.exit_one(pid, p, 31),
            _ => self.exit(pid, p, 31), // Unknown actions fail closed, as Linux does.
        }
        true
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::*;
    #[test]
    fn cached_mapping_decision_is_bound_to_entry_and_filter_identity() {
        let mut policy = Seccomp::default();
        policy.push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
        let args = [0x8000, trames_memory::PAGE_SIZE, 0, 0, 0, 0];
        assert_eq!(
            policy
                .entry_decision(215, 0x4004, args)
                .value_for(&policy, 215, 0x4004, args),
            Some(ALLOW)
        );
        assert!(policy
            .entry_decision(215, 0x4004, args)
            .value_for(&policy, 233, 0x4004, args)
            .is_none());
        assert!(policy
            .entry_decision(215, 0x4004, args)
            .value_for(&policy, 215, 0x4008, args)
            .is_none());
        let mut changed = args;
        changed[1] += trames_memory::PAGE_SIZE;
        assert!(policy
            .entry_decision(215, 0x4004, args)
            .value_for(&policy, 215, 0x4004, changed)
            .is_none());
        let mut p = super::super::tests::process();
        p.cpu.pc = 0x4004;
        p.seccomp = policy.clone();
        p.seccomp_entry = Some(policy.entry_decision(215, p.cpu.pc, args));
        p.seccomp.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x0005_000d)]).unwrap(),
        ));
        let mut kernel = super::super::tests::kernel();
        kernel.call(
            1,
            &mut p,
            215,
            args,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(p.cpu.x(0), error(Errno(13)));
        assert!(p.memory.read_array::<1>(0x8000).is_ok());
        assert!(p.seccomp_entry.is_none());
    }
    #[test]
    fn filtered_membership_changes_stay_joined_before_filter_evaluation_or_effects() {
        for decision in [ALLOW, 0x5007b] {
            let mut p = super::super::tests::process();
            let [fd, _] = p.linux.vfs.pipe(0).unwrap();
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                profile: false,
                streams: p.linux.vfs.stream_descriptors(),
                files: p.linux.vfs.file_descriptors(),
                fd_flags: p.linux.vfs.fd_flags_snapshot(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: trames_linux::DirectSyscalls::default()
                    .with_membership(p.linux.vfs.shared_files()),
                futex: Default::default(),
            };
            for (number, args) in [
                (23, [fd as u64, 0, 0, 0, 0, 0]),
                (24, [fd as u64, 200, 0, 0, 0, 0]),
                (57, [fd as u64, 0, 0, 0, 0, 0]),
                (25, [fd as u64, 0, 160, 0, 0, 0]),
                (25, [fd as u64, 1030, 160, 0, 0, 0]),
            ] {
                p.cpu.set_x(8, number as u64);
                put_args(&mut p.cpu, args);
                assert!(!snapshot.admit(&p.cpu));
                assert_eq!(p.linux.vfs.flags(160), Err(Errno(9)));
                assert_eq!(p.linux.vfs.flags(200), Err(Errno(9)));
                assert!(p.linux.vfs.flags(fd).is_ok());
            }
            assert_eq!(snapshot.direct.fd_control_completed(), 0);
        }
    }
    #[test]
    fn private_shared_futex_wait_wake_and_requeue_require_an_allow_decision() {
        let table = crate::futex::Futexes::default();
        let wait = table
            .wait((0, 7, 0x1000), 3, 1, || Ok::<_, ()>(()))
            .unwrap();
        let mut snapshot = crate::worker_syscalls::Snapshot {
            seccomp: Default::default(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: [0; (MAX_FDS as usize).div_ceil(64)],
            files: [0; (MAX_FDS as usize).div_ceil(64)],
            fd_flags: Default::default(),
            umask: Default::default(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
            futex: crate::futex::Authority::new(table, 7),
        };
        let mut cpu = Cpu::new(0x4004, 0);
        cpu.set_x(8, 98);
        for op in [0, 9, 1, 10, 3, 4, 128, 137, 129, 138, 131, 132] {
            put_args(&mut cpu, [0x1000, op, 1, 1, 0x1004, 1]);
            for decision in [ALLOW, 0x50007, 0x30009, 0, KILL_PROCESS] {
                snapshot.seccomp = Seccomp::default();
                snapshot.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, decision)]).unwrap(),
                ));
                assert_eq!(snapshot.admit(&cpu), decision == ALLOW);
                assert!(!wait.woken());
            }
            snapshot.seccomp.strict = true;
            assert!(!snapshot.admit(&cpu));
        }
    }

    #[test]
    fn allowed_filtered_identity_calls_continue_on_workers_without_peer_checkpoints() {
        let mut p = super::super::tests::process();
        for (index, word) in [0xd2801588u32, 0xd4000001, 0x17ffffff]
            .into_iter()
            .enumerate()
        {
            p.memory
                .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.affinity = 15;
        p.seccomp
            .push(Arc::new(Filter::validate(vec![i(6, 0, 0, ALLOW)]).unwrap()));
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 4;
        kernel.workers = crate::workers::Pool::new(4);
        kernel.per_cpu = vec![Duration::ZERO; 4];
        for id in 2..=4 {
            let mut peer = p.fork();
            peer.parent = 1;
            kernel.processes.insert(id, peer);
        }
        kernel.processes.insert(1, p);
        // Host scheduling and instrumentation can end a round after just one
        // syscall per task. Assert guest progress, not a host-time throughput.
        for _ in 0..128 {
            assert!(kernel
                .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
                .unwrap());
            assert_eq!(
                kernel.syscalls, kernel.worker_syscalls,
                "identity queries must not checkpoint"
            );
            if kernel.worker_syscalls > 100 {
                break;
            }
        }
        assert!(
            kernel.worker_syscalls > 100,
            "allowed calls must stay on their workers: worker={} owner={} instructions={} tasks={:?}",
            kernel.worker_syscalls, kernel.syscalls, kernel.instructions,
            kernel.processes.iter().map(|(id,p)| (*id,p.cpu.pc,p.cpu.x(8),p.cpu.x(0))).collect::<Vec<_>>()
        );
        assert_eq!(
            kernel.syscalls, kernel.worker_syscalls,
            "identity queries must not checkpoint"
        );
    }
    #[test]
    fn worker_filter_snapshots_keep_pc_arguments_and_immutable_installation_order() {
        let mut current = Seccomp::default();
        current.push(Arc::new(
            Filter::validate(vec![
                i(0x20, 0, 0, 8), // post-SVC PC low word
                i(0x15, 0, 4, 0x4004),
                i(0x20, 0, 0, 60), // sixth argument high word
                i(0x15, 0, 2, 7),
                i(0x06, 0, 0, ALLOW | 19),
                i(0x06, 0, 0, KILL_PROCESS),
                i(0x06, 0, 0, 0x30007),
            ])
            .unwrap(),
        ));
        let args = [1, 2, 3, 4, 5, 7 << 32];
        let worker = current.clone();
        current.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x50009)]).unwrap(),
        ));
        // A worker owns only immutable, Send+Sync programs. Later installation
        // does not mutate a snapshot; the next joined epoch gets the new chain.
        std::thread::spawn(move || {
            assert!(worker.allows(113, 0x4004, args));
            assert!(!worker.allows(113, 0x4008, args));
            assert!(!worker.allows(113, 0x4004, [0; 6]));
        })
        .join()
        .unwrap();
        assert!(!current.allows(113, 0x4004, args));
        let strict = Seccomp {
            strict: true,
            ..Default::default()
        };
        assert!(strict.allows(63, 0, [0; 6]));
        assert!(!strict.allows(113, 0, [0; 6]));
    }
    #[test]
    fn strict_allowed_reads_use_worker_local_shared_resources() {
        let mut p = super::super::tests::process();
        let [read, write] = p.linux.vfs.pipe(O_NONBLOCK).unwrap();
        p.linux.vfs.write(write, b"abcdefgh").unwrap();
        p.memory
            .write_array(0x4000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x4004, 0x14000000u32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_x(8, 63);
        put_args(&mut p.cpu, [read as u64, 0x1000, 4, 0, 0, 0]);
        p.affinity = 3;
        p.seccomp.strict = true;
        let mut peer = p.fork();
        peer.parent = 1;
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.workers = crate::workers::Pool::new(2);
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.processes.insert(1, p);
        kernel.processes.insert(2, peer);
        assert!(kernel
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
            .unwrap());
        // A peer may reach the shared budget before the other is scheduled;
        // an epoch ending is not a filter rejection. At least one actual read
        // must complete on its worker, without an RPC or checkpoint.
        assert!(kernel.worker_direct_syscalls > 0);
        assert_eq!(kernel.serviced_syscalls, 0);
        assert_eq!(kernel.service_requests, 0);
        let mut received: Vec<_> = kernel
            .processes
            .values()
            .filter(|p| p.cpu.x(0) == 4)
            .map(|p| p.memory.read_array::<4>(0x1000).unwrap())
            .collect();
        received.sort();
        assert_eq!(received, [*b"abcd", *b"efgh"][..received.len()]);
    }
    #[test]
    fn denied_filtered_reads_do_not_issue_services_or_consume_pipe_bytes() {
        let mut p = super::super::tests::process();
        let [read, write] = p.linux.vfs.pipe(O_NONBLOCK).unwrap();
        p.linux.vfs.write(write, b"unchanged").unwrap();
        p.memory.write_array(0x1000, [0x5a; 8]).unwrap();
        p.memory
            .write_array(0x4000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x4004, 0x17ffffffu32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_x(8, 63);
        put_args(&mut p.cpu, [read as u64, 0x1000, 8, 0, 0, 0]);
        p.affinity = 3;
        p.seccomp.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x5007b)]).unwrap(),
        ));
        let mut peer = p.fork();
        peer.parent = 1;
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.workers = crate::workers::Pool::new(2);
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.processes.insert(1, p);
        kernel.processes.insert(2, peer);
        assert!(kernel
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
            .unwrap());
        assert_eq!(kernel.service_requests, 0);
        assert!(kernel.syscalls > 0);
        for p in kernel.processes.values() {
            assert_eq!(p.memory.read_array::<8>(0x1000), Ok([0x5a; 8]));
            if p.cpu.pc == 0x4004 {
                assert_eq!(p.cpu.x(0), error(Errno(123)));
            }
        }
        assert_eq!(
            kernel
                .processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .read(read, 9)
                .unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn worker_fd_status_controls_obey_seccomp_before_atomic_effects() {
        for allowed in [false, true] {
            for (number, command, argument, bit) in [
                (25, 4, O_NONBLOCK as u64, O_NONBLOCK),
                (29, 0x5421, 0x1000, O_NONBLOCK),
                (25, 2, 1, trames_vfs::O_CLOEXEC),
                (436, u32::MAX as u64, 4, trames_vfs::O_CLOEXEC),
            ] {
                let mut p = super::super::tests::process();
                let [fd, _] = p.linux.vfs.pipe(0).unwrap();
                p.memory.write_array(0x1000, 1u32.to_le_bytes()).unwrap();
                p.cpu.set_x(8, number);
                put_args(&mut p.cpu, [fd as u64, command, argument, 0, 0, 0]);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })])
                        .unwrap(),
                ));
                let snapshot = crate::worker_syscalls::Snapshot {
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    profile: false,
                    streams: p.linux.vfs.stream_descriptors(),
                    files: p.linux.vfs.file_descriptors(),
                    fd_flags: p.linux.vfs.fd_flags_snapshot(),
                    umask: p.linux.vfs.umask_capability(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    direct: Default::default(),
                    futex: Default::default(),
                };
                assert_eq!(snapshot.admit(&p.cpu), allowed);
                if allowed {
                    assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
                }
                assert_eq!(p.linux.vfs.flags(fd).unwrap() & bit != 0, allowed);
            }
        }
    }
    #[test]
    fn worker_flock_checks_seccomp_and_defers_blocking_conversion_before_effects() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            let fd = p.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
            let other = p.linux.vfs.open_at(-100, b"/lock", 2, 0).unwrap();
            p.cpu.set_x(8, 32);
            put_args(&mut p.cpu, [fd as u64, 6, 0, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let mut epoch = trames_vfs::FileEpoch::default();
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                profile: false,
                streams: Default::default(),
                files: Default::default(),
                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                    .with_files(epoch.capture(&p.linux.vfs, true)),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
            }
            assert_eq!(
                p.linux.vfs.flock(other, 6),
                if allowed { Err(Errno(11)) } else { Ok(()) }
            );
            p.linux.vfs.flock(other, 8).unwrap();
            p.linux.vfs.flock(fd, 5).unwrap();
            p.linux.vfs.flock(other, 5).unwrap();
            p.cpu.set_x(1, 2); // A blocking conversion must not drop the SH lock.
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), None);
            assert_eq!(p.linux.vfs.flock(other, 6), Err(Errno(11)));
            epoch.finish();
        }
    }

    #[test]
    fn worker_brk_queries_obey_seccomp_and_mapping_changes_defer() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.cpu.set_x(8, 214);
            put_args(&mut p.cpu, [0; 6]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                profile: false,
                streams: Default::default(),
                files: Default::default(),
                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0xa000));
            }
            let before = p.linux.heap_context();
            p.cpu.set_x(0, 0xb000);
            assert!(!snapshot.admit(&p.cpu));
            assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), None);
            assert_eq!(p.linux.heap_context(), before);
        }
    }

    #[test]
    fn worker_sigaction_queries_obey_seccomp_and_mutations_defer_without_effects() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.signals.actions.set_handler(10, 0x5000);
            p.cpu.set_x(8, 134);
            put_args(&mut p.cpu, [10, 0, 0x1000, 8, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                profile: false,
                streams: Default::default(),
                files: Default::default(),
                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
            }
            assert_eq!(
                p.memory.read_u64(0x1000).unwrap(),
                if allowed { 0x5000 } else { 0 }
            );
            p.cpu.set_x(1, 0x1100);
            assert!(!snapshot.admit(&p.cpu));
            assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), None);
            assert_eq!(p.signals.actions.get(10).handler, 0x5000);
        }
    }
    #[test]
    fn worker_uts_filters_mutation_and_reads_live_namespace() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.memory.write_array(0x1000, *b"worker").unwrap();
            p.cpu.set_x(8, 161);
            put_args(&mut p.cpu, [0x1000, 6, 0, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
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
                uts: Some(p.linux.vfs.uts_capability()),
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                let mut view = p.memory.parallel_view(&mut Default::default()).unwrap();
                assert_eq!(snapshot.invoke(&p.cpu, &mut view), Some(0));
                assert_eq!(p.linux.vfs.uts_name(false), b"worker");
                p.linux.vfs.set_uts_name(false, b"visible").unwrap();
                p.cpu.set_x(8, 160);
                put_args(&mut p.cpu, [0x1000, 0, 0, 0, 0, 0]);
                assert!(snapshot.admit(&p.cpu));
                assert_eq!(snapshot.invoke(&p.cpu, &mut view), Some(0));
                assert_eq!(
                    trames_memory::CpuMemory::read_array::<8>(&view, 0x1000 + 65).unwrap(),
                    *b"visible\0"
                );
            } else {
                assert_eq!(p.linux.vfs.uts_name(false), b"trames");
            }
        }
    }
    #[test]
    fn worker_syslog_checks_filter_authority_and_output_before_clear() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            p.linux.vfs.log(4, "worker syslog retained");
            p.memory
                .map(0x20000, 4096, trames_memory::Permissions::RW)
                .unwrap();
            p.cpu.set_x(8, 116);
            put_args(&mut p.cpu, [4, 0x20000, 4096, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
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
                direct: trames_linux::DirectSyscalls::default()
                    .with_kernel_log(p.linux.vfs.kernel_log_capability()),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                let mut view = p.memory.parallel_view(&mut Default::default()).unwrap();
                put_args(&mut p.cpu, [2, 0x20000, 4096, 0, 0, 0]);
                assert!(snapshot.admit(&p.cpu));
                put_args(&mut p.cpu, [4, 0x20fff, 2, 0, 0, 0]);
                assert_eq!(snapshot.invoke(&p.cpu, &mut view), Some(error(Errno(14))));
                assert!(!p.linux.vfs.syslog(3, 4096).unwrap().is_empty());
                put_args(&mut p.cpu, [4, 0x20000, 4096, 0, 0, 0]);
                let length = snapshot.invoke(&p.cpu, &mut view).unwrap();
                assert!(length > 0 && length < 4096);
                let mut bytes = vec![0; length as usize];
                trames_memory::CpuMemory::read(&view, 0x20000, &mut bytes).unwrap();
                assert!(String::from_utf8(bytes)
                    .unwrap()
                    .contains("worker syslog retained"));
                assert!(p.linux.vfs.syslog(3, 4096).unwrap().is_empty());
            } else {
                assert!(!p.linux.vfs.syslog(3, 4096).unwrap().is_empty());
            }
        }
    }
    #[test]
    fn worker_umask_checks_seccomp_and_shares_only_its_fs_domain() {
        for allowed in [false, true] {
            let mut p = super::super::tests::process();
            let shared = p.linux.vfs.clone_with_resources(false, true);
            let fork = p.linux.vfs.clone();
            p.cpu.set_x(8, 166);
            put_args(&mut p.cpu, [0o1077, 0, 0, 0, 0, 0]);
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })]).unwrap(),
            ));
            let snapshot = crate::worker_syscalls::Snapshot {
                seccomp: p.seccomp.clone(),
                identities: [0; 7],
                started: Instant::now(),
                processor: 0,
                profile: false,
                streams: Default::default(),
                files: Default::default(),
                fd_flags: Default::default(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                program_break: p.linux.program_break(),
                uts: None,
                direct: Default::default(),
                futex: Default::default(),
            };
            assert_eq!(snapshot.admit(&p.cpu), allowed);
            if allowed {
                assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0o022));
            }
            assert_eq!(shared.umask(), if allowed { 0o077 } else { 0o022 });
            assert_eq!(fork.umask(), 0o022);
        }
    }
    #[test]
    fn worker_record_locks_obey_seccomp_before_query_or_commit() {
        for allowed in [false, true] {
            for command in [5, 6] {
                let mut p = super::super::tests::process();
                let fd = p
                    .linux
                    .vfs
                    .open_at(trames_vfs::AT_FDCWD, b"/lock", 0x42, 0o600)
                    .unwrap();
                let mut bytes = [0; 32];
                bytes[..2].copy_from_slice(&1u16.to_le_bytes());
                bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
                p.memory.write_array(0x1000, bytes).unwrap();
                p.cpu.set_x(8, 25);
                put_args(&mut p.cpu, [fd as u64, command, 0x1000, 0, 0, 0]);
                p.seccomp.push(Arc::new(
                    Filter::validate(vec![i(6, 0, 0, if allowed { ALLOW } else { 0x5007b })])
                        .unwrap(),
                ));
                let mut epoch = trames_vfs::FileEpoch::default();
                let snapshot = crate::worker_syscalls::Snapshot {
                    seccomp: p.seccomp.clone(),
                    identities: [0; 7],
                    started: Instant::now(),
                    processor: 0,
                    profile: false,
                    streams: p.linux.vfs.stream_descriptors(),
                    files: p.linux.vfs.file_descriptors(),
                    fd_flags: p.linux.vfs.fd_flags_snapshot(),
                    umask: p.linux.vfs.umask_capability(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: None,
                    direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                        .with_files(epoch.capture(&p.linux.vfs, true))
                        .with_lock_context(p.linux.vfs.record_lock_context(p.tgid)),
                    futex: Default::default(),
                };
                assert_eq!(snapshot.admit(&p.cpu), allowed);
                if allowed {
                    assert_eq!(snapshot.invoke(&p.cpu, &mut p.memory), Some(0));
                }
                if command == 6 {
                    let mut other = p.linux.vfs.normalize_lock(fd, 1, 0, 0, 1).unwrap();
                    other.owner = 99;
                    assert_eq!(
                        p.linux
                            .vfs
                            .record_lock_conflict(fd, other)
                            .unwrap()
                            .is_some(),
                        allowed
                    );
                } else {
                    assert_eq!(
                        p.memory.read_array::<2>(0x1000).unwrap(),
                        (if allowed { 2u16 } else { 1u16 }).to_le_bytes()
                    );
                }
                epoch.finish();
            }
        }
    }
    #[test]
    fn filtered_identity_syscalls_still_checkpoint_and_apply_errno_in_parallel() {
        let mut p = super::super::tests::process();
        for (index, word) in [0xd2801588u32, 0xd4000001, 0x17ffffff]
            .into_iter()
            .enumerate()
        {
            p.memory
                .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.affinity = 3;
        p.seccomp.push(Arc::new(
            Filter::validate(vec![i(6, 0, 0, 0x5007b)]).unwrap(),
        ));
        let mut peer = p.fork();
        peer.parent = 1;
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.workers = crate::workers::Pool::new(2);
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.processes.insert(1, p);
        kernel.processes.insert(2, peer);
        assert!(kernel
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 100_000)
            .unwrap());
        assert_eq!(kernel.worker_syscalls, 0);
        assert!(kernel.syscalls > 0);
        for p in kernel.processes.values().filter(|p| p.cpu.pc == 0x4008) {
            assert_eq!(p.cpu.x(0), error(Errno(123)));
        }
    }
    #[test]
    fn seccomp_trap_preserves_aarch64_arguments_in_the_signal_context() {
        for number in [56, 78] {
            let mut p = super::super::tests::process();
            let mut kernel = super::super::tests::kernel();
            let args = [
                AT_FDCWD as i64 as u64,
                0x1234,
                0xa0000,
                0x5678,
                0x9abc,
                0xdef0,
            ];
            put_args(&mut p.cpu, args);
            p.cpu.set_x(8, number as u64);
            p.cpu.pc = 0x4004;
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, 0x30055)]).unwrap(),
            ));
            p.signals.actions.set(
                31,
                Action {
                    handler: 0x5000,
                    flags: 4,
                    ..Action::default()
                },
            );
            assert!(kernel.filter_syscall(1, &mut p, number, args));
            assert_eq!(p.cpu.pc, 0x5000);
            let sp = p.cpu.sp;
            assert_eq!(p.cpu.x(0), 31);
            for (index, arg) in args.into_iter().enumerate() {
                assert_eq!(p.memory.read_u64(sp + 312 + index as u64 * 8).unwrap(), arg);
            }
            assert_eq!(p.memory.read_u64(sp + 312 + 8 * 8).unwrap(), number as u64);
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 24).unwrap()),
                number
            );
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 28).unwrap()),
                ARCH
            );
            assert_eq!(
                u32::from_le_bytes(p.memory.read_array(sp + 4).unwrap()),
                0x55
            );
            // The broker can set its result in x0 and resume after SVC.
            write_u64(&mut p.memory, sp + 312, error(Errno(13))).unwrap();
            Kernel::sigreturn(&mut p).unwrap();
            assert_eq!(p.cpu.x(0), error(Errno(13)));
            assert_eq!(p.cpu.x(1), args[1]);
            assert_eq!(p.cpu.x(8), number as u64);
            assert_eq!(p.cpu.pc, 0x4004);
        }
    }
    #[test]
    fn ignored_or_blocked_sigsys_cannot_suppress_a_forced_seccomp_trap() {
        for (handler, mask) in [(1, 0), (0x5000, 1u64 << 30)] {
            let mut p = super::super::tests::process();
            let mut kernel = super::super::tests::kernel();
            p.seccomp.push(Arc::new(
                Filter::validate(vec![i(6, 0, 0, 0x30055)]).unwrap(),
            ));
            p.signals.actions.set_handler(31, handler);
            p.signals.mask = mask;
            assert!(kernel.filter_syscall(1, &mut p, 173, [0; 6]));
            assert!(matches!(p.state, State::Zombie(31)));
        }
    }
    fn i(code: u16, yes: u8, no: u8, value: u32) -> Instruction {
        Instruction {
            code,
            yes,
            no,
            value,
        }
    }
    #[test]
    fn filter_loads_arch_arguments_and_verifies_all_paths() {
        let f = Filter::validate(vec![
            i(0x20, 0, 0, 4),
            i(0x15, 1, 0, ARCH),
            i(0x06, 0, 0, KILL_PROCESS),
            i(0x20, 0, 0, 20),
            i(0x15, 0, 1, 7),
            i(0x06, 0, 0, 0x50001),
            i(0x06, 0, 0, ALLOW),
        ])
        .unwrap();
        let mut input = [0; 16];
        input[1] = ARCH;
        input[5] = 7;
        assert_eq!(f.run(&input), 0x50001);
        input[5] = 8;
        assert_eq!(f.run(&input), ALLOW);
        input[1] = 0;
        assert_eq!(f.run(&input), KILL_PROCESS);
        for bad in [
            vec![i(0x20, 0, 0, 64), i(6, 0, 0, ALLOW)],
            vec![i(0x05, 0, 0, u32::MAX), i(6, 0, 0, ALLOW)],
            vec![i(0x60, 0, 0, 0), i(6, 0, 0, ALLOW)],
            vec![i(0x34, 0, 0, 0), i(6, 0, 0, ALLOW)],
            vec![
                i(0x15, 0, 1, 1),
                i(2, 0, 0, 0),
                i(0x60, 0, 0, 0),
                i(6, 0, 0, ALLOW),
            ],
        ] {
            assert!(Filter::validate(bad).is_err());
        }
    }
    #[test]
    fn stacked_filters_keep_restrictions_and_newest_equal_action_data() {
        let a = Arc::new(Filter::validate(vec![i(6, 0, 0, 0x50001)]).unwrap());
        let b = Arc::new(Filter::validate(vec![i(6, 0, 0, 0x50002)]).unwrap());
        let ancestor = Seccomp {
            strict: false,
            evaluations: Arc::default(),
            filters: Arc::new(vec![a.clone()]),
        };
        let current = Seccomp {
            strict: false,
            evaluations: Arc::default(),
            filters: Arc::new(vec![a, b]),
        };
        assert!(ancestor.ancestor_of(&current));
        assert!(!current.ancestor_of(&ancestor));
        assert_eq!(current.decision(172, 0, [0; 6]), 0x50002);
    }
}
