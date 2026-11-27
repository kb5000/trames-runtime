// SPDX-License-Identifier: GPL-3.0-or-later
//! Exec prepares an image before committing task/resource replacement.
use super::*;
#[cfg(all(test, trames_interpreter_conformance))]
#[path = "process_exec_resource_tests.rs"]
mod resource_tests;
#[derive(Debug)]
pub(crate) enum ImageError {
    Rejected(Errno),
    Unmappable,
    Pending(Box<Retry>),
}
pub(crate) struct Retry {
    request: Request,
    wait: Arc<trames_memory::PageWait>,
}
impl std::fmt::Debug for Retry {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("original executable input waiting")
    }
}
impl From<Errno> for ImageError {
    fn from(errno: Errno) -> Self {
        Self::Rejected(errno)
    }
}
impl ImageError {
    // A host launch has no old guest program or PID to terminate.
    pub(super) fn launch_errno(self) -> Errno {
        match self {
            Self::Rejected(errno) => errno,
            Self::Unmappable => Errno(8),
            Self::Pending(_) => unreachable!("pending image input must retain its request"),
        }
    }
}
impl<C: Cpu> Kernel<C> {
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn exec(
        p: &mut Process<C>,
        a: [u64; 6],
        budget: usize,
        clock_origin: Instant,
    ) -> Result<(), Errno> {
        Self::exec_at(p, AT_FDCWD, a, 0, budget, clock_origin)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    fn exec_at(
        p: &mut Process<C>,
        dirfd: i32,
        a: [u64; 6],
        flags: u32,
        budget: usize,
        clock_origin: Instant,
    ) -> Result<(), Errno> {
        let path = Linux::path(&p.memory, a[0])?;
        let mut budget_bytes = trames_linux::image::EXEC_ARGUMENT_BYTES;
        let argv = strings(&p.memory, a[1], &mut budget_bytes)?;
        let envp = strings(&p.memory, a[2], &mut budget_bytes)?;
        Self::exec_strings(p, dirfd, path, argv, envp, flags, budget, clock_origin)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn exec_strings(
        p: &mut Process<C>,
        dirfd: i32,
        path: Vec<u8>,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
        flags: u32,
        budget: usize,
        clock_origin: Instant,
    ) -> Result<(), Errno> {
        // Used only to load a not-yet-admitted host-spawn child (or by tests).
        let mut image =
            Self::prepare_exec_strings(p, dirfd, path, argv, envp, flags, budget, clock_origin)
                .map_err(ImageError::launch_errno)?;
        image
            .memory
            .inherit_total_limit(&p.memory)
            .map_err(|_| Errno(12))?;
        drop(Self::install_exec(p, image, clock_origin));
        Ok(())
    }
    pub(super) fn prepare_exec_request(
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        budget: usize,
        clock_origin: Instant,
    ) -> Result<Option<Image<C>>, Errno> {
        if p.exec_pending
            .as_ref()
            .is_some_and(|pending| !pending.ready())
        {
            // A canceled epoch may return before its accepted image I/O. For
            // exec, Ok(None) normally means the new CPU is already installed,
            // so the generic caller deliberately does not create a wait state.
            // Preserve this unfinished entry explicitly; never run past SVC.
            p.state = State::Blocked(number, a);
            put_args(&mut p.cpu, a);
            return Ok(None);
        }
        let image = if let Some(pending) = p.exec_pending.take() {
            pending.take()
        } else {
            let (dirfd, a, flags) = if number == 221 {
                (AT_FDCWD, a, 0)
            } else {
                (a[0] as i32, [a[1], a[2], a[3], 0, 0, 0], a[4] as u32)
            };
            let path = Linux::path(&p.memory, a[0])?;
            let mut budget_bytes = trames_linux::image::EXEC_ARGUMENT_BYTES;
            let argv = strings(&p.memory, a[1], &mut budget_bytes)?;
            let envp = strings(&p.memory, a[2], &mut budget_bytes)?;
            Self::prepare_exec_strings(p, dirfd, path, argv, envp, flags, budget, clock_origin)
        };
        match image {
            Ok(mut image) => {
                image
                    .memory
                    .inherit_total_limit(&p.memory)
                    .map_err(|_| Errno(12))?;
                Ok(Some(image))
            }
            Err(ImageError::Rejected(errno)) => Err(errno),
            Err(ImageError::Unmappable) => {
                // Equivalent to a Linux segment mapping failure past begin_new_exec.
                // An already accepted fatal group status wins over this SIGSEGV.
                p.signals.io.lifecycle().request_exit(11);
                Ok(None)
            }
            Err(ImageError::Pending(retry)) => {
                let pending = Arc::new(Pending::new());
                pending.complete(Err(ImageError::Pending(retry)));
                p.exec_pending = Some(Preparation::Disk(pending));
                p.state = State::Blocked(number, a);
                put_args(&mut p.cpu, a);
                Ok(None)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_exec_strings(
        p: &Process<C>,
        dirfd: i32,
        path: Vec<u8>,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
        flags: u32,
        budget: usize,
        clock_origin: Instant,
    ) -> Result<Image<C>, ImageError> {
        // In-memory/solo lookup retains its original fast failure path. Do not
        // clone descriptor context for ENOENT/EACCES or resolve the inode twice.
        let file = p.linux.vfs.executable_file_at(dirfd, &path, flags)?;
        let mut request = Request::new(p, dirfd, path, argv, envp, flags, budget, clock_origin);
        request.file = Some(file);
        request.load()
    }
    pub(super) fn install_exec(
        p: &mut Process<C>,
        mut runtime: Image<C>,
        clock_origin: Instant,
    ) -> Memory {
        // Source execution has already admitted this group without blocking a
        // slot. Serialize the final credentials/auxv image with TSYNC publication.
        let policy = p.seccomp.birth_group();
        let _permit = policy.write_owned().into_admission();
        runtime.refresh_credentials(runtime.externally_shared_fs, p.signals.io.is_traced());
        let task = p.linux.vfs.process_context();
        {
            let body = &mut *p;
            body.linux.cancel_uring(&mut body.memory, task)
        };
        Self::clear_exit_resources(p);
        p.pending_open = None;
        p.poll_deadline = None;
        p.socket_deadline = None;
        p.linux.vfs.unshare_descriptors();
        p.linux.vfs.close_exec();
        let credentials = runtime.linux.vfs.credentials.clone();
        let dumpable = runtime.linux.vfs.dumpable_state();
        std::mem::swap(&mut runtime.linux.vfs, &mut p.linux.vfs);
        runtime.linux.vfs.credentials = credentials;
        runtime.linux.vfs.install_exec_dumpable(dumpable);
        runtime.linux.session_keys = p.linux.session_keys.clone();
        runtime.linux.personality = p.linux.personality.clone();
        runtime.linux.memory_policy = p.linux.memory_policy.clone();
        runtime.linux.trace = p.linux.trace;
        runtime.linux.task_limit = p.linux.task_limit;
        runtime.linux.set_uring_clock(clock_origin);
        runtime.linux.set_boot_clock(p.linux.boot_clock());
        runtime.linux.inherit_exec_addresses(&p.linux);
        p.linux = runtime.linux;
        runtime.cpu.inherit_exec(&p.cpu);
        p.cpu = runtime.cpu;
        p.space.retire();
        p.space = Default::default();
        p.signals
            .io
            .lifecycle()
            .retain_image_peak(p.memory.peak_resident_bytes());
        let old_memory = std::mem::replace(&mut p.memory, runtime.memory);
        p.family.mark_exec();
        p.wait_event.exec();
        p.signals.exec();
        if p.linux.vfs.dumpable() != 1 {
            p.signals.io.proc_view.revoke_perf();
        }

        p.membarrier_registered = Arc::new(std::sync::atomic::AtomicU32::new(0));
        p.state = State::Ready;
        old_memory
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn commit_exec_task(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        image: Image<C>,
    ) -> Result<(), trames_memory::MemoryError> {
        // Keep process visibility alive until its replacement is published.
        // Other CPUs may query prlimit/PID resources during de-thread cleanup.
        let old_presence = self
            .processes
            .get(&p.tgid)
            .map(|leader| leader.signals.presence.clone());
        if pid != p.tgid {
            if let Some(leader) = self.processes.get(&p.tgid) {
                p.started = leader.started;
                p.signals.io.inherit_proc_pid(&leader.signals.io);
            }
        }
        let mut image = image;
        image.check_shared_fs(&p.linux.vfs, || {
            self.processes
                .iter()
                .filter(|(id, peer)| {
                    *id != pid
                        && peer.tgid == p.tgid
                        && peer.linux.vfs.owns_context_of(&p.linux.vfs)
                })
                .count()
        });
        let old_memory = Self::install_exec(p, image, self.started);
        let ids: Vec<_> = self
            .processes
            .iter()
            .filter(|(_, t)| t.tgid == p.tgid)
            .map(|(id, _)| id)
            .collect();
        for id in ids {
            if let Some(mut t) = self.processes.remove(&id) {
                t.linux.vfs.sync_task_namespaces();
                // These CPUs were accounted before de-threading. Preserve the
                // process projection without counting their global time twice.
                p.cpu_time += t.cpu_time;

                t.signals.io.exit();
                Self::cancel_native_task(&t);
                {
                    let task = &mut *t;
                    task.linux.cancel_uring(&mut task.memory, id)
                };
                Self::parent_thread_exited(&t, Some((p.tgid, p.signals.io.clone())));
                t.linux.vfs.cgroup_exit(id);
                let address = t.linux.clear_tid_address();
                {
                    let task = &mut *t;
                    task.linux.exit_tid(&mut task.memory)
                };
                self.wake_futex(&t, address, 1, u32::MAX);
                t.linux.vfs.release_descriptors();
                t.linux.vfs.retire_sem_undo(t.tgid);
                t.linux.vfs.retire_context();
                t.space.retire();
                if id != p.tgid {
                    t.signals.presence.visibility().reap();
                }
                Self::release_vfork(&mut t);
                self.retire_detached_memory(std::mem::take(&mut t.memory))?;
            }
        }
        self.timers.clear_process(p.tgid, true);
        Self::release_vfork(p);
        if pid != p.tgid {
            p.linux.vfs.cgroup_exec_rekey(pid, p.tgid);
            p.rekey = Some(p.tgid);
            // Original Parents::publish rekeys this thread and its children
            // when publish_task below installs the new PID; no task scan.
        }
        let resource = self.resource_id();
        p.vm_id = resource;
        if pid != p.tgid {
            p.wait_event.bind_presence(&p.signals.presence);
            p.linux.vfs.set_process_context(p.tgid);
            self.publish_task(p.tgid, p);
        }
        if pid == p.tgid {
            self.publish_task(pid, p);
        }
        if let Some(previous) = old_presence {
            previous.visibility().reap();
        }
        self.retire_detached_memory(old_memory)?;
        p.signals
            .io
            .trace_point(5, None, || p.cpu.architectural_state());
        Ok(())
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn exec_checkpoint(
        &mut self,
        epoch: &crate::run_queue::Epoch<C>,
        checkpoint: &mut crate::run_queue::Checkpoint<C>,
        io: &mut impl GuestOutput,
        replaced: &mut Vec<u32>,
    ) -> Result<bool, RuntimeError> {
        while let Some(index) = checkpoint.jobs.iter().position(|job| {
            job.checkpoint.is_some() && matches!(job.work.cpu.x(8) as u32, 221 | 281)
        }) {
            let job = &mut checkpoint.jobs[index];
            let pid = job.work.pid;
            let p = self.processes.read(&pid);
            if p.signals.io.lifecycle().termination().is_some() {
                job.checkpoint = None;
                continue;
            }
            if p.exec_pending
                .as_ref()
                .is_some_and(|pending| !pending.ready())
            {
                return Ok(false);
            }
            if p.seccomp.mode() != 0 {
                let entry = job.seccomp_entry.take().unwrap_or_else(|| {
                    p.seccomp.entry_decision(
                        job.work.cpu.x(8) as u32,
                        job.work.cpu.pc(),
                        args(&job.work.cpu),
                    )
                });
                let allowed = entry.allowed();
                job.seccomp_entry = Some(entry);
                if !allowed {
                    return Ok(false);
                }
            }
            drop(p);
            let began = Instant::now();
            let mut job = checkpoint.jobs.remove(index);
            let outcome = job.checkpoint.take().expect("exec entry");
            let slot = job.stats.worker;
            // Only CPU/stat custody returns here. The original job retains its
            // background ring/resource state if image preparation fails.
            let mut done = std::mem::take(&mut job.stats).finish(
                pid,
                std::mem::take(&mut job.work.cpu),
                Some(outcome),
                None,
                None,
                None,
            );
            done.task = job.work.task.clone();
            done.seccomp_entry = job.seccomp_entry.take();
            self.adopt_worker_return(done, false);
            let mut p = self.processes.checkout(&pid).expect("exec task");
            let old_vm = p.vm_id;
            let number = p.cpu.x(8) as u32;
            let a = args(&p.cpu);
            let control = p.signals.io.lifecycle().enter(&p.signals.io, pid);
            let mut retirement_error = None;
            self.call_with(pid, &mut p, number, a, io, |kernel, pid, p, _| {
                let Some(image) = Self::prepare_exec_request(
                    p,
                    number,
                    a,
                    kernel.memory_limits.per_process,
                    kernel.started,
                )?
                else {
                    return Ok(None);
                };
                // Accepted images replace every original group peer. Their
                // actual CPUs/statistics return before the shared cleanup path;
                // unrelated CLONE_VM processes retain their original jobs.
                let mut i = 0;
                while i < checkpoint.jobs.len() {
                    let peer = checkpoint.jobs[i].work.pid;
                    if kernel.processes.read(&peer).tgid != p.tgid {
                        i += 1;
                        continue;
                    }
                    let peer_job = checkpoint.jobs.remove(i);
                    epoch.forget_checkpoint_member(peer);
                    let done = peer_job.finish(
                        Some(SliceOutcome::Yield { instructions: 0 }),
                        kernel.instructions,
                    );
                    kernel.adopt_worker_return(done, false);
                }
                if let Err(error) = kernel.commit_exec_task(pid, p, image) {
                    retirement_error = Some(error);
                }
                Ok(None)
            });
            control.finish(Some(p.stop_held()));
            if p.vm_id != old_vm {
                epoch.forget_checkpoint_member(pid);
                let actual = p.rekey.take().unwrap_or(pid);
                p.linux.vfs.set_process_context(actual);
                self.publish_task(actual, &p);
                self.processes.insert(actual, p);
                replaced.push(actual);
                // Drop old accepted authorities before the new image can run.
                drop(job);
            } else {
                p.signals.begin_io();
                job.work.cpu = std::mem::take(&mut p.cpu);
                let before = job.work.cpu.decode_stats();
                job.stats = crate::run_queue::Stats {
                    before,
                    after: before,
                    worker: slot,
                    ..Default::default()
                };
                self.processes.insert(pid, p);
                checkpoint.jobs.push(job);
            }
            self.vm_checkpoint_time[3] += began.elapsed();
            if let Some(error) = retirement_error {
                return Err(error.into());
            }
        }
        Ok(true)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Mutex};
    use trames_memory::CpuMemory;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn mov(reg: u32, value: u32) -> u32 {
        0xd2800000 | (value & 0xffff) << 5 | reg
    }
    pub(super) fn elf(words: &[u32]) -> Vec<u8> {
        let mut b = vec![0; 256 + words.len() * 4];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, v) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 1)] {
            b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        for (at, v) in [
            (24, 0x10100u64),
            (32, 64),
            (72, 0),
            (80, 0x10000),
            (88, 0x10000),
            (96, b.len() as u64),
            (104, b.len() as u64),
            (112, 4096),
        ] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&7u32.to_le_bytes());
        for (i, w) in words.iter().enumerate() {
            b[256 + i * 4..260 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
    struct Backing(Mutex<[u8; PAGE_SIZE as usize]>);
    impl trames_memory::PageBacking for Backing {
        fn parallel_key(&self) -> Option<(u64, u64)> {
            Some((self as *const Self as usize as u64, 0))
        }
        fn check(&self, _: u64) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), trames_memory::MemoryError> {
            out.copy_from_slice(&self.0.lock().unwrap()[offset..offset + out.len()]);
            Ok(())
        }
        fn write(&self, offset: usize, input: &[u8]) -> Result<(), trames_memory::MemoryError> {
            self.0.lock().unwrap()[offset..offset + input.len()].copy_from_slice(input);
            Ok(())
        }
        fn sync(&self) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            0
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(
            &self,
            _: u64,
        ) -> Result<Arc<dyn trames_memory::PageBacking>, trames_memory::MemoryError> {
            Err(trames_memory::MemoryError::InvalidRange)
        }
    }
    #[test]
    fn prepared_exec_rechecks_late_tsync_privileges_and_initial_auxv_without_file_relookup() {
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .import_executable(b"/image", elf(&[0x14000000]))
            .unwrap();
        p.linux.vfs.chmod_at(AT_FDCWD, b"/image", 0o4755).unwrap();
        let mut admin = p.linux.vfs.clone();
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        k.publish_task(1, &p);
        let mut peer = p.fork();
        peer.share_process_context(&p);
        peer.bind_signals();
        peer.seccomp.inherit(
            &p.seccomp,
            true,
            &peer.signals.io,
            2,
            &peer.linux.vfs.credentials.caps.no_new_privs,
            &p.linux.vfs.credentials.caps.no_new_privs,
        );
        let image = Kernel::prepare_exec_strings(
            &p,
            AT_FDCWD,
            b"/image".to_vec(),
            vec![b"/image".to_vec()],
            vec![],
            0,
            32 * 1024 * 1024,
            k.started,
        )
        .unwrap();
        assert_eq!(image.linux.vfs.credentials.euid, 0);
        assert_ne!(image.linux.vfs.credentials.caps.permitted, 0);
        peer.memory.write_array(0x1800, 1u16.to_le_bytes()).unwrap();
        peer.memory
            .write_array(0x1808, 0x1900u64.to_le_bytes())
            .unwrap();
        peer.memory
            .write_array(0x1900, [6, 0, 0, 0, 0, 0, 0xff, 0x7f])
            .unwrap();
        peer.linux.vfs.credentials.caps.no_new_privs.set();
        peer.bind_signals();
        assert_eq!(k.seccomp(&mut peer, [1, 1, 0x1800, 0, 0, 0]), Ok(0));
        // The prepared image keeps accepted readability/metadata. A late NNP
        // must not cause a second path/permission lookup or new guest bytes.
        admin.chmod_at(AT_FDCWD, b"/image", 0o4000).unwrap();
        drop(Kernel::install_exec(&mut p, image, k.started));
        let c = &p.linux.vfs.credentials;
        assert_eq!(
            (c.euid, c.suid, c.fsuid, c.egid, c.sgid, c.fsgid),
            (1000, 1000, 1000, 1000, 1000, 1000)
        );
        assert_eq!(c.caps.permitted, 0);
        assert_eq!(p.linux.vfs.dumpable(), 1);
        assert!(c.caps.no_new_privs.get());
        let base =
            p.cpu.sp() + 8 * (3 + p.linux.arguments.len() + p.linux.environment.len()) as u64;
        for (index, pair) in p.linux.auxiliary.chunks_exact(16).enumerate() {
            let key = u64::from_le_bytes(pair[..8].try_into().unwrap());
            if let Some(expected) = match key {
                11..=14 => Some(1000),
                23 => Some(0),
                _ => None,
            } {
                assert_eq!(u64::from_le_bytes(pair[8..].try_into().unwrap()), expected);
                assert_eq!(
                    p.memory.read_u64(base + index as u64 * 16 + 8).unwrap(),
                    expected
                );
            }
        }
    }
    #[test]
    fn nonleader_exec_preserves_leader_identity_and_queued_old_tid_until_consumed() {
        let mut k = super::super::tests::kernel();
        let mut root = super::super::tests::process();
        let mut output = trames_linux::CapturedOutput::default();
        root.linux
            .vfs
            .import_executable(b"/image", elf(&[0x14000000]))
            .unwrap();
        k.syscall(
            1,
            &mut root,
            220,
            [trames_vfs::CLONE_NEWPID | 17, 0, 0, 0, 0, 0],
            &mut output,
        )
        .unwrap();
        k.processes.insert(1, root);
        let mut init = k.processes.remove(&2).unwrap();
        k.syscall(2, &mut init, 220, [17, 0, 0, 0, 0, 0], &mut output)
            .unwrap();
        k.processes.insert(2, init);
        let mut leader = k.processes.remove(&3).unwrap();
        assert_eq!(leader.linux.personality.call(0x0100_0000), Ok(0));
        k.syscall(3, &mut leader, 220, [0x10f00, 0, 0, 0, 0, 0], &mut output)
            .unwrap();
        k.processes.insert(3, leader);
        let mut thread = k.processes.remove(&4).unwrap();
        assert_eq!(thread.linux.personality.call(0x0200_0000), Ok(0x0100_0000));
        assert_eq!(
            k.processes.read(&3).linux.personality.call(u32::MAX as u64),
            Ok(0x0100_0000)
        );
        let namespace = thread.linux.vfs.pid_namespace().clone();
        assert_eq!(namespace.hierarchy(4), vec![4, 3]);
        k.processes
            .read(&2)
            .signals
            .io
            .inbox
            .enqueue(
                35,
                Info {
                    sender: 4,
                    ..Default::default()
                },
            )
            .unwrap();
        thread.memory.write(0x1000, b"/image\0").unwrap();
        thread.memory.write(0x1100, &[0; 16]).unwrap();
        k.syscall(
            4,
            &mut thread,
            221,
            [0x1000, 0x1100, 0x1108, 0, 0, 0],
            &mut output,
        )
        .unwrap();
        assert!(k.backend_error.is_none());
        assert_eq!(
            thread.linux.personality.call(u32::MAX as u64),
            Ok(0x0200_0000)
        );
        assert_eq!(thread.rekey, Some(3));
        assert_eq!(namespace.local(3), 2);
        assert_eq!(
            namespace.local(4),
            3,
            "pending siginfo owns the old TID translation"
        );
        let info = k
            .processes
            .get_mut(&2)
            .unwrap()
            .take_signal(35, false)
            .unwrap();
        assert_eq!(info.sender, 3);
        assert_eq!(namespace.local(4), 0);
        assert_eq!(
            namespace.local(3),
            2,
            "exec retains the leader's original identity"
        );
    }
    #[test]
    fn successful_exec_preserves_process_age_and_peer_cpu_accounting() {
        let mut k = super::super::tests::kernel();
        let mut leader = super::super::tests::process();
        let origin = Instant::now();
        leader.started = origin - Duration::from_secs(5);
        leader.cpu_time = Duration::from_millis(7);
        leader
            .linux
            .vfs
            .import_executable(b"/image", elf(&[0x14000000]))
            .unwrap();
        leader.memory.write(0x1000, b"/image\0").unwrap();
        k.install_proc_source(&leader, None);
        k.publish_task(1, &leader);
        let proc_leader =
            trames_vfs::ProcSource::task(&**k.proc_source.as_ref().unwrap(), 1).unwrap();
        let paths = leader.linux.vfs.path_queries();
        let files = trames_vfs::DirectFiles::default();
        let mut reads = Vec::new();
        let mut opened = Vec::new();
        for path in [b"/proc/self/comm".as_slice(), b"/proc/self/maps"] {
            let fd = paths
                .open_at_resolve(AT_FDCWD, path, 0, 0, 0, &files)
                .unwrap()
                .unwrap();
            opened.push(fd);
            let target = leader
                .linux
                .vfs
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            reads.push(trames_vfs::FileWork::from_vfs(
                &leader.linux.vfs,
                target,
                trames_vfs::FileCommand::Read {
                    count: 65536,
                    offset: Some(0),
                },
            ));
        }
        drop(paths);
        let mut io = trames_linux::CapturedOutput::default();
        k.syscall(1, &mut leader, 220, [0x10900, 0, 0, 0, 0, 0], &mut io)
            .unwrap();
        k.processes.insert(1, leader);
        let mut caller = k.processes.remove(&2).unwrap();
        let proc_thread =
            trames_vfs::ProcSource::task(&**k.proc_source.as_ref().unwrap(), 2).unwrap();
        caller.started = origin;
        caller.cpu_time = Duration::from_millis(3);
        caller.poll_deadline = Some(origin);
        caller.socket_deadline = Some(origin);
        caller.signals.set_mask(2);
        caller.signals.wait_mask = Some(4);
        // An accepted guarded borrower may keep physical storage after the
        // last task execs. It must not keep the old Linux mm logically alive.
        let retained_memory = caller.memory.parallel_view(&mut k.parallel_memory).unwrap();

        let image = Kernel::<trames_cpu::Cpu>::prepare_exec_request(
            &mut caller,
            221,
            [0x1000, 0, 0, 0, 0, 0],
            k.memory_limits.per_process,
            k.started,
        )
        .unwrap();
        k.commit_exec_task(2, &mut caller, image.unwrap()).unwrap();
        assert_eq!(caller.started, origin - Duration::from_secs(5));
        assert_eq!(caller.cpu_time, Duration::from_millis(10));
        assert_eq!(k.cpu_total, Duration::ZERO);
        assert_eq!(caller.rekey, Some(1));
        assert!(caller.poll_deadline.is_none() && caller.socket_deadline.is_none());
        assert_eq!(caller.signals.mask, 2);
        assert!(caller.signals.wait_mask.is_none());

        assert!(!k.processes.contains_key(&1));
        assert!(caller.signals.presence.present());
        let view = proc_leader
            .observe(trames_vfs::ProcRefresh::Metadata, None)
            .unwrap();
        assert_eq!(view.pid, 1);
        assert_eq!(view.identity, proc_leader.identity());
        assert!(proc_thread
            .observe(trames_vfs::ProcRefresh::Metadata, None)
            .is_none());
        let results = std::thread::spawn(move || {
            reads
                .into_iter()
                .map(|read| {
                    let trames_vfs::FileOutcome::Complete(reply) = read.run() else {
                        panic!("proc read returned to owner")
                    };
                    reply.result.unwrap().into_bytes().expect("read bytes")
                })
                .collect::<Vec<_>>()
        })
        .join()
        .unwrap();
        assert_eq!(results[0], b"image\n");
        assert_eq!(
            results[1], b"",
            "the old maps FD must not read the replacement mm"
        );
        let paths = caller.linux.vfs.path_queries();
        let reopened = paths
            .open_at_resolve(
                AT_FDCWD,
                format!("/proc/self/fd/{}", opened[1]).as_bytes(),
                0,
                0,
                0,
                &files,
            )
            .expect("proc maps FD reopens on its worker")
            .unwrap();
        let target = caller
            .linux
            .vfs
            .shared_files()
            .lookup(reopened)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let trames_vfs::FileOutcome::Complete(reply) = trames_vfs::FileWork::from_vfs(
            &caller.linux.vfs,
            target,
            trames_vfs::FileCommand::Read {
                count: 65536,
                offset: None,
            },
        )
        .run() else {
            panic!("fresh maps read returned to owner")
        };
        assert!(
            !reply
                .result
                .unwrap()
                .into_bytes()
                .expect("maps bytes")
                .is_empty(),
            "reopen uses the current mm rather than cloning the old open plan"
        );
        drop(retained_memory);
    }
    struct Wake(mpsc::Sender<()>);
    impl trames_vfs::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
            let _ = self.0.send(());
        }
    }
    #[test]
    fn detached_exec_memory_commits_late_backed_writes_without_a_kernel() {
        let retired = Arc::new(crate::retired_memory::RetiredMemory::default());
        let backing = Arc::new(Backing(Mutex::new([0; PAGE_SIZE as usize])));
        let mut memory = Memory::default();
        memory
            .map_backed(0x6000, vec![backing.clone()], true, Permissions::RW, false)
            .unwrap();
        let mut borrower = memory.parallel_view(&mut Default::default()).unwrap();
        retired.retire(memory).unwrap();
        borrower.write_array(0x6000, 9u64.to_le_bytes()).unwrap();
        drop(borrower);
        retired.pump().unwrap();
        assert!(retired.is_empty());
        assert_eq!(backing.0.lock().unwrap()[..8], 9u64.to_le_bytes());
    }
    #[test]
    fn source_exec_finishes_without_owner_and_preserves_rekey_against_late_exit() {
        use crate::process::lifecycle::Lifecycle;
        use crate::run_queue::Epoch;
        use crate::workers::{Control, Event};
        use trames_vfs::ProcTask;
        for disk in [false, true] {
            for cpus in [1, 4] {
                // execve, execveat, failed image, live leader, queued leader exit,
                // and an exit already taken by the owner but not yet collected.
                for mode in 0..6 {
                    let mut k = super::super::tests::kernel();
                    k.cpu_count = cpus;
                    k.per_cpu = vec![Duration::ZERO; cpus];
                    k.workers = crate::workers::Pool::new(cpus);
                    let mut root = super::super::tests::admitted_process(&k);
                    let disk_path = std::env::temp_dir().join(format!(
                        "trames-source-image-{}-{}-{cpus}-{mode}",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos()
                    ));
                    if disk {
                        root.linux.vfs =
                            trames_vfs::Vfs::open_disk(&disk_path, Default::default()).unwrap();
                    }
                    let age = Instant::now() - Duration::from_secs(5);
                    root.started = age;
                    root.cpu_time = Duration::from_millis(7);
                    root.linux
                        .vfs
                        .import_executable(
                            b"/image",
                            if mode == 2 {
                                b"not ELF".to_vec()
                            } else {
                                elf(&[mov(0, 42), mov(8, 93), 0xd4000001])
                            },
                        )
                        .unwrap();
                    root.memory.write(0x1000, b"/image\0").unwrap();
                    let fd = root.linux.vfs.open_at(AT_FDCWD, b"/image", 0, 0).unwrap();
                    let mut words = if mode == 1 {
                        vec![
                            mov(0, fd),
                            mov(1, 0x1008),
                            mov(2, 0),
                            mov(3, 0),
                            mov(4, 0x1000),
                            mov(8, 281),
                        ]
                    } else {
                        vec![mov(0, 0x1000), mov(1, 0), mov(2, 0), mov(8, 221)]
                    };
                    words.extend([0xd4000001, mov(0, 123), mov(8, 93), 0xd4000001]);
                    for (i, word) in words.into_iter().enumerate() {
                        root.memory
                            .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                    let [read, write] = root.linux.vfs.pipe(0).unwrap();
                    let release = root
                        .linux
                        .vfs
                        .shared_files()
                        .lookup(write)
                        .unwrap()
                        .unwrap()
                        .direct_byte()
                        .unwrap();
                    for (i, word) in [
                        mov(0, read),
                        mov(1, 0x1500),
                        mov(2, 1),
                        mov(8, 63),
                        0xd4000001,
                        0x17fffefb,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        root.memory
                            .write_array(0x4400 + i as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                    for (i, word) in [mov(0, 0), mov(8, 93), 0xd4000001].into_iter().enumerate() {
                        root.memory
                            .write_array(0x4300 + i as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                    root.memory
                        .write_array(0x4380, 0x14000000u32.to_le_bytes())
                        .unwrap();
                    root.memory
                        .protect(0x4000, PAGE_SIZE, Permissions::RX)
                        .unwrap();
                    root.cpu = trames_cpu::Cpu::new(0x4000, 0);
                    if cpus == 4 {
                        root.linux.vfs.credentials.caps.no_new_privs.set();
                        root.memory
                            .write(0x2000, &[6, 0, 0, 0, 0, 0, 0xff, 0x7f])
                            .unwrap();
                        root.memory.write_array(0x2100, 1u16.to_le_bytes()).unwrap();
                        root.memory
                            .write_array(0x2108, 0x2000u64.to_le_bytes())
                            .unwrap();
                        assert_eq!(k.seccomp(&mut root, [1, 0, 0x2100, 0, 0, 0]), Ok(0));
                    }
                    let policy = root.seccomp.clone();
                    k.install_proc_source(&root, None);
                    k.publish_task(1, &root);
                    let proc_leader =
                        trames_vfs::ProcSource::task(&**k.proc_source.as_ref().unwrap(), 1)
                            .unwrap();
                    if mode >= 3 {
                        k.syscall(
                            1,
                            &mut root,
                            220,
                            [0x10900, 0, 0, 0, 0, 0],
                            &mut trames_linux::CapturedOutput::default(),
                        )
                        .unwrap();
                        let child = &mut *k.processes.get_mut(&2).unwrap();
                        child.cpu_time = Duration::from_millis(3);
                        child.cpu.set_pc(if mode >= 4 { 0x4400 } else { 0x4000 });
                        root.cpu.set_pc(if mode >= 4 { 0x4300 } else { 0x4380 });
                    }
                    if mode >= 3 {
                        k.syscall(
                            1,
                            &mut root,
                            220,
                            [0x10900, 0, 0, 0, 0, 0],
                            &mut trames_linux::CapturedOutput::default(),
                        )
                        .unwrap();
                        k.processes.get_mut(&3).unwrap().cpu.set_pc(0x4380);
                    }
                    k.processes.insert(1, root);
                    let original_peer = (mode >= 3).then(|| k.processes.handle(&3).unwrap());
                    let evaluations = policy.evaluations();
                    let original = k.processes.handle(&1).unwrap();
                    let replacement = k.processes.handle(&if mode >= 3 { 2 } else { 1 }).unwrap();
                    let replacement_io = replacement.read().signals.io.clone();
                    let control = Arc::new(Control::new(u64::MAX / 2));
                    let epoch = Epoch::with_events(control.clone(), k.workers.events(), true);
                    epoch.bind_lifecycle(Lifecycle::capture(&k));
                    let members = if mode >= 3 {
                        vec![(1, 0), (2, 0), (3, 0)]
                    } else {
                        vec![(1, 0)]
                    };
                    for (id, _, view) in k.prepare_parallel_views(&members).unwrap() {
                        epoch.add(k.capture_worker(
                            id,
                            view,
                            &control,
                            &mut Default::default(),
                            &mut Default::default(),
                            &mut Default::default(),
                        ));
                    }
                    k.workers.launch(0, epoch.clone()).unwrap();
                    let mut stopped = 0;
                    let mut released = mode < 4;
                    // Model a completion accepted by the outside driver before
                    // rekey. Production source completion now consumes its own
                    // returned CPU without an owner Retired notification.
                    let late = (mode == 5).then(|| {
                        let mut done = crate::run_queue::Stats::default().finish(
                            1,
                            trames_cpu::Cpu::default(),
                            Some(SliceOutcome::Syscall { instructions: 0 }),
                            None,
                            None,
                            None,
                        );
                        done.task = Some(original.clone());
                        done.thread_exit = Some(0);
                        done
                    });
                    let deadline = Instant::now() + Duration::from_secs(5);
                    loop {
                        match k
                            .workers
                            .event_timeout(
                                deadline
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_millis(10)),
                            )
                            .unwrap()
                        {
                            Some(Event::Retired | Event::Idle) => {}
                            None => assert!(Instant::now() < deadline, "source exec timed out"),
                            Some(Event::EpochStopped(_)) => stopped += 1,
                            _ => {
                                panic!("exec required owner: cpus={cpus} mode={mode}")
                            }
                        }
                        if !released && !original.read().signals.io.live() {
                            assert_eq!(release.write(b"x"), Ok(1));
                            released = true;
                        }
                        if stopped == epoch.active_slots().count_ones() {
                            break;
                        }
                    }
                    assert!(
                        epoch.collect_lifecycle(&mut k).is_none(),
                        "cpus={cpus} mode={mode}"
                    );
                    assert!(epoch.member_ids().is_empty(), "cpus={cpus} mode={mode}");
                    assert!(epoch.drain().is_empty());
                    assert!(!replacement_io.live());
                    assert_eq!(
                        replacement.read().family.status(),
                        Some(if mode == 2 { 123 << 8 } else { 42 << 8 }),
                        "cpus={cpus} mode={mode}"
                    );
                    assert!(k.processes.directory().contains_original(1, &replacement));
                    if mode >= 3 {
                        assert!(!k.processes.directory().contains_original(1, &original));
                        assert!(!k.processes.contains_key(&2));
                        assert!(
                            !original.read().signals.presence.present(),
                            "replaced leader must disappear even with retained original custody"
                        );
                        assert!(
                            !original_peer
                                .as_ref()
                                .unwrap()
                                .read()
                                .signals
                                .presence
                                .present(),
                            "exec peers must disappear before their old bodies are dropped"
                        );
                    }
                    assert!(epoch.collect_lifecycle(&mut k).is_none());
                    assert_eq!(k.vm_checkpoint_groups, 1);
                    let before = replacement.read().memory.coordinator_ownership();
                    if let Some(old) = late {
                        k.accept_source_return(old).unwrap();
                    }
                    assert_eq!(replacement.read().memory.coordinator_ownership(), before);
                    assert_eq!(replacement.read().started, age);
                    if mode != 2 {
                        assert_eq!(
                            proc_leader.identity(),
                            replacement.read().signals.io.identity()
                        );
                    }
                    assert_eq!(k.syscalls, if mode >= 4 { 4 } else { 2 });
                    if cpus == 4 {
                        assert_eq!(
                            policy.evaluations() - evaluations,
                            k.syscalls,
                            "accepted exec policy is consumed once"
                        );
                    }
                    assert!(
                        replacement.read().cpu_time
                            >= Duration::from_millis(if mode >= 3 { 10 } else { 7 })
                    );
                    drop(original);
                    drop(replacement);
                    drop(epoch);
                    drop(k);
                    if disk {
                        std::fs::remove_dir_all(disk_path).unwrap();
                    }
                }
            }
        }
    }
    #[test]
    fn exec_replaces_the_original_task_without_stopping_a_foreign_cpu() {
        // execve, execveat, failed image, nonleader exec, surviving CLONE_VM
        // process and an externally retained old-memory borrower.
        for mode in 0..8 {
            let (publish, handles) = mpsc::channel();
            let (start, go) = mpsc::channel();
            let (finished, done) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut k = super::super::tests::kernel();
                k.cpu_count = 3;
                k.workers = crate::workers::Pool::new(3);
                k.per_cpu = vec![Duration::ZERO; 3];
                k.profile_syscalls = true;
                let mut root = super::super::tests::process();
                root.signals.io.scheduling.set_affinity(7);
                let backing = Arc::new(Backing(Mutex::new([0; PAGE_SIZE as usize])));
                if mode == 5 {
                    root.memory.unmap(0x6000, PAGE_SIZE).unwrap();
                    root.memory
                        .map_backed(0x6000, vec![backing.clone()], true, Permissions::RW, false)
                        .unwrap();
                }

                let [reader, writer] = root.linux.vfs.pipe(0).unwrap();
                let [resume, _] = root.linux.vfs.pipe(0).unwrap();
                let observed = root
                    .linux
                    .vfs
                    .shared_files()
                    .lookup(reader)
                    .unwrap()
                    .unwrap()
                    .direct_byte()
                    .unwrap();
                let body = [
                    mov(0, writer),
                    0x910003e1,
                    mov(2, 80),
                    0x39000022,
                    mov(2, 1),
                    mov(8, 64),
                    0xd4000001,
                    mov(0, resume),
                    0x910003e1,
                    mov(2, 1),
                    mov(8, 63),
                    0xd4000001,
                    0x14000000,
                ];
                root.linux
                    .vfs
                    .import_executable(
                        b"/image",
                        if mode == 2 {
                            b"not ELF".to_vec()
                        } else {
                            elf(&body)
                        },
                    )
                    .unwrap();
                root.memory.write(0x1000, b"/image\0").unwrap();
                root.memory.write(0x1100, b"P").unwrap();
                let execfd = root
                    .linux
                    .vfs
                    .open_at(AT_FDCWD, b"/image", 0x80000, 0)
                    .unwrap();
                if mode == 2 || mode == 7 {
                    root.linux.vfs.set_cloexec(writer, true).unwrap();
                }
                let mut words = if mode == 1 {
                    vec![
                        mov(0, execfd),
                        mov(1, 0x1008),
                        mov(2, 0),
                        mov(3, 0),
                        mov(4, 0x1000),
                        mov(8, 281),
                    ]
                } else {
                    vec![mov(0, 0x1000), mov(1, 0), mov(2, 0), mov(8, 221)]
                };
                words.extend([
                    0xd4000001,
                    mov(0, writer),
                    mov(1, 0x1100),
                    mov(2, 1),
                    mov(8, 64),
                    0xd4000001,
                    mov(0, resume),
                    mov(1, 0x1500),
                    mov(2, 1),
                    mov(8, 63),
                    0xd4000001,
                    0x14000000,
                ]);
                for (i, w) in words.iter().enumerate() {
                    root.memory
                        .write_array(0x4000 + i as u64 * 4, w.to_le_bytes())
                        .unwrap();
                }
                root.memory
                    .write_array(0x4300, 0x14000000u32.to_le_bytes())
                    .unwrap();
                root.memory
                    .protect(0x4000, PAGE_SIZE, Permissions::RX)
                    .unwrap();
                if mode >= 6 {
                    root.memory.write_array(0x2000, 4u64.to_le_bytes()).unwrap();
                    root.memory
                        .write_array(0x2008, 0x2100u64.to_le_bytes())
                        .unwrap();
                    // Filter only execve; all child creation, I/O and exit stay allowed.
                    for (i, (op, jt, jf, value)) in [
                        (0x20u16, 0u8, 0u8, 0u32),
                        (0x15, 0, 1, 221),
                        (6, 0, 0, if mode == 6 { 0x7fff0000 } else { 0x5000d }),
                        (6, 0, 0, 0x7fff0000),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let mut ins = [0; 8];
                        ins[..2].copy_from_slice(&op.to_le_bytes());
                        ins[2] = jt;
                        ins[3] = jf;
                        ins[4..].copy_from_slice(&value.to_le_bytes());
                        root.memory.write_array(0x2100 + i as u64 * 8, ins).unwrap();
                    }
                    root.linux.vfs.credentials.caps.no_new_privs.set();
                    assert_eq!(k.seccomp(&mut root, [1, 0, 0x2000, 0, 0, 0]), Ok(0));
                }
                let mut output = trames_linux::CapturedOutput::default();
                if mode == 3 || mode == 4 {
                    k.syscall(
                        1,
                        &mut root,
                        220,
                        [if mode == 3 { 0x10f00 } else { 0x111 }, 0, 0, 0, 0, 0],
                        &mut output,
                    )
                    .unwrap();
                    if mode == 3 {
                        root.cpu.set_pc(0x4300);
                        k.processes
                            .get_mut(&2)
                            .unwrap()
                            .signals
                            .io
                            .scheduling
                            .set_affinity(2);
                    } else {
                        k.processes.get_mut(&2).unwrap().cpu.set_pc(0x4300);
                    }
                }
                k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut output)
                    .unwrap();
                let foreign = k.task_ids.created();
                k.processes.get_mut(&foreign).unwrap().cpu.set_pc(0x4300);
                k.processes
                    .get_mut(&foreign)
                    .unwrap()
                    .signals
                    .io
                    .scheduling
                    .set_affinity(4);
                let task = if mode == 3 {
                    k.processes.read(&2).signals.io.clone()
                } else {
                    root.signals.io.clone()
                };
                let borrow = if mode == 5 {
                    Some(root.memory.parallel_view(&mut k.parallel_memory).unwrap())
                } else {
                    None
                };
                k.processes.insert(1, root);
                publish.send((observed, task, borrow)).unwrap();
                go.recv().unwrap();
                let result = k.parallel_epoch(&mut output, u64::MAX / 2, true);
                let live_shared = mode != 4 || k.processes.read(&2).signals.io.live();
                let late_write = mode != 5 || backing.0.lock().unwrap()[..8] == 9u64.to_le_bytes();

                finished
                    .send((
                        result.is_ok(),
                        k.cohort_return_syscalls.get(&221).copied().unwrap_or(0)
                            + k.cohort_return_syscalls.get(&281).copied().unwrap_or(0),
                        k.parallel_rounds,
                        live_shared && late_write,
                        k.exit_memory_pending(),
                    ))
                    .unwrap();
            });
            let (observed, task, mut borrow) =
                handles.recv_timeout(Duration::from_secs(5)).unwrap();
            let (wake, readable) = mpsc::channel();
            let target: Arc<dyn trames_vfs::IoWake> = Arc::new(Wake(wake));
            let signal = trames_vfs::IoSignal::new(0, Arc::downgrade(&target));
            let _subscription = observed.subscribe(&signal);
            start.send(()).unwrap();
            let notified = readable.recv_timeout(Duration::from_secs(2));
            let bytes = observed.read(1);
            let early = done.try_recv().ok();
            if let Some(view) = borrow.as_mut() {
                view.write(0x6000, &9u64.to_le_bytes()).unwrap();
            }
            drop(borrow);
            let _ = task.job_signal(9, false, Info::default(), true);
            let result = early
                .map(Ok)
                .unwrap_or_else(|| done.recv_timeout(Duration::from_secs(5)));
            worker.join().unwrap();
            assert!(
                notified.is_ok() && bytes == Ok(b"P".to_vec()) && early.is_none(),
                "mode={mode}: exec stopped foreign CPU: {bytes:?} {result:?}"
            );
            assert!(
                matches!(result, Ok((true, 0, 1, true, false))),
                "mode={mode}: {result:?}"
            );
        }
    }
}

/// An image contains movable guest state, never the thread-affine CPU engine.
pub(crate) struct Image<C: Cpu> {
    pub(super) cpu: C,
    pub(super) memory: Memory,
    pub(super) linux: Linux,
    credentials: trames_vfs::ExecCredentials,
    externally_shared_fs: bool,
    no_new_privs: bool,
}
impl<C: Cpu> Image<C> {
    // Group admission already owns these siblings. Consult membership only
    // for images whose credentials might be elevated by exec.
    pub(super) fn check_shared_fs(
        &mut self,
        vfs: &trames_vfs::Vfs,
        siblings: impl FnOnce() -> usize,
    ) {
        let c = &self.linux.vfs.credentials;
        if (c.euid != vfs.credentials.euid
            || !vfs.credentials.in_group(c.egid)
            || c.caps.permitted & !vfs.credentials.caps.permitted != 0)
            && {
                let users = vfs.live_context_users();
                users > 1 && users > 1 + siblings()
            }
        {
            self.externally_shared_fs = true;
        }
    }
    fn refresh_credentials(&mut self, externally_shared_fs: bool, traced: bool) {
        if !traced && !externally_shared_fs && self.credentials.no_new_privs() == self.no_new_privs
        {
            return;
        }
        self.no_new_privs =
            self.credentials
                .apply_observed_exec(&mut self.linux.vfs, externally_shared_fs, traced);
        let c = &self.linux.vfs.credentials;
        let base = self.cpu.sp()
            + 8 * (3 + self.linux.arguments.len() + self.linux.environment.len()) as u64;
        for (index, pair) in self.linux.auxiliary.chunks_exact_mut(16).enumerate() {
            let value = match u64::from_le_bytes(pair[..8].try_into().unwrap()) {
                11 => c.uid as u64,
                12 => c.euid as u64,
                13 => c.gid as u64,
                14 => c.egid as u64,
                23 => u64::from(c.secure_exec()),
                _ => continue,
            };
            pair[8..].copy_from_slice(&value.to_le_bytes());
            self.memory
                .write_array(base + index as u64 * 16 + 8, value.to_le_bytes())
                .expect("unpublished initial stack");
        }
    }
}
/// Guest strings, filesystem context and capabilities are accepted before I/O.
/// Filesystem objects remain the originals; no Process/Kernel or mm is sent.
pub(crate) struct Request {
    vfs: trames_vfs::Vfs,
    file: Option<Arc<trames_vfs::ExecutableFile>>,
    dirfd: i32,
    path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    flags: u32,
    options: crate::RuntimeOptions,
    clock_origin: Instant,
    search: bool,
    actor: trames_vfs::FileActorSnapshot,
    input: Option<Box<Inputs>>,
}
struct Inputs {
    filename: Vec<u8>,
    inaccessible: bool,
    depth: usize,
    access: Arc<trames_vfs::ExecutingFile>,
    read: trames_vfs::ExecutableRead,
    bytes: Option<Vec<u8>>,
    loader: Option<InterpreterInput>,
    credentials: Option<trames_vfs::ExecCredentials>,
    mapping: Option<trames_elf::Loader>,
    loaded: Option<trames_elf::LoadedElf>,
    entry: Option<crate::InitialEntry>,
    no_new_privs: Option<bool>,
    stack: Option<u64>,
}
struct InterpreterInput {
    file: Arc<trames_vfs::ExecutableFile>,
    _access: Arc<trames_vfs::ExecutingFile>,
    read: trames_vfs::ExecutableRead,
    bytes: Option<Vec<u8>>,
}
impl Request {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new<C: Cpu>(
        p: &Process<C>,
        dirfd: i32,
        path: Vec<u8>,
        argv: Vec<Vec<u8>>,
        envp: Vec<Vec<u8>>,
        flags: u32,
        budget: usize,
        clock_origin: Instant,
    ) -> Self {
        let resources = p
            .signals
            .io
            .cgroup()
            .map(trames_vfs::CgroupTask::resource_context)
            .unwrap_or_default();
        let _resources = resources.enter();
        Self {
            vfs: p.linux.vfs.clone(),
            file: None,
            search: false,
            actor: trames_vfs::FileActorScope::frozen_for(
                &p.linux.vfs.credentials,
                p.linux.vfs.process_context(),
            ),
            input: None,
            dirfd,
            path,
            argv,
            envp,
            flags,
            clock_origin,
            options: crate::RuntimeOptions {
                memory_limits: crate::MemoryLimits {
                    per_process: budget,
                    total: budget,
                },
                pure_accelerator: accelerated(
                    p,
                    trames_accel::native::AUXV_KEY,
                    trames_accel::native::PROFILE,
                ),
                audio_output: p.linux.auxiliary.chunks_exact(16).any(|pair| {
                    pair[..8] == trames_audio::CAPS_KEY.to_le_bytes()
                        && u64::from_le_bytes(pair[8..].try_into().unwrap()) & 1 != 0
                }),
                audio_input: p.linux.auxiliary.chunks_exact(16).any(|pair| {
                    pair[..8] == trames_audio::CAPS_KEY.to_le_bytes()
                        && u64::from_le_bytes(pair[8..].try_into().unwrap()) & 2 != 0
                }),
                video_accelerator: accelerated(p, trames_video::AUXV_KEY, trames_video::PROFILE),
                vulkan_accelerator: accelerated(p, trames_vulkan::AUXV_KEY, trames_vulkan::PROFILE),
                native_bsearch: p.linux.auxiliary.chunks_exact(16).any(|pair| {
                    pair[..8] == trames_accel::callbacks::SEARCH_AUXV_KEY.to_le_bytes()
                        && pair[8..] == 1u64.to_le_bytes()
                }),
                native_allocator: p.linux.auxiliary.chunks_exact(16).any(|pair| {
                    pair[..8] == trames_accel::allocator::AUXV_KEY.to_le_bytes()
                        && pair[8..] == trames_accel::allocator::PROFILE.to_le_bytes()
                }),
            },
        }
    }
    pub(super) fn host<C: Cpu>(
        p: &Process<C>,
        argv: Vec<Vec<u8>>,
        environment: Vec<Vec<u8>>,
        budget: usize,
        clock_origin: Instant,
        resources: trames_vfs::CgroupResourceContext,
    ) -> Self {
        let path = argv[0].clone();
        let mut request = Self::new(
            p,
            AT_FDCWD,
            path,
            argv,
            environment,
            0,
            budget,
            clock_origin,
        );
        request.search = !request.path.contains(&b'/');
        let _resources = resources.enter();
        request.actor = trames_vfs::FileActorScope::frozen_for(
            &request.vfs.credentials,
            request.vfs.process_context(),
        );
        request
    }
    pub(super) fn capture<C: Cpu>(
        p: &Process<C>,
        number: u32,
        a: [u64; 6],
        budget: usize,
        clock_origin: Instant,
    ) -> Result<Self, Errno> {
        let (dirfd, a, flags) = if number == 221 {
            (AT_FDCWD, a, 0)
        } else {
            (a[0] as i32, [a[1], a[2], a[3], 0, 0, 0], a[4] as u32)
        };
        let path = Linux::path(&p.memory, a[0])?;
        let mut budget_bytes = trames_linux::image::EXEC_ARGUMENT_BYTES;
        let argv = strings(&p.memory, a[1], &mut budget_bytes)?;
        let envp = strings(&p.memory, a[2], &mut budget_bytes)?;
        let file = p
            .linux
            .vfs
            .executable_file_from_resident_namespace(dirfd, &path, flags)?;
        let mut request = Self::new(p, dirfd, path, argv, envp, flags, budget, clock_origin);
        request.file = file;
        Ok(request)
    }
    pub(crate) fn load<C: Cpu>(mut self) -> Result<Image<C>, ImageError> {
        let _actor = self.actor.enter();
        let mapping = self
            .input
            .as_ref()
            .is_some_and(|input| input.mapping.is_some() || input.loaded.is_some());
        let wait = if !mapping { self.read_inputs()? } else { None };
        let wait = match wait {
            Some(wait) => Some(wait),
            None => self.prepare_mapping::<C>()?,
        };
        if let Some(wait) = wait {
            return Err(ImageError::Pending(Box::new(Retry {
                request: self,
                wait,
            })));
        }
        let input = *self.input.take().expect("accepted executable inputs");
        self.load_image(input)
    }
    fn begin_input(&mut self) -> Result<(), ImageError> {
        if self.search {
            let paths = self
                .envp
                .iter()
                .find_map(|e| e.strip_prefix(b"PATH="))
                .unwrap_or(b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
            let mut denied = false;
            let mut found = None;
            for directory in paths.split(|b| *b == b':') {
                let mut candidate = directory.to_vec();
                if !candidate.is_empty() {
                    candidate.push(b'/');
                }
                candidate.extend_from_slice(&self.path);
                match self.vfs.executable_file_at(AT_FDCWD, &candidate, 0) {
                    Ok(open) => {
                        found = Some((candidate, open));
                        break;
                    }
                    Err(e) if e.0 == 13 => denied = true,
                    Err(e) if matches!(e.0, 2 | 20) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            let (path, file) = found.ok_or(Errno(if denied { 13 } else { 2 }))?;
            self.path = path;
            self.file = Some(file);
            self.search = false;
        }
        if self.path.is_empty() && self.flags & 0x1000 == 0 {
            return Err(Errno(2).into());
        }
        if self.flags & !0x1100 != 0 {
            return Err(Errno(22).into());
        }
        let via_fd = self.path.is_empty() || !self.path.starts_with(b"/") && self.dirfd != AT_FDCWD;
        let filename = if via_fd {
            let mut name = format!("/dev/fd/{}", self.dirfd).into_bytes();
            if !self.path.is_empty() {
                name.push(b'/');
                name.extend_from_slice(&self.path);
            }
            name
        } else {
            self.path.clone()
        };
        let file = match &self.file {
            Some(file) => file.clone(),
            None => self
                .vfs
                .executable_file_at(self.dirfd, &self.path, self.flags)?,
        };
        let inaccessible =
            via_fd && self.vfs.flags(self.dirfd as u32)? & trames_vfs::O_CLOEXEC != 0;
        if self.argv.is_empty() {
            self.argv.push(Vec::new());
        }
        let access = file.begin_execution()?;
        let read = trames_vfs::ExecutableRead::new(file.clone())?;
        self.file = Some(file);
        self.input = Some(Box::new(Inputs {
            filename,
            inaccessible,
            depth: 0,
            access,
            read,
            bytes: None,
            loader: None,
            credentials: None,
            mapping: None,
            loaded: None,
            entry: None,
            no_new_privs: None,
            stack: None,
        }));
        Ok(())
    }
    fn read_inputs(&mut self) -> Result<Option<Arc<trames_memory::PageWait>>, ImageError> {
        if self.input.is_none() {
            self.begin_input()?;
        }
        loop {
            let input = self.input.as_mut().unwrap();
            if input.bytes.is_none() {
                let Some(bytes) = input.read.run()? else {
                    return Ok(Some(
                        input.read.wait().expect("original executable wait").clone(),
                    ));
                };
                if let Some((interpreter, optional)) = trames_vfs::script_interpreter(&bytes)? {
                    if input.depth == 0 && input.inaccessible {
                        return Err(Errno(2).into());
                    }
                    if input.depth == 5 {
                        return Err(Errno(40).into());
                    }
                    let mut next = vec![interpreter.clone()];
                    next.extend(optional);
                    next.push(if input.depth == 0 {
                        input.filename.clone()
                    } else {
                        self.path.clone()
                    });
                    next.extend(std::mem::take(&mut self.argv).into_iter().skip(1));
                    self.argv = next;
                    self.path = interpreter;
                    let file = self.vfs.executable_file_at(AT_FDCWD, &self.path, 0)?;
                    let access = file.begin_execution()?;
                    let read = trames_vfs::ExecutableRead::new(file.clone())?;
                    self.file = Some(file);
                    input.depth += 1;
                    input.access = access;
                    input.read = read;
                    continue;
                }
                input.bytes = Some(bytes);
            }
            if input.credentials.is_none() {
                let mut credentials = self.vfs.exec_credentials(self.file.as_ref().unwrap())?;
                self.options.memory_limits.validate().map_err(image_error)?;
                let interpreter = trames_elf::interpreter(input.bytes.as_ref().unwrap())
                    .map_err(|e| image_error(RuntimeError::Elf(e)))?;
                if let Some(path) = interpreter {
                    let file = self.vfs.executable_file_at(AT_FDCWD, path, 0)?;
                    credentials.include_interpreter(&self.vfs, &file);
                    let access = file.begin_execution()?;
                    let read = trames_vfs::ExecutableRead::new(file.clone())?;
                    input.loader = Some(InterpreterInput {
                        file,
                        _access: access,
                        read,
                        bytes: None,
                    });
                }
                input.credentials = Some(credentials);
            }
            if let Some(loader) = &mut input.loader {
                if loader.bytes.is_none() {
                    let Some(bytes) = loader.read.run()? else {
                        return Ok(Some(
                            loader.read.wait().expect("original PT_INTERP wait").clone(),
                        ));
                    };
                    loader.bytes = Some(bytes);
                }
            }
            return Ok(None);
        }
    }
    fn prepare_mapping<C: Cpu>(
        &mut self,
    ) -> Result<Option<Arc<trames_memory::PageWait>>, ImageError> {
        let input = self.input.as_mut().expect("accepted executable inputs");
        if input.mapping.is_none() && input.loaded.is_none() {
            self.options.memory_limits.validate().map_err(image_error)?;
            self.options
                .memory_limits
                .configure_shared_memory(&self.vfs);
            if self.options.video_accelerator {
                self.vfs.enable_video_device();
            }
            let interpreter = input.loader.as_mut().map(|loader| {
                (
                    loader.bytes.take().expect("original PT_INTERP bytes"),
                    Some(self.vfs.executable_mapping(&loader.file)),
                )
            });
            input.mapping = Some(
                trames_elf::Loader::new(
                    input.bytes.take().expect("original main image bytes"),
                    self.options.memory_limits.per_process,
                    Some(self.vfs.executable_mapping(self.file.as_ref().unwrap())),
                    interpreter,
                )
                .map_err(|error| image_error(RuntimeError::Elf(error)))?,
            );
        }
        if input.loaded.is_none() {
            let mapping = input.mapping.as_mut().unwrap();
            input.loaded = mapping
                .run()
                .map_err(|error| image_error(RuntimeError::Elf(error)))?;
            if input.loaded.is_none() {
                return Ok(Some(mapping.wait().unwrap().clone()));
            }
            input.mapping = None;
        }
        if input.no_new_privs.is_none() {
            input.no_new_privs = Some(input.credentials.as_ref().unwrap().apply(&mut self.vfs));
        }
        let loaded = input.loaded.as_mut().unwrap();
        if input.entry.is_none() {
            input.entry = Some(crate::InitialEntry::new(&loaded.memory).map_err(image_error)?);
        }
        let result = input.entry.as_mut().unwrap().run::<C>(
            loaded,
            &self.argv,
            &self.envp,
            &self.vfs.credentials,
            self.options,
            Some(&input.filename),
        );
        match result {
            Ok(stack) => {
                input.stack = Some(stack);
                Ok(None)
            }
            Err(RuntimeError::Memory(trames_memory::MemoryError::Pending(fault))) => {
                Ok(Some(fault.wait))
            }
            Err(error) => Err(image_error(error)),
        }
    }
    fn load_image<C: Cpu>(self, mut input: Inputs) -> Result<Image<C>, ImageError> {
        let Self {
            vfs: execute_vfs,
            argv,
            envp,
            options,
            clock_origin,
            ..
        } = self;
        let credentials = input.credentials.take().unwrap();
        let no_new_privs = input.no_new_privs.unwrap();
        let mut runtime = Runtime::<C>::start_image_at(
            input
                .loaded
                .take()
                .expect("completed original image mappings"),
            &argv,
            &envp,
            &execute_vfs,
            options,
            Some(&input.filename),
            Some(input.access),
            input.stack,
        )
        .map_err(image_error)?;
        crate::clock::initialize::<C>(&mut runtime.memory, &runtime.linux.auxiliary, clock_origin)
            .map_err(|_| Errno(12))?;
        if runtime.memory.resident_bytes() > options.memory_limits.per_process {
            return Err(Errno(12).into());
        }
        runtime.linux.command_name.set(
            &(input
                .filename
                .rsplit(|b| *b == b'/')
                .next()
                .unwrap_or_default()
                .iter()
                .copied()
                .take(15)
                .collect::<Vec<_>>()),
        );
        runtime.linux.vfs.credentials = execute_vfs.credentials.clone();
        runtime
            .linux
            .vfs
            .install_exec_dumpable(execute_vfs.dumpable_state());
        Ok(Image {
            cpu: runtime.cpu,
            memory: runtime.memory,
            linux: runtime.linux,
            credentials,
            no_new_privs,
            externally_shared_fs: false,
        })
    }
}
fn image_error(error: RuntimeError) -> ImageError {
    match error {
        RuntimeError::Elf(trames_elf::ElfError::SegmentMapping(_)) => ImageError::Unmappable,
        RuntimeError::Arguments(_) => Errno(7).into(),
        RuntimeError::Memory(_)
        | RuntimeError::Configuration(_)
        | RuntimeError::Elf(trames_elf::ElfError::Memory(_)) => Errno(12).into(),
        RuntimeError::Elf(trames_elf::ElfError::Interpreter(n)) => Errno(n).into(),
        _ => Errno(8).into(),
    }
}

pub(crate) trait Executor<C: Cpu>: Send + Sync {
    fn submit_image(&self, request: Request, result: Arc<Pending<C>>);
}
pub(super) enum Preparation<C: Cpu> {
    PeerExit(Box<Image<C>>, Arc<trames_kernel::signal::ExecPeerExit>),
    Error(Errno),
    Disk(Arc<Pending<C>>),
}
impl<C: Cpu> Preparation<C> {
    pub(super) fn resume(&self, executor: &dyn Executor<C>) {
        if let Self::Disk(pending) = self {
            pending.resume(executor);
        }
    }
    pub(super) fn ready(&self) -> bool {
        match self {
            Self::PeerExit(_, hold) => hold.acknowledgement.finished(),
            Self::Error(_) => true,
            Self::Disk(pending) => pending.ready(),
        }
    }
    pub(super) fn take(self) -> Result<Image<C>, ImageError> {
        match self {
            Self::PeerExit(image, _) => Ok(*image),
            Self::Error(error) => Err(error.into()),
            Self::Disk(pending) => pending.take().expect("ready image result"),
        }
    }
    pub(super) fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        match self {
            Self::PeerExit(_, hold) => vec![hold.acknowledgement.subscribe(signal)],
            Self::Disk(pending) => pending.subscribe(signal),
            Self::Error(_) => unreachable!("inline errors never wait"),
        }
    }
}
pub(crate) struct Pending<C: Cpu> {
    result: std::sync::Mutex<Option<Result<Image<C>, ImageError>>>,
    waiting: std::sync::Mutex<Option<Box<Retry>>>,
    ready: std::sync::atomic::AtomicBool,
    readiness: Arc<trames_shared::Readiness>,
}
impl<C: Cpu> Pending<C> {
    pub(super) fn new() -> Self {
        Self {
            result: Default::default(),
            waiting: Default::default(),
            ready: Default::default(),
            readiness: Arc::default(),
        }
    }
    pub(crate) fn complete(&self, result: Result<Image<C>, ImageError>) {
        match result {
            Err(ImageError::Pending(retry)) => *self.waiting.lock().unwrap() = Some(retry),
            result => {
                *self.result.lock().unwrap() = Some(result);
                self.ready.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        self.readiness.notify_locked();
    }
    fn resume(self: &Arc<Self>, executor: &dyn Executor<C>) {
        let retry = {
            let mut waiting = self.waiting.lock().unwrap();
            if waiting.as_ref().is_some_and(|retry| retry.wait.ready()) {
                waiting.take()
            } else {
                None
            }
        };
        if let Some(retry) = retry {
            let Retry { request, wait } = *retry;
            drop(wait);
            executor.submit_image(request, self.clone());
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }
    fn take(&self) -> Option<Result<Image<C>, ImageError>> {
        self.result.lock().unwrap().take()
    }
    pub(super) fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        let mut subscriptions = vec![self.readiness.subscribe(signal)];
        let wait = self
            .waiting
            .lock()
            .unwrap()
            .as_ref()
            .map(|retry| retry.wait.clone());
        if let Some(wait) = wait {
            subscriptions.extend(wait.subscribe(signal));
            if wait.ready() {
                signal.notify();
            }
        }
        subscriptions
    }
}
