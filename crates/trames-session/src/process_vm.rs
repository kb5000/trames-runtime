// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapping commits quiesce actual mm/backing domains. Other jobs, translations,
//! pending I/O and native calls stay in the existing execution queue.
use super::*;

impl<C: Cpu> Kernel<C> {
    pub(super) fn vm_checkpoint(
        &mut self,
        epoch: &crate::run_queue::Epoch<C>,
        mut checkpoint: crate::run_queue::Checkpoint<C>,
        io: &mut impl GuestOutput,
    ) -> Result<bool, RuntimeError> {
        let began = Instant::now();
        // Every CPU/service of these mm/backing domains has returned. Their
        // coordinator Rc graphs stay here; no unrelated Memory is inspected.
        for job in &mut checkpoint.jobs {
            drop(job.work.memory.take());
        }
        let result = (|| {
            let mut committed = std::collections::BTreeSet::new();
            for job in &checkpoint.jobs {
                let p = &mut self.processes.get_mut(&job.work.pid).unwrap();
                let id = p.memory.coordinator_ownership().0;
                if committed.insert(id) {
                    if !p.memory.parallel_views_quiescent() {
                        return Ok(false); // an externally retained generation
                    }
                    p.memory.commit_parallel()?;
                }
            }
            self.vm_checkpoint_groups += 1;
            self.vm_checkpoint_spaces += committed.len() as u64;
            self.parallel_memory_time += began.elapsed();
            for job in &mut checkpoint.jobs {
                let Some(outcome) = job.checkpoint.take() else {
                    continue;
                };
                assert!(matches!(outcome, SliceOutcome::Syscall { .. }));
                let pid = job.work.pid;
                let mut p = self.processes.remove(&pid).expect("paused task");
                assert!(!p.linux.trace && p.seccomp.mode() == 0);
                p.cpu = std::mem::take(&mut job.work.cpu);
                p.state = State::Ready;
                let number = p.cpu.x(8) as u32;
                assert!(crate::worker_syscalls::vm_call(number));
                let args = std::array::from_fn(|i| p.cpu.x(i));
                self.call(pid, &mut p, number, args, io);
                assert!(matches!(p.state, State::Ready), "mapping call cannot park");
                job.work.cpu = std::mem::take(&mut p.cpu);
                self.processes.insert(pid, p);
                self.vm_local_syscalls += 1;
            }
            let members: Vec<_> = checkpoint
                .jobs
                .iter()
                .map(|job| (job.work.pid, job.stats.worker))
                .collect();
            let began = Instant::now();
            let Some(mut views) = self.prepare_parallel_views(&members) else {
                return Ok(false); // changed to an excluded backing; join once
            };
            self.admit_private_views(&mut views);
            for (pid, _, view) in views {
                checkpoint
                    .jobs
                    .iter_mut()
                    .find(|job| job.work.pid == pid)
                    .unwrap()
                    .work
                    .memory = Some(view);
            }
            self.parallel_memory_time += began.elapsed();
            Ok(true)
        })();
        epoch.restore_checkpoint(checkpoint, matches!(result, Ok(true)));
        result
    }

    pub(super) fn cohort_control(
        &mut self,
        members: &[(u32, usize)],
        io: &mut impl GuestOutput,
    ) -> Result<bool, RuntimeError> {
        self.persistent_control_checks += 1;
        if let Some(root) = self.processes.get(&1) {
            if io
                .poll_control(&root.linux.vfs)
                .map_err(|_| RuntimeError::Arguments("host session control failed"))?
            {
                return Ok(true);
            }
            // Native SCM_RIGHTS and namespace adapters retain their explicit
            // owner boundary. Their FD/control graph is not a worker authority.
            if root.linux.vfs.has_native_services() {
                return Ok(true);
            }
            if root.linux.vfs.live_ptys().iter().any(|pair| {
                pair.host_resize_pending.get()
                    || pair.host_signals.get() != 0
                    || !pair.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                        && !pair.hangup_notified.get()
            }) {
                return Ok(true);
            }
        }
        if let Some(tty) = &self.terminal {
            if !tty.echo.is_empty()
                || !tty.output_queue.is_empty()
                || !tty.eof
                    && io
                        .stdin_ready()
                        .map_err(|_| RuntimeError::Arguments("terminal master input failed"))?
            {
                return Ok(true);
            }
        }
        let now = Instant::now();
        if self
            .timers
            .values()
            .any(|timer| timer.deadline.is_some_and(|d| d <= now))
        {
            return Ok(true);
        }
        let members: std::collections::BTreeSet<_> = members.iter().map(|(pid, _)| *pid).collect();
        Ok(self.processes.iter().any(|(&pid, p)| {
            if members.contains(&pid) || p.frozen(pid) {
                return false;
            }
            match p.state {
                State::Ready | State::Gpu { .. } | State::Blocked(..) => true,
                State::Sleep(d, _) => d <= now,
                State::Futex { deadline, .. } | State::Sigwait { deadline, .. } => {
                    deadline.is_some_and(|d| d <= now)
                }
                _ => false,
            }
        }))
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Process = crate::process::Process<Cpu>;

    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use trames_memory::{MemoryError, PageBacking, Permissions, SharedPage, PAGE_SIZE};

    struct Page {
        bytes: Arc<SharedPage>,
        gate: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
    }
    impl Drop for Page {
        fn drop(&mut self) {
            if let Some((entered, release)) = &self.gate {
                entered.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
        }
    }
    impl PageBacking for Page {
        fn parallel_key(&self) -> Option<(u64, u64)> {
            Some((Arc::as_ptr(&self.bytes) as usize as u64, 0))
        }
        fn shared_page(&self) -> Option<Arc<SharedPage>> {
            Some(self.bytes.clone())
        }
        fn check(&self, _: u64) -> Result<(), MemoryError> {
            Ok(())
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
            self.bytes
                .with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes));
            Ok(())
        }
        fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
            self.bytes
                .with_write(offset, bytes.len(), |out| out.copy_from_slice(bytes));
            Ok(())
        }
        fn writable(&self) -> bool {
            true
        }
        fn sync(&self) -> Result<(), MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            self.bytes.revision()
        }
        fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
            Ok(())
        }
        fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
            Err(MemoryError::InvalidRange)
        }
    }
    fn map(
        p: &mut Process,
        base: u64,
        bytes: Arc<SharedPage>,
        gate: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
    ) {
        p.memory.unmap(base, PAGE_SIZE).unwrap();
        p.memory
            .map_backed(
                base,
                vec![Rc::new(Page { bytes, gate })],
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
    }
    fn code(p: &mut Process, words: &[u32]) {
        let bytes: Vec<_> = words.iter().copied().flat_map(u32::to_le_bytes).collect();
        p.memory.write(0x4000, &bytes).unwrap();
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
    }
    fn count(page: &SharedPage) -> u64 {
        page.with_read(0, 8, |bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
    }
    struct Stop(Arc<AtomicBool>);
    impl GuestOutput for Stop {
        fn poll_control(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<bool> {
            Ok(self.0.load(Ordering::Relaxed))
        }
        fn control(&mut self, _: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
            Ok(!self.0.load(Ordering::Relaxed))
        }
        fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
    }

    #[test]
    fn additive_mmap_reaches_a_running_clone_vm_peer_without_a_vm_checkpoint() {
        struct Completed {
            bytes: Arc<SharedPage>,
            deadline: Instant,
        }
        impl GuestOutput for Completed {
            fn control(&mut self, _: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
                Ok(!self.bytes.with_read(8, 8, |b| b == 17u64.to_le_bytes())
                    && Instant::now() < self.deadline)
            }
            fn poll_control(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<bool> {
                Ok(self.bytes.with_read(8, 8, |b| b == 17u64.to_le_bytes())
                    || Instant::now() >= self.deadline)
            }
            fn write(&mut self, _: OutputFd, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len())
            }
        }
        let mut k = super::super::tests::kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        let mut a = super::super::tests::process();
        let bytes = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
        map(&mut a, 0x1000, bytes.clone(), None);
        // mmap; store 17 in the returned mapping; STLR its pointer; keep running.
        let mut words = vec![
            0xd4000001, 0xaa0003e2, 0xd2800221, 0xf9000041, 0xd2820003, 0xc89ffc62, 0x14000000,
        ];
        words.resize(64, 0xd503201f);
        // LDAR pointer; wait for publication; load through the original View.
        words.extend([
            0xd2820003, 0xc8dffc60, 0xb4ffffe0, 0xf9400001, 0xf9000461, 0xf9400862, 0x91000442,
            0xf9000862, 0x17fffffd,
        ]);
        code(&mut a, &words);
        for (i, x) in [0, 1 << 21, 3, 0x22, u64::MAX, 0].into_iter().enumerate() {
            a.cpu.set_x(i, x);
        }
        a.cpu.set_x(8, 222);
        let memory = a.memory.share();
        let mut b = a.fork_with_memory(memory);
        b.cpu.pc = 0x4100;
        b.affinity = 2;
        k.processes.insert(1, a);
        k.processes.insert(2, b);
        let mut io = Completed {
            bytes: bytes.clone(),
            deadline: Instant::now() + Duration::from_secs(3),
        };
        assert!(matches!(
            k.drive(&mut io, u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        assert_eq!(
            bytes.with_read(8, 8, |b| u64::from_le_bytes(b.try_into().unwrap())),
            17
        );
        assert_eq!(
            k.vm_checkpoint_groups, 0,
            "a pure addition cannot pause same-mm peers"
        );
        assert_eq!(k.vm_local_syscalls, 1);
        assert_eq!(k.service_requests, 1);
        assert_eq!(k.parallel_rounds, 1, "the cohort remains live");
    }

    fn commit_while_peer_runs(relation: u8) {
        let mut k = super::super::tests::kernel();
        k.cpu_count = if relation == 0 { 2 } else { 3 };
        k.workers = crate::workers::Pool::new(k.cpu_count);
        k.per_cpu = vec![Duration::ZERO; k.cpu_count];
        let mut a = super::super::tests::process();
        let (entered, wait) = mpsc::sync_channel(0);
        let (release, receive) = mpsc::sync_channel(0);
        map(
            &mut a,
            0x8000,
            Arc::new(SharedPage::new([0; PAGE_SIZE as usize])),
            Some((entered, receive)),
        );
        code(&mut a, &[0xd4000001, 0x14000000]);
        a.cpu.set_x(0, 0x8000);
        a.cpu.set_x(1, PAGE_SIZE);
        a.cpu.set_x(8, 215);
        let mut paused = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
        let mut related = if relation == 2 {
            map(&mut a, 0x1000, paused.clone(), None);
            let memory = a.memory.share();
            let mut b = a.fork_with_memory(memory);
            b.cpu.pc = 0x4100;
            let loop_code: Vec<_> = [0xf9400020u32, 0x91000400, 0xf9000020, 0x17fffffd]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            // Mapping writes happen before any View is published.
            a.memory
                .protect(0x4000, PAGE_SIZE, Permissions::RW)
                .unwrap();
            a.memory.write(0x4100, &loop_code).unwrap();
            a.memory
                .protect(0x4000, PAGE_SIZE, Permissions::RX)
                .unwrap();
            Some(b)
        } else if matches!(relation, 1 | 3 | 4) {
            let mut b = super::super::tests::process();
            map(&mut b, 0x1000, paused.clone(), None);
            if relation >= 3 {
                let fd = if relation == 4 {
                    a.linux.vfs.memfd_create(b"shared-writer", 0).unwrap()
                } else {
                    a.linux
                        .vfs
                        .open_at(-100, b"/shared-library", 0x42, 0o600)
                        .unwrap()
                };
                a.linux.vfs.truncate_fd(fd, PAGE_SIZE).unwrap();
                for memory in [&mut a.memory, &mut b.memory] {
                    memory.unmap(0x6000, PAGE_SIZE).unwrap();
                    let pages = a
                        .linux
                        .vfs
                        .mapping_pages(fd, 0, PAGE_SIZE, relation == 4, relation == 4)
                        .unwrap();
                    if relation == 4 {
                        paused = pages[0].shared_page().unwrap();
                    }
                    memory
                        .map_backed(
                            0x6000,
                            pages,
                            relation == 4,
                            if relation == 4 {
                                Permissions::RW
                            } else {
                                Permissions::RX
                            },
                            false,
                        )
                        .unwrap();
                }
            } else {
                let shared = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
                map(&mut a, 0x6000, shared.clone(), None);
                map(&mut b, 0x6000, shared, None);
            }
            code(&mut b, &[0xf9400020, 0x91000400, 0xf9000020, 0x17fffffd]);
            Some(b)
        } else {
            None
        };
        a.affinity = 1;
        if let Some(b) = &mut related {
            b.tgid = 2;
            b.vm_id = if relation == 2 { 1 } else { 2 };
            b.affinity = 2;
            b.cpu.set_x(1, if relation == 4 { 0x6000 } else { 0x1000 });
        }
        let mut peer = super::super::tests::process();
        let progressing = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
        map(&mut peer, 0x1000, progressing.clone(), None);
        code(&mut peer, &[0xf9400020, 0x91000400, 0xf9000020, 0x17fffffd]);
        peer.cpu.set_x(1, 0x1000);
        peer.affinity = 1 << (k.cpu_count - 1);
        peer.tgid = 3;
        peer.vm_id = 3;
        k.processes.insert(1, a);
        if let Some(b) = related {
            k.processes.insert(2, b);
        }
        k.processes.insert(3, peer);
        let stopped = Arc::new(AtomicBool::new(false));
        let done = stopped.clone();
        let observer = std::thread::spawn(move || {
            wait.recv_timeout(Duration::from_secs(3)).unwrap();
            let before = count(&progressing);
            let other_before = count(&paused);
            let deadline = Instant::now() + Duration::from_millis(100);
            while (count(&progressing) == before || relation >= 3 && count(&paused) == other_before)
                && Instant::now() < deadline
            {
                std::thread::yield_now();
            }
            let advanced = count(&progressing) > before;
            let quiescent = count(&paused) == other_before;
            done.store(true, Ordering::Relaxed);
            release.send(()).unwrap();
            (advanced, quiescent)
        });
        assert!(matches!(
            k.drive(&mut Stop(stopped), u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        let (advanced, quiescent) = observer.join().unwrap();
        assert!(
            advanced,
            "an unrelated VM stopped during the mapping commit"
        );
        assert_eq!(
            quiescent,
            relation < 3,
            "only same-mm or coupled-provider peers must stop during a local mapping commit"
        );
        assert_eq!(k.vm_checkpoint_groups, 1);
        assert_eq!(k.vm_checkpoint_spaces, if relation == 1 { 2 } else { 1 });
        assert_eq!(k.vm_local_syscalls, 1);
        assert_eq!(k.parallel_rounds, 1);
        assert!(!k.processes[&1]
            .memory
            .regions()
            .iter()
            .any(|(a, b, _)| *a <= 0x8000 && *b > 0x8000));
    }
    #[test]
    fn vm_commit_keeps_an_unrelated_cpu_running_while_the_owner_blocks() {
        commit_while_peer_runs(0);
    }
    #[test]
    fn vm_commit_quiesces_shared_backings_but_keeps_an_unrelated_vm_running() {
        commit_while_peer_runs(1);
    }
    #[test]
    fn vm_commit_keeps_a_shared_readonly_library_peer_running() {
        commit_while_peer_runs(3);
    }
    #[test]
    fn vm_commit_keeps_a_canonical_shared_file_writer_running() {
        commit_while_peer_runs(4);
    }
    #[test]
    fn vm_commit_quiesces_all_clone_vm_cpus_and_keeps_an_unrelated_vm_running() {
        commit_while_peer_runs(2);
    }
    #[test]
    fn persistent_checks_keep_jobs_and_translations_until_actual_cancellation() {
        struct Polls(u64);
        impl GuestOutput for Polls {
            fn poll_control(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<bool> {
                self.0 += 1;
                Ok(self.0 == 5)
            }
            fn control(&mut self, _: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
                Ok(self.0 < 5)
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        let mut k = super::super::tests::kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        for id in 1..=2 {
            let mut p = super::super::tests::process();
            p.tgid = id;
            p.vm_id = id as u64;
            p.affinity = 1 << (id - 1);
            code(&mut p, &[0x14000000]);
            k.processes.insert(id, p);
        }
        let mut polls = Polls(0);
        assert!(matches!(
            k.drive(&mut polls, u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        assert_eq!(polls.0, 5);
        assert_eq!(k.persistent_control_checks, 5);
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.vm_checkpoint_groups, 0);
        assert_eq!(k.parallel_memory.metrics.full_rebuilds, 2);
        assert!(k
            .processes
            .values()
            .all(|p| p.memory.parallel_views_quiescent()));
        let limit = k.instructions + 1000;
        assert!(matches!(
            k.drive(&mut trames_linux::CapturedOutput::default(), limit),
            Err(RuntimeError::BudgetExceeded(_))
        ));
        assert_eq!(k.instructions, limit);
    }
    #[test]
    fn persistent_idle_waits_survive_fd_reuse_and_wake_without_rebuilding_the_cohort() {
        struct Input {
            checks: u64,
            writer: trames_vfs::DirectFd,
            completed: Arc<SharedPage>,
            deadline: Instant,
        }
        impl GuestOutput for Input {
            fn poll_control(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<bool> {
                self.checks += 1;
                if self.checks == 3 {
                    assert_eq!(self.writer.write(b"xy"), Ok(2));
                }
                let completed = self.completed.with_read(0, 16, |bytes| {
                    bytes[..8] == 1u64.to_le_bytes() && bytes[8..] == 1u64.to_le_bytes()
                });
                Ok(self.checks >= 6 && completed || Instant::now() >= self.deadline)
            }
            fn stdin_ready(&mut self) -> std::io::Result<bool> {
                Ok(false)
            }
            fn control(&mut self, _: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
                Ok(self.checks == 0)
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        let mut k = super::super::tests::kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.terminal = Some(Terminal::default());
        let mut a = super::super::tests::process();
        code(&mut a, &[0xf9000120, 0x14000000]); // acknowledge the resumed read, then loop
        let [reader, writer] = a.linux.vfs.pipe(0).unwrap();
        let writer = a.linux.vfs.direct_descriptors().get(writer).unwrap();
        let mut b = a.fork();
        b.tgid = 2;
        b.vm_id = 2;
        b.affinity = 2;
        let completed = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
        let mut io = Input {
            checks: 0,
            writer,
            completed: completed.clone(),
            deadline: Instant::now() + Duration::from_secs(3),
        };
        for (id, mut p) in [(1, a), (2, b)] {
            map(&mut p, 0x2000, completed.clone(), None);
            p.cpu.set_x(9, 0x2000 + (id as u64 - 1) * 8);
            k.call(id, &mut p, 63, [reader as u64, 0x1000, 1, 0, 0, 0], &mut io);
            assert!(p.byte_wait.is_some());
            p.linux.vfs.close(reader).unwrap();
            assert_eq!(p.linux.vfs.eventfd(9, O_NONBLOCK).unwrap(), reader);
            k.processes.insert(id, p);
        }
        assert!(matches!(
            k.drive(&mut io, u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        let mut bytes: Vec<_> = k
            .processes
            .values()
            .map(|p| p.memory.read_array::<1>(0x1000).unwrap()[0])
            .collect();
        bytes.sort_unstable();
        assert_eq!(bytes, b"xy");
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.worker_direct_syscalls, 2);
        assert_eq!(k.service_requests, 0);
        for p in k.processes.values_mut() {
            assert!(p.retained_byte.is_none());
            assert_eq!(p.linux.vfs.read(reader, 8).unwrap(), 9u64.to_le_bytes());
        }
    }
}
