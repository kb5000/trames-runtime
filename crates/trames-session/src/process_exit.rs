// SPDX-License-Identifier: GPL-3.0-or-later
//! Exit resource completion uses original task/mm readiness. Other CPUs keep
//! running; owner-local projections do not require a whole-cohort checkpoint.
use super::*;
use crate::workers::{Done, Event};
use trames_kernel::task_control::Group;

#[derive(Default)]
pub(super) struct Retirements {
    groups: BTreeMap<usize, Arc<Group>>,
    waits: BTreeMap<u32, Wait>,
    pub(super) memory: Arc<crate::retired_memory::RetiredMemory>,
}
impl Retirements {
    pub(super) fn waiting(&self, pid: u32) -> bool {
        self.waits.contains_key(&pid)
    }
}
struct Wait {
    task: Arc<trames_kernel::signal::IoTask>,
    status: i32,
    signal: Arc<trames_vfs::IoSignal>,
    _subscriptions: Vec<trames_vfs::IoSubscription>,
    _target: Arc<dyn trames_vfs::IoWake>,
}
struct Wake<C: Cpu> {
    events: std::sync::mpsc::Sender<Event<C>>,
    owner: std::thread::Thread,
}
impl<C: Cpu> trames_vfs::IoWake for Wake<C> {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
        let _ = self.events.send(Event::Retired);
        self.owner.unpark();
    }
}
impl<C: Cpu> Kernel<C> {
    pub(super) fn memory_retirements(&self) -> Arc<crate::retired_memory::RetiredMemory> {
        self.exits.memory.bind_owner(|| {
            Arc::new(Wake {
                events: self.workers.events(),
                owner: std::thread::current(),
            })
        });
        self.exits.memory.clone()
    }
    pub(super) fn retire_detached_memory(
        &mut self,
        memory: Memory,
    ) -> Result<(), trames_memory::MemoryError> {
        self.memory_retirements().retire(memory)
    }
    pub(super) fn queue_exit_group(&mut self, group: Arc<Group>) {
        self.exits
            .groups
            .entry(Arc::as_ptr(&group) as usize)
            .or_insert(group);
    }
    pub(super) fn accept_source_return(&mut self, mut done: Done<C>) -> Result<(), RuntimeError> {
        let status = done.thread_exit.expect("accepted source exit");
        for group in std::mem::take(&mut done.exit_groups) {
            self.queue_exit_group(group);
        }
        let pid = done.pid;
        let original = done.task.clone();
        // Keep identity validation and original cleanup in the same object
        // custody interval. Source exec admission must not interleave a rekey.
        let _custody = original.as_ref().map(|task| task.collect_admission());
        self.restore_worker_return(done);
        // Exec may have retired/rekeyed this exact task while its asynchronous
        // statistics were in transit. Never apply old cleanup to a replacement.
        if original
            .as_ref()
            .is_some_and(|task| !self.processes.directory().contains_original(pid, task))
        {
            return Ok(());
        }
        self.begin_source_projection(pid, status)
    }
    fn wait_exit_memory(&mut self, pid: u32, status: i32) {
        if self.exits.waits.contains_key(&pid) {
            return;
        }
        let p = &self.processes.read(&pid);
        let target: Arc<dyn trames_vfs::IoWake> = Arc::new(Wake {
            events: self.workers.events(),
            owner: std::thread::current(),
        });
        let signal = trames_vfs::IoSignal::new(pid, Arc::downgrade(&target));
        let subscriptions = lifecycle::layouts::wait_view(&p.memory, &signal);
        self.exits.waits.insert(
            pid,
            Wait {
                task: p.signals.io.clone(),
                status,
                signal,
                _subscriptions: subscriptions,
                _target: target,
            },
        );
    }
    fn begin_source_projection(&mut self, pid: u32, status: i32) -> Result<(), RuntimeError> {
        {
            let p = &mut *self.processes.get_mut(&pid).expect("returned task");
            {
                let task = &mut *p;
                task.linux.vfs.set_lock_owner(task.tgid);
            }
            p.linux.vfs.collect_retired_descriptors();
            Self::clear_exit_resources(p);
        }
        self.finish_source_memory(pid, status)
    }
    fn finish_source_memory(&mut self, pid: u32, status: i32) -> Result<(), RuntimeError> {
        let borrowed = {
            let p = &self.processes.read(&pid);
            if p.memory.coordinator_ownership().1 == 1 {
                p.memory.retire_memory_report();
            }
            p.memory.coordinator_ownership().1 == 1 && !p.memory.parallel_views_quiescent()
        };
        self.exits.waits.remove(&pid);
        let mut custody = self.processes.get_mut(&pid).unwrap();
        let p = &mut *custody;
        if borrowed {
            // All actual task Views have returned. Publish their writes without
            // losing later guarded-borrower marks, then detach physical mm
            // custody from PID/group completion (like an external mm reference).
            if pid != 1 {
                let memory = std::mem::take(&mut p.memory);
                self.memory_retirements().retire(memory)?;
            } else {
                p.memory.commit_retired_parallel()?;
            }
        } else if p.memory.parallel_views_quiescent() {
            p.memory.commit_parallel()?;
        }
        if pid != 1 {
            p.memory = Memory::default();
        }
        p.state = State::Zombie(status);
        let completed = p.signals.io.finish_exit(pid);
        Self::release_vfork(p);
        p.auto_reap = pid != p.tgid;
        if pid == p.tgid {
            p.signals.io.inbox.clear();
        }
        let tgid = p.tgid;
        let family = p.family.clone();
        let group = p.signals.io.lifecycle().clone();
        drop(custody);
        if let Some(status) = completed {
            self.processes.directory().exits().retire(&group);
            let reaped = self.families.complete(&family, status);
            if let Some(mut leader) = self.processes.get_mut(&tgid) {
                leader.state = State::Zombie(status);
                leader.auto_reap = reaped;
            }
        }
        Ok(())
    }
    fn retire_cold_task(
        &mut self,
        pid: u32,
        task: &Arc<trames_kernel::signal::IoTask>,
        status: i32,
    ) -> Result<(), RuntimeError> {
        let Some(mut p) = self.processes.checkout(&pid) else {
            return Ok(());
        };
        if !Arc::ptr_eq(task, &p.signals.io) || !task.live() {
            self.processes.insert(pid, p);
            return Ok(());
        }
        // Private execution actors of this mm are quiescent. Guarded external
        // borrows may remain; use their ordinary permissions/backing model.
        let mut view = p.memory.current_parallel_view().or_else(|| {
            p.memory
                .parallel_views_quiescent()
                .then(|| p.memory.parallel_view(&mut self.parallel_memory))
                .flatten()
        });
        if view.is_none() {
            self.processes.insert(pid, p);
            self.wait_exit_memory(pid, status);
            return Ok(());
        }
        C::prepare_hardware_view(view.as_mut().unwrap());
        if let State::Futex { wait, .. } = &p.state {
            wait.cancel();
        }
        let Some(last) = task.try_exit(pid, status) else {
            self.processes.insert(pid, p);
            return Ok(());
        };
        p.linux.vfs.sync_task_namespaces();
        {
            let task = &mut *p;
            task.linux.vfs.set_lock_owner(task.tgid);
        }
        if last {
            p.linux.vfs.release_process_locks();
            self.timers.clear_process(p.tgid, false);
        }
        Self::cancel_native_task(&p);
        {
            let task = &mut *p;
            task.linux.cancel_uring(&mut task.memory, pid)
        };
        let files = p.linux.vfs.file_table_owner();
        let context = p.linux.vfs.context_owner();
        let futex = crate::futex::Authority::new(self.futexes.clone(), p.vm_id);
        let exit = crate::worker_syscalls::ExitResources {
            task,
            files: &files,
            context: context.as_ref(),
            parents: &p.signals.io_directory.parents,
            uid: p.linux.vfs.credentials.uid,
            futex: &futex,
            native: Some(&p.space),
        }
        .retire(status, last, view.as_mut().unwrap());
        drop(view);
        p.state = State::Zombie(status);
        self.processes.insert(pid, p);
        for group in exit.groups {
            self.queue_exit_group(group);
        }
        self.resume_futex_ready();
        self.begin_source_projection(pid, status)
    }
    pub(super) fn process_exits(
        &mut self,
        epoch: Option<&crate::run_queue::Epoch<C>>,
    ) -> Result<(), RuntimeError> {
        if epoch.is_some_and(|epoch| epoch.source_lifecycle()) {
            // Active executors own both returned CPUs and dormant group
            // members. These owner-local queues are only the outside-epoch
            // driver; never race their task/mm projections against a source.
            return Ok(());
        }
        self.exits.memory.pump()?;
        let ready: Vec<_> = self
            .exits
            .waits
            .iter()
            .filter_map(|(&pid, wait)| {
                let owned = self.processes.get(&pid).is_some_and(|p| {
                    epoch.is_none_or(|epoch| epoch.memory_owned(p.memory.coordinator_ownership().0))
                });
                (wait.signal.ready() || owned).then_some(pid)
            })
            .collect();
        for pid in ready {
            let wait = self.exits.waits.remove(&pid).unwrap();
            if self
                .processes
                .get(&pid)
                .is_none_or(|p| !Arc::ptr_eq(&wait.task, &p.signals.io))
            {
                continue;
            }
            if epoch.is_none_or(|epoch| {
                epoch.memory_owned(self.processes.read(&pid).memory.coordinator_ownership().0)
            }) {
                self.retire_cold_task(pid, &wait.task, wait.status)?;
            } else {
                self.wait_exit_memory(pid, wait.status);
            }
        }
        // Namespace shutdown can enqueue more original groups. Drain that real
        // dependency worklist, rather than recursively walking ProcessMap.
        let mut pending = std::mem::take(&mut self.exits.groups);
        while let Some((_, group)) = pending.pop_first() {
            let status = group.termination().expect("terminal original group");
            for (pid, task) in group.members() {
                if epoch.is_some_and(|epoch| epoch.contains(pid)) {
                    continue;
                }
                let Some(mut p) = self
                    .processes
                    .get_mut(&pid)
                    .filter(|p| Arc::ptr_eq(&task, &p.signals.io))
                else {
                    continue;
                };
                let id = p.memory.coordinator_ownership().0;
                if !p.memory.parallel_views_quiescent()
                    && epoch.is_some_and(|epoch| !epoch.memory_owned(id))
                {
                    // A terminating cold peer is not runnable while its actual
                    // mm completes. Its IoTask stays live until resources retire.
                    Self::cancel_native_task(&p);
                    p.state = State::Zombie(status);
                    drop(p);
                    self.wait_exit_memory(pid, status);
                    if self.processes.read(&pid).memory.parallel_views_quiescent() {
                        self.exits.waits.remove(&pid);
                        self.retire_cold_task(pid, &task, status)?;
                    } else if let Some(epoch) = epoch {
                        epoch.pause_memory(id);
                    }
                } else {
                    drop(p);
                    self.retire_cold_task(pid, &task, status)?;
                }
            }
            pending.append(&mut self.exits.groups);
        }
        Ok(())
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn exit_memory_pending(&self) -> bool {
        !self.exits.waits.is_empty() || !self.exits.memory.is_empty()
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use std::sync::mpsc;
    struct Wake(mpsc::Sender<()>);
    impl trames_vfs::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
            let _ = self.0.send(());
        }
    }
    #[test]
    fn external_mm_borrow_does_not_delay_exit_or_follow_a_reused_pid() {
        let mut k = super::super::tests::kernel();
        let mut root = super::super::tests::process();
        let mut output = trames_linux::CapturedOutput::default();
        k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut output)
            .unwrap();
        k.publish_io_tasks(Some((1, &root)));
        let mut custody = k.processes.get_mut(&2).unwrap();
        let child = &mut *custody;
        let id = child.memory.coordinator_ownership().0;
        let family = child.family.clone();
        let group = child.signals.io.lifecycle().clone();
        let mut borrower = child.memory.parallel_view(&mut k.parallel_memory).unwrap();
        use trames_memory::CpuMemory;
        borrower.write_array(0x1300, 7u64.to_le_bytes()).unwrap();
        drop(custody);
        group.request_exit(27 << 8);
        k.queue_exit_group(group);
        k.process_exits(None).unwrap();
        assert_eq!(family.status(), Some(27 << 8));
        assert!(!k.processes.read(&2).signals.io.live());
        assert!(k.exits.memory.contains(id));
        assert_eq!(k.wait(1, &mut root, [2, 0, 0, 0, 0, 0]), Ok(Some(2)));
        k.reap_waited();
        assert!(!k.processes.contains_key(&2));
        // Force actual PID reuse after reaping while the old physical mm is
        // retained. Completion must still use its original memory identity.
        k.task_ids = Default::default();
        k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut output)
            .unwrap();
        assert_ne!(k.processes.read(&2).memory.coordinator_ownership().0, id);
        borrower.write_array(0x1300, 9u64.to_le_bytes()).unwrap();
        assert_eq!(k.exits.memory.read_u64(id, 0x1300), 9);
        drop(borrower);
        k.process_exits(None).unwrap();
        assert!(!k.exits.memory.contains(id));
        assert!(k.processes.read(&2).signals.io.live());
        assert_eq!(k.processes.read(&2).memory.read_u64(0x1300).unwrap(), 0);
    }
    #[test]
    fn process_completion_resumes_parent_without_stopping_foreign_cpus() {
        // individual/last exit, exit_group, running/sleeping/cold/traced peers,
        // default TERM and synchronous fatal fault, plus a live CLONE_VM process.
        for mode in 0..9 {
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
                root.memory.write(0x1100, b"P").unwrap();
                let mov = |reg: u32, value: u32| 0xd2800000 | value << 5 | reg;
                let child = match mode {
                    5 => vec![mov(0, 2), mov(1, 15), mov(8, 129), 0xd4000001, 0x14000000],
                    8 => vec![mov(0, 0), 0xf9400001, 0x14000000],
                    _ => vec![
                        mov(0, 27),
                        mov(8, if mode == 0 { 93 } else { 94 }),
                        0xd4000001,
                    ],
                };
                for (base, words) in [
                    (
                        0x4000,
                        vec![
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
                        ],
                    ),
                    (0x4100, child),
                    (0x4200, vec![0x14000000]),
                ] {
                    for (i, word) in words.into_iter().enumerate() {
                        root.memory
                            .write_array(base + i as u64 * 4, word.to_le_bytes())
                            .unwrap();
                    }
                }
                root.memory
                    .protect(
                        0x4000,
                        trames_memory::PAGE_SIZE,
                        trames_memory::Permissions::RX,
                    )
                    .unwrap();
                let mut output = trames_linux::CapturedOutput::default();
                for _ in 0..2 {
                    k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut output)
                        .unwrap();
                }
                k.processes.get_mut(&3).unwrap().cpu.set_pc(0x4200);
                let mut child = k.processes.remove(&2).unwrap();
                child.cpu.set_pc(0x4100);
                let peer = if mode >= 2 {
                    k.syscall(2, &mut child, 220, [0x10b00, 0, 0, 0, 0, 0], &mut output)
                        .unwrap();
                    let mut peer = k.processes.remove(&4).unwrap();
                    peer.cpu.set_pc(0x4200);
                    peer.cpu.set_x(8, 96);
                    peer.cpu.set_x(0, 0x1300);
                    k.syscall(4, &mut peer, 96, [0x1300, 0, 0, 0, 0, 0], &mut output)
                        .unwrap();
                    assert_eq!(peer.linux.clear_tid_address(), 0x1300);
                    peer.memory.write_array(0x1300, 4u32.to_le_bytes()).unwrap();
                    if mode == 3 {
                        peer.state = State::Sleep(Instant::now() + Duration::from_secs(3600), 0);
                    }
                    if matches!(mode, 4 | 7) {
                        peer.linux.trace = true;
                        peer.state = State::Suspend(0);
                    }
                    if mode == 6 {
                        peer.linux.trace = true;
                    }
                    let io = peer.signals.io.clone();
                    k.processes.insert(4, peer);
                    Some(io)
                } else {
                    None
                };
                if mode == 7 {
                    k.syscall(2, &mut child, 220, [0x111, 0, 0, 0, 0, 0], &mut output)
                        .unwrap();
                    k.processes.get_mut(&5).unwrap().cpu.set_pc(0x4200);
                }
                // Actual last-close private Rc destruction is part of this
                // original task's completion, never a reason to join peers.
                child.linux.vfs.epoll_create(0).unwrap();
                k.processes.insert(2, child);
                root.state = State::Blocked(260, [2, 0x1200, 0, 0, 0, 0]);
                root.cpu.set_pc(0x4000);
                let task = root.signals.io.clone();
                k.processes.insert(1, root);
                publish.send((observed, task)).unwrap();
                go.recv().unwrap();
                let result = k.parallel_epoch(&mut output, u64::MAX / 2, true);
                let status =
                    u32::from_le_bytes(k.processes.read(&1).memory.read_array(0x1200).unwrap());
                let clear = if mode == 7 {
                    u32::from_le_bytes(k.processes.read(&5).memory.read_array(0x1300).unwrap())
                } else {
                    0
                };
                finished
                    .send((
                        result.is_ok(),
                        status,
                        peer.is_none_or(|p| !p.live()),
                        clear,
                        k.cohort_return_syscalls.get(&93).copied().unwrap_or(0),
                        k.cohort_return_syscalls.get(&94).copied().unwrap_or(0),
                        k.parallel_rounds,
                    ))
                    .unwrap();
            });
            let (observed, task) = handles.recv_timeout(Duration::from_secs(5)).unwrap();
            let (wake, readable) = mpsc::channel();
            let target: Arc<dyn trames_vfs::IoWake> = Arc::new(Wake(wake));
            let signal = trames_vfs::IoSignal::new(0, Arc::downgrade(&target));
            let _subscription = observed.subscribe(&signal);
            start.send(()).unwrap();
            let notified = readable.recv_timeout(Duration::from_secs(1));
            let bytes = observed.read(1);
            let live = matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty));
            // Always release the harness before reporting a lifecycle failure.
            task.job_signal(9, false, Info::default(), true).unwrap();
            let result = done.recv_timeout(Duration::from_secs(5));
            worker.join().unwrap();
            assert!(
                notified.is_ok() && bytes == Ok(b"P".to_vec()) && live,
                "mode={mode}: parent waited for foreign CPUs: {bytes:?} {result:?}"
            );
            let expected = match mode {
                5 => 15,
                8 => 11,
                _ => 27 << 8,
            };
            assert!(
                matches!(result,Ok((true,status,true,0,0,0,1)) if status==expected),
                "mode={mode}: {result:?}"
            );
        }
    }
}
