// SPDX-License-Identifier: GPL-3.0-or-later
//! Dormant task and returned CPU completion on original task/mm resources.
//! A busy object retains its request and releases the existing execution slot.
use super::*;
use crate::workers::Done;
use std::collections::BTreeSet;

pub(super) struct Retiring<C: Cpu> {
    pid: u32,
    task: tasks::Handle<C>,
    original: Option<Arc<trames_kernel::signal::IoTask>>,
    status: i32,
    done: Option<Done<C>>,
    wait: Option<Wait>,
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::workers::{Control, Event};
    use trames_memory::CpuMemory;

    #[test]
    fn dormant_exit_waits_for_original_custody_without_occupying_a_slot_and_survives_cancel() {
        for hold_memory in [false, true] {
            for cancel in [false, true] {
                let mut k = super::super::super::tests::kernel();
                let mut root = super::super::super::tests::admitted_process(&k);
                k.syscall(
                    1,
                    &mut root,
                    220,
                    [0x111, 0, 0, 0, 0, 0],
                    &mut trames_linux::CapturedOutput::default(),
                )
                .unwrap();
                let group = k.processes.read(&2).signals.io.lifecycle().clone();
                let family = k.processes.read(&2).family.clone();
                k.processes.get_mut(&2).unwrap().state = State::Suspend(0);
                let memory = root.memory.share();
                k.publish_task(1, &root);
                k.processes.insert(1, root);
                let original = k.processes.handle(&2).unwrap();
                let control = Arc::new(Control::new(10000));
                let epoch = Epoch::with_events(control.clone(), k.workers.events(), false);
                epoch.bind_lifecycle(Lifecycle::capture(&k));
                let (pid, _, view) = k.prepare_parallel_views(&[(1, 0)]).unwrap().pop().unwrap();
                epoch.add(k.capture_worker(
                    pid,
                    view,
                    &control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
                let (held, ready) = std::sync::mpsc::channel();
                let (release, released) = std::sync::mpsc::channel();
                let holder = std::thread::spawn(move || {
                    let _body = (!hold_memory).then(|| original.write());
                    let _memory = hold_memory.then(|| memory.try_admit().unwrap());
                    held.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                ready.recv_timeout(Duration::from_secs(2)).unwrap();
                group.request_exit(19 << 8);
                let began = Instant::now();
                let job = epoch.take(0).unwrap();
                let elapsed = began.elapsed();
                assert_eq!(family.status(), None);
                epoch.park(job, None);
                if cancel {
                    epoch.stop();
                }
                release.send(()).unwrap();
                holder.join().unwrap();
                assert!(
                    elapsed < Duration::from_secs(1),
                    "busy object kept the only executor"
                );
                if !cancel {
                    let job = epoch.take(0).unwrap();
                    assert_eq!(family.status(), Some(19 << 8));
                    epoch.park(job, None);
                }
                epoch.stop();
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                assert_eq!(epoch.drain().len(), 1);
                k.process_exits(None).unwrap();
                assert_eq!(family.status(), Some(19 << 8));
                assert!(!k.processes.read(&2).signals.io.live());
                while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                    assert!(!matches!(event, Event::VmReady | Event::Retired));
                }
            }
        }
    }

    #[test]
    fn dormant_shared_mm_exit_finishes_on_source_with_a_foreign_job_and_external_borrower() {
        for external in [false, true] {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            let mut io = trames_linux::CapturedOutput::default();
            k.syscall(1, &mut root, 220, [0x111, 0, 0, 0, 0, 0], &mut io)
                .unwrap();
            let mut child = k.processes.remove(&2).unwrap();
            child.cpu.set_x(8, 96);
            child.cpu.set_x(0, 0x1300);
            k.syscall(2, &mut child, 96, [0x1300, 0, 0, 0, 0, 0], &mut io)
                .unwrap();
            child
                .memory
                .write_array(0x1300, 2u32.to_le_bytes())
                .unwrap();
            child.state = State::Suspend(0);
            let group = child.signals.io.lifecycle().clone();
            let family = child.family.clone();
            let original = child.signals.io.clone();
            k.processes.insert(2, child);
            k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut io)
                .unwrap();
            k.publish_task(1, &root);
            k.processes.insert(1, root);
            assert_eq!(
                k.processes.read(&1).memory.coordinator_ownership().0,
                k.processes.read(&2).memory.coordinator_ownership().0
            );
            assert_eq!(original.thread_addresses().unwrap().clear_tid(), 0x1300);
            let borrower = external.then(|| {
                k.processes
                    .get_mut(&1)
                    .unwrap()
                    .memory
                    .parallel_view(&mut k.parallel_memory)
                    .unwrap()
            });
            let control = Arc::new(Control::new(10000));
            let epoch = Epoch::with_events(control.clone(), k.workers.events(), false);
            epoch.bind_lifecycle(Lifecycle::capture(&k));
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (3, 0)]).unwrap() {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
            }
            group.request_exit(23 << 8);
            let job = epoch.take(0).unwrap();
            assert!(!original.live());
            assert_eq!(family.status(), Some(23 << 8));
            assert_eq!(original.thread_addresses().unwrap().clear_tid(), 0);
            if let Some(borrower) = &borrower {
                assert_eq!(borrower.read_array::<4>(0x1300).unwrap(), [0; 4]);
            }
            epoch.park(job, None);
            epoch.stop();
            assert_eq!(epoch.drain().len(), 2);
            k.processes
                .get_mut(&1)
                .unwrap()
                .memory
                .commit_retired_parallel()
                .unwrap();
            assert_eq!(
                k.processes.read(&1).memory.read_array::<4>(0x1300).unwrap(),
                [0; 4]
            );
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                assert!(!matches!(event, Event::VmReady | Event::Retired));
            }
            assert_eq!(k.vm_checkpoint_groups, 1);
        }
    }
    #[test]
    fn last_cpu_removal_retries_a_cold_exit_after_its_memory_pause_was_accepted() {
        let mut k = super::super::super::tests::kernel();
        let mut root = super::super::super::tests::admitted_process(&k);
        let mut io = trames_linux::CapturedOutput::default();
        k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut io)
            .unwrap();
        let mut leader = k.processes.remove(&2).unwrap();
        k.syscall(2, &mut leader, 220, [0x10b00, 0, 0, 0, 0, 0], &mut io)
            .unwrap();
        let group = leader.signals.io.lifecycle().clone();
        let original = leader.signals.io.clone();
        let family = leader.family.clone();
        let memory = leader.memory.coordinator_ownership().0;
        k.processes.insert(2, leader);
        {
            let mut cold = k.processes.get_mut(&3).unwrap();
            cold.state = State::Suspend(0);
            cold.linux.trace = true;
        }
        k.publish_task(1, &root);
        k.processes.insert(1, root);
        let epoch = Epoch::with_events(Arc::new(Control::new(10000)), k.workers.events(), true);
        epoch.bind_lifecycle(Lifecycle::capture(&k));
        for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0)]).unwrap() {
            epoch.add(k.capture_worker(
                id,
                view,
                &epoch.control,
                &mut Default::default(),
                &mut Default::default(),
                &mut Default::default(),
            ));
        }
        let root = epoch.take(0).unwrap();
        let leader = epoch.take(0).unwrap();
        assert_eq!((root.work.pid, leader.work.pid), (1, 2));
        epoch.park(root, None);
        group.request_exit(27 << 8);
        let root = epoch.take(0).unwrap();
        assert_eq!(root.work.pid, 1);
        assert!(
            epoch.contains_memory(memory),
            "accepted pause still has a running CPU"
        );
        assert!(k.processes.read(&3).signals.io.live());
        assert!(original.try_exit(2, 27 << 8).is_some());
        let mut done = leader.finish(None, 0);
        done.thread_exit = Some(27 << 8);
        epoch.finish(done);
        epoch.park(root, None);
        let root = epoch.take(0).unwrap();
        assert!(!epoch.contains_memory(memory));
        assert!(
            !k.processes.read(&3).signals.io.live(),
            "removed domain must wake its cold exit"
        );
        assert_eq!(family.status(), Some(27 << 8));
        epoch.park(root, None);
        epoch.stop();
        assert_eq!(epoch.drain().len(), 1);
        assert!(epoch.collect_lifecycle(&mut k).is_none());
    }
}
enum Wait {
    Resource(tasks::AdmissionWait),
    Memory(u64),
}
impl<C: Cpu> Lifecycle<C> {
    pub(crate) fn retire_memory_domains(&self, ids: Vec<u64>) {
        let mut pending = self.retiring.lock().unwrap();
        let mut ready = false;
        for work in &mut *pending {
            if matches!(work.wait, Some(Wait::Memory(id)) if ids.contains(&id)) {
                work.wait = None;
                ready = true;
            }
        }
        drop(pending);
        if ready {
            // A domain can disappear after pause_memory succeeded, when its
            // last CPU return is collected. There will be no future byte
            // checkpoint for it; retry the retained cold task directly.
            self.notify_retirement();
        }
    }
    pub(crate) fn retirements_pending(&self) -> bool {
        !self.retiring.lock().unwrap().is_empty()
    }
    pub(crate) fn retirement_ready(&self) -> bool {
        self.exit_wake.get().is_some_and(|wake| wake.signal.ready())
    }
    pub(crate) fn notify_retirement(&self) {
        self.exit_groups.notify();
    }
    fn terminal_tasks(&self, epoch: &Epoch<C>) -> Vec<Retiring<C>> {
        let mut work = Vec::new();
        for group in self.exit_groups.take() {
            let Some(status) = group.termination() else {
                continue;
            };
            for (pid, original) in group.members() {
                if epoch.contains(pid) {
                    continue;
                }
                let Some(task) = self.tasks.handle(&pid) else {
                    continue;
                };
                work.push(Retiring {
                    pid,
                    task,
                    original: Some(original),
                    status,
                    done: None,
                    wait: None,
                });
            }
        }
        work
    }
    fn publish_retirements(&self, work: Vec<Retiring<C>>) {
        let mut pending = self.retiring.lock().unwrap();
        pending.extend(work);
        // Publish before checking the latch. Another executor may consume the
        // global wake while this request is still checked out; its original
        // resource signal then remains the authority for a required retry.
        let ready = pending
            .iter()
            .any(|work| matches!(&work.wait, Some(Wait::Resource(wait)) if wait.signal.ready()));
        drop(pending);
        if ready {
            self.notify_retirement();
        }
    }
    fn take_retirements(&self, mut ready: impl FnMut(&Retiring<C>) -> bool) -> Vec<Retiring<C>> {
        let mut pending = self.retiring.lock().unwrap();
        let mut work = Vec::new();
        let mut i = 0;
        while i < pending.len() {
            if ready(&pending[i]) {
                work.push(pending.swap_remove(i));
            } else {
                i += 1;
            }
        }
        work
    }
    pub(crate) fn retire_ready(&self, epoch: &Epoch<C>) {
        self.exit_wake.get().expect("bound exits").signal.reset();
        let mut work = self.take_retirements(|work| match &work.wait {
            Some(Wait::Resource(wait)) => wait.signal.ready(),
            Some(Wait::Memory(_)) => false,
            None => true,
        });
        for cold in self.terminal_tasks(epoch) {
            if !work
                .iter()
                .any(|old| old.pid == cold.pid && old.task.same(&cold.task))
            {
                work.push(cold);
            }
        }
        work.extend(
            epoch
                .take_source_retired()
                .into_iter()
                .map(|done| Retiring {
                    pid: done.pid,
                    task: done.task.as_ref().expect("original returned task").clone(),
                    original: None,
                    status: done.thread_exit.expect("source exit"),
                    done: Some(done),
                    wait: None,
                }),
        );
        let mut pending = Vec::new();
        let mut pauses = BTreeSet::new();
        for mut work in work {
            if match &work.wait {
                Some(Wait::Resource(wait)) => !wait.signal.ready(),
                Some(Wait::Memory(_)) => true,
                None => false,
            } {
                pending.push(work);
                continue;
            }
            work.wait = None;
            match self.retire_task(epoch, &mut work, &BTreeSet::new()) {
                Ok(Some(wait)) => {
                    if let Wait::Memory(id) = &wait {
                        pauses.insert(*id);
                    }
                    work.wait = Some(wait);
                    pending.push(work);
                }
                Ok(None) => {}
                Err(error) => {
                    self.report.lock().unwrap().error = Some(error);
                    pending.push(work);
                    epoch.fail();
                }
            }
        }
        self.publish_retirements(pending);
        for id in pauses {
            if !epoch.pause_memory(id) {
                // Exec can retire the last actor between lookup and pause.
                // Retry the retained body; it must not wait for a vanished mm.
                for work in self.retiring.lock().unwrap().iter_mut() {
                    if matches!(work.wait, Some(Wait::Memory(old)) if old == id) {
                        work.wait = None;
                    }
                }
                self.notify_retirement();
            }
        }
    }
    /// The executor already owns only these returned mm domains. Busy cold
    /// bodies defer that same checkpoint; unrelated address spaces keep running.
    pub(super) fn retire_checkpoint(
        &self,
        epoch: &Epoch<C>,
        ids: &BTreeSet<u64>,
    ) -> Option<tasks::AdmissionWait> {
        let work = self.take_retirements(
            |work| matches!(work.wait, Some(Wait::Memory(id)) if ids.contains(&id)),
        );
        let mut pending = Vec::new();
        let mut blocked = None;
        for mut work in work {
            let Some(Wait::Memory(id)) = work.wait else {
                pending.push(work);
                continue;
            };
            if !ids.contains(&id) || blocked.is_some() {
                pending.push(work);
                continue;
            }
            work.wait = None;
            match self.retire_task(epoch, &mut work, ids) {
                Ok(Some(Wait::Resource(wait))) => {
                    blocked = Some(wait);
                    work.wait = Some(Wait::Memory(id));
                    pending.push(work);
                }
                Ok(Some(wait)) => {
                    work.wait = Some(wait);
                    pending.push(work);
                }
                Ok(None) => {}
                Err(error) => {
                    self.report.lock().unwrap().error = Some(error);
                    work.wait = Some(Wait::Memory(id));
                    pending.push(work);
                    epoch.fail();
                }
            }
        }
        self.publish_retirements(pending);
        blocked
    }
    fn retire_task(
        &self,
        epoch: &Epoch<C>,
        work: &mut Retiring<C>,
        owned: &BTreeSet<u64>,
    ) -> Result<Option<Wait>, RuntimeError> {
        let target: Arc<dyn trames_shared::IoWake> = self.exit_groups.clone();
        let target = Arc::downgrade(&target);
        let _custody = match tasks::admit_one(&work.task, work.pid, &target) {
            Ok(Some(permit)) => permit,
            Ok(None) => return Ok(None),
            Err(wait) => {
                return Ok(Some(Wait::Resource(wait)));
            }
        };
        if !self.tasks.contains_original(work.pid, &work.task) {
            // A nonleader exec already consumed this exact body's resources.
            if let Some(done) = &mut work.done {
                self.report.lock().unwrap().workers.merge(done.take_stats());
            }
            return Ok(None);
        }
        let mut custody = work.task.write();
        let p = &mut *custody;
        if work
            .original
            .as_ref()
            .is_some_and(|original| !Arc::ptr_eq(original, &p.signals.io) || !original.live())
        {
            return Ok(None);
        }
        let leader = (work.pid != p.tgid)
            .then(|| self.tasks.handle(&p.tgid))
            .flatten();
        let _leader = if let Some(leader) = &leader {
            Some(if let Some(permit) = leader.try_admit() {
                permit
            } else {
                let signal = trames_shared::IoSignal::new(p.tgid, target.clone());
                let subscription = leader.subscribe(&signal);
                let Some(permit) = leader.try_admit() else {
                    return Ok(Some(Wait::Resource(tasks::AdmissionWait {
                        signal,
                        subscriptions: vec![subscription],
                    })));
                };
                permit
            })
        } else {
            None
        };
        if let Some(done) = &mut work.done {
            Kernel::<C>::log_worker_diagnostics(p, done);
            p.linux.vfs.sync_task_namespaces();
            p.cpu = std::mem::take(&mut done.cpu);
            p.trace = std::mem::take(&mut done.trace);
            p.signals.finish_io();
            p.last_cpu = done.worker;
            p.cpu_time += done.elapsed;
            for group in std::mem::take(&mut done.exit_groups) {
                self.exit_groups.watch(&group);
            }
        } else {
            if epoch.contains(work.pid) {
                return Ok(None);
            }
            let id = p.memory.coordinator_ownership().0;
            if !owned.contains(&id) && epoch.contains_memory(id) {
                Kernel::<C>::cancel_native_task(p);
                p.state = State::Zombie(work.status);
                return Ok(Some(Wait::Memory(id)));
            }
            let mut registry = self.registry.share();
            let mut view = p.memory.current_parallel_view().or_else(|| {
                p.memory
                    .parallel_views_quiescent()
                    .then(|| p.memory.parallel_view(&mut registry))
                    .flatten()
            });
            if view.is_none() {
                let signal = trames_shared::IoSignal::new(work.pid, target);
                let subscriptions = layouts::wait_view(&p.memory, &signal);
                return Ok(Some(Wait::Resource(tasks::AdmissionWait {
                    signal,
                    subscriptions,
                })));
            }
            let view = view.as_mut().unwrap();
            C::prepare_hardware_view(view);
            if let State::Futex { wait, .. } = &p.state {
                wait.cancel();
            }
            let task = p.signals.io.clone();
            let Some(last) = task.try_exit(work.pid, work.status) else {
                return Ok(None);
            };
            p.linux.vfs.sync_task_namespaces();
            p.linux.vfs.set_lock_owner(p.tgid);
            p.linux.vfs.binder_exit(work.pid, last);
            if last {
                p.linux.vfs.release_process_locks();
                self.timers.clear_process(p.tgid, false);
            }
            Kernel::<C>::cancel_native_task(p);
            p.linux.cancel_uring(&mut p.memory, work.pid);
            let files = p.linux.vfs.file_table_owner();
            let context = p.linux.vfs.context_owner();
            let futex = crate::futex::Authority::new(self.futexes.clone(), p.vm_id);
            let exit = crate::worker_syscalls::ExitResources {
                task: &task,
                files: &files,
                context: context.as_ref(),
                parents: &p.signals.io_directory.parents,
                uid: p.linux.vfs.credentials.uid,
                futex: &futex,
                native: Some(&p.space),
            }
            .retire(work.status, last, view);
            for group in exit.groups {
                self.exit_groups.watch(&group);
            }
            // The View is dropped by this block before final mm projection.
        }
        p.linux.vfs.set_lock_owner(p.tgid);
        p.linux.vfs.collect_retired_descriptors();
        Kernel::<C>::clear_exit_resources(p);
        let last_mm = p.memory.coordinator_ownership().1 == 1;
        if last_mm {
            p.memory.retire_memory_report();
        }
        if last_mm && !p.memory.parallel_views_quiescent() {
            if work.pid != 1 {
                self.memory.retire(std::mem::take(&mut p.memory))?;
            } else {
                p.memory.commit_retired_parallel()?;
            }
        } else if p.memory.parallel_views_quiescent() {
            p.memory.commit_parallel()?;
        }
        if work.pid != 1 {
            p.linux.vfs.retire_task_namespace();
            p.memory = Memory::default();
        }
        p.state = State::Zombie(work.status);
        let completed = p.signals.io.finish_exit(work.pid);
        Kernel::<C>::release_vfork(p);
        p.auto_reap = work.pid != p.tgid;
        if work.pid == p.tgid {
            p.signals.io.inbox.clear();
        }
        if let Some(status) = completed {
            self.exit_groups.retire(p.signals.io.lifecycle());
            let reaped = p
                .family
                .registry()
                .is_some_and(|registry| registry.complete(&p.family, status));
            if let Some(leader) = &leader {
                let leader = &mut *leader.write();
                leader.state = State::Zombie(status);
                leader.auto_reap = reaped;
            } else {
                p.state = State::Zombie(status);
                p.auto_reap = reaped;
            }
            if p.tgid == 1 {
                // PID 1 group completion ends this session, just as the
                // outside-epoch driver does. No owner retirement RPC is needed.
                epoch.complete();
            }
        }
        self.tasks.restore(work.pid, work.pid, &custody);
        if let Some(done) = &mut work.done {
            self.report.lock().unwrap().workers.merge(done.take_stats());
        }
        Ok(None)
    }
    pub(super) fn retain_final_survivors(&self) {
        let mut pending = self.retiring.lock().unwrap();
        for (pid, task) in self.tasks.all() {
            if pid == 1
                || pending
                    .iter()
                    .any(|work| work.pid == pid && work.task.same(&task))
            {
                continue;
            }
            let original = task.read().signals.io.clone();
            if !original.live() {
                continue;
            }
            pending.push(Retiring {
                pid,
                task,
                original: Some(original),
                status: 9,
                done: None,
                wait: None,
            });
        }
    }
    pub(super) fn finish_retirements(&self, epoch: &Epoch<C>) -> Result<(), RuntimeError> {
        struct Wake(std::thread::Thread);
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
                self.0.unpark();
            }
        }
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(std::thread::current()));
        let signal = trames_shared::IoSignal::new(0, Arc::downgrade(&target));
        let _subscription = self.exit_groups.subscribe(&signal);
        let owned = self
            .tasks
            .all()
            .into_iter()
            .map(|(_, task)| task.read().memory.coordinator_ownership().0)
            .collect();
        loop {
            signal.reset();
            let mut work = self.take_retirements(|_| true);
            work.extend(self.terminal_tasks(epoch));
            let mut pending = Vec::new();
            for mut work in work {
                // Every CPU View has drained; only actual foreign resource
                // custody/borrowers can defer this final source operation.
                if let Some(wait) = self.retire_task(epoch, &mut work, &owned)? {
                    work.wait = Some(wait);
                    pending.push(work);
                }
            }
            if pending.is_empty() {
                return Ok(());
            }
            self.publish_retirements(pending);
            if !signal.ready() {
                std::thread::park();
            }
        }
    }
    pub(super) fn retain_final_exit(&self, done: Done<C>) {
        self.retiring.lock().unwrap().push(Retiring {
            pid: done.pid,
            task: done.task.as_ref().expect("original returned task").clone(),
            original: None,
            status: done.thread_exit.expect("source exit"),
            done: Some(done),
            wait: None,
        });
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn collect_retirements(&self, kernel: &mut Kernel<C>) {
        for work in std::mem::take(&mut *self.retiring.lock().unwrap()) {
            if let Some(done) = work.done {
                if let Err(error) = kernel.accept_source_return(done) {
                    self.report.lock().unwrap().error = Some(error);
                }
            } else if let Some(original) = work.original {
                kernel.queue_exit_group(original.lifecycle().clone());
            }
        }
    }
}
