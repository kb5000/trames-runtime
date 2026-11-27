// SPDX-License-Identifier: GPL-3.0-or-later
//! Original mm maintenance on existing executors. Resource contention parks a
//! request, never a CPU slot or a global task-directory lock.
use super::*;

impl<C: Cpu> Lifecycle<C> {
    pub(crate) fn proc_ready(&self) -> bool {
        self.proc_driver
            .get()
            .is_some_and(|driver| driver.signal.ready())
    }
    pub(crate) fn activate_reads(&self, epoch: &Epoch<C>) {
        let Some(driver) = self.proc_driver.get() else {
            return;
        };
        driver.signal.reset();
        let source = self.proc_source.as_ref().expect("bound proc source");
        let target: Arc<dyn trames_shared::IoWake> = source.clone();
        let target = Arc::downgrade(&target);
        for report in source.take_worker_reads(&driver.signal) {
            if !report.alive() || !report.has_requested_reads() {
                continue;
            }
            let mut candidates = self.tasks.memory(&report);
            candidates.sort_by_key(|(pid, _)| !epoch.contains(*pid));
            for (pid, task) in candidates {
                let _custody = match tasks::admit_one(&task, pid, &target) {
                    Ok(Some(custody)) => custody,
                    Ok(None) => continue,
                    Err(wait) => {
                        source.defer_read(report.clone(), wait.signal, wait.subscriptions);
                        break;
                    }
                };
                let p = &mut *task.write();
                if !p.memory.has_memory_report(&report) {
                    continue;
                }
                if p.memory.serve_mapping_statistics(&report) {
                    break;
                }
                if epoch.request_proc_reads(pid) {
                    break;
                }
                // A sleeping/nonmember task is still an original mm owner. Its
                // external borrower release wakes this same resource directly.
                let signal = trames_shared::IoSignal::new(pid, target.clone());
                let subscription = p.memory.subscribe_parallel_idle(&signal);
                if !p.memory.parallel_views_quiescent() {
                    source.defer_read(report.clone(), signal, vec![subscription]);
                    break;
                }
                p.cpu.clear_exclusive();
                if let Err(error) = p.memory.commit_parallel() {
                    self.report.lock().unwrap().error = Some(error.into());
                    epoch.fail();
                    return;
                }
                assert!(p.activate_memory_controls());
                break;
            }
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::workers::{Control, Event};
    struct Wake;
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
    }

    #[test]
    fn pidfd_release_runs_on_the_original_dying_mm_and_drops_real_private_storage() {
        let mut k = super::super::super::tests::kernel();
        let mut caller = super::super::super::tests::admitted_process(&k);
        k.install_proc_source(&caller, None);
        let mut io = trames_linux::CapturedOutput::default();
        let child = k
            .syscall(1, &mut caller, 220, [17, 0, 0, 0, 0, 0], &mut io)
            .unwrap()
            .unwrap() as u32;
        k.publish_task(1, &caller);
        let group = trames_memory::MemoryCgroup::new(None);
        let actor = Arc::new(trames_memory::CgroupMemoryTarget::default());
        actor.set(Some(group.clone()));
        {
            let _allocation = actor.scope();
            let mut target = k.processes.get_mut(&child).unwrap();
            target
                .memory
                .map(0x1000000, 16 * 1024 * 1024, trames_memory::Permissions::RW)
                .unwrap();
            for page in (0x1000000..0x2000000).step_by(4096) {
                target.memory.write(page, &[42]).unwrap();
            }
            assert!(target.memory.resident_bytes() >= 16 * 1024 * 1024);
            assert_eq!(group.current(), 16 * 1024 * 1024);
        }
        k.publish_io_tasks(Some((1, &caller)));
        let routes = trames_kernel::signal::IoRoutes {
            directory: caller.signals.io_directory.clone(),
            namespace: caller.linux.vfs.pid_namespace().clone(),
            uid: caller.linux.vfs.credentials.uid,
            euid: caller.linux.vfs.credentials.euid,
        };
        let fd = routes
            .pidfd_open(&caller.linux.vfs.descriptor_factory(), child as i32, 0)
            .unwrap();
        assert_eq!(
            k.syscall(1, &mut caller, 448, [fd, 0, 0, 0, 0, 0], &mut io),
            Err(trames_vfs::Errno(22))
        );
        k.processes.get(&child).unwrap().signals.io.host_signal(9);
        assert_eq!(
            k.processes
                .get(&child)
                .unwrap()
                .signals
                .io
                .lifecycle()
                .termination(),
            None,
            "SIGKILL admission must work before the target executor delivers it"
        );
        assert_eq!(
            k.syscall(1, &mut caller, 448, [fd, 0, 0, 0, 0, 0], &mut io)
                .unwrap(),
            None
        );
        {
            let mut target = k.processes.get_mut(&child).unwrap();
            assert!(target.memory.activate_proc_reads());
            assert_eq!(target.memory.resident_bytes(), 0);
            assert!(target.memory.memory_report().process_reaped());
            assert_eq!(
                group.current(),
                0,
                "original physical page leases have been released"
            );
        }
        // The accepted operation retains its original mm after the numeric fd
        // is closed; resumption cannot resolve a replacement file or process.
        caller.linux.vfs.close(fd as u32).unwrap();
        assert_eq!(
            k.syscall(1, &mut caller, 448, [fd, 0, 0, 0, 0, 0], &mut io)
                .unwrap(),
            Some(0)
        );
    }

    #[test]
    fn proc_custody_retry_follows_the_current_executor_or_the_joined_driver() {
        for replace in [false, true] {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            k.install_proc_source(&root, None);
            k.publish_task(1, &root);
            let source = k.proc_source.as_ref().unwrap().clone();
            let report = root.memory.memory_report();
            let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
            let first =
                source.bind_reader(trames_shared::IoSignal::new(0, Arc::downgrade(&target)));
            let read = report.request_read_page(0x2000).unwrap();
            assert_eq!(source.take_worker_reads(&first.signal).len(), 1);
            let resource: Arc<dyn trames_shared::IoWake> = source.clone();
            let release = trames_shared::IoSignal::new(1, Arc::downgrade(&resource));
            source.defer_read(report, release.clone(), Vec::new());
            let next = replace.then(|| {
                source.bind_reader(trames_shared::IoSignal::new(0, Arc::downgrade(&target)))
            });
            if let Some(next) = &next {
                next.signal.reset();
            }
            drop(first);
            release.notify();
            let retry = if let Some(next) = &next {
                assert!(next.signal.ready());
                assert!(
                    source.take_reads().is_empty(),
                    "owner cannot take a source retry"
                );
                assert!(k.workers.event_timeout(Duration::ZERO).unwrap().is_none());
                source.take_worker_reads(&next.signal)
            } else {
                assert!(matches!(
                    k.workers.event_timeout(Duration::ZERO).unwrap(),
                    Some(Event::VmReady)
                ));
                source.take_reads()
            };
            assert_eq!(retry.len(), 1);
            assert!(root.memory.has_memory_report(&retry[0]));
            assert!(root.memory.activate_proc_reads());
            assert!(read.ready());
        }
    }

    #[test]
    fn proc_activation_uses_original_mm_and_releases_the_slot_for_external_borrowers() {
        for external in [false, true] {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            root.memory.write(0x2000, b"original bytes").unwrap();
            k.install_proc_source(&root, None);
            let mut io = trames_linux::CapturedOutput::default();
            k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut io)
                .unwrap();
            k.publish_task(1, &root);
            let report = root.memory.memory_report();
            k.processes.insert(1, root);
            let mut borrower = external.then(|| {
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
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0)]).unwrap() {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
            }
            let read = report.request_read_page(0x2000).unwrap();
            assert!(!read.ready());
            let mut job = epoch.take(0).unwrap();
            if external {
                assert_eq!(job.work.pid, 2, "only slot serves the unrelated mm");
                assert!(!read.ready());
                drop(borrower.take());
                epoch.park(job, None);
                job = epoch.take(0).unwrap();
            }
            assert!(read.ready());
            let mut bytes = [0; 14];
            assert_eq!(read.read_chunk(0x2000, &mut bytes), Some(Ok(bytes.len())));
            assert_eq!(&bytes, b"original bytes");
            epoch.park(job, None);
            epoch.stop();
            assert_eq!(epoch.drain().len(), 2);
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                assert!(!matches!(event, Event::VmReady));
            }
            assert_eq!(k.vm_checkpoint_groups, 1);
        }
    }
}
