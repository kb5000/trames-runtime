// SPDX-License-Identifier: GPL-3.0-or-later
//! File layout work retains its original backing across source and serial
//! execution. Native I/O uses the existing disk pool; no process scan or pause.
use super::*;
impl<C: Cpu> Kernel<C> {
    /// Serial/traced execution uses the same backing publication as source
    /// CPUs. Waiting retains readiness on the task, never a process-wide pause.
    pub(super) fn admit_owner_layouts(
        &self,
        pid: u32,
        p: &mut Process<C>,
    ) -> Result<bool, RuntimeError> {
        if p.layout_wait
            .as_ref()
            .is_some_and(|wait| !wait.signal.ready())
        {
            return Ok(false);
        }
        p.layout_wait = None;
        if p.memory.admit_parallel_layouts() {
            return Ok(true);
        }
        let signal = trames_shared::IoSignal::new(pid, Arc::downgrade(&self.byte_target));
        let mut subscriptions = lifecycle::layouts::wait_view(&p.memory, &signal);
        // A writer may have arrived after this mm's last commit. Release the
        // root lease before parking; external generations retain their own.
        subscriptions.push(p.memory.subscribe_parallel_idle(&signal));
        p.cpu.clear_exclusive();
        p.memory.commit_retired_parallel()?;
        p.layout_wait = Some(tasks::AdmissionWait {
            signal,
            subscriptions,
        });
        Ok(false)
    }
    pub(super) fn file_layout_work(&self) -> Arc<trames_linux::FileLayouts> {
        self.layout_work
            .get_or_init(|| {
                let layouts = trames_linux::FileLayouts::new(self.workers.file_executor());
                layouts.bind_owner(trames_shared::IoSignal::new(
                    0,
                    Arc::downgrade(&self.byte_target),
                ));
                layouts
            })
            .clone()
    }
    pub(super) fn start_file_checkpoint(
        &mut self,
        _pid: u32,
        p: &mut Process<C>,
        _number: u32,
        _args: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        match p.file_checkpoint.take().unwrap().take() {
            trames_linux::FileBoundary::Owner { work, output } => {
                let reply = work.run_owner(&mut p.linux.vfs);
                p.file_entry = None;
                output.apply(reply.result, &mut p.memory).map(Some)
            }
            trames_linux::FileBoundary::Signal { value } => {
                trames_vfs::TaskSignal::raise(&*p.signals.io, 25);
                p.file_entry = None;
                value.map(Some)
            }
            trames_linux::FileBoundary::Layout { work, output } => {
                let target = work.target().cloned();
                let result = Arc::new(trames_linux::FileResult::wake_joined());
                let pending = trames_linux::FilePending::new(result.clone(), output, target);
                p.retained_file = Some(pending);
                if let Err(work) = self.file_layout_work().submit(work, result) {
                    // Layout outcomes always retain a regular-file target.
                    drop(work);
                    return Err(Errno(5));
                }
                Ok(None)
            }
        }
    }
    pub(super) fn poll_file_layouts(&mut self) {
        if let Some(layouts) = self.layout_work.get().cloned() {
            let tasks = self.processes.directory();
            for mut request in layouts.take_owner() {
                if lifecycle::layouts::join_layout(&tasks, None, &mut request).is_err() {
                    layouts.fail(request, 5);
                } else if let Err(request) = layouts.try_submit(request) {
                    layouts.restore(request);
                }
            }
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use trames_execution::Registers;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn file_layout_waits_for_original_views_and_retires_once_without_global_pauses() {
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .import_file(b"/mapped", vec![0xa5; PAGE_SIZE as usize])
            .unwrap();
        let fd = p.linux.vfs.open_at(-100, b"/mapped", 2, 0).unwrap();
        p.memory
            .map_backed(
                0x10000,
                p.linux
                    .vfs
                    .mapping_pages(fd, 0, PAGE_SIZE, true, true)
                    .unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let peer = p.fork();
        k.processes.insert(2, peer);
        k.processes.insert(3, super::super::tests::process());
        let view = p.memory.parallel_view(&mut Default::default()).unwrap();
        let args = [fd as u64, 1, 0, 0, 0, 0];
        let mut io = trames_linux::CapturedOutput::default();
        let layouts = k.file_layout_work();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !layouts.pending() {
            k.call(1, &mut p, 46, args, &mut io);
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(p.file_checkpoint.is_none());
        let result = p.byte_wait.as_ref().unwrap().file_pending().unwrap().result;
        assert_eq!(p.linux.vfs.seek(fd, 0, 2).unwrap(), PAGE_SIZE);
        k.processes.insert(1, p);
        k.poll_file_layouts();
        assert!(
            !result.finished(),
            "original external View excludes mutation"
        );
        let mut peer = k.processes.remove(&2).unwrap();
        assert!(!k.admit_owner_layouts(2, &mut peer).unwrap());
        assert!(!peer.layout_wait.as_ref().unwrap().signal.ready());
        k.processes.insert(2, peer);
        let mut foreign = k.processes.remove(&3).unwrap();
        assert!(k.admit_owner_layouts(3, &mut foreign).unwrap());
        k.processes.insert(3, foreign);
        drop(view);
        while !result.finished() {
            k.poll_file_layouts();
            assert!(Instant::now() < deadline);
            std::thread::park_timeout(Duration::from_millis(1));
        }
        let mut p = k.processes.remove(&1).unwrap();
        assert!(k.admit_owner_layouts(1, &mut p).unwrap());
        k.call(1, &mut p, 46, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 0);
        assert!(p.file_entry.is_none());
        assert_eq!(p.linux.vfs.seek(fd, 0, 2).unwrap(), 1);
        assert!(!layouts.pending());
        let mut peer = k.processes.remove(&2).unwrap();
        assert!(k.admit_owner_layouts(2, &mut peer).unwrap());
    }
    #[test]
    fn caught_signal_keeps_the_accepted_native_result_instead_of_restarting_input() {
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::process();
        p.linux.vfs.import_file(b"/file", Vec::new()).unwrap();
        let fd = p.linux.vfs.open_at(-100, b"/file", 2, 0).unwrap();
        let target = p
            .linux
            .vfs
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let result = Arc::new(trames_linux::FileResult::default());
        let args = [fd as u64, 0x1000, 7, 0, 0, 0];
        p.retained_file = Some(trames_linux::FilePending::new(
            result.clone(),
            trames_linux::FileOutput::None,
            target,
        ));
        p.file_entry = Some((p.cpu.pc(), 64, args));
        p.state = State::Blocked(64, args);
        p.signals.actions.set_handler(10, 0x5000);
        Kernel::<trames_cpu::Cpu>::queue_one(1, &mut p, 10, 1);
        assert_eq!(k.deliver(1, &mut p), Ok(false));
        assert!(p.file_entry.is_some());
        result.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
            result: Ok(trames_vfs::FileValue::Count(7)),
            file_size_signal: false,
            scratch: None,
        }));
        k.call(
            1,
            &mut p,
            64,
            args,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(p.cpu.x(0), 7);
        assert!(p.file_entry.is_none());
        assert_eq!(k.deliver(1, &mut p), Ok(true));
        assert_eq!(p.cpu.pc(), 0x5000);
        assert_eq!(p.cpu.x(0), 10);
    }
}
