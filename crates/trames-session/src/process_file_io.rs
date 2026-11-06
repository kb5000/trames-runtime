// SPDX-License-Identifier: GPL-3.0-or-later
//! Only file-backed mapping layout needs joined mm ownership. The filesystem
//! algorithm itself runs on the existing disk pool, never as an owner service.
use super::*;
use std::collections::BTreeSet;

pub(super) struct FileLayout {
    spaces: BTreeSet<u64>,
    result: Arc<trames_linux::FileResult>,
}
impl<C: Cpu> Kernel<C> {
    pub(super) fn start_file_checkpoint(
        &mut self,
        _pid: u32,
        p: &mut Process<C>,
        _number: u32,
        _args: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        let checkpoint = p
            .file_checkpoint
            .as_ref()
            .expect("accepted file checkpoint");
        let mut spaces = BTreeSet::new();
        if let Some(domains) = checkpoint.layout_domains() {
            let domains: BTreeSet<_> = domains.into_iter().collect();
            spaces.insert(p.memory.instruction_identity().0);
            for process in self.processes.values() {
                if process.memory.uses_backing_domains(&domains) {
                    spaces.insert(process.memory.instruction_identity().0);
                }
            }
            if !p.memory.parallel_views_quiescent()
                || self.processes.values().any(|process| {
                    spaces.contains(&process.memory.instruction_identity().0)
                        && !process.memory.parallel_views_quiescent()
                })
            {
                return Ok(None);
            }
            // Publication joins only the original mapped address spaces. No
            // filesystem byte operation, host I/O or durability runs here.
            p.memory.commit_parallel().map_err(|_| Errno(5))?;
            for mut process in self.processes.values_mut() {
                if spaces.contains(&process.memory.instruction_identity().0) {
                    process.memory.commit_parallel().map_err(|_| Errno(5))?;
                }
            }
        }
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
                // Preserve all overlapping layout pauses, including a caller
                // that maps no bytes from the file it is changing.
                p.file_pauses += 1;
                for mut process in self.processes.values_mut() {
                    if spaces.contains(&process.memory.instruction_identity().0) {
                        process.file_pauses += 1;
                    }
                }
                self.file_layouts.push(FileLayout {
                    spaces,
                    result: result.clone(),
                });
                p.retained_file = Some(pending);
                self.workers
                    .file_executor()
                    .submit_file(work.exclusive(), result);
                Ok(None)
            }
        }
    }
    pub(super) fn poll_file_layouts(&mut self) {
        let mut actors = std::collections::BTreeMap::new();
        for process in self.processes.values() {
            if let Some(actor) = process.linux.uring_actor_root().get() {
                actors
                    .entry(Arc::as_ptr(actor) as usize)
                    .or_insert_with(|| actor.clone());
            }
        }
        for actor in actors.into_values() {
            for (owner, task) in actor.take_file_signals() {
                if let Some(process) = self
                    .processes
                    .get_mut(&task)
                    .filter(|p| p.memory.instruction_identity().0 == owner)
                {
                    trames_vfs::TaskSignal::raise(&*process.signals.io, 25);
                }
            }
            for layout in actor.take_file_layouts() {
                let domains: BTreeSet<_> = layout.work.layout_domains().into_iter().collect();
                let spaces: BTreeSet<_> = self
                    .processes
                    .values()
                    .filter(|p| p.memory.uses_backing_domains(&domains))
                    .map(|p| p.memory.instruction_identity().0)
                    .collect();
                if self.processes.values().any(|p| {
                    spaces.contains(&p.memory.instruction_identity().0)
                        && !p.memory.parallel_views_quiescent()
                }) {
                    actor.restore_file_layout(layout);
                    continue;
                }
                let mut failed = false;
                for mut process in self
                    .processes
                    .values_mut()
                    .filter(|p| spaces.contains(&p.memory.instruction_identity().0))
                {
                    if process.memory.commit_parallel().is_err() {
                        failed = true;
                    }
                }
                if failed {
                    layout.result.fail(5);
                    continue;
                }
                for mut process in self
                    .processes
                    .values_mut()
                    .filter(|p| spaces.contains(&p.memory.instruction_identity().0))
                {
                    process.file_pauses += 1;
                }
                layout.result.wake_owner();
                self.file_layouts.push(FileLayout {
                    spaces,
                    result: layout.result.clone(),
                });
                self.workers
                    .file_executor()
                    .submit_file(layout.work.exclusive(), layout.result);
            }
        }
        let pending = std::mem::take(&mut self.file_layouts);
        for layout in pending {
            if !layout.result.finished() {
                self.file_layouts.push(layout);
                continue;
            }
            for mut process in self.processes.values_mut() {
                if layout
                    .spaces
                    .contains(&process.memory.instruction_identity().0)
                {
                    process.file_pauses -= 1;
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
    fn await_native(p: &Process<trames_cpu::Cpu>) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !p
            .byte_wait
            .as_ref()
            .and_then(trames_linux::PendingIo::file_pending)
            .is_none_or(|wait| wait.result.ready())
        {
            assert!(Instant::now() < deadline);
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }
    #[test]
    fn file_layout_waits_for_views_pauses_only_affected_mms_and_retires_once() {
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
        k.call(1, &mut p, 46, args, &mut io);
        await_native(&p);
        if p.file_checkpoint.is_none() {
            k.call(1, &mut p, 46, args, &mut io);
        }
        assert!(p.file_checkpoint.is_some());
        assert!(k.file_layouts.is_empty());
        assert_eq!(p.linux.vfs.seek(fd, 0, 2).unwrap(), PAGE_SIZE);
        drop(view);
        k.call(1, &mut p, 46, args, &mut io);
        assert_eq!(p.file_pauses, 1);
        assert_eq!(k.processes.read(&2).file_pauses, 1);
        assert_eq!(k.processes.read(&3).file_pauses, 0);
        k.processes.insert(1, p);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !k.file_layouts.is_empty() {
            k.poll_file_layouts();
            assert!(Instant::now() < deadline);
            std::thread::park_timeout(Duration::from_millis(10));
        }
        let mut p = k.processes.remove(&1).unwrap();
        assert_eq!(p.file_pauses, 0);
        assert_eq!(k.processes.read(&2).file_pauses, 0);
        k.call(1, &mut p, 46, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 0);
        assert!(p.file_entry.is_none());
        assert_eq!(p.linux.vfs.seek(fd, 0, 2).unwrap(), 1);
        assert!(k.file_layouts.is_empty());
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
