// SPDX-License-Identifier: GPL-3.0-or-later
//! Exceptional native access uses original task/mm custody on an existing CPU.
//! Only the affected bytes quiesce; context/device waits retain their source job.
use super::*;
use trames_accel::native::{Error, Registry, Return};

impl<C: Cpu> Lifecycle<C> {
    pub(super) fn native_calls(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &mut Checkpoint<C>,
        report: &mut Report,
        slot: usize,
    ) {
        if !checkpoint
            .jobs
            .iter()
            .any(|job| matches!(job.checkpoint, Some(SliceOutcome::NativeCall { .. })))
        {
            return;
        }
        let mut registry = Registry::default();
        for job in &mut checkpoint.jobs {
            let Some(SliceOutcome::NativeCall {
                pc,
                module,
                function,
                ..
            }) = job.checkpoint.as_ref()
            else {
                continue;
            };
            let (pc, module, function) = (*pc, *module, *function);
            job.checkpoint = None;
            let original = job
                .work
                .task
                .as_ref()
                .expect("original native task")
                .clone();
            let p = &mut *original.write();
            if p.signals.io.lifecycle().termination().is_some() {
                job.work.control.refund(1);
                continue;
            }
            let began = Instant::now();
            let _execution = job.domain.as_ref().expect("native mm").enter_scoped(slot);
            let control = p.signals.io.lifecycle().enter(&p.signals.io, job.work.pid);
            let a = [job.work.cpu.x(0), job.work.cpu.x(1), job.work.cpu.x(2)];
            // A changed backing may invalidate a stub observation. Retry before
            // effects with the same bounded rule as solo execution; an unstable
            // entry becomes its original guest fault, never an owner handoff.
            let mut attempt = invoke(
                p,
                &job.work,
                &mut registry,
                pc,
                module,
                function,
                a,
                epoch,
                &mut job.stats.gpu,
            );
            for _ in 0..2 {
                if !matches!(attempt, crate::gpu::Attempt::Checkpoint) {
                    break;
                }
                attempt = invoke(
                    p,
                    &job.work,
                    &mut registry,
                    pc,
                    module,
                    function,
                    a,
                    epoch,
                    &mut job.stats.gpu,
                );
            }
            match attempt {
                crate::gpu::Attempt::Complete(Ok(value)) => {
                    job.work.cpu.set_x(0, value.value);
                    job.work.cpu.set_x(1, u64::from(value.fallback));
                    job.work.cpu.set_pc(pc + 4);
                    job.stats.instructions += 1;
                }
                crate::gpu::Attempt::Blocked(pending) => {
                    // Compile/fence acceptance retires exactly once. Waiting
                    // for the context before acceptance returns the reservation.
                    if pending.compile.is_some() {
                        job.stats.instructions += 1;
                    } else {
                        job.work.control.refund(1);
                    }
                    p.signals.io.proc_view.waiting(true);
                    job.stats.gpu.waits += 1;
                    job.gpu_pending = Some(pending);
                }
                failed => {
                    let error = match failed {
                        crate::gpu::Attempt::Complete(Err(error)) => error,
                        crate::gpu::Attempt::Checkpoint => Error::InvalidEntry,
                        _ => unreachable!(),
                    };
                    job.work.control.refund(1);
                    job.pending_cpu = Some(crate::workers::native_fault(
                        error,
                        pc,
                        module,
                        function,
                        &mut job.stats.rejected_native,
                    ));
                }
            }
            p.memory.memory_report();
            control.finish(job.stop_hold());
            if let Some(cgroup) = p.signals.io.cgroup() {
                cgroup.acknowledge();
            }
            let elapsed = began.elapsed();
            p.signals.io.proc_view.account(elapsed, slot);
            job.stats.cpu_times[slot] += elapsed;
            job.stats.elapsed += elapsed;
            report.time[3] += elapsed;
            registry.metrics.worker_calls = registry.metrics.calls;
            job.stats
                .native
                .merge(std::mem::take(&mut registry.metrics));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn invoke<C: Cpu>(
    p: &mut Process<C>,
    work: &crate::workers::Work<C>,
    registry: &mut Registry,
    pc: u64,
    module: u64,
    function: u64,
    a: [u64; 3],
    epoch: &Epoch<C>,
    stats: &mut crate::workers::GpuStats,
) -> crate::gpu::Attempt {
    let result = if matches!(
        module,
        trames_vulkan::PROFILE | trames_video::PROFILE | trames_audio::PROFILE
    ) {
        let key = match module {
            trames_vulkan::PROFILE => trames_vulkan::AUXV_KEY,
            trames_video::PROFILE => trames_video::AUXV_KEY,
            _ => trames_audio::AUXV_KEY,
        };
        if !accelerated(p, key, module) {
            return crate::gpu::Attempt::Complete(Err(Error::InvalidEntry));
        }
        match registry.authorize_stateful(&p.memory, pc, module, function) {
            Err(Error::Checkpoint) => return crate::gpu::Attempt::Checkpoint,
            Err(error) => return crate::gpu::Attempt::Complete(Err(error)),
            Ok(()) => {}
        }
        match module {
            trames_vulkan::PROFILE => {
                let Some(authority) = &work.gpu else {
                    return crate::gpu::Attempt::Complete(Err(Error::InvalidEntry));
                };
                return crate::gpu::Pending::new(crate::gpu::Call {
                    pc,
                    operation: a[0],
                    args: a,
                })
                .progress(
                    authority,
                    &mut p.memory,
                    work.pid,
                    &epoch.io_target,
                    stats,
                    epoch.progress.load(std::sync::atomic::Ordering::Relaxed),
                );
            }
            trames_video::PROFILE => {
                let Some(authority) = &work.gpu else {
                    return crate::gpu::Attempt::Complete(Err(Error::InvalidEntry));
                };
                crate::devices::video(
                    &authority.video,
                    authority.events.as_ref(),
                    authority.images.as_ref(),
                    &mut p.memory,
                    a[0],
                    a[1],
                    a[2],
                )
            }
            _ => {
                let Some(authority) = &work.audio else {
                    return crate::gpu::Attempt::Complete(Err(Error::InvalidEntry));
                };
                crate::devices::audio(
                    &authority.context,
                    Some(&authority.events),
                    &mut p.memory,
                    a[0],
                    a[1],
                    a[2],
                )
            }
        }
        .map(|value| Return {
            value,
            fallback: false,
        })
        .map_err(Error::Memory)
    } else {
        registry.invoke(&mut p.memory, pc, module, function, a)
    };
    match result {
        Err(Error::Checkpoint) => crate::gpu::Attempt::Checkpoint,
        value => crate::gpu::Attempt::Complete(value),
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::workers::{Control, Event};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use trames_cpu::Cpu;
    use trames_engine::Cpu as _;
    use trames_memory::CpuMemory;
    use trames_memory::{MemoryError, PageBacking, Permissions, PAGE_SIZE};

    struct Live {
        bytes: Mutex<[u8; PAGE_SIZE as usize]>,
        version: AtomicU64,
        unstable: AtomicBool,
    }
    impl Default for Live {
        fn default() -> Self {
            Self {
                bytes: Mutex::new([0; PAGE_SIZE as usize]),
                version: AtomicU64::new(0),
                unstable: AtomicBool::new(false),
            }
        }
    }
    impl PageBacking for Live {
        fn parallel_key(&self) -> Option<(u64, u64)> {
            Some((self as *const Self as usize as u64, 0))
        }
        fn check(&self, _: u64) -> Result<(), MemoryError> {
            Ok(())
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
            out.copy_from_slice(&self.bytes.lock().unwrap()[offset..offset + out.len()]);
            if self.unstable.load(Ordering::Relaxed) {
                self.version.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
        fn write(&self, offset: usize, input: &[u8]) -> Result<(), MemoryError> {
            self.bytes.lock().unwrap()[offset..offset + input.len()].copy_from_slice(input);
            self.version.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn native_resident(&self) -> bool {
            true
        }
        fn sync(&self) -> Result<(), MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            self.version.load(Ordering::Relaxed)
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
            Err(MemoryError::InvalidRange)
        }
    }
    fn setup(k: &Kernel<Cpu>, unstable: bool) -> (Box<Process<Cpu>>, Arc<Live>) {
        let mut p = super::super::super::tests::admitted_process(k);
        let data = Arc::new(Live::default());
        p.memory
            .map_backed(0x2000, vec![data.clone()], false, Permissions::RW, true)
            .unwrap();
        let code = Arc::new(Live::default());
        let words = [
            0xd2800030u32,
            0xf2a00030,
            0xd2800071,
            trames_accel::native::INSTRUCTION,
            0xd65f03c0,
        ];
        for (i, word) in words.into_iter().enumerate() {
            code.write(i * 4, &word.to_le_bytes()).unwrap();
        }
        p.memory
            .map_backed(0x4000, vec![code.clone()], false, Permissions::RX, true)
            .unwrap();
        for (i, word) in [0x39400000u32, 0xd2800ba8, 0xd4000001]
            .into_iter()
            .enumerate()
        {
            p.memory
                .write_array(0x5000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(0x5000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_native_calls(true);
        p.cpu.set_x(0, 0x2000);
        p.cpu.set_x(1, 7);
        p.cpu.set_x(2, 128);
        p.cpu.set_x(30, 0x5000);
        code.unstable.store(unstable, Ordering::Relaxed);
        (p, data)
    }
    fn admit(k: &mut Kernel<Cpu>, control: Arc<Control>) -> Arc<Epoch<Cpu>> {
        let epoch = Epoch::with_events(control.clone(), k.workers.events(), false);
        epoch.bind_lifecycle(Lifecycle::capture(k));
        let ids: Vec<_> = k.processes.iter().map(|(id, _)| (id, 0)).collect();
        for (id, _, view) in k.prepare_parallel_views(&ids).unwrap() {
            epoch.add(k.capture_worker(
                id,
                view,
                &control,
                &mut Default::default(),
                &mut Default::default(),
                &mut Default::default(),
            ));
        }
        epoch
    }
    #[test]
    fn original_native_checkpoint_completes_or_faults_without_joining_and_ignores_stale_x8() {
        for unstable in [false, true] {
            for stale in [220, 221, 281, 222, 93] {
                let mut k = super::super::super::tests::kernel();
                let (mut p, data) = setup(&k, unstable);
                p.cpu.set_x(8, stale);
                let family = p.family.clone();
                k.processes.insert(1, p);
                k.publish_io_tasks(None);
                let control = Arc::new(Control::new(1000));
                let epoch = admit(&mut k, control);
                k.workers.launch(0, epoch.clone()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match k
                        .workers
                        .event_timeout(deadline.saturating_duration_since(Instant::now()))
                        .unwrap()
                    {
                        Some(Event::Retired) => {}
                        Some(Event::EpochStopped(0)) => break,
                        _ => panic!("native source requested joined work or timed out"),
                    }
                }
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                let done = epoch.drain();
                assert!(done.iter().all(|done| done.thread_exit.is_some()));
                assert_eq!(family.status(), Some(if unstable { 4 } else { 7 << 8 }));
                assert_eq!(
                    &data.bytes.lock().unwrap()[..128],
                    &[0; 128],
                    "private COW never writes its file backing"
                );
                assert_eq!(k.vm_checkpoint_groups, 1);
                assert_eq!(k.serviced_syscalls, 0);
                if !unstable {
                    assert_eq!(
                        k.instructions + done.iter().map(|done| done.instructions).sum::<u64>(),
                        8
                    );
                }
                while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                    assert!(!matches!(event, Event::VmReady), "no owner native request");
                }
            }
        }
    }
    #[test]
    fn original_native_context_wait_releases_mm_and_slot_then_retires_once() {
        let mut k = super::super::super::tests::kernel();
        let (mut p, _) = setup(&k, false);
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        p.memory
            .write_array(0x4000, 0xd28000d0u32.to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x4008, 0xd2800031u32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.memory
            .protect(0x5000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        // Keep namespace init alive until the independent peer can finish.
        for (i, word) in [
            0xd28c0000u32,
            0xd2800001,
            0xd2800ca8,
            0xd4000001,
            0xd2800540,
            0xd2800ba8,
            0xd4000001,
        ]
        .into_iter()
        .enumerate()
        {
            p.memory
                .write_array(0x5000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory.write_array(0x6000, 0u64.to_le_bytes()).unwrap();
        p.memory
            .write_array(0x6008, 50_000_000u64.to_le_bytes())
            .unwrap();
        p.memory
            .protect(0x5000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.memory
            .write_array(0x2000, 0x3000u64.to_le_bytes())
            .unwrap();
        p.memory.write(0x3000, &[0xa5; 32]).unwrap();
        p.linux
            .auxiliary
            .extend(trames_vulkan::AUXV_KEY.to_le_bytes());
        p.linux
            .auxiliary
            .extend(trames_vulkan::PROFILE.to_le_bytes());
        p.cpu.set_vulkan_calls(true);
        let family = p.family.clone();
        let context = p.gpu_context(&k.gpu_budget, &k.gpu_display);
        k.processes.insert(1, p);
        let mut foreign = super::super::super::tests::admitted_process(&k);
        for (i, word) in [0xd28000e0u32, 0xd2800ba8, 0xd4000001]
            .into_iter()
            .enumerate()
        {
            foreign
                .memory
                .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        foreign
            .memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        foreign.tgid = 4;
        foreign.set_group(4);
        foreign.cpu = Cpu::new(0x4000, 0);
        let foreign_family = foreign.family.clone();
        k.processes.insert(4, foreign);
        k.publish_io_tasks(None);
        // The pending HLT has reserved one credit before entering the scope.
        let control = Arc::new(Control::new(999));
        let epoch = admit(&mut k, control);
        let mut caller = epoch.take(0).unwrap();
        assert_eq!(caller.work.pid, 1);
        caller.work.cpu.set_pc(0x400c);
        caller.work.cpu.set_x(8, 221);
        caller.work.cpu.set_x(0, 79);
        caller.work.cpu.set_x(1, 0x2000);
        caller.work.cpu.set_x(2, 128);
        let original = caller.work.task.as_ref().unwrap().clone();
        let lease = context.try_lock().unwrap();
        epoch.checkpoint(
            caller,
            SliceOutcome::NativeCall {
                instructions: 0,
                pc: 0x400c,
                module: trames_vulkan::PROFILE,
                function: 1,
            },
        );
        assert!(
            epoch.take_checkpoint().is_none(),
            "native scope stays source-owned"
        );
        let foreign = epoch.take(0).unwrap();
        assert_eq!(foreign.work.pid, 4);
        {
            let task = original.write();
            assert_eq!(task.memory.read_array::<32>(0x3000).unwrap(), [0xa5; 32]);
        }
        drop(lease);
        epoch.park(foreign, None);
        k.workers.launch(0, epoch.clone()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match k
                .workers
                .event_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                Some(Event::Retired) => {}
                Some(Event::EpochStopped(0)) => break,
                _ => panic!("GPU context wait requested joined work"),
            }
        }
        assert!(epoch.collect_lifecycle(&mut k).is_none());
        let done = epoch.drain();
        assert!(
            done.iter().all(|done| done.thread_exit.is_some()),
            "returned: {:?}; families {:?}/{:?}",
            done.iter()
                .map(|done| (done.pid, done.thread_exit, done.cpu.pc, done.instructions))
                .collect::<Vec<_>>(),
            family.status(),
            foreign_family.status()
        );
        assert_eq!(family.status(), Some(42 << 8));
        assert_eq!(foreign_family.status(), Some(7 << 8));
        assert_eq!(
            k.instructions + done.iter().map(|done| done.instructions).sum::<u64>(),
            12
        );
        assert_eq!(
            k.worker_gpu_calls + done.iter().map(|done| done.gpu.calls).sum::<u64>(),
            1
        );
        assert_eq!(k.vm_checkpoint_groups, 1);
        assert_eq!(k.serviced_syscalls, 0);
    }
    #[test]
    fn original_native_custody_wait_preserves_hlt_and_cancellation_without_blocking_peer() {
        for memory in [false, true] {
            for cancel in [false, true] {
                let mut k = super::super::super::tests::kernel();
                let (mut p, _) = setup(&k, false);
                let external = p.memory.share();
                k.processes.insert(1, p);
                let mut foreign = super::super::super::tests::admitted_process(&k);
                foreign.tgid = 4;
                foreign.set_group(4);
                k.processes.insert(4, foreign);
                k.publish_io_tasks(None);
                let epoch = admit(&mut k, Arc::new(Control::new(999)));
                let mut caller = epoch.take(0).unwrap();
                assert_eq!(caller.work.pid, 1);
                caller.work.cpu.set_pc(0x400c);
                let original = caller.work.task.as_ref().unwrap().clone();
                let (ready, held) = std::sync::mpsc::channel();
                let (release, released) = std::sync::mpsc::channel();
                let holder = std::thread::spawn(move || {
                    let _task = (!memory).then(|| original.write());
                    let _memory = memory.then(|| external.try_admit().unwrap());
                    ready.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                held.recv_timeout(Duration::from_secs(5)).unwrap();
                epoch.checkpoint(
                    caller,
                    SliceOutcome::NativeCall {
                        instructions: 0,
                        pc: 0x400c,
                        module: trames_accel::native::PROFILE,
                        function: 3,
                    },
                );
                assert!(epoch.take_checkpoint().is_none());
                let foreign = epoch.take(0).unwrap();
                assert_eq!(
                    foreign.work.pid, 4,
                    "source admission releases its only slot"
                );
                epoch.park(foreign, Some(crate::run_queue::WaitState::OwnerEvent));
                if cancel {
                    epoch.stop();
                }
                release.send(()).unwrap();
                holder.join().unwrap();
                assert!(
                    epoch.take_checkpoint().is_none(),
                    "retry remains source-owned"
                );
                if !cancel {
                    let caller = epoch.take(0).unwrap();
                    assert_eq!(caller.work.pid, 1);
                    assert_eq!(caller.work.cpu.pc, 0x4010);
                    assert_eq!(
                        caller
                            .work
                            .memory
                            .as_ref()
                            .unwrap()
                            .read_array::<128>(0x2000)
                            .unwrap(),
                        [7; 128]
                    );
                    assert_eq!(caller.stats.instructions, 1);
                    epoch.park(caller, Some(crate::run_queue::WaitState::OwnerEvent));
                    epoch.stop();
                }
                let done = epoch.drain();
                assert_eq!(done.len(), 2);
                if cancel {
                    let caller = done.iter().find(|done| done.pid == 1).unwrap();
                    assert_eq!(caller.cpu.pc, 0x400c);
                    assert_eq!(caller.cpu.x(0), 0x2000);
                    assert!(matches!(
                        caller.outcome,
                        Some(SliceOutcome::NativeCall { .. })
                    ));
                    let task = k.processes.handle(&1).unwrap();
                    let p = &mut *task.write();
                    p.memory.commit_parallel().unwrap();
                    assert_eq!(p.memory.read_array::<128>(0x2000).unwrap(), [0; 128]);
                }
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                assert_eq!(k.vm_checkpoint_groups, u64::from(!cancel));
            }
        }
    }
    #[test]
    fn original_native_device_entry_instability_faults_before_device_effects() {
        for (module, key) in [
            (trames_vulkan::PROFILE, trames_vulkan::AUXV_KEY),
            (trames_video::PROFILE, trames_video::AUXV_KEY),
            (trames_audio::PROFILE, trames_audio::AUXV_KEY),
        ] {
            let mut k = super::super::super::tests::kernel();
            let (mut p, data) = setup(&k, false);
            let code = Arc::new(Live::default());
            for (i, word) in [
                0xd2800010u32 | (((module as u32) & 0xffff) << 5),
                0xf2a00030,
                0xd2800031,
                trames_accel::native::INSTRUCTION,
                0xd65f03c0,
            ]
            .into_iter()
            .enumerate()
            {
                code.write(i * 4, &word.to_le_bytes()).unwrap();
            }
            code.unstable.store(true, Ordering::Relaxed);
            p.memory
                .map_backed(0x4000, vec![code], false, Permissions::RX, true)
                .unwrap();
            p.linux.auxiliary.extend(key.to_le_bytes());
            p.linux.auxiliary.extend(module.to_le_bytes());
            p.cpu.set_vulkan_calls(true);
            p.cpu.set_video_calls(true);
            p.cpu.set_audio_calls(true);
            p.cpu.set_x(8, 221);
            let family = p.family.clone();
            k.processes.insert(1, p);
            k.publish_io_tasks(None);
            let epoch = admit(&mut k, Arc::new(Control::new(999)));
            let mut caller = epoch.take(0).unwrap();
            caller.work.cpu.set_pc(0x400c);
            epoch.checkpoint(
                caller,
                SliceOutcome::NativeCall {
                    instructions: 0,
                    pc: 0x400c,
                    module,
                    function: 1,
                },
            );
            k.workers.launch(0, epoch.clone()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match k
                    .workers
                    .event_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap()
                {
                    Some(Event::Retired) => {}
                    Some(Event::EpochStopped(0)) => break,
                    _ => panic!("unstable device entry requested joined work"),
                }
            }
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            let done = epoch.drain();
            assert!(
                done.iter().all(|done| done.thread_exit.is_some()),
                "module={module:x}, scope={}, family={:?}, done={:?}",
                k.vm_checkpoint_groups,
                family.status(),
                done.iter()
                    .map(|d| (d.pid, d.thread_exit, d.cpu.pc, format!("{:?}", d.outcome)))
                    .collect::<Vec<_>>()
            );
            assert_eq!(family.status(), Some(4));
            assert_eq!(k.vm_checkpoint_groups, 1);
            assert_eq!(k.worker_gpu_calls, 0);
            assert_eq!(&data.bytes.lock().unwrap()[..128], &[0; 128]);
        }
    }
}
