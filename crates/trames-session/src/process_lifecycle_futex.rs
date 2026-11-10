// SPDX-License-Identifier: GPL-3.0-or-later
//! Unbound futex delivery belongs to the original table. An existing executor
//! admits the exact sleeping task; custody waits retain notifications, not CPUs.
use super::*;

impl<C: Cpu> Lifecycle<C> {
    pub(crate) fn futex_pending(&self) -> bool {
        self.futex_driver
            .get()
            .is_some_and(|driver| self.futexes.source_pending(&driver.signal))
    }
    pub(crate) fn futex_ready(&self) -> bool {
        self.futex_driver
            .get()
            .is_some_and(|driver| driver.signal.ready())
    }
    pub(crate) fn activate_futexes(&self, epoch: &Epoch<C>) {
        let driver = self.futex_driver.get().expect("bound futex resource");
        driver.signal.reset();
        let target = self.futexes.ready_target();
        for ticket in self.futexes.take_source_ready(&driver.signal) {
            if epoch.wake(&ticket) {
                continue;
            }
            let pid = ticket.pid;
            let Some(task) = self.tasks.handle(&pid) else {
                continue;
            };
            let _custody = match tasks::admit_one(&task, pid, &target) {
                Ok(Some(custody)) => custody,
                Ok(None) => continue,
                Err(wait) => {
                    self.futexes
                        .defer_ready(ticket, wait.signal, wait.subscriptions);
                    continue;
                }
            };
            let memory = {
                let p = task.read();
                // A numerical PID is only a lookup hint. Timeout, cancellation,
                // replacement waits and PID reuse cannot donate an old wake.
                if !self.tasks.contains_original(pid, &task)
                    || !matches!(&p.state, State::Futex { wait, .. } if Arc::ptr_eq(&wait.ticket, &ticket))
                {
                    continue;
                }
                p.memory.instruction_identity().0
            };
            // Another source may have admitted the same original actor while
            // custody was contested. Never capture its CPU/trace twice.
            if epoch.wake(&ticket) {
                continue;
            }
            let job = self.dispatch.job(
                (pid, task),
                None,
                &epoch.control,
                &mut Default::default(),
                &mut Default::default(),
                &mut Default::default(),
            );
            epoch.admit_dormant(job, memory);
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::workers::{Control, Event};
    use trames_cpu::Cpu;
    use trames_engine::Cpu as _;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn mov(r: u32, value: u32) -> u32 {
        0xd2800000 | (value << 5) | r
    }
    fn call(code: &mut Vec<u32>, number: u32, args: &[u32]) {
        code.extend(
            args.iter()
                .enumerate()
                .map(|(r, &value)| mov(r as u32, value)),
        );
        code.extend([mov(8, number), 0xd4000001]);
    }
    fn sleep(code: &mut Vec<u32>) {
        call(code, 98, &[0x3000, 128, 0, 0]);
        code.push(0x14000000);
    }
    fn write(p: &mut Process<Cpu>, at: u64, code: &[u32]) {
        p.memory.protect(at, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in code.iter().enumerate() {
            p.memory
                .write_array(at + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory.protect(at, PAGE_SIZE, Permissions::RX).unwrap();
    }
    fn setup(mode: u32, slots: usize) -> Kernel<Cpu> {
        let mut k = super::super::super::tests::kernel();
        k.cpu_count = slots.max(4);
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; k.cpu_count];
        let mut root = super::super::super::tests::admitted_process(&k);
        let mut code = Vec::new();
        match mode {
            0 => call(&mut code, 98, &[0x2000, 129, 1]),
            1 => call(&mut code, 98, &[0x2000, 138, 1, 0, 0, 2]),
            2 => {
                call(&mut code, 98, &[0x2000, 132, 0, 1, 0x2004]);
                code.push(0xaa0003f4); // retain moved count
                call(&mut code, 98, &[0x2004, 129, 1]);
            }
            3 => call(&mut code, 98, &[0x2000, 133, 1, 0, 0x2004, 0]),
            4..=6 => {
                root.memory
                    .write_array(0x2000, 42u32.to_le_bytes())
                    .unwrap();
                root.cpu.set_x(8, 96);
                root.cpu.set_x(0, 0x2000);
                k.syscall(
                    1,
                    &mut root,
                    96,
                    [0x2000, 0, 0, 0, 0, 0],
                    &mut trames_linux::CapturedOutput::default(),
                )
                .unwrap();
                if mode == 5 {
                    call(&mut code, 277, &[0, 0, 0]);
                    call(&mut code, 172, &[]);
                } else {
                    call(&mut code, 93, &[0]);
                }
            }
            _ => unreachable!(),
        }
        code.push(0xaa0003f3); // retain wake return
        sleep(&mut code);
        write(&mut root, 0x4000, &code);
        let mut resumed = vec![0xaa0003f3, mov(0, 0x2800), mov(1, 1), 0xb9000001];
        sleep(&mut resumed);
        write(&mut root, 0x5000, &resumed);
        let mut peer = Vec::new();
        sleep(&mut peer);
        write(&mut root, 0x6000, &peer);
        let shared = root.memory.share();
        let mut cold = root.fork_with_memory(shared);
        cold.cpu.set_pc(0x5000);
        cold.tgid = 3;
        cold.state = State::Futex {
            wait: k
                .futexes
                .wait((0, 1, 0x2000), 3, 2, || Ok::<_, Errno>(()))
                .unwrap(),
            deadline: None,
        };
        let shared = root.memory.share();
        let mut peer = root.fork_with_memory(shared);
        peer.cpu.set_pc(0x6000);
        peer.tgid = 2;
        // Keep clear_tid's original address only on the exiting task.
        for p in [&mut cold, &mut peer] {
            p.cpu.set_x(8, 96);
            p.cpu.set_x(0, 0);
            k.syscall(
                p.tgid,
                p,
                96,
                [0, 0, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default(),
            )
            .unwrap();
        }
        let (producer, observer) = if mode >= 4 {
            root.tgid = 2;
            peer.tgid = 1;
            (2, 1)
        } else {
            (1, 2)
        };
        for (pid, p) in [(producer, root), (observer, peer), (3, cold)] {
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
            k.publish_task(pid, &p);
            k.processes.insert(pid, p);
        }
        if mode == 6 {
            let group = k.processes.read(&2).signals.io.lifecycle().clone();
            k.processes.get_mut(&2).unwrap().state = State::Suspend(0);
            group.request_exit(9);
            k.queue_exit_group(group);
        }
        k
    }
    fn epoch(k: &mut Kernel<Cpu>, persistent: bool) -> Arc<Epoch<Cpu>> {
        let epoch = Epoch::with_events(
            Arc::new(Control::new(u64::MAX / 2)),
            k.workers.events(),
            persistent,
        );
        epoch.bind_lifecycle(Lifecycle::capture(k));
        let members: Vec<_> = [1, 2]
            .into_iter()
            .filter(|id| matches!(k.processes.read(id).state, State::Ready))
            .map(|id| (id, 0))
            .collect();
        for (pid, _, view) in k.prepare_parallel_views(&members).unwrap() {
            epoch.add(k.capture_worker(
                pid,
                view,
                &epoch.control,
                &mut Default::default(),
                &mut Default::default(),
                &mut Default::default(),
            ));
        }
        epoch
    }
    fn stop(k: &mut Kernel<Cpu>, epoch: &Epoch<Cpu>) {
        epoch.stop();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stopped = 0;
        while stopped < epoch.active_slots().count_ones() {
            match k
                .workers
                .event_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                Some(Event::EpochStopped(_)) => stopped += 1,
                Some(Event::Retired | Event::Idle) => {}
                _ => panic!("unexpected futex owner handoff"),
            }
        }
        assert!(epoch.collect_lifecycle(k).is_none());
        for done in epoch.drain() {
            k.adopt_worker_return(done, false);
        }
    }
    #[test]
    fn all_unbound_wake_operations_and_clear_tid_admit_the_original_task_on_existing_workers() {
        for slots in [1, 4, 12] {
            for mode in 0..7 {
                let mut k = setup(mode, slots);
                let epoch = epoch(&mut k, true);
                // Deliberately cold original actor: this is the old ready-table
                // route, not the already-bound fast path tested elsewhere.
                assert!(!epoch.contains(3));
                k.workers.launch(0, epoch.clone()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match k
                        .workers
                        .event_timeout(deadline.saturating_duration_since(Instant::now()))
                        .unwrap()
                    {
                        Some(Event::Idle) => break,
                        Some(Event::Retired) => {}
                        _ => panic!("mode={mode} slots={slots}: unbound futex stopped the cohort"),
                    }
                }
                assert!(!epoch.control.stopped());
                assert!(epoch.contains(3), "mode={mode} slots={slots}");
                stop(&mut k, &epoch);
                assert_eq!(
                    k.processes.read(&3).memory.read_array::<4>(0x2800).unwrap(),
                    1u32.to_le_bytes(),
                    "mode={mode} slots={slots}"
                );
                assert_eq!(k.processes.read(&3).cpu.x(19), 0);
                if mode < 4 {
                    assert_eq!(k.processes.read(&1).cpu.x(19), 1);
                }
                if mode == 2 {
                    assert_eq!(k.processes.read(&1).cpu.x(20), 1);
                }
                if mode >= 4 {
                    assert_eq!(
                        k.processes.read(&3).memory.read_array::<4>(0x2000).unwrap(),
                        [0; 4]
                    );
                }
                assert_eq!(k.service_requests, 0);
                assert!(k.cohort_return_syscalls.is_empty());
            }
        }
    }
    #[test]
    fn unbound_futex_custody_wait_releases_the_slot_and_preserves_handoff_and_identity() {
        for memory in [false, true] {
            for disposition in 0..4 {
                let mut k = setup(0, 1);
                let epoch = epoch(&mut k, true);
                let task = k.processes.handle(&3).unwrap();
                let original = match &task.read().state {
                    State::Futex { wait, .. } => wait.clone(),
                    _ => unreachable!(),
                };
                let mm = task.write().memory.share();
                let (held, ready) = std::sync::mpsc::channel();
                let (release, released) = std::sync::mpsc::channel();
                let held_task = task.clone();
                let holder = std::thread::spawn(move || {
                    let _body = (!memory).then(|| held_task.write());
                    let _mm = memory.then(|| mm.try_admit().unwrap());
                    held.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                ready.recv_timeout(Duration::from_secs(2)).unwrap();
                assert_eq!(k.futexes.wake((0, 1, 0x2000), 1, 2), 1);
                let start = Instant::now();
                let job = epoch.take(0).unwrap();
                assert!(start.elapsed() < Duration::from_secs(1));
                assert_ne!(job.work.pid, 3);
                epoch.park(job, None);
                assert!(!epoch.contains(3));
                release.send(()).unwrap();
                holder.join().unwrap();
                if disposition == 1 {
                    epoch.stop();
                    let mut ready = Vec::new();
                    k.futexes.take_ready(&mut ready);
                    assert_eq!(ready.len(), 1);
                    assert!(Arc::ptr_eq(&ready[0], &original.ticket));
                } else {
                    if disposition >= 2 {
                        // Replace either the wait or the whole PID after the
                        // original wake, before custody retry is accepted.
                        if disposition == 3 {
                            let replacement = k.processes.read(&3).fork();
                            drop(k.processes.remove(&3));
                            k.processes.insert(3, replacement);
                        }
                        task.write().state = State::Ready;
                        k.processes.get_mut(&3).unwrap().state = State::Futex {
                            wait: k
                                .futexes
                                .wait((0, 1, 0x2000), 3, 2, || Ok::<_, Errno>(()))
                                .unwrap(),
                            deadline: None,
                        };
                    }
                    let job = epoch.take(0).unwrap();
                    epoch.park(job, None);
                    assert_eq!(epoch.contains(3), disposition == 0);
                }
                epoch.stop();
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                for done in epoch.drain() {
                    k.adopt_worker_return(done, false);
                }
            }
        }
    }
}
