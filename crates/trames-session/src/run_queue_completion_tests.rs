// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed interleavings at the original execution queue's publication boundaries.
use super::{tests::job, *};
use std::sync::mpsc;
use trames_cpu::Cpu;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
type TestEpoch = super::Epoch<Cpu>;

struct ProtocolGate {
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    changed: Arc<trames_shared::Readiness>,
    fail: bool,
}
impl trames_shared::HostProtocol for ProtocolGate {
    fn identity(&self) -> usize {
        self as *const Self as usize
    }
    fn alive(&self) -> bool {
        true
    }
    fn changed(&self) -> Arc<trames_shared::Readiness> {
        self.changed.clone()
    }
    fn progress(&self, _: &Arc<trames_vfs::IoSignal>) -> std::io::Result<()> {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        if self.fail {
            Err(std::io::Error::other("protocol failure"))
        } else {
            Ok(())
        }
    }
    fn interests(&self) -> std::io::Result<trames_shared::ProtocolInterests> {
        Ok((Vec::new(), None))
    }
}
impl trames_vfs::IoWake for ProtocolGate {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}

fn widths() -> Vec<usize> {
    let full = std::thread::available_parallelism().unwrap().get().min(32);
    let mut n = vec![1, 2, full];
    n.sort_unstable();
    n.dedup();
    n
}
fn sleeping(epoch: &TestEpoch, slots: usize) {
    let mask = (1u64 << slots) - 1;
    let until = Instant::now() + Duration::from_secs(2);
    let mut q = epoch.queues.lock().unwrap();
    while q.sleeping_slots & mask != mask {
        let left = until.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "workers did not register their waits");
        q = epoch.changed.wait_timeout(q, left).unwrap().0;
    }
}

#[test]
fn unlocked_protocol_return_observes_completion_before_dispatch_or_sleep() {
    for slots in widths() {
        for ending in 0..6 {
            for queued in [false, true] {
                if ending == 5 && queued {
                    continue;
                }
                let (events, _) = mpsc::channel();
                let epoch = TestEpoch::with_events(
                    Arc::new(Control::with_budget(1000, true)),
                    events,
                    true,
                );
                epoch.bind_session(true);
                epoch.queues.lock().unwrap().idle_notified = true;
                let (entered, entrance) = mpsc::sync_channel(1);
                let (release, resume) = mpsc::channel();
                epoch.protocols.register(
                    Arc::new(ProtocolGate {
                        entered,
                        release: Mutex::new(resume),
                        changed: Arc::default(),
                        fail: ending == 5,
                    }),
                    epoch.io_target.clone(),
                );
                let (done, returned) = mpsc::channel();
                let threads: Vec<_> = (0..slots)
                    .map(|slot| {
                        let e = epoch.clone();
                        let done = done.clone();
                        std::thread::spawn(move || {
                            let no_dispatch = e.take(slot).is_none();
                            done.send(no_dispatch).unwrap();
                        })
                    })
                    .collect();
                entrance.recv_timeout(Duration::from_secs(2)).unwrap();
                match ending {
                    0 => epoch.stop(),
                    1 => epoch.cancel(),
                    2 => epoch.complete(),
                    3 => epoch.fail(),
                    4 => epoch.end(crate::execution_control::End::Budget),
                    5 => {} // The returning protocol itself fails the session.
                    _ => unreachable!(),
                }
                if queued {
                    epoch.add(job(7, &epoch));
                }
                release.send(()).unwrap();
                let until = Instant::now() + Duration::from_secs(1);
                let outcomes: Vec<_> = (0..slots)
                    .map(|_| returned.recv_timeout(until.saturating_duration_since(Instant::now())))
                    .collect();
                // Recover a failed implementation after recording its missing
                // completion, so a regression fails instead of hanging CI.
                epoch.cancel();
                if outcomes.iter().any(Result::is_err) {
                    epoch.add(job(99, &epoch));
                }
                for thread in threads {
                    thread.join().unwrap();
                }
                assert!(
                    outcomes.iter().all(|r| *r == Ok(true)),
                    "slots={slots} ending={ending} queued={queued}: {outcomes:?}"
                );
                let drained = epoch.drain();
                assert_eq!(drained.len(), usize::from(queued));
                if queued {
                    assert_eq!(drained[0].pid, 7);
                }
            }
        }
    }
}

#[test]
fn new_ready_admission_wakes_already_active_idle_slots() {
    for slots in widths() {
        let (events, _) = mpsc::channel();
        let epoch = TestEpoch::with_events(Arc::new(Control::new(1000)), events, true);
        epoch.queues.lock().unwrap().idle_notified = true;
        let (done, returned) = mpsc::channel();
        let threads: Vec<_> = (0..slots)
            .map(|slot| {
                let e = epoch.clone();
                let done = done.clone();
                std::thread::spawn(move || {
                    done.send((
                        slot,
                        e.take(slot).map(|j| {
                            let pid = j.work.pid;
                            e.park(j, Some(WaitState::OwnerEvent));
                            pid
                        }),
                    ))
                    .unwrap()
                })
            })
            .collect();
        sleeping(&epoch, slots);
        for slot in 0..slots {
            let mut j = job(slot as u32 + 1, &epoch);
            j.affinity = 1 << slot;
            epoch.add(j);
        }
        let until = Instant::now() + Duration::from_secs(1);
        let outcomes: Vec<_> = (0..slots)
            .map(|_| returned.recv_timeout(until.saturating_duration_since(Instant::now())))
            .collect();
        epoch.cancel();
        for t in threads {
            t.join().unwrap();
        }
        assert!(
            outcomes.iter().all(|r| r
                .as_ref()
                .is_ok_and(|(slot, pid)| *pid == Some(*slot as u32 + 1))),
            "slots={slots}: {outcomes:?}"
        );
        assert_eq!(epoch.drain().len(), slots);
    }
}

#[test]
fn new_deadline_interrupts_an_indefinite_idle_wait() {
    let (events, _) = mpsc::channel();
    let epoch = TestEpoch::with_events(Arc::new(Control::new(1000)), events, true);
    epoch.queues.lock().unwrap().idle_notified = true;
    let (done, returned) = mpsc::channel();
    let e = epoch.clone();
    let worker = std::thread::spawn(move || {
        done.send(e.take(0).map(|j| {
            let pid = j.work.pid;
            assert!(j.waiting.is_none(), "deadline was not completed");
            e.park(j, Some(WaitState::OwnerEvent));
            pid
        }))
        .unwrap()
    });
    sleeping(&epoch, 1);
    let mut j = job(1, &epoch);
    j.waiting = Some(WaitState::Sleep {
        deadline: Instant::now() + Duration::from_millis(5),
        remaining: 0,
    });
    epoch.add(j);
    let result = returned.recv_timeout(Duration::from_secs(1));
    epoch.cancel();
    worker.join().unwrap();
    assert_eq!(result, Ok(Some(1)));
    assert_eq!(epoch.drain().len(), 1);
}

#[test]
fn completed_admission_cannot_start_a_late_cpu_slot() {
    for ending in 0..3 {
        let pool = crate::workers::Pool::<Cpu>::new(2);
        let epoch = TestEpoch::with_events(
            Arc::new(Control::with_budget(1000, true)),
            pool.events(),
            true,
        );
        epoch.bind_session(true);
        epoch.bind_starter(pool.starter());
        match ending {
            0 => epoch.cancel(),
            1 => epoch.complete(),
            _ => epoch.fail(),
        }
        epoch.activate(0).unwrap();
        assert_eq!(
            epoch.active_slots(),
            0,
            "late activation after ending={ending}"
        );
        assert!(!epoch.activation_failed());
    }
}

#[test]
fn cpu_activation_failure_wakes_existing_idle_executors() {
    let pool = crate::workers::Pool::<Cpu>::new(2);
    let epoch = TestEpoch::with_events(
        Arc::new(Control::with_budget(1000, true)),
        pool.events(),
        true,
    );
    epoch.bind_starter(pool.starter());
    drop(pool); // Original source pool is no longer available for activation.
    let (done, returned) = mpsc::channel();
    let e = epoch.clone();
    let waiter = std::thread::spawn(move || done.send(e.take(0).is_none()).unwrap());
    sleeping(&epoch, 1);
    assert!(epoch.activate(1).is_err());
    let result = returned.recv_timeout(Duration::from_secs(1));
    epoch.cancel();
    waiter.join().unwrap();
    assert_eq!(result, Ok(true));
    assert!(epoch.activation_failed());
    assert_eq!(
        epoch.control.end(),
        Some(crate::execution_control::End::Failed)
    );
    assert_eq!(epoch.active_slots(), 0);
}

#[test]
fn unlocked_timer_delivery_observes_completion_before_sleep() {
    for ending in 0..3 {
        let (events, _) = mpsc::channel();
        let epoch =
            TestEpoch::with_events(Arc::new(Control::with_budget(1000, true)), events, true);
        epoch.bind_session(true);
        epoch.queues.lock().unwrap().idle_notified = true;
        let timers = Arc::new(trames_kernel::timers::Timers::default());
        epoch.bind_timers(timers.clone());
        let directory = trames_kernel::signal::IoDirectory::default();
        let task = Arc::new(trames_kernel::signal::IoTask::default());
        directory.publish(&task, 42, 42, 42, 0, 0);
        let (entered, entrance) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::channel();
        let gate: Arc<dyn trames_vfs::IoWake> = Arc::new(ProtocolGate {
            entered,
            release: Mutex::new(resume),
            changed: Arc::default(),
            fail: false,
        });
        let signal = trames_vfs::IoSignal::new(42, Arc::downgrade(&gate));
        task.set_wake(&signal);
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x1018, 1u64.to_le_bytes()).unwrap();
        timers
            .call(
                103,
                [0, 0x1000, 0, 0, 0, 0],
                &mut memory,
                Instant::now(),
                &task,
                &directory,
                &trames_vfs::PidNamespace::default(),
            )
            .unwrap();
        let (done, returned) = mpsc::channel();
        let e = epoch.clone();
        let worker = std::thread::spawn(move || done.send(e.take(0).is_none()).unwrap());
        entrance.recv_timeout(Duration::from_secs(2)).unwrap();
        match ending {
            0 => epoch.cancel(),
            1 => epoch.complete(),
            _ => epoch.fail(),
        }
        release.send(()).unwrap();
        let result = returned.recv_timeout(Duration::from_secs(1));
        epoch.cancel();
        if result.is_err() {
            epoch.add(job(99, &epoch));
        }
        worker.join().unwrap();
        assert_eq!(result, Ok(true), "ending={ending}");
        assert!(timers.next_deadline().is_none());
    }
}

#[test]
fn new_deadline_interrupts_native_host_wait_without_socket_traffic() {
    let (v, fd, _peer) = super::tests::tcp();
    let direct =
        trames_linux::DirectSyscalls::new(v.direct_descriptors()).with_network(v.direct_network());
    let (events, _) = mpsc::channel();
    let epoch = TestEpoch::with_events(Arc::new(Control::new(1000)), events, true);
    super::tests::tcp_wait(&epoch, &direct, fd, 1);
    let (done, returned) = mpsc::channel();
    let e = epoch.clone();
    let worker = std::thread::spawn(move || {
        done.send(e.take(0).map(|j| {
            let pid = j.work.pid;
            e.park(j, Some(WaitState::OwnerEvent));
            pid
        }))
        .unwrap()
    });
    super::tests::await_host_wait(&epoch);
    let mut sleeper = job(2, &epoch);
    sleeper.waiting = Some(WaitState::Sleep {
        deadline: Instant::now() + Duration::from_millis(5),
        remaining: 0,
    });
    epoch.add(sleeper);
    let result = returned.recv_timeout(Duration::from_secs(1));
    epoch.cancel();
    worker.join().unwrap();
    assert_eq!(result, Ok(Some(2)));
    let drained = epoch.drain();
    assert_eq!(drained.len(), 2);
    assert!(
        drained.iter().any(|j| j.pid == 1 && j.io.is_some()),
        "TCP wait lost its original pending call"
    );
}
