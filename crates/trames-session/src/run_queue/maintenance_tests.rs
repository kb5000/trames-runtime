// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_cpu::Cpu;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

struct Publication {
    epoch: Weak<Epoch<Cpu>>,
    timers: Option<Arc<trames_kernel::timers::Timers>>,
    observed: AtomicBool,
    changed: Arc<trames_shared::Readiness>,
}
impl Publication {
    fn check(&self) {
        let epoch = self.epoch.upgrade().unwrap();
        if let Some(timers) = &self.timers {
            assert!(
                timers.next_deadline().is_none(),
                "deadline already consumed"
            );
        }
        // This callback is the real interval after consuming the event source
        // and before publishing its result. A peer may acquire the queue here.
        let mut q = epoch.queues.lock().unwrap();
        q.idle_probe = q.idle_probe.wrapping_add(1);
        q.idle_notified = true;
        let observed = q.idle_probe;
        assert!(!epoch.close_idle(&mut q, observed, false));
        drop(q);
        self.observed.store(true, Ordering::Relaxed);
        epoch.control.close(crate::execution_control::End::Exited);
    }
}
impl trames_vfs::IoWake for Publication {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
        self.check();
    }
}
impl trames_shared::HostProtocol for Publication {
    fn identity(&self) -> usize {
        1
    }
    fn alive(&self) -> bool {
        true
    }
    fn changed(&self) -> Arc<trames_shared::Readiness> {
        self.changed.clone()
    }
    fn progress(&self, _: &Arc<trames_vfs::IoSignal>) -> std::io::Result<()> {
        self.check();
        Ok(())
    }
    fn interests(&self) -> std::io::Result<trames_shared::ProtocolInterests> {
        Ok((Vec::new(), None))
    }
}

#[test]
fn consumed_timer_remains_live_until_its_original_signal_callback_returns() {
    let epoch = Epoch::<Cpu>::new(Arc::new(Control::new(1000)));
    let timers = Arc::new(trames_kernel::timers::Timers::default());
    epoch.bind_timers(timers.clone());
    let directory = trames_kernel::signal::IoDirectory::default();
    let task = Arc::new(trames_kernel::signal::IoTask::default());
    directory.publish(&task, 42, 42, 42, 0, 0);
    let publication = Arc::new(Publication {
        epoch: Arc::downgrade(&epoch),
        timers: Some(timers.clone()),
        observed: AtomicBool::new(false),
        changed: Arc::default(),
    });
    let target: Arc<dyn trames_vfs::IoWake> = publication.clone();
    let signal = trames_vfs::IoSignal::new(42, Arc::downgrade(&target));
    task.set_wake(&signal);
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let namespace = trames_vfs::PidNamespace::default();
    let started = Instant::now() - Duration::from_secs(1);
    timers
        .call(
            107,
            [1, 0, 0x1000, 0, 0, 0],
            &mut memory,
            started,
            &task,
            &directory,
            &namespace,
        )
        .unwrap();
    let id = u32::from_le_bytes(memory.read_array::<4>(0x1000).unwrap());
    memory.write_array(0x1118, 1u64.to_le_bytes()).unwrap();
    // Absolute guest time 1ns is already past; no sleep or racing test thread.
    timers
        .call(
            110,
            [id as u64, 1, 0x1100, 0, 0, 0],
            &mut memory,
            started,
            &task,
            &directory,
            &namespace,
        )
        .unwrap();
    assert!(timers.due());
    assert!(epoch.take(0).is_none());
    assert!(publication.observed.load(Ordering::Relaxed));
    assert_eq!(epoch.queues.lock().unwrap().completing, 0);
    assert_eq!(
        epoch.control.end(),
        Some(crate::execution_control::End::Exited)
    );
}

#[test]
fn original_protocol_progress_remains_live_until_its_callback_returns() {
    let epoch = Epoch::<Cpu>::new(Arc::new(Control::new(1000)));
    let publication = Arc::new(Publication {
        epoch: Arc::downgrade(&epoch),
        timers: None,
        observed: AtomicBool::new(false),
        changed: Arc::default(),
    });
    let protocol: Arc<dyn trames_shared::HostProtocol> = publication.clone();
    trames_vfs::IoWake::register_protocol(epoch.as_ref(), protocol).unwrap();
    assert!(epoch.take(0).is_none());
    assert!(publication.observed.load(Ordering::Relaxed));
    assert_eq!(epoch.queues.lock().unwrap().completing, 0);
    assert_eq!(
        epoch.control.end(),
        Some(crate::execution_control::End::Exited)
    );
}
