// SPDX-License-Identifier: GPL-3.0-or-later
//! Resource notifications are shared with GPU/external completion sources.
pub(super) use trames_shared::Readiness;
pub use trames_shared::{IoSignal, IoSubscription, IoWake};

use crate::poll_mask;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// A proc table's change counter is shared by all opens. Each open file
/// description owns its cursor; dup shares it and a new open starts current.
#[derive(Default)]
pub(crate) struct ProcEvents {
    generation: AtomicU64,
    readiness: Arc<Readiness>,
}

impl ProcEvents {
    pub fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.readiness.notify_atomic();
    }
    pub fn watch(self: &Arc<Self>, normal: u16) -> Arc<ProcWatch> {
        Arc::new(ProcWatch {
            events: self.clone(),
            observed: AtomicU64::new(self.generation.load(Ordering::Relaxed)),
            normal,
        })
    }
}

pub(crate) struct ProcWatch {
    events: Arc<ProcEvents>,
    observed: AtomicU64,
    normal: u16,
}
impl ProcWatch {
    pub fn reopen(&self) -> Arc<Self> {
        self.events.watch(self.normal)
    }
    pub fn poll(&self, interest: u16) -> (u16, [u64; 2]) {
        let ready = self.peek(interest);
        self.acknowledge(ready.1[0]);
        ready
    }
    pub fn peek(&self, interest: u16) -> (u16, [u64; 2]) {
        let generation = self.events.generation.load(Ordering::Relaxed);
        let mask = if generation == self.observed.load(Ordering::Relaxed) {
            interest & self.normal
        } else {
            (interest & (poll_mask::READ_NORMAL | 2)) | 8
        };
        (mask, [generation, 0])
    }
    pub fn acknowledge(&self, generation: u64) {
        if self.observed.load(Ordering::Relaxed) < generation {
            self.observed.fetch_max(generation, Ordering::Relaxed);
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.events.readiness.subscribe(signal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DirectFd, Errno, Vfs};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Target {
        fd: Option<DirectFd>,
        calls: AtomicUsize,
    }
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            // Re-enter the same resource: callback must run after resource and
            // subscription unlock (including recursive readiness notification).
            if let Some(fd) = &self.fd {
                assert_eq!(fd.read(1).unwrap(), b"x");
            }
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn callbacks_run_after_unlock_and_subscription_drop_removes_listeners() {
        let mut vfs = Vfs::default();
        let [r, w] = vfs.pipe(0).unwrap();
        let fds = vfs.direct_descriptors();
        let target = Arc::new(Target {
            fd: Some(fds.get(r).unwrap().clone()),
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn IoWake> = target.clone();
        let signal = IoSignal::new(7, Arc::downgrade(&erased));
        let subs = fds.get(r).unwrap().subscribe(&signal);
        assert_eq!(fds.get(r).unwrap().read(1), Err(Errno(11)));
        assert_eq!(fds.get(w).unwrap().write(b"x"), Ok(1));
        assert_eq!(target.calls.load(Ordering::Relaxed), 1);
        assert!(signal.ready());
        drop(subs);
        signal.reset();
        assert_eq!(fds.get(w).unwrap().write(b"y"), Ok(1));
        assert!(!signal.ready());
        let source = Arc::new(Readiness::default());
        for _ in 0..1024 {
            drop(source.subscribe(&signal));
        }
        source.notify_atomic();
        assert!(!signal.ready());
    }
    #[test]
    fn atomic_subscribe_retry_observes_data_or_a_notification() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(0, 0).unwrap();
        let fd = vfs.direct_descriptors().get(event).unwrap().clone();
        let target = Arc::new(Target {
            fd: None,
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn IoWake> = target;
        let barrier = std::sync::Barrier::new(2);
        let mut missed = 0;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..4096 {
                    barrier.wait();
                    assert_eq!(fd.write(&1u64.to_le_bytes()), Ok(8));
                    barrier.wait();
                    barrier.wait();
                }
            });
            for _ in 0..4096 {
                barrier.wait();
                let signal = IoSignal::new(7, Arc::downgrade(&erased));
                let subs = fd.subscribe(&signal);
                let read = fd.read(8);
                barrier.wait();
                if read == Err(Errno(11)) {
                    missed += usize::from(!signal.ready());
                    assert_eq!(fd.read(8).unwrap(), 1u64.to_le_bytes());
                } else {
                    assert_eq!(read.unwrap(), 1u64.to_le_bytes());
                }
                drop(subs);
                barrier.wait();
            }
        });
        assert_eq!(missed, 0);
    }
}
