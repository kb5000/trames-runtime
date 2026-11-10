// SPDX-License-Identifier: GPL-3.0-or-later
//! Native completion owns its unfinished graph; the kernel owner never polls it.
//! A busy context defers to its existing unlock notification, without blocking a
//! driver callback or creating another resource/service thread.
use super::{Inner, OwnedBackend};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, OnceLock, Weak,
};
use trames_shared::{IoSignal, IoSubscription, IoWake};

pub(super) struct Retirement {
    context: Arc<Inner>,
    pending: AtomicBool,
    running: AtomicU8,
    closing: AtomicBool,
    unlock: OnceLock<Registration>,
    completion: OnceLock<Registration>,
}
struct Registration {
    _wake: Arc<dyn IoWake>,
    _signal: Arc<IoSignal>,
    _subscription: IoSubscription,
}
struct Wake {
    retirement: Weak<Retirement>,
}
impl IoWake for Wake {
    fn wake_io(&self, signal: &Arc<IoSignal>) {
        signal.reset();
        if let Some(retirement) = self.retirement.upgrade() {
            // A normal caller may collect a completion itself, or a resumed
            // driver may change fence state. Unlock is an actual resource event.
            retirement.pending.store(true, Ordering::Relaxed);
            retirement.drain();
        }
    }
}
impl Retirement {
    fn acquire(context: &Arc<Inner>, closing: bool) -> Arc<Self> {
        let mut current = context.retirement.lock().unwrap();
        let retirement = current.get_or_insert_with(|| {
            let retirement = Arc::new(Self {
                context: context.clone(),
                pending: AtomicBool::new(true),
                running: AtomicU8::new(0),
                closing: AtomicBool::new(closing),
                unlock: OnceLock::new(),
                completion: OnceLock::new(),
            });
            let wake: Arc<dyn IoWake> = Arc::new(Wake {
                retirement: Arc::downgrade(&retirement),
            });
            let signal = IoSignal::new(0, Arc::downgrade(&wake));
            let subscription = context.available.subscribe(&signal);
            let _ = retirement.unlock.set(Registration {
                _wake: wake,
                _signal: signal,
                _subscription: subscription,
            });
            retirement
        });
        if closing {
            retirement.closing.store(true, Ordering::Relaxed);
        }
        retirement.pending.store(true, Ordering::Relaxed);
        retirement.clone()
    }
    fn bind_completion(self: &Arc<Self>, backend: &mut OwnedBackend) {
        self.completion.get_or_init(|| {
            let wake: Arc<dyn IoWake> = Arc::new(Wake {
                retirement: Arc::downgrade(self),
            });
            let signal = IoSignal::new(0, Arc::downgrade(&wake));
            let subscription = backend.0.subscribe_completion(&signal);
            Registration {
                _wake: wake,
                _signal: signal,
                _subscription: subscription,
            }
        });
    }
    pub(super) fn arm(context: &Arc<Inner>, backend: &mut OwnedBackend, closing: bool) {
        Self::acquire(context, closing).bind_completion(backend);
    }
    /// The original resource retains itself until its active lease unlocks.
    /// No CPU slot or host caller waits for an unrelated native invocation.
    pub(super) fn close(context: &Arc<Inner>) {
        Self::acquire(context, true).drain();
    }
    fn drain(self: &Arc<Self>) {
        if !self.pending.load(Ordering::Relaxed) {
            return;
        }
        // Notification state: 0 idle, 1 running, 2 notified. Release/acquire
        // belongs to this wake handshake, not ordinary guest-memory accesses.
        if self.running.swap(2, Ordering::AcqRel) != 0 {
            return;
        }
        loop {
            self.running.store(1, Ordering::Relaxed);
            if !self.pending.swap(false, Ordering::Relaxed) {
                if self
                    .running
                    .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return;
                }
                continue;
            }
            let mut backend = match self.context.backend.try_lock() {
                Ok(backend) => backend,
                Err(std::sync::TryLockError::WouldBlock) => {
                    self.pending.store(true, Ordering::Relaxed);
                    // A real unlock may already have notified this runner.
                    // Retry that event, otherwise return until an actual wake.
                    if self
                        .running
                        .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return;
                    }
                    continue;
                }
                Err(std::sync::TryLockError::Poisoned(_)) => panic!("GPU context poisoned"),
            };
            let mut current = self.context.retirement.lock().unwrap();
            if !current.as_ref().is_some_and(|r| Arc::ptr_eq(r, self)) {
                drop(current);
                drop(backend);
                self.running.store(0, Ordering::Release);
                self.context
                    .available
                    .notify_atomic_except(&self.unlock.get().unwrap()._signal);
                return;
            }
            self.bind_completion(&mut backend);
            let closing = self.closing.load(Ordering::Relaxed);
            if closing {
                backend.0.retire_jobs();
            }
            backend.0.reap_abandoned();
            let done = !backend.0.has_abandoned() && (!closing || backend.0.retirement_ready());
            let released = if done { current.take() } else { None };
            drop(current);
            drop(backend);
            // This lease also displaced normal native callers. Publish its
            // unlock; the running state coalesces reentrant resource callbacks.
            self.context
                .available
                .notify_atomic_except(&self.unlock.get().unwrap()._signal);
            // Break the temporary keepalive cycle outside both object locks.
            drop(released);
            if done {
                self.running.store(0, Ordering::Release);
                return;
            }
            if self
                .running
                .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}
