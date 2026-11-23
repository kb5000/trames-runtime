// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest memory barriers over original execution leases, never guest bytes.
use std::sync::{
    atomic::{fence, AtomicU32, AtomicUsize, Ordering},
    Arc, Mutex,
};
use trames_vfs::{Errno, IoSignal, IoSubscription, Readiness};

#[derive(Clone, Copy)]
pub(crate) enum Scope {
    Private,
    Global,
    RegisteredGlobal,
}
pub(crate) enum Action {
    Complete(u64),
    Fence(Scope),
}
pub(crate) const REGISTER_GLOBAL: u32 = 4;
pub(crate) const REGISTER_PRIVATE: u32 = 16;

pub(crate) fn prepare(registered: &AtomicU32, command: u64, flags: u64) -> Result<Action, Errno> {
    if flags as u32 != 0 {
        return Err(Errno(22));
    }
    match command as u32 {
        0 => Ok(Action::Complete(1 | 2 | 4 | 8 | 16 | 512)),
        command @ (REGISTER_GLOBAL | REGISTER_PRIVATE) => {
            registered.fetch_or(command, Ordering::Relaxed);
            Ok(Action::Complete(0))
        }
        512 => Ok(Action::Complete(registered.load(Ordering::Relaxed).into())),
        8 if registered.load(Ordering::Relaxed) & REGISTER_PRIVATE == 0 => Err(Errno(1)),
        8 => Ok(Action::Fence(Scope::Private)),
        2 => Ok(Action::Fence(Scope::RegisteredGlobal)),
        1 => Ok(Action::Fence(Scope::Global)),
        _ => Err(Errno(22)),
    }
}
/// The seed prevents early completion while the caller visits other domains.
/// Remaining acknowledgements retain only this request, never a task or View.
pub(crate) struct Request {
    remaining: AtomicUsize,
    changed: Arc<Readiness>,
}
impl Request {
    pub fn new() -> Arc<Self> {
        fence(Ordering::SeqCst);
        Arc::new(Self {
            remaining: AtomicUsize::new(1),
            changed: Arc::default(),
        })
    }
    pub fn add(&self) {
        self.remaining.fetch_add(1, Ordering::Relaxed);
    }
    pub fn acknowledge(&self) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.changed.notify_atomic();
        }
    }
    pub fn ready(&self) -> bool {
        self.remaining.load(Ordering::Acquire) == 0
    }
    pub fn finish(&self) -> Option<u64> {
        if !self.ready() {
            return None;
        }
        fence(Ordering::SeqCst);
        Some(0)
    }
}
pub(crate) struct Wait {
    pub request: Arc<Request>,
    subscription: Mutex<Option<IoSubscription>>,
}
impl Wait {
    pub fn new(request: Arc<Request>) -> Arc<Self> {
        Arc::new(Self {
            request,
            subscription: Mutex::default(),
        })
    }
    pub fn bind(&self, signal: &Arc<IoSignal>) {
        *self.subscription.lock().unwrap() = Some(self.request.changed.subscribe(signal));
    }
    pub fn ready(&self) -> bool {
        self.request.ready()
    }
    pub fn finish(&self) -> Option<u64> {
        self.request.finish()
    }
}
