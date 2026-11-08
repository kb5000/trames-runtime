// SPDX-License-Identifier: GPL-3.0-or-later
//! Original host launch resources. Existing execution/disk workers own progress;
//! accepted images and cancellation survive execution-cohort replacement.
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex, Weak,
};
use trames_shared::{IoSignal, IoSubscription, IoWake};

pub(super) enum Phase<C: Cpu> {
    Request(Box<trames_linux::HostSpawn>),
    Image(birth::HostChild<C>, exec::Preparation<C>),
    Published(
        u32,
        tasks::Handle<C>,
        Option<crate::run_queue::HostAdmission<C>>,
    ),
    Taken,
}
pub(super) struct Launch<C: Cpu> {
    pub process: Arc<trames_linux::HostProcess>,
    pub phase: Phase<C>,
    pub wait: Option<tasks::AdmissionWait>,
    _cancel: IoSubscription,
    pub signal: Arc<IoSignal>,
}
impl<C: Cpu> Launch<C> {
    fn ready(&self) -> bool {
        self.process.cancelled() || self.wait.as_ref().is_none_or(|wait| wait.signal.ready())
    }
}
struct State<C: Cpu> {
    pending: Vec<Launch<C>>,
    reader: Option<Weak<IoSignal>>,
}
pub(super) struct Launches<C: Cpu> {
    state: Mutex<State<C>>,
    count: AtomicUsize,
    owner: std::thread::Thread,
}
impl<C: Cpu> Default for Launches<C> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                pending: Vec::new(),
                reader: None,
            }),
            count: Default::default(),
            owner: std::thread::current(),
        }
    }
}
pub(super) struct Driver<C: Cpu> {
    source: Arc<Launches<C>>,
    pub signal: Arc<IoSignal>,
}
impl<C: Cpu> Drop for Driver<C> {
    fn drop(&mut self) {
        let mut state = self.source.state.lock().unwrap();
        if state
            .reader
            .as_ref()
            .is_some_and(|old| old.ptr_eq(&Arc::downgrade(&self.signal)))
        {
            state.reader = None;
            let ready = state.pending.iter().any(Launch::ready);
            drop(state);
            if ready {
                self.source.owner.unpark();
            }
        }
    }
}
impl<C: Cpu> Launches<C> {
    pub fn submit(self: &Arc<Self>, request: trames_linux::HostSpawn) {
        let target: Arc<dyn IoWake> = self.clone();
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        let cancel = request.process.subscribe(&signal);
        let launch = Launch {
            process: request.process.clone(),
            phase: Phase::Request(Box::new(request)),
            wait: None,
            _cancel: cancel,
            signal,
        };
        let mut state = self.state.lock().unwrap();
        self.count.fetch_add(1, Ordering::Relaxed);
        state.pending.push(launch);
        drop(state);
        self.notify();
    }
    pub fn pending(&self) -> bool {
        self.count.load(Ordering::Relaxed) != 0
    }
    pub fn bind(self: &Arc<Self>, signal: Arc<IoSignal>) -> Driver<C> {
        let mut state = self.state.lock().unwrap();
        state.reader = Some(Arc::downgrade(&signal));
        let ready = state.pending.iter().any(Launch::ready);
        drop(state);
        if ready {
            signal.notify();
        }
        Driver {
            source: self.clone(),
            signal,
        }
    }
    fn selected(state: &State<C>, signal: Option<&Arc<IoSignal>>) -> bool {
        let reader = state.reader.as_ref().and_then(Weak::upgrade);
        match (reader, signal) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(&a, b),
            _ => false,
        }
    }
    pub fn take(&self, signal: Option<&Arc<IoSignal>>) -> Vec<Launch<C>> {
        let mut state = self.state.lock().unwrap();
        if !Self::selected(&state, signal) {
            return Vec::new();
        }
        if let Some(signal) = signal {
            signal.reset();
        }
        let mut ready = Vec::new();
        let mut waiting = Vec::new();
        for launch in std::mem::take(&mut state.pending) {
            if launch.ready() {
                ready.push(launch)
            } else {
                waiting.push(launch)
            }
        }
        state.pending = waiting;
        ready
    }
    pub fn retain(&self, work: Vec<Launch<C>>) {
        let ready = work.iter().any(Launch::ready);
        self.state.lock().unwrap().pending.extend(work);
        if ready {
            self.notify();
        }
    }
    pub fn completed(&self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
    fn notify(&self) {
        let reader = self
            .state
            .lock()
            .unwrap()
            .reader
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(reader) = reader {
            reader.notify();
        } else {
            self.owner.unpark();
        }
    }
}
impl<C: Cpu> IoWake for Launches<C> {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.notify();
    }
}
impl<C: Cpu> Drop for Launches<C> {
    fn drop(&mut self) {
        for work in self.state.get_mut().unwrap().pending.drain(..) {
            if work.process.status() == trames_linux::HOST_RUNNING {
                work.process.fail(125);
            }
        }
    }
}
