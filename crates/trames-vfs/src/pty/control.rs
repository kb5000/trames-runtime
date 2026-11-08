// SPDX-License-Identifier: GPL-3.0-or-later
//! The original process controlling-terminal reference, shared by its threads
//! and retained query contexts. Metadata does not borrow another tty object.
use super::*;
use std::sync::{atomic::AtomicU32, Mutex};

/// Trusted terminal events address the original live process resources. The
/// route outlives any individual caller; a PTY never retains a task CPU.
pub trait TerminalSignals: Send + Sync {
    fn signal(&self, session: u32, group: u32, signal: u32);
    fn clear_session(&self, terminal: u32, session: u32);
    fn hangup(&self, terminal: u32, session: u32, group: u32);
}
pub trait TerminalTask: TerminalSignals {
    fn namespace(&self) -> &crate::PidNamespace;
    fn access(&self) -> TerminalAccess;
    fn ignored(&self, signal: u32) -> bool;
    fn orphaned(&self) -> bool;
    fn subscribe_job(&self, signal: &Arc<crate::IoSignal>) -> Option<crate::IoSubscription>;
    fn visible(&self, id: u32) -> u32;
    fn foreground(&self, session: u32, group: u32) -> Result<u32>;
    fn acquire(
        &self,
        terminal: &Arc<Pty>,
        steal: bool,
        readable: bool,
        automatic: bool,
    ) -> Result<()>;
    fn detach(&self, terminal: &Arc<Pty>, exiting: bool) -> Result<()>;
}

/// Stop/restart is scheduler state, never an invented guest EAGAIN result.
pub enum TerminalIo<T> {
    Complete(Result<T>),
    Stopped,
}

type Binding = (u32, Option<Arc<Pty>>);
type State = Option<Binding>;
pub struct ControllingTerminal {
    id: AtomicU32,
    state: Mutex<State>,
}
impl Default for ControllingTerminal {
    fn default() -> Self {
        Self {
            id: AtomicU32::new(u32::MAX),
            state: Mutex::default(),
        }
    }
}
pub struct ControllingGuard<'a> {
    source: &'a ControllingTerminal,
    state: Option<std::sync::MutexGuard<'a, State>>,
    retired: Vec<Binding>,
    changed: bool,
}
impl ControllingGuard<'_> {
    pub fn id(&self) -> Option<u32> {
        self.state.as_ref().unwrap().as_ref().map(|s| s.0)
    }
    pub fn replace(&mut self, value: Option<(u32, Option<Arc<Pty>>)>) {
        self.changed = true;
        if let Some(old) = std::mem::replace(&mut **self.state.as_mut().unwrap(), value) {
            self.retired.push(old);
        }
    }
}
impl Drop for ControllingGuard<'_> {
    fn drop(&mut self) {
        if self.changed {
            self.source
                .id
                .store(self.id().unwrap_or(u32::MAX), Ordering::Relaxed);
        }
        drop(self.state.take());
        // Actual retained terminal release happens outside its reference lock.
        self.retired.clear();
    }
}
impl ControllingTerminal {
    pub fn pair(&self) -> Option<Arc<Pty>> {
        self.state.lock().unwrap().as_ref()?.1.clone()
    }
    pub fn id(&self) -> Option<u32> {
        let id = self.id.load(Ordering::Relaxed);
        (id != u32::MAX).then_some(id)
    }
    pub(crate) fn fork(&self) -> Self {
        let state = self.state.lock().unwrap().clone();
        Self {
            id: AtomicU32::new(state.as_ref().map_or(u32::MAX, |s| s.0)),
            state: Mutex::new(state),
        }
    }
    pub fn lock(&self) -> ControllingGuard<'_> {
        ControllingGuard {
            source: self,
            state: Some(self.state.lock().unwrap()),
            retired: Vec::new(),
            changed: false,
        }
    }
    pub fn set(&self, terminal: Option<(u32, Option<Arc<Pty>>)>) {
        self.lock().replace(terminal);
    }
}
impl Vfs {
    pub fn terminal_task(&self) -> Option<Arc<dyn TerminalTask>> {
        self.terminal_task.get().cloned()
    }
    pub fn bind_terminal_task(&self, make: impl FnOnce() -> Arc<dyn TerminalTask>) {
        self.terminal_task.get_or_init(make);
    }
    pub fn controlling_terminal(&self) -> Option<u32> {
        self.controlling.get()?.id()
    }
    pub fn controlling_state(&self) -> Arc<ControllingTerminal> {
        self.controlling.get_or_init(Arc::default).clone()
    }
    pub fn share_controlling(&mut self, original: &Vfs) {
        self.controlling = std::sync::OnceLock::from(original.controlling_state());
    }
    pub fn inherit_controlling(&mut self, original: Option<&ControllingTerminal>) {
        let binding = original.and_then(|s| s.state.lock().unwrap().clone());
        self.controlling_state().set(binding);
    }
}
