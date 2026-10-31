// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared event queue and watch admission. No inode/path/owner Rc lives here.
use super::*;
use crate::readiness::Readiness;
#[cfg(all(feature = "hostfs", unix))]
use std::collections::BTreeSet;
use std::sync::Mutex;

#[derive(Default)]
struct State {
    watches: BTreeMap<i32, u32>,
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    epoch: u64,
    #[cfg(all(feature = "hostfs", unix))]
    native_wds: BTreeSet<i32>,
    // Native vnode events coalesce. Remember guest events until the next drain
    // so the host echo does not duplicate an event already emitted by the VFS.
    #[cfg(all(feature = "hostfs", unix))]
    echoes: BTreeSet<(i32, u32, Vec<u8>)>,
}
#[derive(Default)]
pub(crate) struct Queue {
    state: Mutex<State>,
    pub(crate) readiness: Arc<Readiness>,
    #[cfg(all(feature = "hostfs", unix))]
    native: std::sync::OnceLock<Arc<hostfs::notify::Native>>,
}
impl Queue {
    fn change<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self.state.lock().unwrap();
        let before = state.epoch;
        let result = f(&mut state);
        let changed = state.epoch != before;
        drop(state);
        if changed {
            self.readiness.notify_locked();
        }
        result
    }
    pub(super) fn contains(&self, wd: i32) -> bool {
        self.state.lock().unwrap().watches.contains_key(&wd)
    }
    fn updated_mask(old: u32, mask: u32) -> Result<u32> {
        if mask & 0x10000000 != 0 {
            return Err(Errno(17));
        }
        Ok(if mask & 0x20000000 != 0 {
            old | mask
        } else {
            mask
        })
    }
    /// The deciding existence check and update share one queue transaction.
    /// A one-shot consumed by a worker must never be resurrected under its
    /// already-ignored watch descriptor by an add-watch racing with delivery.
    pub(super) fn update_watch(&self, wd: i32, mask: u32) -> Result<bool> {
        let mut state = self.state.lock().unwrap();
        let Some(old) = state.watches.get_mut(&wd) else {
            return Ok(false);
        };
        *old = Self::updated_mask(*old, mask)?;
        Ok(true)
    }
    pub(super) fn set_watch(&self, wd: i32, mask: u32) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(old) = state.watches.get_mut(&wd) {
            *old = Self::updated_mask(*old, mask)?;
        } else {
            state.watches.insert(wd, mask);
        }
        Ok(())
    }
    pub(crate) fn remove(&self, wd: i32) -> bool {
        let removed = self.change(|state| state.remove(wd));
        #[cfg(all(feature = "hostfs", unix))]
        if removed {
            self.retire_native(wd);
        }
        removed
    }
    #[cfg(all(feature = "hostfs", unix))]
    fn retire_native(&self, wd: i32) {
        let mut state = self.state.lock().unwrap();
        let registered = state.native_wds.remove(&wd);
        state.echoes.retain(|event| event.0 != wd);
        drop(state);
        // Closing a native backend can drop the last Source, which re-enters
        // watch retirement. The already-retired descriptor must not lock that
        // backend again while its source is being destroyed.
        if registered {
            if let Some(native) = self.native.get() {
                native.remove(wd);
            }
        }
    }
    pub(super) fn close(&self) {
        // Final OFD release retires registrations. Weak prepared caches and
        // queue-only capabilities cannot keep the instance active.
        let mut state = self.state.lock().unwrap();
        state.watches.clear();
        #[cfg(all(feature = "hostfs", unix))]
        {
            state.native_wds.clear();
            state.echoes.clear();
        }
        drop(state);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(native) = self.native.get() {
            native.close();
        }
    }
    pub(super) fn send(
        &self,
        wd: i32,
        mask: u32,
        cookie: u32,
        name: &[u8],
        unlinked: bool,
    ) -> bool {
        let alive = self.change(|state| {
            let Some(&watch) = state.watches.get(&wd) else {
                return false;
            };
            if mask & watch & ALL == 0 || unlinked && watch & 0x04000000 != 0 {
                return true;
            }
            #[cfg(all(feature = "hostfs", unix))]
            if state.native_wds.contains(&wd)
                && mask & hostfs::notify::NATIVE_MASK != 0
                && state.echoes.len() < MAX_EVENTS
            {
                state.echoes.insert((wd, mask & ALL, name.to_vec()));
            }
            state.push(wd, mask, cookie, name);
            if watch & 0x80000000 != 0 {
                state.remove(wd);
                false
            } else {
                true
            }
        });
        #[cfg(all(feature = "hostfs", unix))]
        if !alive {
            self.retire_native(wd);
        }
        alive
    }
    pub(crate) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        let subscription = self.readiness.subscribe(signal);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(fd) = self.native_fd() {
            return subscription.with_host(fd, signal);
        }
        subscription
    }
    pub(crate) fn has_native(&self) -> bool {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(native) = self.native.get() {
            return native.active();
        }
        false
    }
    #[cfg(all(feature = "hostfs", unix))]
    pub(crate) fn native_fd(&self) -> Option<std::os::fd::OwnedFd> {
        self.native
            .get()
            .and_then(|n| if n.active() { n.fd() } else { None })
    }
    #[cfg(all(feature = "hostfs", unix))]
    pub(super) fn attach_native(
        &self,
        wd: i32,
        host: &hostfs::HostFile,
        source: Arc<Source>,
        directory: bool,
    ) -> Result<()> {
        let mask = *self
            .state
            .lock()
            .unwrap()
            .watches
            .get(&wd)
            .ok_or(Errno(22))?;
        if mask & hostfs::notify::NATIVE_MASK == 0 {
            self.retire_native(wd);
            return Ok(());
        }
        if self.native.get().is_none() {
            let _ = self.native.set(Arc::new(hostfs::notify::Native::new()?));
        }
        self.native
            .get()
            .unwrap()
            .add(wd, host, source, directory, mask)?;
        let mut state = self.state.lock().unwrap();
        if state.watches.contains_key(&wd) {
            state.native_wds.insert(wd);
        } else {
            drop(state);
            self.native.get().unwrap().remove(wd);
        }
        Ok(())
    }
    fn pump_native(&self) {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(native) = self.native.get() {
            // Backend/source drops and scheduler callbacks never run under the
            // queue mutex. Native state is separate from guest queue state.
            let events = native.drain().unwrap_or_else(|_| {
                vec![hostfs::notify::Event {
                    wd: -1,
                    mask: 0x4000,
                    cookie: 0,
                    name: Vec::new(),
                }]
            });
            let retired = self.change(|state| {
                for event in events {
                    if event.wd == -1 {
                        state.push(-1, 0x4000, 0, b"");
                        continue;
                    }
                    if event.mask & IGNORED != 0 {
                        state.remove(event.wd);
                        continue;
                    }
                    let Some(&watch) = state.watches.get(&event.wd) else {
                        continue;
                    };
                    if event.mask & watch & ALL == 0 {
                        continue;
                    }
                    if state
                        .echoes
                        .contains(&(event.wd, event.mask & ALL, event.name.clone()))
                    {
                        continue;
                    }
                    state.push(event.wd, event.mask, event.cookie, &event.name);
                    if watch & 0x80000000 != 0 {
                        state.remove(event.wd);
                    }
                }
                state.echoes.clear();
                let retired: Vec<_> = state
                    .native_wds
                    .iter()
                    .filter(|wd| !state.watches.contains_key(wd))
                    .copied()
                    .collect();
                for wd in &retired {
                    state.native_wds.remove(wd);
                }
                retired
            });
            for wd in retired {
                native.remove(wd);
            }
        }
    }
    pub(crate) fn available(&self) -> usize {
        self.pump_native();
        self.state.lock().unwrap().bytes
    }
    pub(crate) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.pump_native();
        let state = self.state.lock().unwrap();
        (
            if state.bytes != 0 { events & 1 } else { 0 },
            [state.epoch, 0],
        )
    }
    pub(crate) fn read(&self, count: usize) -> Result<Vec<u8>> {
        self.pump_native();
        self.state.lock().unwrap().read(count)
    }
}
impl State {
    fn push(&mut self, wd: i32, mask: u32, cookie: u32, name: &[u8]) {
        let (wd, mask, cookie, name) = if self.queue.len() >= MAX_EVENTS {
            (-1, 0x4000, 0, b"".as_slice())
        } else {
            (wd, mask, cookie, name)
        };
        let len = if name.is_empty() {
            0
        } else {
            (name.len() + 1).next_multiple_of(16)
        };
        let mut bytes = Vec::with_capacity(16 + len);
        bytes.extend(wd.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
        bytes.extend(cookie.to_le_bytes());
        bytes.extend((len as u32).to_le_bytes());
        bytes.extend(name);
        bytes.resize(16 + len, 0);
        // Preserve adjacent-event coalescing and the single overflow record.
        if self.queue.back() == Some(&bytes) || self.queue.len() > MAX_EVENTS {
            return;
        }
        self.bytes += bytes.len();
        self.queue.push_back(bytes);
        self.epoch = self.epoch.wrapping_add(1);
    }
    fn remove(&mut self, wd: i32) -> bool {
        if self.watches.remove(&wd).is_none() {
            return false;
        }
        self.push(wd, IGNORED, 0, b"");
        true
    }
    fn read(&mut self, count: usize) -> Result<Vec<u8>> {
        let Some(first) = self.queue.front() else {
            return Err(Errno(11));
        };
        if count < first.len() {
            return Err(Errno(22));
        }
        let mut out = Vec::new();
        while self
            .queue
            .front()
            .is_some_and(|e| e.len() <= count - out.len())
        {
            let event = self.queue.pop_front().expect("front event");
            self.bytes -= event.len();
            out.extend(event);
        }
        Ok(out)
    }
}
