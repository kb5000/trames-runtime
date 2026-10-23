// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared event queue and watch admission. No inode/path/owner Rc lives here.
use super::*;
use crate::readiness::Readiness;
use std::sync::Mutex;

#[derive(Default)]
struct State {
    watches: BTreeMap<i32, u32>,
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    epoch: u64,
}
#[derive(Default)]
pub(crate) struct Queue {
    state: Mutex<State>,
    pub(crate) readiness: Arc<Readiness>,
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
        self.change(|state| state.remove(wd))
    }
    pub(super) fn close(&self) {
        // Byte/poll snapshots are not inotify OFDs. They may retain the queue,
        // but must not keep registrations active after the last owner closes.
        self.state.lock().unwrap().watches.clear();
    }
    pub(super) fn send(
        &self,
        wd: i32,
        mask: u32,
        cookie: u32,
        name: &[u8],
        unlinked: bool,
    ) -> bool {
        self.change(|state| {
            let Some(&watch) = state.watches.get(&wd) else {
                return false;
            };
            if mask & watch & ALL == 0 || unlinked && watch & 0x04000000 != 0 {
                return true;
            }
            state.push(wd, mask, cookie, name);
            if watch & 0x80000000 != 0 {
                state.remove(wd);
                false
            } else {
                true
            }
        })
    }
    pub(crate) fn available(&self) -> usize {
        self.state.lock().unwrap().bytes
    }
    pub(crate) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let state = self.state.lock().unwrap();
        (
            if state.bytes != 0 { events & 1 } else { 0 },
            [state.epoch, 0],
        )
    }
    pub(crate) fn read(&self, count: usize) -> Result<Vec<u8>> {
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
