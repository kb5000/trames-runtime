// SPDX-License-Identifier: GPL-3.0-or-later
//! The IPC namespace owns keys and IDs. IPC_RMID unlinks the key immediately;
//! attachments keep the original ID and sparse bytes until the last mm detaches.
use super::*;
use crate::sysv_ipc::{now, Permissions};
use std::sync::Mutex;
use trames_memory::{MemoryError, PageBacking, SegmentAttachment, SharedAnonymousPages, PAGE_SIZE};

pub(super) const MAX_SEGMENTS: u64 = 4096;
pub(super) const MAX_SIZE: u64 = u64::MAX - (1 << 24);
const SLOT_MASK: u32 = 32767;
#[derive(Default)]
pub(super) struct Segments(Mutex<Directory>);
#[derive(Default)]
struct Directory {
    next: u32,
    slots: BTreeMap<u32, Arc<Segment>>,
    keys: BTreeMap<i32, u32>,
    pages: u64,
}
struct Segment {
    id: u32,
    key: i32,
    size: u64,
    creator: u32,
    _creator_ref: Option<PidReference>,
    pages: SharedAnonymousPages,
    state: Mutex<State>,
}
struct State {
    perm: Permissions,
    removed: bool,
    attached: u64,
    pending: u64,
    changed: u64,
    atime: u64,
    dtime: u64,
    last: u32,
    last_ref: Option<PidReference>,
}
impl Directory {
    fn by_id(&self, id: u32) -> Result<&Arc<Segment>> {
        self.slots
            .get(&(id & SLOT_MASK))
            .filter(|s| s.id == id)
            .ok_or(Errno(22))
    }
    fn reap(&mut self, s: &Segment, state: &State) {
        if state.removed && state.attached == 0 && state.pending == 0 {
            self.slots.remove(&(s.id & SLOT_MASK));
            self.pages -= s.size.div_ceil(PAGE_SIZE);
        }
    }
}
pub struct Attachment {
    ns: Arc<linux_namespace::IpcNamespace>,
    segment: Arc<Segment>,
    pid_ns: PidNamespace,
    pid: std::sync::atomic::AtomicU32,
    active: bool,
}
impl Attachment {
    pub fn size(&self) -> u64 {
        self.segment.size
    }
    pub fn pages(&self) -> Vec<Arc<dyn PageBacking>> {
        self.segment
            .pages
            .mapping(self.size().div_ceil(PAGE_SIZE) as usize)
    }
    /// Publish once, after the mm has accepted the mapping. Dropping a pending
    /// attach releases its pin without changing the guest-visible timestamps.
    pub fn commit(mut self) -> Arc<Self> {
        let pid = self.pid.load(Ordering::Relaxed);
        let mut st = self.segment.state.lock().unwrap();
        st.pending -= 1;
        st.attached += 1;
        st.atime = now();
        st.last = pid;
        st.last_ref = self.pid_ns.retain(pid);
        drop(st);
        self.active = true;
        Arc::new(self)
    }
}
impl SegmentAttachment for Attachment {
    fn detached_by(&self, pid: u32) {
        self.pid.store(pid, Ordering::Relaxed);
    }
    fn fork(&self, pid: u32) -> Arc<dyn SegmentAttachment> {
        let pid = if pid == 0 {
            self.pid.load(Ordering::Relaxed)
        } else {
            pid
        };
        let mut st = self.segment.state.lock().unwrap();
        st.attached += 1;
        st.atime = now();
        st.last = pid;
        st.last_ref = self.pid_ns.retain(pid);
        Arc::new(Self {
            ns: self.ns.clone(),
            segment: self.segment.clone(),
            pid_ns: self.pid_ns.clone(),
            pid: pid.into(),
            active: true,
        })
    }
    fn page(&self, offset: u64) -> std::result::Result<Arc<dyn PageBacking>, MemoryError> {
        let index = offset / PAGE_SIZE;
        if index >= self.size().div_ceil(PAGE_SIZE) {
            return Err(MemoryError::InvalidRange);
        }
        self.segment
            .pages
            .page(index as usize)
            .ok_or(MemoryError::InvalidRange)
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        let mut dir = self.ns.shm.0.lock().unwrap();
        let mut st = self.segment.state.lock().unwrap();
        if self.active {
            st.attached -= 1;
            st.dtime = now();
            st.last = *self.pid.get_mut();
            st.last_ref = self.pid_ns.retain(st.last);
        } else {
            st.pending -= 1
        }
        dir.reap(&self.segment, &st);
    }
}
impl DescriptorFactory {
    pub fn shm_get(&self, key: i32, size: u64, flags: u32, pid: u32) -> Result<u32> {
        let ns = &self.ipc_namespace;
        let mut dir = ns.shm.0.lock().unwrap();
        if key != 0 {
            if let Some(&id) = dir.keys.get(&key) {
                if flags & 0x600 == 0x600 {
                    return Err(Errno(17));
                }
                let s = dir.by_id(id)?;
                if size > s.size {
                    return Err(Errno(22));
                }
                let bits = (flags | flags >> 3 | flags >> 6) & 7;
                if !s.state.lock().unwrap().perm.allowed(
                    &self.credentials,
                    bits,
                    &ns.user_namespace,
                ) {
                    return Err(Errno(13));
                }
                return Ok(id);
            }
            if flags & 0x200 == 0 {
                return Err(Errno(2));
            }
        }
        if !(1..=MAX_SIZE).contains(&size) {
            return Err(Errno(22));
        }
        if flags & 0o4000 != 0 {
            return Err(Errno(95));
        }
        let total = dir
            .pages
            .checked_add(size.div_ceil(PAGE_SIZE))
            .filter(|n| *n <= MAX_SIZE)
            .ok_or(Errno(28))?;
        if dir.slots.len() >= MAX_SEGMENTS as usize {
            return Err(Errno(28));
        }
        let id = loop {
            let id = dir.next;
            dir.next = (id + 1) & 0x7fff_ffff;
            if !dir.slots.contains_key(&(id & SLOT_MASK)) {
                break id;
            }
        };
        let s = Segment {
            id,
            key,
            size,
            creator: pid,
            _creator_ref: self.pid_namespace.retain(pid),
            pages: Default::default(),
            state: Mutex::new(State {
                perm: Permissions::new(&self.credentials, flags),
                removed: false,
                attached: 0,
                pending: 0,
                changed: now(),
                atime: 0,
                dtime: 0,
                last: 0,
                last_ref: None,
            }),
        };
        dir.slots.insert(id & SLOT_MASK, Arc::new(s));
        if key != 0 {
            dir.keys.insert(key, id);
        }
        dir.pages = total;
        Ok(id)
    }
    pub fn shm_attach(&self, id: u32, bits: u32, pid: u32) -> Result<Attachment> {
        let ns = &self.ipc_namespace;
        let dir = ns.shm.0.lock().unwrap();
        let segment = dir.by_id(id)?.clone();
        let mut st = segment.state.lock().unwrap();
        if !st.perm.allowed(&self.credentials, bits, &ns.user_namespace) {
            return Err(Errno(13));
        }
        st.pending += 1;
        drop(st);
        Ok(Attachment {
            ns: ns.clone(),
            segment,
            pid_ns: self.pid_namespace.clone(),
            pid: pid.into(),
            active: false,
        })
    }
    pub fn shm_control(
        &self,
        id: u32,
        cmd: u32,
        input: Option<&[u8; 112]>,
    ) -> Result<(u64, Vec<u8>)> {
        let ns = &self.ipc_namespace;
        let mut dir = ns.shm.0.lock().unwrap();
        if matches!(cmd, 3 | 14) {
            let last = dir.slots.keys().next_back().copied().unwrap_or(0);
            let fields = if cmd == 3 {
                vec![
                    MAX_SIZE,
                    1,
                    MAX_SEGMENTS,
                    MAX_SEGMENTS,
                    MAX_SIZE,
                    0,
                    0,
                    0,
                    0,
                ]
            } else {
                let rss = dir.slots.values().map(|s| s.pages.resident_pages()).sum();
                vec![dir.slots.len() as u64, dir.pages, rss, 0, 0, 0]
            };
            return Ok((
                last.into(),
                fields.into_iter().flat_map(u64::to_le_bytes).collect(),
            ));
        }
        let s = if matches!(cmd, 13 | 15) {
            dir.slots.get(&id).ok_or(Errno(22))?
        } else {
            dir.by_id(id)?
        }
        .clone();
        let c = &self.credentials;
        let mut st = s.state.lock().unwrap();
        match cmd {
            0 | 1 => {
                if !st.perm.controls(c, &ns.user_namespace) {
                    return Err(Errno(1));
                }
                if cmd == 0 {
                    if !st.removed && s.key != 0 {
                        dir.keys.remove(&s.key);
                    }
                    st.removed = true;
                    dir.reap(&s, &st);
                } else {
                    let b = input.ok_or(Errno(14))?;
                    let word = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
                    let uid = c.mapped_id(false, word(4))?;
                    let gid = c.mapped_id(true, word(8))?;
                    st.perm.uid = uid;
                    st.perm.gid = gid;
                    st.perm.mode = word(20) & 0o777;
                    st.changed = now();
                }
                Ok((0, vec![]))
            }
            2 | 13 | 15 => {
                if cmd != 15 && !st.perm.allowed(c, 4, &ns.user_namespace) {
                    return Err(Errno(13));
                }
                let mut out = vec![0; 112];
                for (i, val) in [
                    (0, if st.removed { 0 } else { s.key as u32 }),
                    (4, c.local_id(false, st.perm.uid)),
                    (8, c.local_id(true, st.perm.gid)),
                    (12, c.local_id(false, st.perm.cuid)),
                    (16, c.local_id(true, st.perm.cgid)),
                    (20, st.perm.mode | if st.removed { 0o1000 } else { 0 }),
                    (24, s.id >> 15),
                    (80, self.local_pid(s.creator)),
                    (84, self.local_pid(st.last)),
                ] {
                    out[i..i + 4].copy_from_slice(&val.to_le_bytes())
                }
                for (i, val) in [
                    (48, s.size),
                    (56, st.atime),
                    (64, st.dtime),
                    (72, st.changed),
                    (88, st.attached),
                ] {
                    out[i..i + 8].copy_from_slice(&val.to_le_bytes())
                }
                Ok((if cmd == 2 { 0 } else { s.id.into() }, out))
            }
            _ => Err(Errno(22)),
        }
    }
}
