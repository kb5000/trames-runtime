// SPDX-License-Identifier: GPL-3.0-or-later
//! Imported poll requests retain shared OFDs; owner controls stay explicit.
use crate::state::Linux;
use std::sync::Arc;
use std::time::Instant;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{DirectFd, DirectFds, Errno, IoSignal, IoSubscription, OfdIdentity, Vfs};

#[derive(Clone)]
enum Source {
    Ignored,
    Invalid,
    Direct(DirectFd),
    Owner(OfdIdentity),
}
impl Source {
    fn owner(vfs: &Vfs, fd: u32) -> Self {
        vfs.open_description_identity(fd)
            .map_or(Self::Invalid, Self::Owner)
    }
    fn joined(vfs: &Vfs, fds: &DirectFds, fd: u32) -> Self {
        if let Some(resource) = fds.get(fd).filter(|fd| !fd.is_epoll()) {
            Self::Direct(resource)
        } else {
            Self::owner(vfs, fd)
        }
    }
}
#[derive(Clone)]
struct Entry {
    address: u64,
    fd: u32,
    events: u16,
    source: Source,
}
impl Entry {
    fn waits_for_stdin(&self, vfs: &Vfs) -> bool {
        matches!(&self.source, Source::Owner(id)
            if vfs.matches_open_description(self.fd, id)
                && vfs.fd_kind(self.fd).ok() == Some(trames_vfs::FdKind::Stdin))
    }
    fn ready(
        &self,
        joined: bool,
        owner: &mut impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<u16, Errno> {
        Ok(match &self.source {
            Source::Ignored => 0,
            Source::Invalid => 32,
            Source::Owner(id) => owner(self.fd, id, self.events)?,
            Source::Direct(fd) if joined && !fd.retains_ofd() => {
                owner(self.fd, &fd.ofd_identity(), self.events)?
            }
            Source::Direct(fd) => fd.poll_ready(self.events).expect("pollable resource"),
        })
    }
}
pub(crate) struct Poll {
    entries: Vec<Entry>,
}
/// The imported poll array and its accepted shared OFDs survive a checkpoint.
/// Cloning checkpoint metadata does not clone every descriptor or re-import
/// guest buffers. Owner-only controls are rebound at their joined boundary.
#[derive(Clone)]
pub struct RetainedPoll(Arc<Poll>);
struct SelectSet {
    address: u64,
    events: u16,
    entries: Vec<Entry>,
}
/// pselect stays owner-side, with the same accepted shared/OFD identities.
#[derive(Clone)]
pub struct RetainedSelect {
    sets: Arc<[SelectSet]>,
    size: usize,
}
pub type PollOutput = Vec<(u64, Vec<u8>)>;
impl Poll {
    pub fn prepare(
        fds: &DirectFds,
        memory: &impl CpuMemory,
        a: [u64; 6],
    ) -> Option<Result<Self, Errno>> {
        Self::prepare_inner(fds, None, memory, a)
    }
    fn prepare_inner(
        fds: &DirectFds,
        owner: Option<&Vfs>,
        memory: &impl CpuMemory,
        a: [u64; 6],
    ) -> Option<Result<Self, Errno>> {
        if a[1] > 256 {
            return Some(Err(Errno(22)));
        }
        if let Err(e) = Linux::check(memory, a[0], a[1] as usize * 8, Access::Write) {
            return Some(Err(e));
        }
        let mut entries = Vec::with_capacity(a[1] as usize);
        for i in 0..a[1] {
            let address = a[0] + i * 8;
            let bytes = match memory.read_array::<8>(address) {
                Ok(b) => b,
                Err(_) => return Some(Err(Errno(14))),
            };
            let fd = i32::from_le_bytes(bytes[..4].try_into().unwrap());
            let events = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
            let source = if fd < 0 {
                Source::Ignored
            } else if let Some(resource) = fds.get(fd as u32).filter(|fd| !fd.is_epoll()) {
                Source::Direct(resource)
            } else {
                Source::owner(owner?, fd as u32)
            };
            entries.push(Entry {
                address: address + 6,
                fd: fd as u32,
                events,
                source,
            });
        }
        Some(Ok(Self { entries }))
    }
    pub(crate) fn retain(self) -> RetainedPoll {
        RetainedPoll(Arc::new(self))
    }
    fn ready(
        &self,
        joined: bool,
        mut owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<Vec<(u64, u16)>, Errno> {
        self.entries
            .iter()
            .map(|entry| Ok((entry.address, entry.ready(joined, &mut owner)?)))
            .collect()
    }
    pub fn check(
        &self,
        memory: &mut impl CpuMemory,
        deadline: Option<Instant>,
    ) -> Result<u64, Errno> {
        let results = self.ready(false, |_, _, _| Err(Errno(95)))?;
        let count = results.iter().filter(|(_, ready)| *ready != 0).count() as u64;
        if count == 0 && !deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(11));
        }
        for (address, ready) in results {
            memory
                .write_array(address, ready.to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        Ok(count)
    }
    fn direct(&self) -> impl Iterator<Item = &DirectFd> {
        self.entries.iter().filter_map(|entry| match &entry.source {
            Source::Direct(fd) => Some(fd),
            _ => None,
        })
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.direct().flat_map(|fd| fd.subscribe(signal)).collect()
    }
    pub fn poll_identities(&self) -> Vec<usize> {
        self.direct().flat_map(|fd| fd.poll_identities()).collect()
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .iter()
            .filter_map(|entry| match &entry.source {
                Source::Direct(fd) if entry.events & 1 != 0 => fd.next_deadline(),
                _ => None,
            })
            .min()
    }
}
impl RetainedPoll {
    /// Query accepted descriptors, never re-import the guest poll buffer.
    pub fn waits_for_stdin(&self, vfs: &Vfs) -> bool {
        self.0
            .entries
            .iter()
            .any(|entry| entry.waits_for_stdin(vfs))
    }
    pub fn prepare_joined(
        vfs: &Vfs,
        memory: &impl CpuMemory,
        args: [u64; 6],
    ) -> Result<Self, Errno> {
        Poll::prepare_inner(&vfs.direct_descriptors(), Some(vfs), memory, args)
            .expect("joined poll has an owner fallback")
            .map(Poll::retain)
    }
    pub fn ready_joined(
        &self,
        owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<Vec<(u64, u16)>, Errno> {
        self.0.ready(true, owner)
    }
    pub fn supports_worker(&self, vfs: &Vfs) -> bool {
        self.0.entries.iter().all(|entry| match &entry.source {
            Source::Owner(id) => {
                vfs.matches_open_description(entry.fd, id) && vfs.uring(entry.fd).is_ok()
            }
            _ => true,
        })
    }
    pub fn owner_controls(&self) -> Vec<(u32, OfdIdentity)> {
        self.0
            .entries
            .iter()
            .filter_map(|entry| match &entry.source {
                Source::Owner(id) => Some((entry.fd, id.clone())),
                Source::Direct(fd) if !fd.retains_ofd() => Some((entry.fd, fd.ofd_identity())),
                _ => None,
            })
            .collect()
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        fds.shares_with(self.0.direct())
    }
    pub(crate) fn rearm(&self, fds: &DirectFds) -> Option<Self> {
        if self.0.entries.iter().all(|entry| match &entry.source {
            Source::Ignored | Source::Invalid => true,
            Source::Direct(fd) => fd.retains_ofd(),
            Source::Owner(_) => false,
        }) {
            return Some(self.clone());
        }
        let entries = self
            .0
            .entries
            .iter()
            .cloned()
            .map(|mut entry| {
                match &entry.source {
                    Source::Owner(id) => {
                        let fresh = fds
                            .get(entry.fd)
                            .filter(|fd| !fd.is_epoll() && &fd.ofd_identity() == id)?;
                        entry.source = Source::Direct(fresh);
                    }
                    Source::Direct(old) if !old.retains_ofd() => {
                        entry.source = fds
                            .get(entry.fd)
                            .filter(|fd| fd.ofd_identity() == old.ofd_identity())
                            .map_or(Source::Invalid, Source::Direct);
                    }
                    _ => {}
                }
                Some(entry)
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Poll { entries }.retain())
    }
    pub(crate) fn check(
        &self,
        memory: &mut impl CpuMemory,
        deadline: Option<Instant>,
    ) -> Result<u64, Errno> {
        self.0.check(memory, deadline)
    }
    pub(crate) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.0.subscribe(signal)
    }
    pub(crate) fn poll_identities(&self) -> Vec<usize> {
        self.0.poll_identities()
    }
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.0.next_deadline()
    }
}
impl RetainedSelect {
    /// Host input remains an event source even with no native socket or PTY.
    pub fn waits_for_stdin(&self, vfs: &Vfs) -> bool {
        self.sets
            .iter()
            .any(|set| set.entries.iter().any(|entry| entry.waits_for_stdin(vfs)))
    }
    pub fn prepare_joined(
        vfs: &Vfs,
        memory: &impl CpuMemory,
        args: [u64; 6],
    ) -> Result<Self, Errno> {
        if args[0] > 256 {
            return Err(Errno(22));
        }
        let size = args[0].div_ceil(64) as usize * 8;
        let fds = vfs.direct_descriptors();
        let mut sets = Vec::new();
        for (index, events) in [(1, 1), (2, 4), (3, 2)] {
            if args[index] == 0 {
                continue;
            }
            Linux::check(memory, args[index], size, Access::Write)?;
            let mut bits = vec![0; size];
            memory.read(args[index], &mut bits).map_err(|_| Errno(14))?;
            let entries = (0..args[0] as u32)
                .filter(|fd| bits[*fd as usize / 8] & (1 << (*fd % 8)) != 0)
                .map(|fd| Entry {
                    address: 0,
                    fd,
                    events,
                    source: Source::joined(vfs, &fds, fd),
                })
                .collect();
            sets.push(SelectSet {
                address: args[index],
                events,
                entries,
            });
        }
        Ok(Self {
            sets: sets.into(),
            size,
        })
    }
    pub fn ready_joined(
        &self,
        mut owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<(u64, PollOutput), Errno> {
        let mut count = 0;
        let mut outputs = Vec::with_capacity(self.sets.len());
        for set in self.sets.iter() {
            let mut result = vec![0; self.size];
            for entry in &set.entries {
                let ready = entry.ready(true, &mut owner)?;
                if ready & 32 != 0 {
                    return Err(Errno(9));
                }
                if ready & (set.events | 8 | 16) != 0 && set.events != 2 {
                    result[entry.fd as usize / 8] |= 1 << (entry.fd % 8);
                    count += 1;
                }
            }
            outputs.push((set.address, result));
        }
        Ok((count, outputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::DirectPoll;

    struct EpochPoll {
        id: usize,
        counter: DirectFd,
    }
    impl DirectPoll for EpochPoll {
        fn identity(&self) -> usize {
            self.id
        }
        fn poll(&self, events: u16) -> (u16, [u64; 2]) {
            self.counter.poll_state(events).unwrap()
        }
        fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
            self.counter.subscribe(signal).pop().unwrap()
        }
    }
    #[test]
    fn owner_poll_rebinds_epoch_capability_only_for_the_same_actual_ofd() {
        let mut v = Vfs::default();
        let (fd, ring) = v.uring_create(2, 4).unwrap();
        let mut counters = Vfs::default();
        let old_counter = counters.eventfd(0, 0).unwrap();
        let new_counter = counters.eventfd(1, 0).unwrap();
        let counter_caps = counters.direct_descriptors();
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1000, fd.to_le_bytes()).unwrap();
        m.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        let key = Rc::as_ptr(&ring) as usize;
        let old: Arc<dyn DirectPoll> = Arc::new(EpochPoll {
            id: 1,
            counter: counter_caps.get(old_counter).unwrap(),
        });
        let fresh: Arc<dyn DirectPoll> = Arc::new(EpochPoll {
            id: 2,
            counter: counter_caps.get(new_counter).unwrap(),
        });
        let before = v.direct_descriptors_with_polls(&BTreeMap::from([(key, old)]));
        let poll = Poll::prepare(&before, &m, [0x1000, 1, 0, 0, 0, 0])
            .unwrap()
            .unwrap()
            .retain();
        assert_eq!(poll.poll_identities(), [1]);
        assert_eq!(poll.check(&mut m, None), Err(Errno(11)));
        let after = v.direct_descriptors_with_polls(&BTreeMap::from([(key, fresh.clone())]));
        let resumed = poll.rearm(&after).unwrap();
        assert_eq!(resumed.poll_identities(), [2]);
        assert_eq!(resumed.check(&mut m, None), Ok(1));
        assert_eq!(poll.check(&mut m, None), Err(Errno(11)));
        let joined = RetainedPoll::prepare_joined(&v, &m, [0x1000, 1, 0, 0, 0, 0]).unwrap();
        assert!(joined.supports_worker(&v));
        let joined_rearmed = joined.rearm(&after).unwrap();
        assert_eq!(joined_rearmed.poll_identities(), [2]);
        assert_eq!(joined_rearmed.check(&mut m, None), Ok(1));

        // An independent VFS starts with the same numeric descriptor and local
        // counters. Its actual OFD must never satisfy the old weak identity.
        let mut unrelated = Vfs::default();
        let (other_fd, other_ring) = unrelated.uring_create(2, 4).unwrap();
        assert_eq!(fd, other_fd);
        let other = unrelated.direct_descriptors_with_polls(&BTreeMap::from([(
            Rc::as_ptr(&other_ring) as usize,
            fresh,
        )]));
        let invalid = poll.rearm(&other).unwrap();
        assert!(joined.rearm(&other).is_none());
        assert!(invalid.poll_identities().is_empty());
        assert_eq!(invalid.check(&mut m, None), Ok(1));
        assert_eq!(m.read_array::<2>(0x1006).unwrap(), 32u16.to_le_bytes());
    }
}
