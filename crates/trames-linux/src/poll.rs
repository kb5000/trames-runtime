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
}
#[derive(Clone)]
struct Entry {
    address: u64,
    fd: u32,
    events: u16,
    source: Source,
}
impl Entry {
    fn native_wait_fds(&self, vfs: &Vfs) -> Vec<trames_vfs::HostFd> {
        match &self.source {
            Source::Direct(fd) => fd.native_wait_fds(),
            Source::Owner(id) if vfs.matches_open_description(self.fd, id) => {
                vfs.native_wait_fds_for(self.fd)
            }
            _ => Vec::new(),
        }
    }
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
#[derive(Clone)]
pub(crate) struct Poll {
    entries: Vec<Entry>,
}
/// The imported poll array and its accepted shared OFDs survive a checkpoint.
/// Parking shares the enclosing RetainedWait; ready calls need no extra Arc
/// allocation around this poll array. Owner controls rebind at their boundary.
#[derive(Clone)]
pub struct RetainedPoll(Poll);
struct SelectSet {
    address: u64,
    events: u16,
    entries: Vec<Entry>,
}
/// Original pselect sets and OFDs, shared by worker and owner execution.
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
        RetainedPoll(self)
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
    pub fn poll_resources(&self) -> Vec<Arc<dyn trames_vfs::DirectPoll>> {
        self.direct().flat_map(|fd| fd.poll_resources()).collect()
    }
    #[cfg(test)]
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
    pub(crate) fn fully_retained(&self) -> bool {
        self.0.entries.iter().all(|entry| match &entry.source {
            Source::Ignored | Source::Invalid => true,
            Source::Direct(fd) => fd.retains_ofd(),
            Source::Owner(_) => false,
        })
    }
    pub fn native_wait_fds(&self, vfs: &Vfs) -> Vec<trames_vfs::HostFd> {
        self.0
            .entries
            .iter()
            .flat_map(|entry| entry.native_wait_fds(vfs))
            .collect()
    }
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
    pub(crate) fn ready(
        &self,
        joined: bool,
        owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<Vec<(u64, u16)>, Errno> {
        self.0.ready(joined, owner)
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
        if self.fully_retained() {
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
    pub(crate) fn poll_resources(&self) -> Vec<Arc<dyn trames_vfs::DirectPoll>> {
        self.0.poll_resources()
    }
    #[cfg(test)]
    pub(crate) fn poll_identities(&self) -> Vec<usize> {
        self.0.poll_identities()
    }
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.0.next_deadline()
    }
}
impl RetainedSelect {
    pub(crate) fn same_capture(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.sets, &other.sets)
    }
    pub fn native_wait_fds(&self, vfs: &Vfs) -> Vec<trames_vfs::HostFd> {
        self.sets
            .iter()
            .flat_map(|set| set.entries.iter())
            .flat_map(|entry| entry.native_wait_fds(vfs))
            .collect()
    }
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
        Self::prepare_inner(&vfs.direct_descriptors(), Some(vfs), memory, args)
            .expect("joined select has owner controls")
    }
    pub(crate) fn prepare_worker(
        fds: &DirectFds,
        memory: &impl CpuMemory,
        args: [u64; 6],
    ) -> Option<Result<Self, Errno>> {
        Self::prepare_inner(fds, None, memory, args)
    }
    fn prepare_inner(
        fds: &DirectFds,
        owner: Option<&Vfs>,
        memory: &impl CpuMemory,
        args: [u64; 6],
    ) -> Option<Result<Self, Errno>> {
        if args[0] > 256 {
            return Some(Err(Errno(22)));
        }
        let size = args[0].div_ceil(64) as usize * 8;
        let mut sets = Vec::new();
        for (index, events) in [(1, 1), (2, 4), (3, 2)] {
            if args[index] == 0 {
                continue;
            }
            if let Err(e) = Linux::check(memory, args[index], size, Access::Write) {
                return Some(Err(e));
            }
            let mut bits = vec![0; size];
            if memory.read(args[index], &mut bits).is_err() {
                return Some(Err(Errno(14)));
            }
            let mut entries = Vec::new();
            for fd in
                (0..args[0] as u32).filter(|fd| bits[*fd as usize / 8] & (1 << (*fd % 8)) != 0)
            {
                let source = if let Some(resource) = fds.get(fd).filter(|fd| !fd.is_epoll()) {
                    Source::Direct(resource)
                } else if let Some(vfs) = owner {
                    Source::owner(vfs, fd)
                } else if fds
                    .shared_files()
                    .is_some_and(|files| files.lookup(fd).is_some_and(|f| f.is_err()))
                {
                    Source::Invalid
                } else {
                    return None;
                };
                entries.push(Entry {
                    address: 0,
                    fd,
                    events,
                    source,
                });
            }
            sets.push(SelectSet {
                address: args[index],
                events,
                entries,
            });
        }
        Some(Ok(Self {
            sets: sets.into(),
            size,
        }))
    }
    fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.sets.iter().flat_map(|s| &s.entries)
    }
    fn direct(&self) -> impl Iterator<Item = &DirectFd> {
        self.entries().filter_map(|e| {
            if let Source::Direct(fd) = &e.source {
                Some(fd)
            } else {
                None
            }
        })
    }
    pub(crate) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.direct().flat_map(|fd| fd.subscribe(signal)).collect()
    }
    pub(crate) fn poll_resources(&self) -> Vec<Arc<dyn trames_vfs::DirectPoll>> {
        self.direct().flat_map(|fd| fd.poll_resources()).collect()
    }
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.entries()
            .filter(|e| e.events & 1 != 0)
            .filter_map(|e| {
                if let Source::Direct(fd) = &e.source {
                    fd.next_deadline()
                } else {
                    None
                }
            })
            .min()
    }
    pub(crate) fn supports_worker(&self) -> bool {
        self.entries().all(|e| {
            matches!(
                &e.source,
                Source::Direct(_) | Source::Invalid | Source::Ignored
            )
        })
    }
    pub(crate) fn owner_controls(&self) -> Vec<(u32, OfdIdentity)> {
        self.entries()
            .filter_map(|e| {
                if let Source::Owner(id) = &e.source {
                    Some((e.fd, id.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
    pub(crate) fn shares_resources(&self, fds: &DirectFds) -> bool {
        fds.shares_with(self.direct())
    }
    pub(crate) fn rearm(&self, fds: &DirectFds) -> Option<Self> {
        if self.entries().all(|e| {
            matches!(&e.source,Source::Direct(fd) if fd.retains_ofd())
                || matches!(e.source, Source::Invalid | Source::Ignored)
        }) {
            return Some(self.clone());
        }
        let sets = self
            .sets
            .iter()
            .map(|s| {
                let entries = s
                    .entries
                    .iter()
                    .cloned()
                    .map(|mut e| {
                        let id = match &e.source {
                            Source::Owner(id) => Some(id.clone()),
                            Source::Direct(fd) if !fd.retains_ofd() => Some(fd.ofd_identity()),
                            _ => None,
                        };
                        if let Some(id) = id {
                            e.source = Source::Direct(
                                fds.get(e.fd)
                                    .filter(|fd| !fd.is_epoll() && fd.ofd_identity() == id)?,
                            );
                        }
                        Some(e)
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(SelectSet {
                    address: s.address,
                    events: s.events,
                    entries,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            sets: sets.into(),
            size: self.size,
        })
    }
    pub fn ready_joined(
        &self,
        owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<(u64, PollOutput), Errno> {
        self.ready(true, owner)
    }
    pub(crate) fn ready(
        &self,
        joined: bool,
        mut owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<(u64, PollOutput), Errno> {
        let mut count = 0;
        let mut outputs = Vec::with_capacity(self.sets.len());
        for set in self.sets.iter() {
            let mut result = vec![0; self.size];
            for entry in &set.entries {
                let ready = entry.ready(joined, &mut owner)?;
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
    use trames_memory::{Memory, Permissions, PAGE_SIZE};

    #[test]
    fn accepted_poll_keeps_the_live_ring_across_captures_and_numeric_fd_replacement() {
        let mut v = Vfs::default();
        let (fd, ring) = v.uring_create(2, 4).unwrap();
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1000, fd.to_le_bytes()).unwrap();
        m.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        let key = Arc::as_ptr(&ring) as usize;
        let poll = Poll::prepare(&v.direct_descriptors(), &m, [0x1000, 1, 0, 0, 0, 0])
            .unwrap()
            .unwrap()
            .retain();
        assert_eq!(poll.poll_identities(), [key]);
        assert_eq!(poll.check(&mut m, None), Err(Errno(11)));
        let joined = RetainedPoll::prepare_joined(&v, &m, [0x1000, 1, 0, 0, 0, 0]).unwrap();
        assert!(joined.supports_worker(&v));
        let resumed = poll.rearm(&v.direct_descriptors()).unwrap();
        assert_eq!(resumed.poll_identities(), [key]);
        {
            let mut state = ring.state.lock().unwrap();
            state.overflow.push_back((1, 0, 0));
            ring.flush(&mut state).unwrap();
        }
        assert_eq!(poll.check(&mut m, None), Ok(1));
        assert_eq!(resumed.check(&mut m, None), Ok(1));
        let mut unrelated = Vfs::default();
        let (other_fd, other) = unrelated.uring_create(2, 4).unwrap();
        assert_eq!(fd, other_fd);
        let rearmed = joined.rearm(&unrelated.direct_descriptors()).unwrap();
        assert_eq!(rearmed.poll_identities(), [key]);
        assert_eq!(rearmed.check(&mut m, None), Ok(1));
        let fresh = Poll::prepare(&unrelated.direct_descriptors(), &m, [0x1000, 1, 0, 0, 0, 0])
            .unwrap()
            .unwrap();
        assert_eq!(fresh.poll_identities(), [Arc::as_ptr(&other) as usize]);
        assert_eq!(fresh.check(&mut m, None), Err(Errno(11)));
    }
}
