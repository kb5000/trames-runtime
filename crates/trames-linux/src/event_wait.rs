// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted event wait: original resources, copied sets/mask and deadline.
use crate::{
    direct,
    poll::{Poll, PollOutput},
    RetainedPoll, RetainedSelect,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use trames_memory::CpuMemory;
use trames_vfs::{
    DirectFd, DirectFds, DirectPoll, Errno, IoSignal, IoSubscription, OfdIdentity, Vfs,
};

#[derive(Clone)]
enum Sources {
    Poll(RetainedPoll),
    Select(RetainedSelect),
    Epoll(DirectFd),
}
impl Sources {
    fn dynamic(&self) -> bool {
        match self {
            Self::Poll(poll) => poll.dynamic_sources(),
            Self::Select(select) => select.dynamic_sources(),
            Self::Epoll(fd) => fd.dynamic_poll_sources(),
        }
    }
}
#[derive(Clone)]
pub struct RetainedWait {
    sources: Sources,
    pub number: u32,
    pub args: [u64; 6],
    pub deadline: Option<Instant>,
    pub mask: Option<u64>,
    remaining: u64,
    dynamic_sources: bool,
}
pub fn event_wait(number: u32) -> bool {
    matches!(number, 22 | 72 | 73 | 441)
}

pub fn wait_mask(
    memory: &impl CpuMemory,
    number: u32,
    args: [u64; 6],
) -> Result<Option<u64>, Errno> {
    let (pointer, length) = match number {
        72 if args[5] != 0 => (
            memory.read_u64(args[5]).map_err(|_| Errno(14))?,
            memory.read_u64(args[5] + 8).map_err(|_| Errno(14))?,
        ),
        72 => (0, 0),
        73 => (args[3], args[4]),
        22 | 441 => (args[4], args[5]),
        _ => return Ok(None),
    };
    if pointer == 0 {
        return Ok(None);
    }
    if length != 8 {
        return Err(Errno(22));
    }
    memory.read_u64(pointer).map(Some).map_err(|_| Errno(14))
}
impl RetainedWait {
    fn parameters(
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Result<(Option<Instant>, Option<u64>, u64), Errno> {
        let remaining = match number {
            72 => args[4],
            73 => args[2],
            _ => 0,
        };
        let duration = if matches!(number, 22 | 441) {
            direct::epoll_parameters(memory, number, args)?
        } else if remaining != 0 && saved.is_none() {
            let bytes = memory.read_array::<16>(remaining).map_err(|_| Errno(14))?;
            let sec = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let ns = u64::from_le_bytes(bytes[8..].try_into().unwrap());
            if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
                return Err(Errno(22));
            }
            Some(Duration::new(sec, ns as u32))
        } else {
            None
        };
        let deadline = if saved.is_some() {
            saved
        } else {
            duration
                .map(|d| Instant::now().checked_add(d).ok_or(Errno(22)))
                .transpose()?
        };
        Ok((deadline, wait_mask(memory, number, args)?, remaining))
    }
    pub fn prepare_worker(
        fds: &DirectFds,
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Option<Result<Self, Errno>> {
        let (deadline, mask, remaining) = match Self::parameters(memory, number, args, saved) {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        let sources = match number {
            73 => Sources::Poll(match Poll::prepare(fds, memory, args)? {
                Ok(p) => p.retain(),
                Err(e) => return Some(Err(e)),
            }),
            72 => Sources::Select(match RetainedSelect::prepare_worker(fds, memory, args)? {
                Ok(s) => s,
                Err(e) => return Some(Err(e)),
            }),
            22 | 441 => Sources::Epoll(match fds.epoll(args[0] as u32)? {
                Ok(fd) => fd,
                Err(error) => return Some(Err(error)),
            }),
            _ => return None,
        };
        Some(Ok(Self {
            dynamic_sources: sources.dynamic(),
            sources,
            number,
            args,
            deadline,
            mask,
            remaining,
        }))
    }
    pub fn prepare_joined(
        vfs: &Vfs,
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Option<Result<Self, Errno>> {
        if matches!(number, 22 | 441) {
            return Self::prepare_worker(&vfs.direct_descriptors(), memory, number, args, saved);
        }
        Some((|| {
            let (deadline, mask, remaining) = Self::parameters(memory, number, args, saved)?;
            let sources = if number == 73 {
                Sources::Poll(RetainedPoll::prepare_joined(vfs, memory, args)?)
            } else {
                Sources::Select(RetainedSelect::prepare_joined(vfs, memory, args)?)
            };
            Ok(Self {
                dynamic_sources: sources.dynamic(),
                sources,
                number,
                args,
                deadline,
                mask,
                remaining,
            })
        })())
    }
    pub fn output(
        &self,
        joined: bool,
        owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<(u64, PollOutput), Errno> {
        match &self.sources {
            Sources::Poll(p) => {
                let rows = p.ready(joined, owner)?;
                Ok((
                    rows.iter().filter(|(_, r)| *r != 0).count() as u64,
                    rows.into_iter()
                        .map(|(a, r)| (a, r.to_le_bytes().to_vec()))
                        .collect(),
                ))
            }
            Sources::Select(s) => s.ready(joined, owner),
            Sources::Epoll(fd) => {
                let events = fd.epoll_wait(self.args[2] as usize)?;
                let mut bytes = Vec::with_capacity(events.len() * 16);
                for (events, data) in &events {
                    bytes.extend(events.to_le_bytes());
                    bytes.extend(0u32.to_le_bytes());
                    bytes.extend(data.to_le_bytes());
                }
                Ok((events.len() as u64, vec![(self.args[1], bytes)]))
            }
        }
    }
    pub fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
    pub fn copy_output(
        &self,
        memory: &mut impl CpuMemory,
        count: u64,
        outputs: PollOutput,
    ) -> Result<u64, Errno> {
        if count == 0 && !self.expired() {
            return Err(Errno(11));
        }
        for (address, bytes) in outputs {
            memory.write(address, &bytes).map_err(|_| Errno(14))?;
        }
        Ok(count)
    }
    pub fn check(&self, memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        match &self.sources {
            Sources::Poll(p) => p.check(memory, self.deadline),
            Sources::Select(s) => {
                let (count, outputs) = s.ready(false, |_, _, _| Err(Errno(95)))?;
                self.copy_output(memory, count, outputs)
            }
            Sources::Epoll(fd) => {
                direct::epoll_buffer(memory, self.args)?;
                let events = fd.epoll_wait(self.args[2] as usize)?;
                if events.is_empty() && !self.expired() {
                    return Err(Errno(11));
                }
                direct::epoll_scatter(memory, self.args[1], &events)
            }
        }
    }
    pub fn finish(
        &self,
        memory: &mut impl CpuMemory,
        result: Result<u64, Errno>,
    ) -> Result<u64, Errno> {
        if self.remaining != 0 {
            if let Some(deadline) = self.deadline {
                let d = deadline.saturating_duration_since(Instant::now());
                // Linux's final raw timeout update is best effort. A timeout
                // unmapped/read-only after acceptance does not replace the
                // original readiness/EINTR result with a new guest error.
                let _ = memory.write_array(self.remaining, d.as_secs().to_le_bytes());
                let _ =
                    memory.write_array(self.remaining + 8, (d.subsec_nanos() as u64).to_le_bytes());
            }
        }
        result
    }
    pub fn rearm(self: &Arc<Self>, fds: &DirectFds) -> Option<Arc<Self>> {
        let sources = match &self.sources {
            Sources::Epoll(fd) => {
                let fresh = fd.refresh_epoll()?;
                if fresh.epoll_accepted_revision() == fd.epoll_accepted_revision() {
                    return Some(self.clone());
                }
                Sources::Epoll(fresh)
            }
            Sources::Poll(p) => {
                if p.fully_bound() && p.epoll_revision(true) == p.epoll_revision(false) {
                    return Some(self.clone());
                }
                Sources::Poll(p.rearm(fds)?)
            }
            Sources::Select(s) => {
                let next = s.rearm(fds)?;
                if s.same_capture(&next) {
                    return Some(self.clone());
                }
                Sources::Select(next)
            }
        };
        let mut wait = (**self).clone();
        wait.dynamic_sources = sources.dynamic();
        wait.sources = sources;
        Some(Arc::new(wait))
    }
    pub fn dynamic_sources(&self) -> bool {
        self.dynamic_sources
    }
    pub fn epoll_revision(&self) -> Option<u64> {
        match &self.sources {
            Sources::Epoll(fd) => fd.epoll_revision(),
            Sources::Poll(p) => p.epoll_revision(false),
            Sources::Select(s) => s.epoll_revision(false),
        }
    }
    pub fn epoll_accepted_revision(&self) -> Option<u64> {
        match &self.sources {
            Sources::Epoll(fd) => fd.epoll_accepted_revision(),
            Sources::Poll(p) => p.epoll_revision(true),
            Sources::Select(s) => s.epoll_revision(true),
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        match &self.sources {
            Sources::Poll(p) => p.subscribe(signal),
            Sources::Select(s) => s.subscribe(signal),
            Sources::Epoll(fd) => fd.subscribe(signal),
        }
    }
    pub fn poll_resources(&self) -> Vec<Arc<dyn DirectPoll>> {
        match &self.sources {
            Sources::Poll(p) => p.poll_resources(),
            Sources::Select(s) => s.poll_resources(),
            Sources::Epoll(fd) => fd.poll_resources(),
        }
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        match &self.sources {
            Sources::Poll(p) => p.next_deadline(),
            Sources::Select(s) => s.next_deadline(),
            Sources::Epoll(fd) => fd.next_deadline(),
        }
    }
    pub fn native_wait_fds(&self, vfs: &Vfs) -> Vec<trames_vfs::HostFd> {
        match &self.sources {
            Sources::Poll(p) => p.native_wait_fds(vfs),
            Sources::Select(s) => s.native_wait_fds(vfs),
            Sources::Epoll(fd) => fd.native_wait_fds(),
        }
    }
    pub fn supports_worker(&self, vfs: &Vfs) -> bool {
        match &self.sources {
            Sources::Poll(p) => p.supports_worker(vfs),
            Sources::Select(s) => s.supports_worker(),
            Sources::Epoll(_) => true,
        }
    }
    pub fn waits_for_stdin(&self, vfs: &Vfs) -> bool {
        match &self.sources {
            Sources::Poll(p) => p.waits_for_stdin(vfs),
            Sources::Select(s) => s.waits_for_stdin(vfs),
            Sources::Epoll(_) => false,
        }
    }
    pub fn owner_controls(&self) -> Vec<(u32, OfdIdentity)> {
        match &self.sources {
            Sources::Poll(p) => p.owner_controls(),
            Sources::Select(s) => s.owner_controls(),
            Sources::Epoll(_) => vec![],
        }
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        match &self.sources {
            Sources::Poll(p) => p.shares_resources(fds),
            Sources::Select(s) => s.shares_resources(fds),
            Sources::Epoll(fd) => fds.shares_with(std::iter::once(fd)),
        }
    }
}
