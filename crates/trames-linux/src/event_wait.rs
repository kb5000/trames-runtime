// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted event wait: original resources, copied sets/mask and deadline.
use crate::{
    direct,
    poll::{Poll, PollOutput},
    RetainedPoll, RetainedSelect,
};
use std::{
    sync::{Arc, Mutex},
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
    timeout_write: bool,
    dynamic_sources: bool,
    copy: Arc<Mutex<Copy>>,
}
#[derive(Default)]
struct Copy {
    native_mask: bool,
    mask_lease: Option<Arc<dyn trames_vfs::TemporaryMask>>,
    delivery: Option<trames_vfs::EpollDelivery>,
    blocked: Option<trames_vfs::EpollBlocked>,
    needs_owner: bool,
    count: Option<u64>,
    output: crate::copy_replay::Replay,
    copied: Option<Result<u64, Errno>>,
    result: Option<Result<u64, Errno>>,
    timeout: Option<crate::copy_replay::Replay>,
    timeout_done: bool,
}
pub fn event_wait(number: u32) -> bool {
    matches!(number, 22 | 72 | 73 | 441)
}

pub fn wait_mask(
    memory: &impl CpuMemory,
    number: u32,
    args: [u64; 6],
) -> Result<Option<u64>, Errno> {
    let (pointer, length) = mask_descriptor(memory, number, args)?;
    mask_value(memory, pointer, length)
}
pub(crate) fn mask_descriptor(
    memory: &impl CpuMemory,
    number: u32,
    args: [u64; 6],
) -> Result<(u64, u64), Errno> {
    let (pointer, length) = match number {
        72 if args[5] != 0 => (
            memory.read_u64(args[5]).map_err(|_| Errno(14))?,
            memory.read_u64(args[5] + 8).map_err(|_| Errno(14))?,
        ),
        72 => (0, 0),
        73 => (args[3], args[4]),
        22 | 441 => (args[4], args[5]),
        _ => return Ok((0, 0)),
    };
    Ok((pointer, length))
}
pub(crate) fn mask_value(
    memory: &impl CpuMemory,
    pointer: u64,
    length: u64,
) -> Result<Option<u64>, Errno> {
    if pointer == 0 {
        return Ok(None);
    }
    if length != 8 {
        return Err(Errno(22));
    }
    memory.read_u64(pointer).map(Some).map_err(|_| Errno(14))
}
impl RetainedWait {
    pub(crate) fn timeout(
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Result<(Option<Instant>, bool), Errno> {
        if saved.is_some() {
            return Ok((saved, Self::remaining(number, args) != 0));
        }
        let remaining = Self::remaining(number, args);
        let duration = if matches!(number, 22 | 441) {
            direct::epoll_timeout(memory, number, args)?
        } else if remaining != 0 {
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
        let write = Self::remaining(number, args) != 0
            && duration.is_some_and(|duration| !duration.is_zero());
        Ok((
            duration
                .map(|duration| Instant::now().checked_add(duration).ok_or(Errno(22)))
                .transpose()?,
            write,
        ))
    }
    pub(crate) fn remaining(number: u32, args: [u64; 6]) -> u64 {
        match number {
            72 => args[4],
            73 => args[2],
            _ => 0,
        }
    }
    fn parameters(
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Result<(Option<Instant>, Option<u64>, u64, bool), Errno> {
        let (pointer, length) = mask_descriptor(memory, number, args)?;
        let (deadline, timeout_write) = Self::timeout(memory, number, args, saved)?;
        let mask = mask_value(memory, pointer, length)?;
        if matches!(number, 22 | 441) {
            direct::epoll_buffer(memory, args)?;
        }
        Ok((deadline, mask, Self::remaining(number, args), timeout_write))
    }
    pub fn prepare_worker(
        fds: &DirectFds,
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Option<Result<Self, Errno>> {
        let parameters = match Self::parameters(memory, number, args, saved) {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        Self::prepare_parameters(fds, memory, number, args, parameters, None, None)
    }
    pub(crate) fn prepare_parameters(
        fds: &DirectFds,
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        parameters: (Option<Instant>, Option<u64>, u64, bool),
        owner: Option<&Vfs>,
        count: Option<u32>,
    ) -> Option<Result<Self, Errno>> {
        let (deadline, mask, remaining, timeout_write) = parameters;
        let sources = match number {
            73 => Sources::Poll(
                match if let Some(count) = count {
                    RetainedPoll::prepare_captured(fds, owner, memory, args, count)
                } else if let Some(vfs) = owner {
                    Some(RetainedPoll::prepare_joined(vfs, memory, args))
                } else {
                    Poll::prepare(fds, memory, args).map(|result| result.map(Poll::retain))
                }? {
                    Ok(p) => p,
                    Err(e) => return Some(Err(e)),
                },
            ),
            72 => Sources::Select(
                match if let Some(count) = count {
                    RetainedSelect::prepare_captured(fds, owner, memory, args, count)
                } else if let Some(vfs) = owner {
                    Some(RetainedSelect::prepare_joined(vfs, memory, args))
                } else {
                    RetainedSelect::prepare_worker(fds, memory, args)
                }? {
                    Ok(s) => s,
                    Err(e) => return Some(Err(e)),
                },
            ),
            22 | 441 => Sources::Epoll(match fds.epoll_original(args[0] as u32)? {
                Ok(fd) => fds.bind_poll(&fd).unwrap_or(fd),
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
            timeout_write,
            copy: Default::default(),
        }))
    }
    pub fn prepare_joined(
        vfs: &Vfs,
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Option<Result<Self, Errno>> {
        let parameters = match Self::parameters(memory, number, args, saved) {
            Ok(p) => p,
            Err(error) => return Some(Err(error)),
        };
        Self::prepare_parameters(
            &vfs.direct_descriptors(),
            memory,
            number,
            args,
            parameters,
            Some(vfs),
            None,
        )
    }
    pub(crate) fn final_error(
        number: u32,
        args: [u64; 6],
        parameters: (Option<Instant>, Option<u64>, u64, bool),
        error: Errno,
    ) -> Self {
        let (deadline, mask, remaining, timeout_write) = parameters;
        Self {
            sources: Sources::Poll(RetainedPoll::empty()),
            number,
            args,
            deadline,
            mask,
            remaining,
            timeout_write,
            dynamic_sources: false,
            copy: Arc::new(Mutex::new(Copy {
                result: Some(Err(error)),
                ..Default::default()
            })),
        }
    }
    pub(crate) fn attach_mask(&self, lease: Option<Arc<dyn trames_vfs::TemporaryMask>>) {
        let mut copy = self.copy.lock().unwrap();
        copy.native_mask = lease.is_some();
        copy.mask_lease = lease;
    }
    pub fn outer_mask(&self) -> Option<u64> {
        (!self.copy.lock().unwrap().native_mask)
            .then_some(self.mask)
            .flatten()
    }
    pub fn native_mask(&self) -> bool {
        self.copy.lock().unwrap().native_mask
    }
    /// Provider admission for this captured wait, before any output effects.
    /// Interests can still change; execution rechecks the original resources.
    pub fn fully_bound(&self) -> bool {
        match &self.sources {
            Sources::Poll(p) => p.fully_bound(),
            Sources::Select(s) => s.supports_worker(),
            Sources::Epoll(fd) => fd.epoll_accepted_revision().is_some(),
        }
    }
    pub fn output(
        &self,
        joined: bool,
        mut owner: impl FnMut(u32, &OfdIdentity, u16) -> Result<u16, Errno>,
    ) -> Result<(u64, PollOutput), Errno> {
        self.output_inner(
            joined,
            |fd, id, _, events| owner(fd, id, events),
            |delivery, max| delivery.prepare(max),
        )
    }
    fn output_owned(
        &self,
        vfs: &Vfs,
        pending: u64,
        mut special: impl FnMut(&trames_vfs::FdKind, u16) -> Result<Option<(u16, [u64; 2])>, Errno>,
    ) -> Result<(u64, PollOutput), Errno> {
        if matches!(&self.sources, Sources::Epoll(_)) {
            self.output_inner(
                true,
                |_, _, _, _| unreachable!("epoll has its original delivery"),
                |delivery, max| delivery.prepare_owned(max, vfs, pending, &mut special),
            )
        } else {
            self.output_inner(
                true,
                |_, _, file, events| vfs.poll_original(file, events, pending, &mut special),
                |delivery, max| delivery.prepare(max),
            )
        }
    }
    fn output_inner(
        &self,
        joined: bool,
        owner: impl FnMut(u32, &OfdIdentity, &trames_vfs::SharedFd, u16) -> Result<u16, Errno>,
        prepare: impl FnOnce(
            &mut trames_vfs::EpollDelivery,
            usize,
        ) -> Result<(), trames_vfs::EpollPrepareError>,
    ) -> Result<(u64, PollOutput), Errno> {
        let mut observations = trames_vfs::EpollObservations::default();
        let _previous_blocked;
        let mut copy = self.copy.lock().unwrap();
        if let Some(result) = copy.result {
            return result.map(|count| (count, Vec::new()));
        }
        if let Some(count) = copy.count {
            return Ok((count, Vec::new()));
        }
        _previous_blocked = copy.blocked.take();
        copy.needs_owner = false;
        match &self.sources {
            Sources::Poll(p) => p.observe_epolls(&mut observations),
            Sources::Select(s) => s.observe_epolls(&mut observations),
            Sources::Epoll(_) => {}
        }
        if let Err(blocked) = observations.admit() {
            copy.blocked = Some(blocked);
            return Err(Errno(11));
        }
        let ready = match &self.sources {
            Sources::Poll(p) => p.ready_with(joined, owner).map(|rows| {
                (
                    rows.iter().filter(|(_, r)| *r != 0).count() as u64,
                    rows.into_iter()
                        .map(|(a, r)| (a, r.to_le_bytes().to_vec()))
                        .collect(),
                )
            }),
            Sources::Select(s) => s.ready_with(joined, owner),
            Sources::Epoll(fd) => {
                if copy.delivery.is_none() {
                    copy.delivery = Some(fd.epoll_delivery()?);
                }
                let delivery = copy.delivery.as_mut().unwrap();
                if let Err(error) = prepare(delivery, direct::epoll_count(self.args)?) {
                    match error {
                        trames_vfs::EpollPrepareError::Blocked(blocked) => {
                            copy.blocked = Some(blocked);
                            return Err(Errno(11));
                        }
                        trames_vfs::EpollPrepareError::Owner => {
                            copy.needs_owner = true;
                            return Err(Errno(95));
                        }
                        trames_vfs::EpollPrepareError::Error(error) => return Err(error),
                    }
                }
                let mut outputs = Vec::with_capacity(delivery.len() * 2);
                for (i, (events, data)) in delivery.events().enumerate() {
                    let address = self.args[1] + i as u64 * 16;
                    outputs.push((address, events.to_le_bytes().to_vec()));
                    outputs.push((address + 8, data.to_le_bytes().to_vec()));
                }
                Ok((delivery.len() as u64, outputs))
            }
        };
        let (count, outputs) = match ready {
            Err(Errno(95)) => {
                copy.needs_owner = true;
                return Err(Errno(95));
            }
            result => result?,
        };
        if count != 0 || self.expired() {
            for (address, bytes) in &outputs {
                copy.output.capture(*address, bytes);
            }
            copy.count = Some(count);
            Ok((count, Vec::new()))
        } else {
            let delivery = copy.delivery.take();
            drop(copy);
            drop(delivery);
            Ok((count, outputs))
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
        let mut copy = self.copy.lock().unwrap();
        if let Some(result) = copy.result {
            return result;
        }
        if let Some(result) = copy.copied {
            return result;
        }
        if copy.count.is_none() && count == 0 && !self.expired() {
            return Err(Errno(11));
        }
        if copy.count.is_none() {
            for (address, bytes) in outputs {
                copy.output.capture(address, &bytes);
            }
            copy.count = Some(count);
        }
        let mut result = copy
            .output
            .progress(memory)
            .map(|()| copy.count.unwrap())
            .map_err(|_| Errno(14));
        let committed = copy.output.completed_writes() / 2;
        if let Some(delivery) = &mut copy.delivery {
            delivery.commit(committed);
            if result.is_err() && copy.output.fault.is_none() && committed != 0 {
                result = Ok(committed as u64);
            }
        }
        let delivery = if copy.output.fault.is_none() {
            copy.copied = Some(result);
            copy.delivery.take()
        } else {
            None
        };
        drop(copy);
        drop(delivery);
        result
    }
    pub fn check(&self, memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        let (count, outputs) = self.output(false, |_, _, _| Err(Errno(95)))?;
        self.copy_output(memory, count, outputs)
    }
    pub fn check_owned(
        &self,
        memory: &mut impl CpuMemory,
        vfs: &Vfs,
        pending: u64,
        special: impl FnMut(&trames_vfs::FdKind, u16) -> Result<Option<(u16, [u64; 2])>, Errno>,
    ) -> Result<u64, Errno> {
        let (count, output) = self.output_owned(vfs, pending, special)?;
        self.copy_output(memory, count, output)
    }
    pub(crate) fn needs_owner(&self) -> bool {
        self.copy.lock().unwrap().needs_owner
    }
    pub(crate) fn take_fault(&self) -> Option<trames_memory::PageFault> {
        let mut copy = self.copy.lock().unwrap();
        copy.output
            .fault
            .take()
            .or_else(|| copy.timeout.as_mut()?.fault.take())
    }
    pub(crate) fn output_started(&self) -> bool {
        let copy = self.copy.lock().unwrap();
        copy.count.is_some()
            || copy.result.is_some()
            || copy.delivery.is_some()
            || copy.blocked.is_some()
    }
    pub(crate) fn blocker(&self) -> Option<trames_vfs::EpollBlocked> {
        self.copy.lock().unwrap().blocked.clone()
    }
    pub fn finish(
        &self,
        memory: &mut impl CpuMemory,
        result: Result<u64, Errno>,
    ) -> Result<u64, Errno> {
        let mut copy = self.copy.lock().unwrap();
        let result = *copy.result.get_or_insert(result);
        if let Some(lease) = copy.mask_lease.take() {
            if result == Err(Errno(4)) {
                lease.interrupted();
            } else {
                lease.finish();
            }
        }
        if !copy.timeout_done && self.timeout_write {
            if let Some(deadline) = self.deadline {
                if copy.timeout.is_none() {
                    let d = deadline.saturating_duration_since(Instant::now());
                    let mut timeout = crate::copy_replay::Replay::default();
                    timeout.capture(self.remaining, &d.as_secs().to_le_bytes());
                    timeout.capture(self.remaining + 8, &(d.subsec_nanos() as u64).to_le_bytes());
                    copy.timeout = Some(timeout);
                }
                let timeout = copy.timeout.as_mut().unwrap();
                let _ = timeout.progress(memory);
                if timeout.fault.is_some() {
                    return Err(Errno(14));
                }
            }
        }
        // A permanent timeout-copy error is best effort. An asynchronous page
        // wait instead retains this original result and its accepted duration.
        copy.timeout_done = true;
        result
    }
    pub fn rearm(self: &Arc<Self>, fds: &DirectFds) -> Option<Arc<Self>> {
        if self.output_started() {
            return Some(self.clone());
        }
        let sources = match &self.sources {
            Sources::Epoll(fd) => {
                let fresh = fds.bind_poll(fd)?;
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
