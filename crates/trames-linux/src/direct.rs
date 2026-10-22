// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker-local syscalls on retained shared resources. All byte ABI helpers are
//! the original Linux implementations; only resource ownership differs.
use crate::state::Linux;
use std::cell::{Cell, RefCell};
use std::{
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use trames_memory::{Access, CpuMemory};
use trames_vfs::{DirectFds, Errno};
use trames_vfs::{IoSignal, IoSubscription, IoWake};

/// A stopped syscall, not a re-executed SVC. Subscriptions do not retain guest
/// FD table entries or count as additional pipe endpoints.
pub struct PendingIo {
    pub number: u32,
    pub args: [u64; 6],
    pub deadline: Option<Instant>,
    pub signal: Arc<IoSignal>,
    resource_deadline: Option<Instant>,
    poll: Option<crate::poll::Poll>,
    _subscriptions: Vec<IoSubscription>,
}
impl PendingIo {
    pub fn wake_deadline(&self) -> Option<Instant> {
        [self.deadline, self.resource_deadline]
            .into_iter()
            .flatten()
            .min()
    }
}
pub enum IoAttempt {
    Complete(Result<u64, Errno>),
    Blocked(PendingIo),
    Checkpoint,
}
/// Shared epoll ABI for both joined and worker-local implementations.
pub fn epoll_parameters(
    memory: &impl CpuMemory,
    number: u32,
    a: [u64; 6],
) -> Result<Option<Duration>, Errno> {
    epoll_buffer(memory, a)?;
    if number == 441 {
        if a[3] == 0 {
            return Ok(None);
        }
        let bytes = memory.read_array::<16>(a[3]).map_err(|_| Errno(14))?;
        let sec = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let ns = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
            return Err(Errno(22));
        }
        Ok(Some(Duration::new(sec, ns as u32)))
    } else {
        let ms = a[3] as i32;
        Ok((ms >= 0).then(|| Duration::from_millis(ms as u64)))
    }
}
fn epoll_buffer(memory: &impl CpuMemory, a: [u64; 6]) -> Result<(), Errno> {
    if a[2] == 0 || a[2] > (crate::MAX_WRITE / 16) as u64 {
        return Err(Errno(22));
    }
    Linux::check(memory, a[1], a[2] as usize * 16, Access::Write)
}
pub fn epoll_scatter(
    memory: &mut impl CpuMemory,
    address: u64,
    events: &[(u32, u64)],
) -> Result<u64, Errno> {
    for (i, (events, data)) in events.iter().enumerate() {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&events.to_le_bytes());
        bytes[8..].copy_from_slice(&data.to_le_bytes());
        memory
            .write_array(address + i as u64 * 16, bytes)
            .map_err(|_| Errno(14))?;
    }
    Ok(events.len() as u64)
}

#[derive(Default)]
pub struct DirectSyscalls {
    descriptors: DirectFds,
    files: trames_vfs::DirectFiles,
    disk_cache: RefCell<trames_vfs::DiskReadCache>,
    file_completed: Cell<u64>,
    socket_completed: Cell<u64>,
    timer_completed: Cell<u64>,
    poll_completed: Cell<u64>,
    started: Option<Instant>,
    scratch: RefCell<Vec<u8>>,
    completed: Cell<u64>,
}
impl DirectSyscalls {
    pub fn new(descriptors: DirectFds) -> Self {
        Self {
            descriptors,
            files: Default::default(),
            disk_cache: Default::default(),
            file_completed: Cell::new(0),
            socket_completed: Cell::new(0),
            timer_completed: Cell::new(0),
            poll_completed: Cell::new(0),
            started: None,
            scratch: RefCell::new(Vec::new()),
            completed: Cell::new(0),
        }
    }
    pub fn with_files(mut self, files: trames_vfs::DirectFiles) -> Self {
        self.files = files;
        self
    }
    pub fn file_completed(&self) -> u64 {
        self.file_completed.get()
    }
    pub fn socket_completed(&self) -> u64 {
        self.socket_completed.get()
    }
    pub fn timer_completed(&self) -> u64 {
        self.timer_completed.get()
    }
    pub fn poll_completed(&self) -> u64 {
        self.poll_completed.get()
    }
    pub fn with_clock(mut self, started: Instant) -> Self {
        self.started = Some(started);
        self
    }
    /// File deferral is before effects and uses the ordinary owner service.
    /// It is distinct from byte-resource blocking/pipe signal handling.
    pub fn invoke_file(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if !matches!(number, 62..=70 | 80) {
            return None;
        }
        let file = self.files.get(a[0] as u32)?;
        let deferred = Cell::new(false);
        let read = |count, offset| {
            file.read(count, offset, &mut self.disk_cache.borrow_mut())
                .unwrap_or_else(|| {
                    deferred.set(true);
                    Err(Errno(11))
                })
        };
        let write = |bytes: &[u8], offset| {
            file.write(bytes, offset, &mut self.disk_cache.borrow_mut())
                .unwrap_or_else(|| {
                    deferred.set(true);
                    Err(Errno(11))
                })
                .map(|n| n as u64)
        };
        let result = match number {
            62 => file.seek(a[1] as i64, a[2] as u32)?,
            63 => Linux::read_transport(a, memory, |count| read(count, None)),
            64 => Linux::write_transport(a, memory, &mut self.scratch.borrow_mut(), |bytes| {
                write(bytes, None)
            }),
            65 => Linux::readv_transport_mode(a, memory, false, |count| read(count, None)),
            66 => Linux::writev_transport_mode(
                a,
                memory,
                &mut self.scratch.borrow_mut(),
                false,
                |bytes| write(bytes, None),
            ),
            67 => Linux::read_transport(a, memory, |count| read(count, Some(a[3]))),
            68 => Linux::write_transport(a, memory, &mut self.scratch.borrow_mut(), |bytes| {
                write(bytes, Some(a[3]))
            }),
            69 | 70 => (|| {
                let (parts, total) = Linux::positioned_vector_parts(memory, a, number == 70)?;
                if number == 70 {
                    let mut scratch = self.scratch.borrow_mut();
                    Linux::gather_parts(memory, &parts, total, &mut scratch)?;
                    write(&scratch, Some(a[3]))
                } else {
                    let bytes = read(total, Some(a[3]))?;
                    Linux::scatter(memory, &parts, &bytes)?;
                    Ok(bytes.len() as u64)
                }
            })(),
            80 => (|| {
                let stat = file.stat()?;
                Linux::check(memory, a[1], 128, Access::Write)?;
                memory.write(a[1], &stat).map_err(|_| Errno(14))?;
                Ok(0)
            })(),
            _ => unreachable!(),
        };
        if deferred.get() {
            return None;
        }
        self.completed.set(self.completed.get() + 1);
        self.file_completed.set(self.file_completed.get() + 1);
        Some(result)
    }
    pub fn supports(&self, number: u32, fd: u32) -> bool {
        self.descriptors.get(fd).is_some_and(|fd| {
            if matches!(number, 22 | 441) {
                fd.is_epoll()
            } else if matches!(number, 86 | 87) {
                fd.timer().is_some()
            } else if matches!(number, 206 | 207 | 210..=212) {
                fd.is_unix()
            } else if number == 29 {
                fd.has_readable_bytes()
            } else {
                matches!(number, 63..=66) && !fd.is_epoll()
            }
        })
    }
    pub fn swap_disk_cache(&self, cache: &mut trames_vfs::DiskReadCache) {
        std::mem::swap(&mut *self.disk_cache.borrow_mut(), cache);
    }
    pub fn completed(&self) -> u64 {
        self.completed.get()
    }
    /// Move the persistent worker's bounded byte buffer into/out of a dispatch.
    /// No borrow or partially executed operation survives this ownership swap.
    pub fn swap_scratch(&self, buffer: &mut Vec<u8>) {
        std::mem::swap(&mut *self.scratch.borrow_mut(), buffer);
    }
    pub fn supports_call(&self, number: u32, args: [u64; 6]) -> bool {
        if number == 73 {
            return args[3] == 0;
        }
        self.supports(number, args[0] as u32)
            && (!matches!(number, 22 | 441) || args[4] == 0)
            && (number != 29 || args[1] as u32 == 0x541b)
    }
    fn transfer(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let fd = self
            .descriptors
            .get(args[0] as u32)
            .expect("retained resource");
        let deferred = Cell::new(false);
        let flags = socket_flags(number, args);
        let read = |count| {
            let result = if matches!(number, 207 | 212) {
                fd.recv(count, flags | if fd.nonblocking() { 0x40 } else { 0 })
            } else {
                fd.read_attempt(count)
            };
            result.unwrap_or_else(|| {
                deferred.set(true);
                Err(Errno(11))
            })
        };
        let write = |bytes: &[u8]| {
            if matches!(number, 206 | 211) {
                fd.send(bytes, flags)
            } else {
                fd.write(bytes)
            }
            .map(|n| n as u64)
        };
        let result = match number {
            86 | 87 => crate::timerfd_control(
                fd.timer().expect("timerfd resource"),
                number,
                args,
                memory,
                self.started.unwrap_or_else(Instant::now),
            ),
            29 => (|| {
                Linux::check(memory, args[2], 4, Access::Write)?;
                memory
                    .write_array(
                        args[2],
                        (fd.readable_bytes().min(i32::MAX as usize) as i32).to_le_bytes(),
                    )
                    .map_err(|_| Errno(14))?;
                Ok(0)
            })(),
            63 => Linux::read_transport(args, memory, read),
            64 => Linux::write_transport(args, memory, &mut self.scratch.borrow_mut(), |bytes| {
                write(bytes)
            }),
            65 => Linux::readv_transport_mode(args, memory, fd.is_eventfd(), read),
            66 => Linux::writev_transport_mode(
                args,
                memory,
                &mut self.scratch.borrow_mut(),
                fd.is_eventfd(),
                write,
            ),
            206 => crate::network::local::send(args, memory, &mut self.scratch.borrow_mut(), write),
            207 => crate::network::local::recv(args, memory, read),
            210 => fd.shutdown(args[1] as u32).map(|()| 0),
            211 | 212 => crate::network::local::message(
                number,
                args,
                memory,
                &mut self.scratch.borrow_mut(),
                read,
                write,
            )?,
            _ => unreachable!(),
        };
        if deferred.get() {
            None
        } else {
            Some(result)
        }
    }
    fn nonblocking(&self, number: u32, args: [u64; 6]) -> bool {
        self.descriptors.get(args[0] as u32).unwrap().nonblocking()
            || socket_flags(number, args) & 0x40 != 0
    }
    fn complete(&self, number: u32, args: [u64; 6], result: Result<u64, Errno>) -> IoAttempt {
        self.completed.set(self.completed.get() + 1);
        if number == 73 {
            self.poll_completed.set(self.poll_completed.get() + 1);
            return IoAttempt::Complete(result);
        }
        if self
            .descriptors
            .get(args[0] as u32)
            .is_some_and(|fd| fd.timer().is_some())
        {
            self.timer_completed.set(self.timer_completed.get() + 1);
        }
        if self
            .descriptors
            .get(args[0] as u32)
            .is_some_and(|fd| fd.is_unix())
        {
            self.socket_completed.set(self.socket_completed.get() + 1);
        }
        IoAttempt::Complete(result)
    }
    /// Subscribe before the deciding resource check. No notification can be lost
    /// between an EAGAIN result and publishing the parked task to its run queue.
    pub fn start(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        saved_deadline: Option<Instant>,
    ) -> Option<IoAttempt> {
        if !self.supports_call(number, args) {
            return None;
        }
        let mut poll = None;
        let deadline = if number == 73 {
            let deadline = match poll_deadline(memory, args[2], saved_deadline) {
                Ok(deadline) => deadline,
                Err(error) => return Some(self.complete(number, args, Err(error))),
            };
            let prepared = match crate::poll::Poll::prepare(&self.descriptors, memory, args) {
                Some(Ok(poll)) => poll,
                Some(Err(error)) => return Some(self.complete(number, args, Err(error))),
                None => return Some(IoAttempt::Checkpoint),
            };
            match prepared.check(memory, deadline) {
                Err(Errno(11)) => {}
                result => return Some(self.complete(number, args, result)),
            }
            poll = Some(prepared);
            deadline
        } else if matches!(number, 22 | 441) {
            match epoll_parameters(memory, number, args).and_then(|timeout| {
                if saved_deadline.is_some() {
                    Ok(saved_deadline)
                } else {
                    timeout
                        .map(|d| Instant::now().checked_add(d).ok_or(Errno(22)))
                        .transpose()
                }
            }) {
                Ok(deadline) => {
                    match self.epoll_once(args, deadline, memory) {
                        Err(Errno(11)) => {}
                        result => return Some(self.complete(number, args, result)),
                    }
                    deadline
                }
                Err(error) => return Some(self.complete(number, args, Err(error))),
            }
        } else {
            let Some(result) = self.transfer(number, args, memory) else {
                return Some(IoAttempt::Checkpoint);
            };
            match result {
                Err(Errno(11)) if !self.nonblocking(number, args) => {}
                Err(Errno(32)) if signals_pipe(number, args) => return Some(IoAttempt::Checkpoint),
                result => return Some(self.complete(number, args, result)),
            }
            None
        };
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = if let Some(poll) = &poll {
            poll.subscribe(&signal)
        } else {
            self.descriptors
                .get(args[0] as u32)
                .unwrap()
                .subscribe(&signal)
        };
        Some(self.resume(
            PendingIo {
                number,
                args,
                deadline,
                signal,
                poll,
                resource_deadline: None,
                _subscriptions: subscriptions,
            },
            memory,
        ))
    }
    fn epoll_once(
        &self,
        args: [u64; 6],
        deadline: Option<Instant>,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let events = self
            .descriptors
            .get(args[0] as u32)
            .unwrap()
            .epoll_wait(args[2] as usize)?;
        if events.is_empty() && !deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Errno(11));
        }
        epoll_scatter(memory, args[1], &events)
    }
    pub fn resume(&self, mut pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        pending.signal.reset();
        let result = if let Some(poll) = &pending.poll {
            poll.check(memory, pending.deadline)
        } else if matches!(pending.number, 22 | 441) {
            epoll_buffer(memory, pending.args)
                .and_then(|()| self.epoll_once(pending.args, pending.deadline, memory))
        } else {
            let Some(result) = self.transfer(pending.number, pending.args, memory) else {
                return IoAttempt::Checkpoint;
            };
            result
        };
        match result {
            Err(Errno(11)) => {
                pending.resource_deadline = if let Some(poll) = &pending.poll {
                    poll.next_deadline()
                } else {
                    self.descriptors
                        .get(pending.args[0] as u32)
                        .unwrap()
                        .next_deadline()
                };
                IoAttempt::Blocked(pending)
            }
            Err(Errno(32)) if signals_pipe(pending.number, pending.args) => IoAttempt::Checkpoint,
            result => self.complete(pending.number, pending.args, result),
        }
    }
    /// Legacy single-assignment entry. None means no effects and the caller must
    /// use its scheduling/signal path; completed transfers are never replayed.
    pub fn invoke(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if matches!(number, 22 | 441) || !self.supports_call(number, args) {
            return None;
        }
        if number == 73 {
            let result = match poll_deadline(memory, args[2], None) {
                Ok(deadline) => crate::poll::Poll::prepare(&self.descriptors, memory, args)?
                    .and_then(|p| p.check(memory, deadline)),
                Err(error) => Err(error),
            };
            if result == Err(Errno(11)) {
                return None;
            }
            self.complete(number, args, result);
            return Some(result);
        }
        match self.transfer(number, args, memory)? {
            Err(Errno(11)) if !self.nonblocking(number, args) => None,
            Err(Errno(32)) if signals_pipe(number, args) => None,
            result => {
                self.complete(number, args, result);
                Some(result)
            }
        }
    }
}

fn poll_deadline(
    memory: &impl CpuMemory,
    address: u64,
    saved: Option<Instant>,
) -> Result<Option<Instant>, Errno> {
    if address == 0 {
        return Ok(saved);
    }
    let timeout = crate::timer::duration(memory, address)?;
    if saved.is_some() {
        Ok(saved)
    } else {
        Instant::now()
            .checked_add(timeout)
            .map(Some)
            .ok_or(Errno(22))
    }
}

fn socket_flags(number: u32, args: [u64; 6]) -> u32 {
    match number {
        206 | 207 => args[3] as u32,
        211 | 212 => args[2] as u32,
        _ => 0,
    }
}
fn signals_pipe(number: u32, args: [u64; 6]) -> bool {
    matches!(number, 64 | 66)
        || matches!(number, 206 | 211) && socket_flags(number, args) & 0x4000 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::{Vfs, O_NONBLOCK};
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m
    }
    #[test]
    fn timer_control_preflights_outputs_and_keeps_relative_and_absolute_state() {
        let mut vfs = Vfs::default();
        let fd = vfs.timerfd(1, 0).unwrap();
        let started = Instant::now();
        let direct = DirectSyscalls::new(vfs.direct_descriptors()).with_clock(started);
        let mut m = memory();
        m.write_array(0x1110, 3600u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(86, [fd as u64, 0, 0x1100, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(87, [fd as u64, 0x1200, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert!(m.read_u64(0x1210).unwrap() >= 3599);
        assert_eq!(
            direct.invoke(86, [fd as u64, 0, 0x1100, 0x2000, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert!(vfs.timerfd_get(fd).unwrap().1.as_secs() >= 3599);
        assert_eq!(
            direct.invoke(86, [fd as u64, 2, 0x1100, 0, 0, 0], &mut m),
            Some(Err(Errno(95)))
        );
        assert_eq!(
            direct.invoke(86, [fd as u64, 1, 0x1100, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        let old_deadline = vfs.timerfd_resource(fd).unwrap().update(None).1;
        assert!(old_deadline.as_secs() >= 3599);
        vfs.timerfd_set(fd, Duration::ZERO, Some(Instant::now()))
            .unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1300, 7, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1300, 8, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(m.read_u64(0x1300).unwrap(), 1);
    }
    #[test]
    fn timer_rearm_and_disarm_refresh_a_parked_reads_resource_deadline() {
        let mut v = Vfs::default();
        let fd = v.timerfd(1, 0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let first = Instant::now() + Duration::from_secs(3600);
        v.timerfd_set(fd, Duration::ZERO, Some(first)).unwrap();
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(
                    63,
                    [fd as u64, 0x1100, 8, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert_eq!(wait.deadline, None);
        assert_eq!(wait.wake_deadline(), Some(first));
        let next = first + Duration::from_secs(3600);
        v.timerfd_set(fd, Duration::ZERO, Some(next)).unwrap();
        assert!(wait.signal.ready());
        let wait = pending(direct.resume(wait, &mut m));
        assert_eq!(wait.wake_deadline(), Some(next));
        v.timerfd_set(fd, Duration::ZERO, None).unwrap();
        assert!(wait.signal.ready());
        let wait = pending(direct.resume(wait, &mut m));
        assert_eq!(wait.wake_deadline(), None);
        drop(wait);
        assert_eq!(direct.timer_completed(), 0);
    }
    #[test]
    fn ppoll_mixed_resources_preflight_defer_and_preserve_timeout_and_mask_boundaries() {
        let mut v = Vfs::default();
        let [r, w] = v.pipe(0).unwrap();
        let event = v.eventfd(1, 0).unwrap();
        let [a, b] = v.socketpair(1, 1, 0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        for (i, fd) in [r, event, a, u32::MAX].into_iter().enumerate() {
            let at = 0x1100 + i as u64 * 8;
            m.write_array(at, fd.to_le_bytes()).unwrap();
            m.write_array(at + 4, 0xaabb0001u32.to_le_bytes()).unwrap();
        }
        v.write(w, b"p").unwrap();
        v.write(b, b"s").unwrap();
        let args = [0x1100, 4, 0, 0, 0, 0];
        assert_eq!(direct.invoke(73, args, &mut m), Some(Ok(3)));
        for i in 0..4 {
            assert_eq!(
                m.read_array::<2>(0x1106 + i * 8).unwrap(),
                (if i < 3 { 1u16 } else { 0 }).to_le_bytes()
            );
        }
        let before = m.read_array::<32>(0x1100).unwrap();
        m.write_array(0x1118, 999u32.to_le_bytes()).unwrap();
        assert_eq!(direct.invoke(73, args, &mut m), None);
        assert_eq!(m.read_array::<24>(0x1100).unwrap(), before[..24]);
        assert_eq!(
            direct.invoke(73, [0x1ffc, 1, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert!(!direct.supports_call(73, [0, 0, 0, 0x1200, 8, 0]));
        assert_eq!(
            direct.invoke(73, [0, 0, 0x1200, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(v.read(r, 1).unwrap(), b"p");
        assert_eq!(v.read(a, 1).unwrap(), b"s");
    }
    fn unix_message(memory: &mut Memory, control_size: u64) {
        for (address, value) in [
            (0x1010, 0x1080u64),
            (0x1018, 2),
            (0x1020, 0x1300),
            (0x1028, control_size),
            (0x1080, 0x1100),
            (0x1088, 2),
            (0x1090, 0x1102),
            (0x1098, 2),
        ] {
            memory.write_array(address, value.to_le_bytes()).unwrap();
        }
        memory.write(0x1100, b"abcd").unwrap();
    }
    #[test]
    fn unix_scalar_and_message_bytes_match_the_original_socket_abi() {
        for number in [206, 207, 211, 212] {
            for flags in [
                0,
                if matches!(number, 207 | 212) {
                    2
                } else {
                    0x4000
                },
            ] {
                let mut results = Vec::new();
                for worker in [false, true] {
                    let mut linux = Linux::new(0x10000);
                    let [fd, peer] = linux.vfs.socketpair(1, 1, 0).unwrap();
                    let mut m = memory();
                    let receive = matches!(number, 207 | 212);
                    unix_message(&mut m, if receive { 32 } else { 0 });
                    m.write_array(0x1260, 2u32.to_le_bytes()).unwrap();
                    if receive {
                        linux.vfs.write(peer, b"wxyz").unwrap();
                    }
                    let args = if number < 210 {
                        [
                            fd as u64,
                            0x1100,
                            4,
                            flags,
                            if receive { 0x1250 } else { 0 },
                            0x1260,
                        ]
                    } else {
                        [fd as u64, 0x1000, flags, 0, 0, 0]
                    };
                    let result = if worker {
                        let direct = DirectSyscalls::new(linux.vfs.direct_descriptors());
                        let result = direct.invoke(number, args, &mut m).expect("byte-only call");
                        assert_eq!(direct.socket_completed(), 1);
                        result
                    } else {
                        linux.network_syscall(number as u64, args, &mut m)
                    };
                    assert_eq!(result, Ok(4));
                    let queued = if receive {
                        linux.vfs.readable_bytes(fd).unwrap().unwrap() as u64
                    } else {
                        assert_eq!(linux.vfs.read(peer, 4).unwrap(), b"abcd");
                        0
                    };
                    results.push((m.read_array::<1024>(0x1000).unwrap(), queued));
                }
                assert_eq!(results[0], results[1], "number={number} flags={flags}");
            }
        }
    }
    #[test]
    fn unix_preflight_waitall_nonblocking_shutdown_and_sigpipe_keep_their_boundaries() {
        let mut vfs = Vfs::default();
        let [fd, peer] = vfs.socketpair(1, 1, 0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        unix_message(&mut m, 0);
        vfs.write(peer, b"ab").unwrap();
        m.write_array(0x1090, 0x2000u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(212, [fd as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.readable_bytes(fd).unwrap(), Some(2));
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x100, 0, 0], &mut m),
            None
        );
        assert_eq!(vfs.readable_bytes(fd).unwrap(), Some(2));
        assert_eq!(
            direct.invoke(29, [fd as u64, 0x541b, 0x1180, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(m.read_array::<4>(0x1180).unwrap(), 2u32.to_le_bytes());
        assert!(!direct.supports_call(29, [fd as u64, 0x1234, 0, 0, 0, 0]));
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x140, 0, 0], &mut m),
            Some(Ok(2))
        );
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x40, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
        assert_eq!(
            direct.invoke(210, [peer as u64, 1, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(207, [fd as u64, 0x1100, 4, 0x100, 0, 0], &mut m),
            Some(Ok(0))
        );
        vfs.close(peer).unwrap();
        assert_eq!(
            direct.invoke(206, [fd as u64, 0x1100, 1, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(
            direct.invoke(206, [fd as u64, 0x1100, 1, 0x4000, 0, 0], &mut m),
            Some(Err(Errno(32)))
        );
    }
    #[test]
    fn unix_message_rights_defer_before_bytes_and_use_the_original_owner_once() {
        let mut linux = Linux::new(0x10000);
        let [fd, peer] = linux.vfs.socketpair(1, 1, 0).unwrap();
        let [reader, writer] = linux.vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(linux.vfs.direct_descriptors());
        let mut m = memory();
        unix_message(&mut m, 24);
        m.write_array(0x1300, 20u64.to_le_bytes()).unwrap();
        m.write_array(0x1308, 1u32.to_le_bytes()).unwrap();
        m.write_array(0x130c, 1u32.to_le_bytes()).unwrap();
        m.write_array(0x1310, writer.to_le_bytes()).unwrap();
        let args = [fd as u64, 0x1000, 0, 0, 0, 0];
        assert_eq!(direct.invoke(211, args, &mut m), None);
        assert_eq!(linux.vfs.readable_bytes(peer).unwrap(), Some(0));
        let receive = [peer as u64, 0x1000, 0x40000000, 0, 0, 0];
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let pending = pending(
            direct
                .start(212, receive, &mut m, 7, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert_eq!(linux.network_syscall(211, args, &mut m), Ok(4));
        assert!(pending.signal.ready());
        assert!(matches!(
            direct.resume(pending, &mut m),
            IoAttempt::Checkpoint
        ));
        assert_eq!(linux.vfs.readable_bytes(peer).unwrap(), Some(4));
        assert_eq!(linux.network_syscall(212, receive, &mut m), Ok(4));
        let received = u32::from_le_bytes(m.read_array(0x1310).unwrap());
        assert_ne!(
            linux.vfs.flags(received).unwrap() & trames_vfs::O_CLOEXEC,
            0
        );
        linux.vfs.close(writer).unwrap();
        linux.vfs.write(received, b"still alive").unwrap();
        assert_eq!(linux.vfs.read(reader, 16).unwrap(), b"still alive");
        assert_eq!(direct.socket_completed(), 0);
    }
    #[test]
    fn file_scalar_vector_positioned_seek_and_stat_share_the_original_abi() {
        for number in 63..=70 {
            let mut vfs = Vfs::default();
            vfs.import_file(b"/data", b"abcdefgh".to_vec()).unwrap();
            let fd = vfs.open_at(trames_vfs::AT_FDCWD, b"/data", 2, 0).unwrap();
            let mut epoch = trames_vfs::FileEpoch::default();
            let direct =
                DirectSyscalls::new(vfs.direct_descriptors()).with_files(epoch.capture(&vfs, true));
            let mut m = memory();
            m.write(0x1100, b"1234").unwrap();
            for (address, value) in [(0x1000, 0x1100), (0x1008, 2), (0x1010, 0x1102), (0x1018, 2)] {
                m.write_array(address, (value as u64).to_le_bytes())
                    .unwrap();
            }
            let vector = matches!(number, 65 | 66 | 69 | 70);
            let args = [
                fd as u64,
                if vector { 0x1000 } else { 0x1100 },
                if vector { 2 } else { 4 },
                2,
                0,
                0,
            ];
            assert_eq!(direct.invoke_file(number, args, &mut m), Some(Ok(4)));
            assert_eq!(vfs.seek(fd, 0, 1).unwrap(), if number < 67 { 4 } else { 0 });
            if number % 2 == 0 {
                assert_eq!(
                    vfs.pread(fd, 8, 0).unwrap(),
                    if number < 67 {
                        b"1234efgh"
                    } else {
                        b"ab1234gh"
                    }
                );
            } else {
                assert_eq!(
                    m.read_array::<4>(0x1100).unwrap(),
                    if number < 67 { *b"abcd" } else { *b"cdef" }
                );
            }
            assert_eq!(
                direct.invoke_file(80, [fd as u64, 0x1200, 0, 0, 0, 0], &mut m),
                Some(Ok(0))
            );
            assert_eq!(
                m.read_array::<128>(0x1200).unwrap(),
                vfs.stat_fd(fd).unwrap()
            );
            assert_eq!(
                direct.invoke_file(62, [fd as u64, 0, 1, 0, 0, 0], &mut m),
                Some(Ok(if number < 67 { 4 } else { 0 }))
            );
            assert_eq!(direct.file_completed(), 3);
            epoch.finish();
        }
    }
    #[test]
    fn file_preflight_and_growth_deferral_never_consume_a_partial_vector() {
        let mut vfs = Vfs::default();
        vfs.import_file(b"/data", b"abcd".to_vec()).unwrap();
        let fd = vfs.open_at(trames_vfs::AT_FDCWD, b"/data", 2, 0).unwrap();
        let mut epoch = trames_vfs::FileEpoch::default();
        let direct =
            DirectSyscalls::new(vfs.direct_descriptors()).with_files(epoch.capture(&vfs, true));
        let mut m = memory();
        m.write(0x1100, b"12345678").unwrap();
        for (address, value) in [(0x1000, 0x1100), (0x1008, 2), (0x1010, 0x2000), (0x1018, 2)] {
            m.write_array(address, (value as u64).to_le_bytes())
                .unwrap();
        }
        assert_eq!(
            direct.invoke_file(70, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"abcd");
        assert_eq!(
            direct.invoke_file(64, [fd as u64, 0x1100, 8, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(vfs.seek(fd, 0, 1).unwrap(), 0);
        assert_eq!(vfs.pread(fd, 8, 0).unwrap(), b"abcd");
        assert_eq!(vfs.write(fd, b"12345678").unwrap(), 8);
        vfs.seek(fd, 0, 0).unwrap();
        assert_eq!(
            direct.invoke_file(63, [fd as u64, 0x1100, 8, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(m.read_array::<8>(0x1100).unwrap(), *b"12345678");
        assert_eq!(
            direct.invoke_file(67, [fd as u64, 0x2000, 8, u64::MAX, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke_file(69, [fd as u64, 0x2000, 2, u64::MAX, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        epoch.finish();
    }
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    fn pending(attempt: IoAttempt) -> PendingIo {
        match attempt {
            IoAttempt::Blocked(pending) => pending,
            _ => panic!("expected blocked I/O"),
        }
    }
    fn complete(attempt: IoAttempt) -> Result<u64, Errno> {
        match attempt {
            IoAttempt::Complete(result) => result,
            _ => panic!("expected completed I/O"),
        }
    }
    #[test]
    fn pipe_backpressure_rechecks_pipe_buf_and_broken_pipe_keeps_signal_path() {
        let mut vfs = Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let bytes = [42; 4096];
        while vfs.write(write, &bytes).is_ok() {}
        m.write(0x1000, &bytes).unwrap();
        let wait = pending(
            direct
                .start(
                    64,
                    [write as u64, 0x1000, 4096, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert_eq!(vfs.read(read, 1).unwrap(), [42]);
        assert!(wait.signal.ready());
        let wait = pending(direct.resume(wait, &mut m));
        assert!(!wait.signal.ready());
        assert_eq!(vfs.read(read, 4095).unwrap(), [42; 4095]);
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(4096));
        let wait = pending(
            direct
                .start(
                    64,
                    [write as u64, 0x1000, 4096, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        vfs.close(read).unwrap();
        assert!(wait.signal.ready());
        assert!(matches!(direct.resume(wait, &mut m), IoAttempt::Checkpoint));
        assert_eq!(direct.completed(), 1);
    }
    #[test]
    fn blocked_eventfd_writer_and_pipe_eof_resume_without_replaying_completed_transfers() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(0, 0).unwrap();
        vfs.write(event, &(u64::MAX - 1).to_le_bytes()).unwrap();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        m.write_array(0x1000, 1u64.to_le_bytes()).unwrap();
        let wait = pending(
            direct
                .start(
                    64,
                    [event as u64, 0x1000, 8, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        assert!(!wait.signal.ready());
        assert_eq!(vfs.read(event, 8).unwrap(), (u64::MAX - 1).to_le_bytes());
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(8));
        assert_eq!(vfs.read(event, 8).unwrap(), 1u64.to_le_bytes());
        let wait = pending(
            direct
                .start(
                    63,
                    [read as u64, 0x1000, 8, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        vfs.close(write).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(0));
        assert_eq!(direct.completed(), 2);
    }
    #[test]
    fn epoll_deadline_preflight_event_layout_and_no_temporary_mask_admission() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(0, 0).unwrap();
        let ep = vfs.epoll_create(0).unwrap();
        vfs.epoll_ctl(ep, 1, event, 0x40000001, 0x123456789abcdef0)
            .unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let args = [ep as u64, 0x1100, 1, 1000, 0, 0];
        let wait = pending(
            direct
                .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        let deadline = wait.deadline.unwrap();
        let wait = pending(direct.resume(wait, &mut m));
        assert_eq!(wait.deadline, Some(deadline));
        vfs.write(event, &1u64.to_le_bytes()).unwrap();
        assert!(wait.signal.ready());
        // Failed output validation must not consume ONESHOT.
        let mut bad = wait;
        bad.args[1] = 0x1ffc;
        assert_eq!(complete(direct.resume(bad, &mut m)), Err(Errno(14)));
        assert_eq!(
            complete(
                direct
                    .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(1)
        );
        assert_eq!(
            m.read_array::<16>(0x1100).unwrap(),
            [1, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]
        );
        let mut args = args;
        args[3] = 0;
        assert_eq!(
            complete(
                direct
                    .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(0)
        );
        args[4] = 0x1000;
        assert!(direct
            .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
            .is_none());
        args[4] = 0;
        m.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
        m.write_array(0x1008, 1_000_000_000u64.to_le_bytes())
            .unwrap();
        args[3] = 0x1000;
        assert_eq!(
            complete(
                direct
                    .start(441, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Err(Errno(22))
        );
        m.write_array(0x1008, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            complete(
                direct
                    .start(441, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
            ),
            Ok(0)
        );
    }
    #[test]
    fn blocking_and_sigpipe_defer_without_effects_or_retrying_completed_io() {
        let mut vfs = Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        assert_eq!(
            direct.invoke(63, [read as u64, 0x1000, 8, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(direct.completed(), 0);
        m.write(0x1000, b"hello").unwrap();
        assert_eq!(
            direct.invoke(64, [write as u64, 0x1000, 5, 0, 0, 0], &mut m),
            Some(Ok(5))
        );
        assert_eq!(vfs.read(read, 8).unwrap(), b"hello");
        vfs.close(read).unwrap();
        assert_eq!(
            direct.invoke(64, [write as u64, 0x1000, 5, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(direct.completed(), 1);
        vfs.set_status_flags(write, O_NONBLOCK).unwrap();
    }
    #[test]
    fn scalar_and_vector_preflight_does_not_consume_eventfd_or_pipe_bytes() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(7, O_NONBLOCK).unwrap();
        let [read, write] = vfs.pipe(O_NONBLOCK).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        assert_eq!(
            direct.invoke(63, [event as u64, 0x1ffc, 8, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.read(event, 8).unwrap(), 7u64.to_le_bytes());
        // Two readv destinations: the first is valid but the second is not.
        for (address, value) in [(0x1000, 0x1100), (0x1008, 4), (0x1010, 0x2000), (0x1018, 4)] {
            m.write_array(address, (value as u64).to_le_bytes())
                .unwrap();
        }
        vfs.write(write, b"abcdefgh").unwrap();
        assert_eq!(
            direct.invoke(65, [read as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.read(read, 8).unwrap(), b"abcdefgh");
        assert_eq!(
            direct.invoke(66, [write as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(vfs.read(read, 8), Err(Errno(11)));
        assert_eq!(
            direct.invoke(63, [read as u64, 0x1100, 8, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
    }
    #[test]
    fn vector_eventfd_obeys_record_sizes_and_commits_partial_progress_once() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let mut m = memory();
        for (address, value) in [(0x1000, 0x1100), (0x1008, 3), (0x1010, 0x1103), (0x1018, 5)] {
            m.write_array(address, (value as u64).to_le_bytes())
                .unwrap();
        }
        m.write_array(0x1100, 42u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(66, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(vfs.read(fd, 8), Err(Errno(11)));
        m.write_array(0x1008, 8u64.to_le_bytes()).unwrap();
        m.write_array(0x1010, 0x1108u64.to_le_bytes()).unwrap();
        m.write_array(0x1018, 8u64.to_le_bytes()).unwrap();
        m.write_array(0x1108, 1u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(66, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Ok(16))
        );
        m.write_array(0x1100, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Ok(8))
        );
        assert_eq!(m.read_u64(0x1100).unwrap(), 43);
        assert_eq!(m.read_u64(0x1108).unwrap(), 1);
        assert_eq!(
            direct.invoke(64, [fd as u64, 0x1100, 7, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(vfs.read(fd, 8), Err(Errno(11)));
    }
}
