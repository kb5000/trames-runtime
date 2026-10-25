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
mod uring;
pub use uring::{UringEpoch, UringSnapshot};

fn tcp_wait_fd(tcp: &trames_net::DirectTcp) -> std::io::Result<trames_vfs::HostFd> {
    let (fd, lease) = tcp.readiness_fd()?;
    Ok(trames_vfs::HostFd::retained(fd, lease.into_keepalive()))
}

/// A stopped syscall, not a re-executed SVC. Subscriptions do not retain guest
/// FD table entries or count as additional pipe endpoints.
pub struct PendingIo {
    pub number: u32,
    pub args: [u64; 6],
    pub deadline: Option<Instant>,
    pub signal: Arc<IoSignal>,
    pub flock: Option<trames_vfs::FlockRequest>,
    pub retained_byte: Option<RetainedByte>,
    resource_deadline: Option<Instant>,
    poll: Option<crate::poll::Poll>,
    _subscriptions: Vec<IoSubscription>,
    host_subscription: Option<trames_vfs::HostSubscription>,
    uring: Option<Box<uring::Wait>>,
    poll_uring: Option<Box<uring::PollWait>>,
    target: Weak<dyn IoWake>,
}
/// Authority accepted for one byte syscall. The complete OFD lease, rather
/// than its numeric table slot or a copied pipe counter, owns the endpoint.
#[derive(Clone)]
pub struct RetainedByte {
    fd: trames_vfs::DirectFd,
}
impl PendingIo {
    pub fn external_wait(&self) -> bool {
        self.host_subscription.is_some()
            || self.uring.as_ref().is_some_and(|w| w.external())
            || self.poll_uring.as_ref().is_some_and(|w| w.external())
    }
    pub fn wake_deadline(&self) -> Option<Instant> {
        [self.deadline, self.resource_deadline]
            .into_iter()
            .flatten()
            .min()
    }
}
// Ready attempts must remain allocation-free. A parked PendingIo moves into an
// existing boxed task/job; boxing this variant would add a separate wait allocation.
#[allow(clippy::large_enum_variant)]
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
    urings: UringSnapshot,
    descriptors: DirectFds,
    network: trames_vfs::DirectNetwork,
    terminal: Option<trames_vfs::TerminalAccess>,
    kernel_log: Option<trames_vfs::KernelLogAccess>,
    files: trames_vfs::DirectFiles,
    membership: Option<trames_vfs::SharedFiles>,
    lock_context: Option<trames_vfs::RecordLockContext>,
    disk_cache: RefCell<trames_vfs::DiskReadCache>,
    file_completed: Cell<u64>,
    socket_completed: Cell<u64>,
    timer_completed: Cell<u64>,
    poll_completed: Cell<u64>,
    fd_control_completed: Cell<u64>,
    started: Option<Instant>,
    scratch: RefCell<Vec<u8>>,
    completed: Cell<u64>,
}
impl DirectSyscalls {
    pub fn new(descriptors: DirectFds) -> Self {
        let membership = descriptors.shared_files();
        Self {
            urings: Default::default(),
            descriptors,
            network: Default::default(),
            terminal: None,
            kernel_log: None,
            files: Default::default(),
            membership,
            lock_context: None,
            disk_cache: Default::default(),
            file_completed: Cell::new(0),
            socket_completed: Cell::new(0),
            timer_completed: Cell::new(0),
            poll_completed: Cell::new(0),
            fd_control_completed: Cell::new(0),
            started: None,
            scratch: RefCell::new(Vec::new()),
            completed: Cell::new(0),
        }
    }
    pub fn with_lock_context(mut self, context: trames_vfs::RecordLockContext) -> Self {
        self.lock_context = Some(context);
        self
    }
    pub fn with_files(mut self, files: trames_vfs::DirectFiles) -> Self {
        self.files = files;
        self
    }
    pub fn with_membership(mut self, files: trames_vfs::SharedFiles) -> Self {
        self.membership = Some(files);
        self
    }
    /// Only additions are admitted here. Removal/replacement waits for retained
    /// byte/poll requests and checkpoint handoff to preserve original OFDs.
    pub fn invoke_membership(&self, number: u32, args: [u64; 6]) -> Option<Result<u64, Errno>> {
        let files = self.membership.as_ref()?;
        let result = match number {
            23 => files.duplicate(args[0] as u32, 0, false),
            24 => files.duplicate_to_empty(args[0] as u32, args[1] as u32, args[2] as u32),
            25 if matches!(args[1], 0 | 1030) => {
                files.duplicate(args[0] as u32, args[2] as u32, args[1] == 1030)
            }
            _ => return None,
        }?;
        self.record_fd_control();
        Some(result.map(u64::from))
    }
    pub fn with_terminal(mut self, access: trames_vfs::TerminalAccess) -> Self {
        self.terminal = Some(access);
        self
    }
    pub fn with_kernel_log(mut self, log: trames_vfs::KernelLogAccess) -> Self {
        self.kernel_log = Some(log);
        self
    }
    pub fn with_network(mut self, network: trames_vfs::DirectNetwork) -> Self {
        self.network = network;
        self
    }
    pub fn with_urings(mut self, snapshot: UringSnapshot) -> Self {
        if let Some(descriptors) = &snapshot.descriptors {
            self.descriptors = descriptors.clone();
        }
        self.urings = snapshot;
        self
    }
    pub fn uring_completed(&self) -> u64 {
        self.urings.completed()
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
    pub fn fd_control_completed(&self) -> u64 {
        self.fd_control_completed.get()
    }
    pub fn record_fd_control(&self) {
        self.fd_control_completed
            .set(self.fd_control_completed.get() + 1);
    }
    pub fn with_clock(mut self, started: Instant) -> Self {
        self.started = Some(started);
        self.urings.clock = Some(started);
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
        // Legacy dispatch defers blocking flock before effects. In particular,
        // a failed conversion may already have released the old lock: it must
        // not be attempted speculatively and then replayed on fallback.
        if number == 32 && (a[1] as u32 & 4 != 0 || a[1] as u32 == 8) {
            let result = self.files.get(a[0] as u32)?.flock(a[1] as u32).map(|()| 0);
            self.record_fd_control();
            return Some(result);
        }
        if number == 25 && matches!(a[1], 5 | 6) {
            let context = self.lock_context.as_ref()?;
            let file = self.files.get(a[0] as u32)?;
            let result = if !file.allows_record_locks() {
                Err(Errno(9))
            } else {
                crate::record_locks::call(
                    memory,
                    a[1],
                    a[2],
                    |kind, whence, start, length| {
                        file.normalize_lock(kind, whence, start, length, context.owner)
                    },
                    |requested| Ok(file.record_lock_conflict(requested)),
                    |requested| file.record_lock_set(requested),
                    |owner| context.visible_pid(owner),
                )?
            };
            self.record_fd_control();
            return Some(result);
        }
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
        if self.network.get(fd).is_some() {
            return matches!(number, 63..=66);
        }
        self.descriptors.get(fd).is_some_and(|fd| {
            if number == 62 {
                fd.is_kmsg()
            } else if matches!(number, 22 | 441) {
                fd.is_epoll()
            } else if matches!(number, 86 | 87) {
                fd.timer().is_some()
            } else if number == 28 {
                fd.is_inotify()
            } else if matches!(number, 206 | 207 | 210..=212) {
                fd.is_unix()
            } else if number == 29 {
                fd.has_readable_bytes()
            } else {
                matches!(number, 63..=66) && !fd.is_epoll() && !fd.is_poll_only()
            }
        })
    }
    pub fn swap_disk_cache(&self, cache: &mut trames_vfs::DiskReadCache) {
        std::mem::swap(&mut *self.disk_cache.borrow_mut(), cache);
    }
    pub fn completed(&self) -> u64 {
        self.completed.get() + self.urings.completed()
    }
    /// Move the persistent worker's bounded byte buffer into/out of a dispatch.
    /// No borrow or partially executed operation survives this ownership swap.
    pub fn swap_scratch(&self, buffer: &mut Vec<u8>) {
        std::mem::swap(&mut *self.scratch.borrow_mut(), buffer);
    }
    pub fn supports_call(&self, number: u32, args: [u64; 6]) -> bool {
        if number == 116 {
            return self.kernel_log.is_some();
        }
        if number == 32 {
            return self.files.get(args[0] as u32).is_some();
        }
        if number == 426 {
            return self.urings.contains(args[0] as u32);
        }
        if number == 427 {
            return self.urings.supports_register(args);
        }
        if number == 73 {
            return args[3] == 0;
        }
        self.supports(number, args[0] as u32)
            && (!matches!(number, 22 | 441) || args[4] == 0)
            && (number != 29
                || args[1] as u32 == 0x541b
                || self
                    .descriptors
                    .get(args[0] as u32)
                    .is_some_and(|fd| fd.is_pty())
                    && matches!(args[1] as u32, 0x5401 | 0x5413))
    }
    fn transfer(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if number == 116 {
            return Some(crate::syslog(self.kernel_log.as_ref()?, args, memory));
        }
        if let Some(fd) = self.network.get(args[0] as u32) {
            let read = |count| {
                if fd.flags & trames_vfs::O_PATH != 0 || fd.flags & 3 == 1 {
                    return Err(Errno(9));
                }
                fd.tcp.recv(count, 0).map_err(|e| Errno(e.0))
            };
            let write = |bytes: &[u8]| {
                if fd.flags & trames_vfs::O_PATH != 0 || fd.flags & 3 == 0 {
                    return Err(Errno(9));
                }
                fd.tcp
                    .send(bytes, 0)
                    .map(|n| n as u64)
                    .map_err(|e| Errno(e.0))
            };
            return Some(match number {
                63 => Linux::read_transport(args, memory, read),
                64 => Linux::write_transport(args, memory, &mut self.scratch.borrow_mut(), write),
                65 => Linux::readv_transport_mode(args, memory, false, read),
                66 => Linux::writev_transport_mode(
                    args,
                    memory,
                    &mut self.scratch.borrow_mut(),
                    false,
                    write,
                ),
                _ => unreachable!("native TCP byte call"),
            });
        }
        let fd = self.descriptors.get(args[0] as u32)?;
        self.transfer_fd(&fd, number, args, memory)
    }
    fn transfer_fd(
        &self,
        fd: &trames_vfs::DirectFd,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let deferred = Cell::new(false);
        let flags = socket_flags(number, args);
        let read = |count| {
            let result = if fd.is_pty() {
                fd.terminal_read(count, self.terminal)
            } else if matches!(number, 207 | 212) {
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
            let result = if fd.is_pty() {
                fd.terminal_write(bytes, self.terminal)
            } else if matches!(number, 206 | 211) {
                Some(fd.send(bytes, flags))
            } else {
                Some(fd.write(bytes))
            };
            result
                .unwrap_or_else(|| {
                    deferred.set(true);
                    Err(Errno(11))
                })
                .map(|n| n as u64)
        };
        let result = match number {
            62 => fd.kmsg_seek(args[1] as i64, args[2] as u32),
            28 => fd.inotify_remove(args[1] as i32),
            86 | 87 => crate::timerfd_control(
                fd.timer().expect("timerfd resource"),
                number,
                args,
                memory,
                self.started.unwrap_or_else(Instant::now),
            ),
            29 => (|| {
                if args[1] as u32 != 0x541b {
                    let bytes = fd.terminal_query(args[1] as u32).expect("terminal query");
                    Linux::check(memory, args[2], bytes.len(), Access::Write)?;
                    memory.write(args[2], &bytes).map_err(|_| Errno(14))?;
                    return Ok(0);
                }
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
            65 => Linux::readv_transport_mode(args, memory, fd.readv_records(), read),
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
        if number == 116 {
            return false;
        }
        if let Some(fd) = self.network.get(args[0] as u32) {
            return fd.nonblocking();
        }
        self.descriptors.get(args[0] as u32).unwrap().nonblocking()
            || socket_flags(number, args) & 0x40 != 0
    }
    fn complete(&self, number: u32, args: [u64; 6], result: Result<u64, Errno>) -> IoAttempt {
        self.completed.set(self.completed.get() + 1);
        if matches!(number, 28 | 32) {
            self.record_fd_control();
        }
        if matches!(number, 32 | 116) {
            return IoAttempt::Complete(result);
        }
        if matches!(number, 22 | 73 | 441) {
            self.poll_completed.set(self.poll_completed.get() + 1);
            return IoAttempt::Complete(result);
        }
        let fd = self.descriptors.get(args[0] as u32);
        if fd.as_ref().is_some_and(|fd| fd.timer().is_some()) {
            self.timer_completed.set(self.timer_completed.get() + 1);
        }
        if fd.as_ref().is_some_and(|fd| fd.is_unix()) || self.network.get(args[0] as u32).is_some()
        {
            self.socket_completed.set(self.socket_completed.get() + 1);
        }
        IoAttempt::Complete(result)
    }
    fn complete_byte(&self, result: Result<u64, Errno>) -> IoAttempt {
        // Accepted shared pipe calls already own their complete authority.
        // Accounting must not re-resolve the numeric FD after close/reuse.
        self.completed.set(self.completed.get() + 1);
        IoAttempt::Complete(result)
    }
    fn complete_pending(&self, pending: &PendingIo, result: Result<u64, Errno>) -> IoAttempt {
        if pending.retained_byte.is_some() {
            self.complete_byte(result)
        } else {
            self.complete(pending.number, pending.args, result)
        }
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
        if let Some(file) = self.retain_byte(number, args) {
            return Some(match file {
                Ok(file) => self.start_retained_byte(file, number, args, memory, pid, target),
                Err(error) => self.complete(number, args, Err(error)),
            });
        }
        if number == 32 {
            let request = match self
                .files
                .get(args[0] as u32)?
                .flock_request(args[1] as u32)
            {
                Ok(request) => request,
                Err(error) => return Some(self.complete(number, args, Err(error))),
            };
            return Some(self.start_flock(request, args, memory, pid, target));
        }
        if number == 427 {
            return self.urings.register(args, memory, pid);
        }
        if number == 426 {
            let attempt = self.urings.start(args, memory, pid, target)?;
            return Some(attempt);
        }
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
            if !self.urings.poll_pump(&prepared.poll_identities(), memory) {
                return Some(IoAttempt::Checkpoint);
            }
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
                    if !self.urings.poll_pump(
                        &self
                            .descriptors
                            .get(args[0] as u32)
                            .unwrap()
                            .poll_identities(),
                        memory,
                    ) {
                        return Some(IoAttempt::Checkpoint);
                    }
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
            if number == 116 {
                None
            } else {
                saved_deadline.or_else(|| {
                    self.network
                        .get(args[0] as u32)
                        .and_then(|fd| fd.timeouts[usize::from(matches!(number, 63 | 65))])
                        .and_then(|d| Instant::now().checked_add(d))
                })
            }
        };
        let signal = IoSignal::new(pid, target.clone());
        let mut host_subscription = None;
        let subscriptions = if number == 116 {
            vec![self.kernel_log.as_ref().unwrap().subscribe(&signal)]
        } else if let Some(fd) = self
            .network
            .get(args[0] as u32)
            .filter(|_| matches!(number, 63..=66))
        {
            let subscription = (|| {
                let events = target.upgrade()?.host_events()?;
                events
                    .subscribe(
                        tcp_wait_fd(&fd.tcp).ok()?,
                        matches!(number, 64 | 66),
                        &signal,
                    )
                    .ok()
            })();
            let Some(subscription) = subscription else {
                return Some(IoAttempt::Checkpoint);
            };
            host_subscription = Some(subscription);
            Vec::new()
        } else if let Some(poll) = &poll {
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
                flock: None,
                retained_byte: None,
                _subscriptions: subscriptions,
                host_subscription,
                uring: None,
                poll_uring: None,
                target: target.clone(),
            },
            memory,
        ))
    }
    fn retain_byte(&self, number: u32, args: [u64; 6]) -> Option<Result<RetainedByte, Errno>> {
        if !matches!(number, 63..=66) {
            return None;
        }
        let file = match self.membership.as_ref()?.lookup(args[0] as u32)? {
            Ok(file) => file,
            Err(error) => return Some(Err(error)),
        };
        let fd = file.direct_byte()?;
        Some(Ok(RetainedByte { fd }))
    }
    /// Joined execution uses the same ABI and resource wait, but owns SIGPIPE
    /// delivery itself. Only complete shared byte OFDs (currently pipes) enter.
    pub fn start_owned_byte(
        &self,
        retained: Option<RetainedByte>,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let retained = retained
            .map(Ok)
            .or_else(|| self.retain_byte(number, args))?;
        Some(match retained {
            Ok(file) => self.start_byte(file, number, args, memory, pid, target, false),
            Err(error) => self.complete(number, args, Err(error)),
        })
    }
    pub fn start_retained_byte(
        &self,
        file: RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        self.start_byte(file, number, args, memory, pid, target, true)
    }
    #[allow(clippy::too_many_arguments)]
    fn start_byte(
        &self,
        file: RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        checkpoint_pipe: bool,
    ) -> IoAttempt {
        match self.transfer_fd(&file.fd, number, args, memory) {
            Some(Err(Errno(11))) if !file.fd.nonblocking() => {}
            Some(Err(Errno(32))) if checkpoint_pipe => return IoAttempt::Checkpoint,
            Some(result) => return self.complete_byte(result),
            None => return IoAttempt::Checkpoint,
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = file.fd.subscribe(&signal);
        self.resume_inner(
            PendingIo {
                number,
                args,
                deadline: None,
                signal,
                flock: None,
                retained_byte: Some(file),
                resource_deadline: None,
                poll: None,
                _subscriptions: subscriptions,
                host_subscription: None,
                uring: None,
                poll_uring: None,
                target: target.clone(),
            },
            memory,
            checkpoint_pipe,
        )
    }
    /// Retry the retained request, never the numeric FD. Subscribe only after
    /// contention, then recheck so unlock-before-park cannot be lost.
    pub fn start_flock(
        &self,
        request: trames_vfs::FlockRequest,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        match request.try_lock() {
            Err(Errno(11)) if !request.nonblocking() => {}
            result => return self.complete(32, args, result.map(|()| 0)),
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![request.subscribe(&signal)];
        self.resume(
            PendingIo {
                number: 32,
                args,
                deadline: None,
                signal,
                flock: Some(request),
                retained_byte: None,
                resource_deadline: None,
                poll: None,
                _subscriptions: subscriptions,
                host_subscription: None,
                uring: None,
                poll_uring: None,
                target: target.clone(),
            },
            memory,
        )
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
    pub fn resume(&self, pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        self.resume_inner(pending, memory, true)
    }
    pub fn resume_owned_byte(&self, pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        assert!(pending.retained_byte.is_some());
        self.resume_inner(pending, memory, false)
    }
    fn resume_inner(
        &self,
        mut pending: PendingIo,
        memory: &mut impl CpuMemory,
        checkpoint_pipe: bool,
    ) -> IoAttempt {
        if pending.uring.is_some() {
            return self.urings.resume(pending, memory);
        }
        pending.signal.reset();
        if let Some(request) = &pending.flock {
            return match request.try_lock() {
                Err(Errno(11)) => IoAttempt::Blocked(pending),
                result => self.complete(32, pending.args, result.map(|()| 0)),
            };
        }
        if pending.poll_uring.is_none() {
            let ids = if let Some(poll) = &pending.poll {
                poll.poll_identities()
            } else if matches!(pending.number, 22 | 441) {
                self.descriptors
                    .get(pending.args[0] as u32)
                    .unwrap()
                    .poll_identities()
            } else {
                Vec::new()
            };
            pending.poll_uring = self
                .urings
                .poll_wait(ids, pending.target.clone())
                .map(Box::new);
        }
        if let Some(wait) = &mut pending.poll_uring {
            if !wait.refresh(&pending.signal, memory) {
                return IoAttempt::Checkpoint;
            }
        }
        if pending
            .host_subscription
            .as_ref()
            .is_some_and(|s| s.rearm().is_err())
        {
            return IoAttempt::Checkpoint;
        }
        let result = if let Some(file) = &pending.retained_byte {
            self.transfer_fd(&file.fd, pending.number, pending.args, memory)
                .expect("shared pipe byte operation")
        } else if let Some(poll) = &pending.poll {
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
                if (matches!(pending.number, 63..=66 | 206 | 207 | 210..=212)
                    && pending.retained_byte.as_ref().map_or_else(
                        || self.nonblocking(pending.number, pending.args),
                        |file| file.fd.nonblocking(),
                    ))
                    || pending.external_wait()
                        && pending.deadline.is_some_and(|d| Instant::now() >= d)
                {
                    return self.complete_pending(&pending, Err(Errno(11)));
                }
                let resource_deadline = if let Some(file) = &pending.retained_byte {
                    file.fd.next_deadline()
                } else if pending.number == 116 {
                    None
                } else if let Some(poll) = &pending.poll {
                    poll.next_deadline()
                } else {
                    self.descriptors
                        .get(pending.args[0] as u32)
                        .and_then(|fd| fd.next_deadline())
                };
                pending.resource_deadline = [
                    resource_deadline,
                    pending.poll_uring.as_ref().and_then(|w| w.deadline),
                ]
                .into_iter()
                .flatten()
                .min();
                IoAttempt::Blocked(pending)
            }
            Err(Errno(32)) if checkpoint_pipe && signals_pipe(pending.number, pending.args) => {
                IoAttempt::Checkpoint
            }
            result => self.complete_pending(&pending, result),
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
        if matches!(number, 22 | 32 | 441) || !self.supports_call(number, args) {
            return None;
        }
        if number == 73 {
            let result = match poll_deadline(memory, args[2], None) {
                Ok(deadline) => {
                    let poll = crate::poll::Poll::prepare(&self.descriptors, memory, args)?;
                    if poll.as_ref().is_ok_and(|p| !p.poll_identities().is_empty()) {
                        return None;
                    }
                    poll.and_then(|p| p.check(memory, deadline))
                }
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
    #[test]
    fn membership_additions_use_the_actual_table_and_defer_replacement_without_effects() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let direct = DirectSyscalls::default().with_membership(v.shared_files());
        assert_eq!(
            direct.invoke_membership(25, [writer as u64, 1030, 160, 0, 0, 0]),
            Some(Ok(160))
        );
        assert_eq!(
            direct.invoke_membership(24, [160, 200, 0, 0, 0, 0]),
            Some(Ok(200))
        );
        assert_ne!(v.flags(160).unwrap() & trames_vfs::O_CLOEXEC, 0);
        assert_eq!(v.flags(200).unwrap() & trames_vfs::O_CLOEXEC, 0);
        assert!(direct
            .invoke_membership(24, [writer as u64, reader as u64, 0, 0, 0, 0])
            .is_none());
        assert!(direct
            .invoke_membership(57, [writer as u64, 0, 0, 0, 0, 0])
            .is_none());
        assert_eq!(direct.fd_control_completed(), 2);
        v.write(200, b"live").unwrap();
        assert_eq!(v.read(reader, 4).unwrap(), b"live");
    }
    #[test]
    fn syslog_subscription_retries_without_lost_wake_and_cancel_drops_listener() {
        use std::sync::atomic::{AtomicU64, Ordering};
        struct Wake {
            log: trames_vfs::KernelLogAccess,
            count: AtomicU64,
        }
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {
                // Callback must run outside the log lock.
                assert!(self.log.size(9).unwrap() > 0);
                self.count.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut v = Vfs::default();
        v.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
        let fd = v.open_at(-100, b"/dev/kmsg", 1, 0).unwrap();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_kernel_log(v.kernel_log_capability());
        let target = Arc::new(Wake {
            log: v.kernel_log_capability(),
            count: AtomicU64::new(0),
        });
        let wake: Arc<dyn IoWake> = target.clone();
        let mut m = memory();
        let args = [2, 0x1000, 1024, 0, 0, 0];
        for _ in 0..3 {
            let pending = pending(
                direct
                    .start(116, args, &mut m, 1, &Arc::downgrade(&wake), None)
                    .unwrap(),
            );
            assert!(!pending.signal.ready());
            assert_eq!(
                direct.descriptors.get(fd).unwrap().write(b"wake-reader"),
                Ok(11)
            );
            assert!(pending.signal.ready());
            assert!(matches!(direct.resume(pending, &mut m), IoAttempt::Complete(Ok(n)) if n > 0));
        }
        assert_eq!(target.count.load(Ordering::Relaxed), 3);
        let cancelled = pending(
            direct
                .start(116, args, &mut m, 1, &Arc::downgrade(&wake), None)
                .unwrap(),
        );
        drop(cancelled);
        v.log(4, "cancelled waiter");
        assert_eq!(target.count.load(Ordering::Relaxed), 3);
        assert!(
            matches!(direct.start(116, args, &mut m, 1, &Arc::downgrade(&wake), None), Some(IoAttempt::Complete(Ok(n))) if n > 0)
        );
        assert!(matches!(
            direct.start(
                116,
                [2, 0x1fff, 2, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&wake),
                None
            ),
            Some(IoAttempt::Complete(Err(Errno(14))))
        ));
    }
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m
    }
    #[test]
    fn native_tcp_vectors_faults_and_blocking_checkpoint_preserve_stream_bytes() {
        use std::{
            io::{Read, Write},
            net::{Ipv4Addr, TcpListener},
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        let direct = DirectSyscalls::new(v.direct_descriptors()).with_network(v.direct_network());
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        assert!(matches!(
            direct.start(
                63,
                [fd as u64, 0x1100, 4, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
                None
            ),
            Some(IoAttempt::Checkpoint)
        ));
        assert_eq!(direct.completed(), 0);
        assert_eq!(
            direct.invoke(64, [fd as u64, 0x1fff, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        m.write(0x1100, b"abcd").unwrap();
        for (address, value) in [
            (0x1200, 0x1100u64),
            (0x1208, 1),
            (0x1210, 0x1101),
            (0x1218, 3),
        ] {
            m.write_array(address, value.to_le_bytes()).unwrap();
        }
        assert_eq!(
            direct.invoke(66, [fd as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        let mut actual = [0; 4];
        peer.read_exact(&mut actual).unwrap();
        assert_eq!(&actual, b"abcd");
        peer.write_all(b"wxyz").unwrap();
        trames_net::wait(&[(socket.clone(), 1)], Duration::from_secs(2)).unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1fff, 4, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(m.read_array::<4>(0x1100).unwrap(), *b"wxyz");
        assert!(!direct.supports(22, fd));
        assert!(!direct.supports(206, fd));
        let before = direct.socket_completed();
        v.set_status_flags(fd, v.flags(fd).unwrap() | O_NONBLOCK)
            .unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
        assert_eq!(direct.socket_completed(), before + 1);
    }
    #[test]
    fn pty_vectors_queries_and_faults_preserve_bytes_and_original_abi() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let master = v
            .open_at(trames_vfs::AT_FDCWD, b"/dev/ptmx", 2 | O_NONBLOCK, 0)
            .unwrap();
        v.pty(master).unwrap().unwrap().pair.locked.set(false);
        let slave = v.open_pty_peer(master, 2 | O_NONBLOCK).unwrap();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_terminal(trames_vfs::TerminalAccess {
                session: 0,
                group: 0,
                controlling: None,
                ignore_ttou: false,
            });
        let mut m = memory();
        m.write(0x1100, b"ab\nc").unwrap();
        for (at, value) in [
            (0x1200, 0x1100u64),
            (0x1208, 2),
            (0x1210, 0x1102),
            (0x1218, 2),
        ] {
            m.write_array(at, value.to_le_bytes()).unwrap();
        }
        assert_eq!(
            direct.invoke(66, [slave as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(
            direct.invoke(29, [master as u64, 0x541b, 0x1300, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(m.read_array::<4>(0x1300).unwrap(), 5u32.to_le_bytes());
        assert_eq!(
            direct.invoke(63, [master as u64, 0x1ffe, 5, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke(65, [master as u64, 0x1200, 2, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(m.read_array::<4>(0x1100).unwrap(), *b"ab\r\n");
        assert_eq!(
            direct.invoke(63, [master as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Ok(1))
        );
        assert_eq!(m.read_array::<1>(0x1100).unwrap(), *b"c");
        let queries = {
            let end = v.pty(slave).unwrap().unwrap();
            let tty = end.pair.terminal.borrow();
            [
                (0x5401, tty.attributes.to_vec()),
                (0x5413, tty.window.to_vec()),
            ]
        };
        for (request, expected) in queries {
            assert_eq!(
                direct.invoke(29, [slave as u64, request, 0x1fff, 0, 0, 0], &mut m),
                Some(Err(Errno(14)))
            );
            assert_eq!(
                direct.invoke(29, [slave as u64, request, 0x1400, 0, 0, 0], &mut m),
                Some(Ok(0))
            );
            let mut out = vec![0; expected.len()];
            m.read(0x1400, &mut out).unwrap();
            assert_eq!(out, expected);
        }
        assert!(!direct.supports_call(29, [slave as u64, 0x5402, 0, 0, 0, 0]));
        m.write(0x1100, b"safe\x03").unwrap();
        assert_eq!(
            direct.invoke(64, [master as u64, 0x1100, 5, 0, 0, 0], &mut m),
            None
        );
        assert_eq!(
            direct.invoke(63, [slave as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
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
    #[test]
    fn accepted_ppoll_keeps_original_pipe_after_close_and_numeric_reuse() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let mut m = memory();
        m.write_array(0x1100, reader.to_le_bytes()).unwrap();
        m.write_array(0x1104, 1u32.to_le_bytes()).unwrap();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let wait = pending(
            direct
                .start(
                    73,
                    [0x1100, 1, 0, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        v.close(reader).unwrap();
        let [replacement, new_writer] = v.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        v.write(new_writer, b"new").unwrap();
        let wait = pending(direct.resume(wait, &mut m));
        v.write(writer, b"old").unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<2>(0x1106).unwrap(), 1u16.to_le_bytes());
        assert_eq!(v.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(v.read(replacement, 3).unwrap(), b"new");
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
    #[test]
    fn blocking_flock_notification_and_retry_keep_original_lease_after_fd_reuse() {
        let mut v = Vfs::default();
        let a = v.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = v.open_at(-100, b"/lock", 2, 0).unwrap();
        v.flock(a, 5).unwrap();
        v.flock(b, 5).unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_files(files.capture(&v, true));
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let args = [a as u64, 2, 0, 0, 0, 0];
        // Legacy dispatch cannot speculatively release a conversion's old SH.
        assert!(direct.invoke_file(32, args, &mut m).is_none());
        assert_eq!(v.flock(b, 6), Err(Errno(11)));
        v.flock(b, 5).unwrap();
        let wait = pending(
            direct
                .start(32, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(!wait.signal.ready());
        // The failed EX conversion released a's SH, allowing b to convert.
        v.flock(b, 6).unwrap();
        let request = wait.flock.as_ref().unwrap().clone();
        let (_, retained) = v.retain_flock(a, 2).unwrap();
        v.close(a).unwrap();
        let reused = v.open_at(-100, b"/new", 0x42, 0o600).unwrap();
        assert_eq!(reused, a);
        v.flock(reused, 6).unwrap();
        v.flock(b, 8).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(0));
        assert_eq!(v.flock(b, 6), Err(Errno(11)));
        assert_eq!(direct.fd_control_completed(), 1);
        drop(retained);
        drop(request); // last original reference unlocks /lock.
        assert_eq!(v.flock(b, 6), Ok(()));
        files.finish();
    }

    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }

    #[test]
    fn shared_byte_wait_and_fresh_dispatch_keep_original_ofd_after_close_and_reuse() {
        let mut vfs = Vfs::default();
        let [reader, writer] = vfs.pipe(0).unwrap();
        let direct = DirectSyscalls::default().with_membership(vfs.shared_files());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let args = [reader as u64, 0x1100, 1, 0, 0, 0];
        let wait = pending(
            direct
                .start(63, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(wait.retained_byte.is_some());
        assert!(!wait.signal.ready());
        vfs.close(reader).unwrap();
        let [replacement, replacement_writer] = vfs.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        vfs.write(replacement_writer, b"n").unwrap();
        assert!(!wait.signal.ready());
        let retained = wait.retained_byte.clone().unwrap();
        drop(wait); // checkpoint drops subscriptions, not accepted authority.
        let fresh = DirectSyscalls::default();
        let wait = pending(fresh.start_retained_byte(
            retained,
            63,
            args,
            &mut m,
            1,
            &Arc::downgrade(&target),
        ));
        vfs.write(writer, b"o").unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(fresh.resume(wait, &mut m)), Ok(1));
        assert_eq!(m.read_array::<1>(0x1100).unwrap(), *b"o");
        assert_eq!(vfs.read(replacement, 1).unwrap(), b"n");
        assert_eq!(vfs.write(writer, b"x"), Err(Errno(32))); // completed lease released.
    }

    #[test]
    fn shared_blocked_writer_keeps_original_endpoint_and_reports_epipe_to_owner() {
        let mut vfs = Vfs::default();
        let [reader, writer] = vfs.pipe(0).unwrap();
        vfs.write(writer, &vec![0; 65536]).unwrap();
        let direct = DirectSyscalls::default().with_membership(vfs.shared_files());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        m.write(0x1100, b"x").unwrap();
        let args = [writer as u64, 0x1100, 1, 0, 0, 0];
        let wait = pending(
            direct
                .start_owned_byte(None, 64, args, &mut m, 1, &Arc::downgrade(&target))
                .unwrap(),
        );
        vfs.close(writer).unwrap();
        let [replacement, _] = vfs.pipe(0).unwrap();
        assert_eq!(replacement, writer);
        vfs.close(reader).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(
            complete(direct.resume_owned_byte(wait, &mut m)),
            Err(Errno(32))
        );
    }

    #[test]
    fn parked_byte_retry_reads_live_nonblock_but_poll_ignores_status_flags() {
        let mut vfs = Vfs::default();
        let [read, _write] = vfs.pipe(0).unwrap();
        let alias = vfs.dup(read, 0, false).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let flags = vfs.fd_flags_snapshot();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let wait = pending(
            direct
                .start(
                    63,
                    [read as u64, 0x1100, 1, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        flags.set_nonblocking(alias, true).unwrap();
        assert!(!wait.signal.ready(), "FIONBIO is not a resource wake");
        assert_eq!(complete(direct.resume(wait, &mut m)), Err(Errno(11)));
        m.write_array(0x1200, [0u8; 8]).unwrap();
        m.write_array(0x1200, read.to_le_bytes()).unwrap();
        m.write_array(0x1204, 1u16.to_le_bytes()).unwrap();
        let wait = pending(
            direct
                .start(
                    73,
                    [0x1200, 1, 0, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        drop(pending(direct.resume(wait, &mut m)));
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
    fn inotify_read_vectors_queries_and_waits_use_the_shared_queue_without_replay() {
        let mut vfs = Vfs::default();
        let fd = vfs.inotify_init(0).unwrap();
        let wd = vfs.inotify_add(fd, b"/", 0x100).unwrap();
        let direct = DirectSyscalls::new(vfs.direct_descriptors());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        let wait = pending(
            direct
                .start(
                    63,
                    [fd as u64, 0x1100, 32, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None,
                )
                .unwrap(),
        );
        vfs.mkdir_at(-100, b"/a", 0o700).unwrap();
        assert!(wait.signal.ready());
        assert_eq!(complete(direct.resume(wait, &mut m)), Ok(32));
        assert_eq!(
            u32::from_le_bytes(m.read_array::<4>(0x1100).unwrap()) as i32,
            wd
        );
        assert_eq!(
            u32::from_le_bytes(m.read_array::<4>(0x1104).unwrap()),
            0x40000100
        );
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(0));
        vfs.mkdir_at(-100, b"/b", 0o700).unwrap();
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1ff0, 32, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 31, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(
            direct.invoke(29, [fd as u64, 0x541b, 0x1200, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(u32::from_le_bytes(m.read_array::<4>(0x1200).unwrap()), 32);
        for (address, value) in [
            (0x1000, 0x1100u64),
            (0x1008, 7),
            (0x1010, 0x1107),
            (0x1018, 25),
        ] {
            m.write_array(address, value.to_le_bytes()).unwrap();
        }
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(32));
        vfs.mkdir_at(-100, b"/c", 0o700).unwrap();
        m.write_array(0x1008, 32u64.to_le_bytes()).unwrap();
        m.write_array(0x1010, 0x1180u64.to_le_bytes()).unwrap();
        m.write_array(0x1018, 8u64.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke(65, [fd as u64, 0x1000, 2, 0, 0, 0], &mut m),
            Some(Ok(32))
        );
        assert_eq!(m.read_array::<2>(0x1110).unwrap(), *b"b\0");
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(32));
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 32, 0, 0, 0], &mut m),
            Some(Ok(32))
        );
        assert_eq!(m.read_array::<2>(0x1110).unwrap(), *b"c\0");
        assert_eq!(vfs.inotify_available(fd).unwrap(), Some(0));
        assert_eq!(
            direct.invoke(64, [fd as u64, 0x1100, 1, 0, 0, 0], &mut m),
            Some(Err(Errno(9)))
        );
        assert_eq!(
            direct.invoke(28, [fd as u64, wd as u64, 0, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(
            direct.invoke(28, [fd as u64, wd as u64, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(22)))
        );
        assert_eq!(direct.fd_control_completed(), 2);
        assert_eq!(
            direct.invoke(63, [fd as u64, 0x1100, 16, 0, 0, 0], &mut m),
            Some(Ok(16))
        );
        assert_eq!(
            u32::from_le_bytes(m.read_array::<4>(0x1104).unwrap()),
            0x8000
        );
        assert_eq!(vfs.inotify_remove(fd, wd), Err(Errno(22)));
        let replacement = vfs.inotify_add(fd, b"/", 0x100).unwrap();
        assert_ne!(replacement, wd);
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
