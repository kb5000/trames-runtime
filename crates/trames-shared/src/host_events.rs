// SPDX-License-Identifier: GPL-3.0-or-later
//! An existing idle executor drives host readiness. No reactor/service thread.
//! Each pending call owns a distinct duplicate FD and one-shot registration;
//! several readers/writers on one open description cannot overwrite each other.
use crate::IoSignal;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Instant,
};

/// A wait-scoped host descriptor and optional actual-resource ownership. Drop
/// the duplicate before the resource lease, so final transport close precedes
/// returning its quota. The lease is opaque; the reactor never controls it.
pub struct HostFd {
    fd: OwnedFd,
    _lease: Option<Arc<dyn Send + Sync>>,
}
impl HostFd {
    pub fn retained(fd: OwnedFd, lease: Arc<dyn Send + Sync>) -> Self {
        Self {
            fd,
            _lease: Some(lease),
        }
    }
}
impl From<OwnedFd> for HostFd {
    fn from(fd: OwnedFd) -> Self {
        Self { fd, _lease: None }
    }
}
impl AsRawFd for HostFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}
struct Entry {
    fd: HostFd,
    write: bool,
    signal: Weak<IoSignal>,
    armed: bool,
}
#[derive(Default)]
struct Registrations {
    next: u64,
    entries: BTreeMap<u64, Entry>,
}
pub struct HostEvents {
    backend: backend::Poller,
    read: UnixStream,
    write: UnixStream,
    armed: AtomicBool,
    registrations: Mutex<Registrations>,
}
pub struct HostSubscription {
    source: Arc<HostEvents>,
    id: u64,
}
impl HostEvents {
    pub fn new() -> io::Result<Arc<Self>> {
        let (read, write) = UnixStream::pair()?;
        read.set_nonblocking(true)?;
        write.set_nonblocking(true)?;
        let backend = backend::Poller::new(read.as_raw_fd())?;
        Ok(Arc::new(Self {
            backend,
            read,
            write,
            armed: AtomicBool::new(false),
            registrations: Mutex::default(),
        }))
    }
    pub fn subscribe(
        self: &Arc<Self>,
        fd: impl Into<HostFd>,
        write: bool,
        signal: &Arc<IoSignal>,
    ) -> io::Result<HostSubscription> {
        let fd = fd.into();
        let mut r = self.registrations.lock().unwrap();
        let id = r
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("host wait IDs exhausted"))?;
        r.next = id;
        self.backend.set(fd.as_raw_fd(), write, id, false)?;
        r.entries.insert(
            id,
            Entry {
                fd,
                write,
                signal: Arc::downgrade(signal),
                armed: true,
            },
        );
        Ok(HostSubscription {
            source: self.clone(),
            id,
        })
    }
    /// Called under the scheduler queue lock before releasing it to wait. Queue
    /// mutations take that same lock, then wake(), closing the lost-wake gap.
    /// A single elected executor may be armed/waiting at a time.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::Release);
    }
    pub fn wake(&self) {
        if self.armed.load(Ordering::Relaxed) && self.armed.swap(false, Ordering::AcqRel) {
            // A full nonblocking socket already contains a wake. Both ends
            // outlive this call, so this cannot signal a closed peer.
            loop {
                match (&self.write).write(&[1]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
        }
    }
    pub fn wait(&self, deadline: Option<Instant>) -> io::Result<()> {
        let ids = self.backend.wait(deadline)?;
        if ids.contains(&0) {
            let mut bytes = [0; 1024];
            loop {
                match (&self.read).read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        }
        let signals: Vec<_> = {
            let mut r = self.registrations.lock().unwrap();
            ids.iter()
                .filter_map(|id| {
                    let entry = r.entries.get_mut(id)?;
                    entry.armed = false;
                    entry.signal.upgrade()
                })
                .collect()
        };
        // Callbacks may re-enter the run queue and cancel subscriptions. Never
        // retain the registry or scheduler mutex across notification.
        for signal in signals {
            signal.fire();
        }
        Ok(())
    }
}
impl HostSubscription {
    /// Rearm before retrying the original nonblocking resource operation.
    pub fn rearm(&self) -> io::Result<()> {
        let mut r = self.source.registrations.lock().unwrap();
        let e = r
            .entries
            .get_mut(&self.id)
            .expect("retained host registration");
        if e.armed {
            return Ok(());
        }
        self.source
            .backend
            .set(e.fd.as_raw_fd(), e.write, self.id, true)?;
        e.armed = true;
        Ok(())
    }
}
impl Drop for HostSubscription {
    fn drop(&mut self) {
        let removed = {
            let mut r = self.source.registrations.lock().unwrap();
            let removed = r.entries.remove(&self.id);
            if let Some(e) = &removed {
                self.source.backend.remove(e.fd.as_raw_fd(), e.write);
            }
            removed
        };
        // Close only after deleting: stale returned events use a never reused
        // ID. Final resource destruction must not run under the registry lock.
        drop(removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsFd, sync::atomic::AtomicUsize, time::Duration};
    struct Target(AtomicUsize);
    impl crate::IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn signal(pid: u32) -> (Arc<dyn crate::IoWake>, Arc<IoSignal>) {
        let target: Arc<dyn crate::IoWake> = Arc::new(Target(AtomicUsize::new(0)));
        let signal = IoSignal::new(pid, Arc::downgrade(&target));
        (target, signal)
    }
    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        (a, b)
    }
    #[test]
    fn retained_resource_drops_after_fd_and_outside_registry_even_on_failure() {
        struct Probe {
            hub: Weak<HostEvents>,
            peer: UnixStream,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                let hub = self.hub.upgrade().unwrap();
                assert!(hub.registrations.try_lock().is_ok());
                assert_eq!(self.peer.read(&mut [0]).unwrap(), 0);
                self.dropped.store(true, Ordering::Relaxed);
            }
        }
        for fail in [false, true] {
            let hub = HostEvents::new().unwrap();
            let (a, b) = pair();
            let dropped = Arc::new(AtomicBool::new(false));
            let fd = HostFd::retained(
                a.as_fd().try_clone_to_owned().unwrap(),
                Arc::new(Probe {
                    hub: Arc::downgrade(&hub),
                    peer: b,
                    dropped: dropped.clone(),
                }),
            );
            drop(a);
            if fail {
                hub.registrations.lock().unwrap().next = u64::MAX;
            }
            let (_target, signal) = signal(1);
            let subscription = hub.subscribe(fd, false, &signal);
            if fail {
                assert!(subscription.is_err());
            } else {
                assert!(!dropped.load(Ordering::Relaxed));
                let subscription = subscription.unwrap();
                std::thread::spawn(move || drop(subscription))
                    .join()
                    .unwrap();
            }
            assert!(dropped.load(Ordering::Relaxed));
        }
    }
    #[test]
    fn multiple_waiters_rearm_independently_and_half_close_delivers_eof() {
        let hub = HostEvents::new().unwrap();
        let (mut a, mut b) = pair();
        let (_t1, s1) = signal(1);
        let (_t2, s2) = signal(2);
        let first = hub
            .subscribe(a.as_fd().try_clone_to_owned().unwrap(), false, &s1)
            .unwrap();
        let second = hub
            .subscribe(a.as_fd().try_clone_to_owned().unwrap(), false, &s2)
            .unwrap();
        b.write_all(b"a").unwrap();
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert!(s1.ready() && s2.ready());
        let mut byte = [0];
        assert_eq!(a.read(&mut byte).unwrap(), 1);
        s1.reset();
        s2.reset();
        second.rearm().unwrap();
        // A consumed one-shot must not fire again merely because data remains.
        b.write_all(b"b").unwrap();
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert!(!s1.ready() && s2.ready());
        assert_eq!(a.read(&mut byte).unwrap(), 1);
        s2.reset();
        second.rearm().unwrap();
        b.shutdown(std::net::Shutdown::Write).unwrap();
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert!(s2.ready());
        assert_eq!(a.read(&mut byte).unwrap(), 0);
        drop((first, second));
        assert!(hub.registrations.lock().unwrap().entries.is_empty());
    }
    #[test]
    fn write_backpressure_and_cancelled_events_keep_registration_identity() {
        let hub = HostEvents::new().unwrap();
        let (mut a, mut b) = pair();
        let bytes = [1; 16384];
        loop {
            match a.write(&bytes) {
                Ok(n) => assert!(n > 0 && n <= bytes.len()),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }
        }
        let (_t1, s1) = signal(1);
        let (_t2, s2) = signal(2);
        let cancelled = hub
            .subscribe(a.as_fd().try_clone_to_owned().unwrap(), true, &s1)
            .unwrap();
        drop(cancelled);
        let active = hub
            .subscribe(a.as_fd().try_clone_to_owned().unwrap(), true, &s2)
            .unwrap();
        let mut buf = [0; 16384];
        while b.read(&mut buf).is_ok() {}
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert!(!s1.ready() && s2.ready());
        assert!(a.write(b"x").is_ok());
        drop(active);
    }
    #[test]
    fn wake_before_wait_is_coalesced_and_deadline_does_not_notify_a_socket() {
        let hub = HostEvents::new().unwrap();
        hub.arm();
        for _ in 0..4096 {
            hub.wake();
        }
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        hub.disarm();
        let (a, _b) = pair();
        let (_t, s) = signal(1);
        let _guard = hub
            .subscribe(a.as_fd().try_clone_to_owned().unwrap(), false, &s)
            .unwrap();
        hub.wait(Some(Instant::now())).unwrap();
        assert!(!s.ready());
    }
    #[test]
    fn concurrent_subscribe_and_socket_change_do_not_lose_wakes() {
        let hub = HostEvents::new().unwrap();
        let (mut a, mut b) = pair();
        let (_t, s) = signal(1);
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..256 {
                    barrier.wait();
                    b.write_all(b"x").unwrap();
                    barrier.wait();
                }
            });
            for _ in 0..256 {
                s.reset();
                barrier.wait();
                let _guard = hub
                    .subscribe(a.as_fd().try_clone_to_owned().unwrap(), false, &s)
                    .unwrap();
                hub.wait(Some(Instant::now() + Duration::from_secs(2)))
                    .unwrap();
                assert!(s.ready());
                assert_eq!(a.read(&mut [0; 1]).unwrap(), 1);
                barrier.wait();
            }
        });
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod backend {
    use super::*;
    use std::os::fd::{FromRawFd, RawFd};
    pub struct Poller(OwnedFd);
    impl Poller {
        pub fn new(wake: RawFd) -> io::Result<Self> {
            // SAFETY: new owned FD; all epoll buffers below are initialized POD
            // and bounded. FDs are retained by HostEvents/registration guards.
            let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let poller = Self(unsafe { OwnedFd::from_raw_fd(fd) });
            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: 0,
            };
            if unsafe { libc::epoll_ctl(fd, libc::EPOLL_CTL_ADD, wake, &mut event) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(poller)
        }
        pub fn set(&self, fd: RawFd, write: bool, id: u64, rearm: bool) -> io::Result<()> {
            let flags = if write {
                libc::EPOLLOUT
            } else {
                libc::EPOLLIN | libc::EPOLLRDHUP
            };
            let mut event = libc::epoll_event {
                events: (flags | libc::EPOLLONESHOT) as u32,
                u64: id,
            };
            if unsafe {
                libc::epoll_ctl(
                    self.0.as_raw_fd(),
                    if rearm {
                        libc::EPOLL_CTL_MOD
                    } else {
                        libc::EPOLL_CTL_ADD
                    },
                    fd,
                    &mut event,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn remove(&self, fd: RawFd, _: bool) {
            unsafe {
                libc::epoll_ctl(
                    self.0.as_raw_fd(),
                    libc::EPOLL_CTL_DEL,
                    fd,
                    std::ptr::null_mut(),
                );
            }
        }
        pub fn wait(&self, deadline: Option<Instant>) -> io::Result<Vec<u64>> {
            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
            loop {
                let ms = deadline.map_or(-1, |d| {
                    let left = d.saturating_duration_since(Instant::now());
                    left.as_millis()
                        .saturating_add(u128::from(left.subsec_nanos() % 1_000_000 != 0))
                        .min(i32::MAX as u128) as i32
                });
                let count = unsafe {
                    libc::epoll_wait(
                        self.0.as_raw_fd(),
                        events.as_mut_ptr(),
                        events.len() as i32,
                        ms,
                    )
                };
                if count >= 0 {
                    return Ok(events[..count as usize].iter().map(|e| e.u64).collect());
                }
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
mod backend {
    use super::*;
    use std::os::fd::{FromRawFd, RawFd};
    pub struct Poller(OwnedFd);
    impl Poller {
        pub fn new(wake: RawFd) -> io::Result<Self> {
            // SAFETY: fresh kqueue FD; initialized public kevent ABI. udata
            // stores opaque IDs only and is never dereferenced as a pointer.
            let fd = unsafe { libc::kqueue() };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let poller = Self(unsafe { OwnedFd::from_raw_fd(fd) });
            poller.change(wake, false, 0, libc::EV_ADD)?;
            Ok(poller)
        }
        fn change(&self, fd: RawFd, write: bool, id: u64, flags: u16) -> io::Result<()> {
            let event = libc::kevent {
                ident: fd as usize,
                filter: if write {
                    libc::EVFILT_WRITE
                } else {
                    libc::EVFILT_READ
                },
                flags,
                fflags: 0,
                data: 0,
                udata: id as usize as *mut libc::c_void,
            };
            if unsafe {
                libc::kevent(
                    self.0.as_raw_fd(),
                    &event,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn set(&self, fd: RawFd, write: bool, id: u64, _: bool) -> io::Result<()> {
            self.change(fd, write, id, libc::EV_ADD | libc::EV_ONESHOT)
        }
        pub fn remove(&self, fd: RawFd, write: bool) {
            let _ = self.change(fd, write, 0, libc::EV_DELETE);
        }
        pub fn wait(&self, deadline: Option<Instant>) -> io::Result<Vec<u64>> {
            let mut events: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
            loop {
                let timeout = deadline.map(|d| {
                    let left = d.saturating_duration_since(Instant::now());
                    libc::timespec {
                        tv_sec: left.as_secs().min(i64::MAX as u64) as _,
                        tv_nsec: left.subsec_nanos() as _,
                    }
                });
                let count = unsafe {
                    libc::kevent(
                        self.0.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        events.len() as i32,
                        timeout.as_ref().map_or(std::ptr::null(), |t| t),
                    )
                };
                if count >= 0 {
                    if events[..count as usize]
                        .iter()
                        .any(|e| e.flags & libc::EV_ERROR != 0)
                    {
                        return Err(io::Error::other("host kevent error"));
                    }
                    return Ok(events[..count as usize]
                        .iter()
                        .map(|e| e.udata as usize as u64)
                        .collect());
                }
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}
