// SPDX-License-Identifier: GPL-3.0-or-later
//! Waitable vnode changes, driven by existing executor host-readiness polling.
use super::*;
#[cfg(target_vendor = "apple")]
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;

pub(super) struct Unlock {
    #[cfg(target_vendor = "apple")]
    queue: OwnedFd,
    _file: Arc<OpenFile>,
}
impl Unlock {
    #[cfg(target_vendor = "apple")]
    pub fn new(file: Arc<OpenFile>) -> Result<Self> {
        let queue = unsafe { libc::kqueue() };
        if queue < 0 {
            return Err(errno(std::io::Error::last_os_error()));
        }
        let queue = unsafe { OwnedFd::from_raw_fd(queue) };
        let event = libc::kevent {
            ident: file.file.as_raw_fd() as usize,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_FUNLOCK,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        status(unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        })?;
        Ok(Self { queue, _file: file })
    }
    #[cfg(not(target_vendor = "apple"))]
    pub fn new(_: Arc<OpenFile>) -> Result<Self> {
        Err(Errno(95))
    }
    #[cfg(target_vendor = "apple")]
    pub fn fd(&self) -> Result<OwnedFd> {
        self.queue.as_fd().try_clone_to_owned().map_err(errno)
    }
    #[cfg(not(target_vendor = "apple"))]
    pub fn fd(&self) -> Result<OwnedFd> {
        Err(Errno(95))
    }
    pub fn drain(&self) {
        #[cfg(target_vendor = "apple")]
        {
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
            unsafe {
                libc::kevent(
                    self.queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    event.as_mut_ptr(),
                    1,
                    &timeout,
                );
            }
        }
    }
}

pub(crate) struct Flock {
    file: Arc<OpenFile>,
    used: AtomicBool,
    wait: std::sync::OnceLock<Unlock>,
}
impl Flock {
    pub fn new(file: Arc<OpenFile>) -> Self {
        Self {
            file,
            used: AtomicBool::new(false),
            wait: std::sync::OnceLock::new(),
        }
    }
    pub fn apply(&self, requested: u32) -> Result<()> {
        let kind = requested & !4;
        if let Some(wait) = self.wait.get() {
            wait.drain();
        }
        if kind != 8 {
            self.used.store(true, Ordering::Relaxed);
        }
        let operation = match kind {
            1 => libc::LOCK_SH,
            2 => libc::LOCK_EX,
            _ => libc::LOCK_UN,
        };
        let mut result =
            unsafe { libc::flock(self.file.file.as_raw_fd(), operation | libc::LOCK_NB) };
        if result != 0
            && requested & 4 == 0
            && kind != 8
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
        {
            if self.wait.get().is_none() {
                let wait = Unlock::new(self.file.clone())?;
                let _ = self.wait.set(wait);
            }
            // Register native unlock interest before the deciding retry.
            result = unsafe { libc::flock(self.file.file.as_raw_fd(), operation | libc::LOCK_NB) };
        }
        if result != 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            return Err(Errno(11));
        }
        status(result)
    }
    pub fn fd(&self) -> Option<OwnedFd> {
        self.wait.get().and_then(|wait| wait.fd().ok())
    }
    pub fn subscribe(
        &self,
        subscription: IoSubscription,
        signal: &Arc<IoSignal>,
    ) -> IoSubscription {
        match self.fd() {
            Some(fd) => subscription.with_host(fd, signal),
            None => subscription,
        }
    }
}
impl Drop for Flock {
    fn drop(&mut self) {
        if self.used.load(Ordering::Relaxed) {
            unsafe {
                libc::flock(self.file.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
