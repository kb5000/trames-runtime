// SPDX-License-Identifier: GPL-3.0-or-later
//! A pidfd retains only the identity and two terminal transitions of its target.
use super::*;
use std::sync::atomic::AtomicU8;

pub const PIDFD_THREAD: u32 = 0x80; // O_EXCL

pub struct PidFd {
    pid: u32,
    state: AtomicU8,
    changed: Arc<Readiness>,
    namespace: std::sync::OnceLock<(PidNamespace, Option<PidReference>)>,
}

impl PidFd {
    pub fn new(pid: u32, exited: bool, reaped: bool) -> Self {
        Self {
            pid,
            state: AtomicU8::new(if reaped { 2 } else { u8::from(exited) }),
            changed: Arc::default(),
            namespace: Default::default(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn exited(&self) -> bool {
        self.state.load(Ordering::Relaxed) != 0
    }

    /// Retain only original PID translations, never the target's task or Files.
    /// CLONE_PIDFD binds after successful birth; pidfd_open binds the live target.
    pub fn bind_namespace(&self, namespace: &PidNamespace) {
        self.namespace
            .get_or_init(|| (namespace.clone(), namespace.retain(self.pid)));
    }

    pub(super) fn proc_ids(&self, observer: &PidNamespace) -> Vec<i64> {
        if self.state.load(Ordering::Relaxed) == 2 {
            return vec![-1];
        }
        self.namespace.get().map_or_else(
            || vec![i64::from(observer.local(self.pid))],
            |(namespace, _)| {
                namespace
                    .relative_hierarchy(observer, self.pid)
                    .into_iter()
                    .map(i64::from)
                    .collect()
            },
        )
    }

    pub fn publish(&self, reaped: bool) {
        let state = if reaped { 2 } else { 1 };
        if self.state.fetch_max(state, Ordering::Relaxed) < state {
            self.changed.notify_atomic();
        }
    }
}

impl DirectPoll for PidFd {
    fn identity(&self) -> usize {
        self as *const Self as usize
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let state = self.state.load(Ordering::Relaxed);
        let mask = match state {
            0 => 0,
            1 => events & 0x41,
            _ => events & 0x41 | 0x10,
        };
        (mask, [u64::from(state), 0])
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
}

pub struct PendingPidFd {
    slot: fd_table::ReservedFd,
    description: Descriptor,
}
impl PendingPidFd {
    pub fn number(&self) -> u32 {
        self.slot.number()
    }
    pub fn publish(self) -> Result<u32> {
        self.slot.publish(self.description, None)
    }
}
impl DescriptorFactory {
    pub fn reserve_pidfd(&self, target: Arc<PidFd>, flags: u32) -> Result<PendingPidFd> {
        let slot = self.files.reserve()?;
        let description = events::anonymous_descriptor(
            self.open_id(),
            flags | O_CLOEXEC,
            events::Anonymous::Pid(target),
        );
        Ok(PendingPidFd { slot, description })
    }
}
impl FdFlags {
    pub fn retained_pidfd(&self, fd: u32) -> Result<(SharedFd, Arc<PidFd>, u32)> {
        self.descriptor_control(fd)?.retained_pidfd()
    }
    pub fn pidfd(&self, fd: u32) -> Result<(Arc<PidFd>, bool)> {
        let (target, flags) = self.pidfd_flags(fd)?;
        Ok((target, flags & O_NONBLOCK != 0))
    }
    pub fn pidfd_flags(&self, fd: u32) -> Result<(Arc<PidFd>, u32)> {
        self.descriptor_control(fd)?.pidfd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getfd_shares_the_open_description_and_uses_real_credentials() {
        let mut sender = Vfs::default();
        let fd = sender.open_at(AT_FDCWD, b"/file", 0x42, 0o600).unwrap();
        sender.write(fd, b"abcdef").unwrap();
        sender.seek(fd, 1, 0).unwrap();
        let mut receiver = Vfs::default();
        let target = CredentialState::default();
        let mut owner = Credentials::user(12, 34);
        owner.caps.permitted = 1;
        let dumpable = sender.dumpable_state();
        target.publish_pidfd_resources(
            &owner,
            &sender.shared_files(),
            dumpable.clone(),
            sender.pidfd_namespace_source(),
        );

        let mut caller = owner.clone();
        caller.fsuid = 99;
        caller.fsgid = 99;
        caller.caps.effective = 0;
        let copy = |caller: &Credentials| {
            target.receive_pidfd_file(caller, false, fd, &receiver.shared_files(), false)
        };
        caller.caps.permitted = 0;
        assert_eq!(copy(&caller), Err(Errno(1)));
        caller.caps.permitted = 1;
        dumpable.set(false);
        assert_eq!(copy(&caller), Err(Errno(1)));
        dumpable.set(true);
        caller.uid = 99;
        assert_eq!(copy(&caller), Err(Errno(1)));
        caller.uid = owner.uid;
        let dup = copy(&caller).unwrap();
        assert!(receiver.descriptor(dup).unwrap().cloexec.get());
        assert!(!sender.descriptor(fd).unwrap().cloexec.get());
        assert_eq!(receiver.read(dup, 2).unwrap(), b"bc");
        assert_eq!(sender.seek(fd, 0, 1), Ok(3));
        sender.close(fd).unwrap();
        assert_eq!(receiver.read(dup, 3).unwrap(), b"def");
        assert_eq!(
            target.receive_pidfd_file(&caller, false, fd, &receiver.shared_files(), false),
            Err(Errno(9))
        );
    }
}
