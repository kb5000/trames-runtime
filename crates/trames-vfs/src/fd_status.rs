// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared OFD status and per-descriptor bits resolved through live membership.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32};

#[derive(Clone)]
pub(super) struct CloseOnExec(Arc<AtomicBool>);
impl From<bool> for CloseOnExec {
    fn from(value: bool) -> Self {
        Self(Arc::new(AtomicBool::new(value)))
    }
}
impl CloseOnExec {
    pub(super) fn same_slot(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(super) fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, value: bool) {
        // This flag publishes neither FD membership nor resource bytes.
        self.0.store(value, Ordering::Relaxed);
    }
    pub(super) fn fork(&self) -> Self {
        self.get().into()
    }
}

pub(super) fn mark_cloexec_range<'a>(
    first: u32,
    last: u32,
    entries: impl Iterator<Item = (u32, &'a CloseOnExec)>,
) -> Result<()> {
    if first > last {
        return Err(Errno(22));
    }
    for (fd, bit) in entries {
        if fd >= first && fd <= last {
            bit.set(true);
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct StatusFlags {
    fixed: u32,
    mutable: Arc<MutableStatus>,
}
struct MutableStatus {
    bits: AtomicU32,
    update: std::sync::Mutex<()>,
    asynchronous: std::sync::OnceLock<Arc<async_io::AsyncState>>,
}
// Direct I/O is a cache policy hint here: the guest has no block filesystem
// page cache or DMA alignment requirement. Host cache policy is independent.
const CHANGEABLE: u32 = 0x400 | O_NONBLOCK | O_NOATIME | 0x2000 | O_DIRECT;
/// One accepted original descriptor for controls needing inode/credential data.
/// This has no Files root and never resolves a numeric FD after acceptance.
pub struct DescriptorControl(Descriptor);
impl DescriptorControl {
    pub(super) fn pidfd(&self) -> Result<(Arc<PidFd>, u32)> {
        let open = self.0.open.borrow();
        match &open.control {
            Some(events::SharedControl::Pid(pid)) if open.flags.get() & O_PATH == 0 => {
                Ok((pid.clone(), open.flags.get()))
            }
            _ => Err(Errno(9)),
        }
    }

    pub fn status_ioctl_request(request: u32) -> bool {
        matches!(request, 0x5421 | 0x5450..=0x5452 | 0x8901..=0x8904)
    }

    /// Per-slot CLOEXEC and OFD controls accept the descriptor once. A concurrent
    /// close/dup2 cannot redirect a guest pointer access to a replacement file.
    pub fn status_ioctl(
        &self,
        fd: u32,
        request: u32,
        argument: u64,
        memory: &mut impl trames_memory::CpuMemory,
        owners: &impl AsyncOwners,
    ) -> Result<u64> {
        let open = self.0.open.borrow().shared.clone();
        if open.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        match request {
            0x5450 | 0x5451 => self.0.cloexec.set(request == 0x5451),
            0x5421 | 0x5452 => {
                let enabled = memory.read_array::<4>(argument).map_err(|_| Errno(14))? != [0; 4];
                if request == 0x5421 {
                    open.flags.nonblocking(enabled)?;
                } else {
                    let _update = open.flags.lock_update();
                    if (open.flags.get() & 0x2000 != 0) != enabled {
                        if !Self::change_async(&open, fd, enabled)? {
                            return Err(Errno(25));
                        }
                        open.flags.set_async(enabled);
                    }
                }
            }
            0x8901..=0x8904 if open.kind == FdKind::Socket => {
                if request <= 0x8902 {
                    let pid =
                        u32::from_le_bytes(memory.read_array(argument).map_err(|_| Errno(14))?);
                    open.flags
                        .owner_control(8, u64::from(pid), memory, owners)?;
                } else {
                    let pid = open.flags.owner_control(9, 0, memory, owners)? as u32;
                    memory
                        .write_array(argument, pid.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
            }
            _ => return Err(Errno(25)),
        }
        Ok(0)
    }

    fn change_async(open: &Arc<SharedOpenDescription>, fd: u32, enabled: bool) -> Result<bool> {
        // Linux F_SETFL ignores FASYNC for files lacking an fasync operation.
        // Resolve readiness only when a supported endpoint changes registration.
        if let Some(events::SharedControl::Fuse(file)) = &open.control {
            file.connection()?;
        } else if open.pty.is_none() && open.pipe.is_none() && open.local.is_none() {
            // Known files without a Linux fasync callback. Other device types
            // retain their unsupported result until a notification source exists.
            if open.node.as_ref().is_some_and(|node| node.regular_file)
                || open.native_image.is_some()
                || matches!(
                    &open.control,
                    Some(
                        events::SharedControl::Pid(_)
                            | events::SharedControl::Signal(_)
                            | events::SharedControl::Timer(_)
                            | events::SharedControl::Event(_)
                            | events::SharedControl::Epoll(_)
                    )
                )
            {
                return Ok(false);
            }
            return Err(Errno(95));
        }
        let target = SharedFd::new(open.clone()).direct_poll().ok_or(Errno(95))?;
        open.flags.async_state().enable(&target, fd, enabled)?;
        Ok(true)
    }

    pub fn flags(&self) -> u32 {
        self.0.open.borrow().flags.get() | if self.0.cloexec.get() { O_CLOEXEC } else { 0 }
    }
    pub fn filesystem_target(&self) -> FileTarget {
        SharedFd::new(self.0.open.borrow().shared.clone()).filesystem_target()
    }
    pub fn short(
        &self,
        fd: u32,
        command: u64,
        argument: u64,
        credentials: &Credentials,
    ) -> Result<u64> {
        let open = self.0.open.borrow();
        let flags = open.flags.clone();
        if flags.get() & O_PATH != 0 && !matches!(command, 0..=3 | 1030) {
            return Err(Errno(9));
        }
        match command {
            1031 | 1032 => {
                let pipe = open.shared.pipe.as_ref().ok_or(Errno(9))?;
                let mut data = pipe.pipe.data.lock().unwrap();
                if command == 1031 {
                    let requested = argument as u32;
                    if requested > i32::MAX as u32 {
                        return Err(Errno(22));
                    }
                    let size = requested
                        .max(4096)
                        .checked_next_power_of_two()
                        .ok_or(Errno(22))? as usize;
                    if size > 1024 * 1024 && !credentials.has_cap(capabilities::SYS_RESOURCE) {
                        return Err(Errno(1));
                    }
                    if size < data.bytes.len() + data.write_reserved {
                        return Err(Errno(16));
                    }
                    if size != data.capacity {
                        data.capacity = size;
                        data.io_epoch[1] = data.io_epoch[1].wrapping_add(1);
                    }
                }
                Ok(data.capacity as u64)
            }
            1 | 3 => query_fd_flags(
                flags.get() | if self.0.cloexec.get() { O_CLOEXEC } else { 0 },
                command,
            ),
            2 => {
                self.0.cloexec.set(argument & 1 != 0);
                Ok(0)
            }
            4 => {
                let _update = flags.lock_update();
                check_status(&open, credentials, argument as u32)?;
                let mut requested = argument as u32;
                if (flags.get() ^ requested) & 0x2000 != 0
                    && !Self::change_async(&open.shared, fd, requested & 0x2000 != 0)?
                {
                    requested &= !0x2000;
                }
                flags.store_locked(requested)?;
                Ok(0)
            }
            _ => Err(Errno(22)),
        }
    }
}
pub(super) fn check_status(
    open: &OpenDescription,
    credentials: &Credentials,
    flags: u32,
) -> Result<()> {
    if flags & O_NOATIME != 0 && open.flags.get() & O_NOATIME == 0 {
        let (uid, gid) = open.metadata_node().map_or(open.owner, |node| {
            let n = node.borrow();
            (n.uid, n.gid)
        });
        if credentials.fsuid != uid && !credentials.inode_cap(capabilities::FOWNER, uid, gid) {
            return Err(Errno(1));
        }
    }
    StatusFlags::validate(flags)
}
impl DescriptorFactory {
    pub fn descriptor_control(&self, fd: u32) -> Result<DescriptorControl> {
        self.files.observation_descriptor(fd).map(DescriptorControl)
    }
}
impl Vfs {
    pub fn descriptor_control(&self, fd: u32) -> Result<DescriptorControl> {
        self.descriptor(fd).map(DescriptorControl)
    }
}
impl From<u32> for StatusFlags {
    fn from(flags: u32) -> Self {
        Self {
            fixed: flags & !CHANGEABLE,
            mutable: Arc::new(MutableStatus {
                bits: AtomicU32::new(flags & CHANGEABLE),
                update: Default::default(),
                asynchronous: Default::default(),
            }),
        }
    }
}
impl StatusFlags {
    pub(super) fn get(&self) -> u32 {
        self.fixed | self.mutable.bits.load(Ordering::Relaxed)
    }
    pub(super) fn async_state(&self) -> Arc<async_io::AsyncState> {
        self.mutable.asynchronous.get_or_init(Arc::default).clone()
    }
    pub(super) fn set_async(&self, enabled: bool) {
        if enabled {
            self.mutable.bits.fetch_or(0x2000, Ordering::Relaxed);
        } else {
            self.mutable.bits.fetch_and(!0x2000, Ordering::Relaxed);
        }
    }
    pub(super) fn set(&self, flags: u32) -> Result<()> {
        let _update = self.lock_update();
        self.store_locked(flags)
    }
    pub(super) fn lock_update(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mutable.update.lock().unwrap()
    }
    pub(super) fn store_locked(&self, flags: u32) -> Result<()> {
        Self::validate(flags)?;
        self.mutable
            .bits
            .store(flags & CHANGEABLE, Ordering::Relaxed);
        Ok(())
    }
    pub(super) fn validate(_flags: u32) -> Result<()> {
        // F_SETFL ignores immutable and unknown bits; openat validates its own
        // creation flags before constructing this original status word.
        // Immutable authority is stored separately. Replacing the complete
        // mutable word needs one store, not a CAS loop or a resource lock.
        // This flag word publishes no guest bytes or descriptor membership.
        Ok(())
    }
    pub(super) fn nonblocking(&self, enabled: bool) -> Result<()> {
        self.swap_nonblocking(enabled).map(drop)
    }
    pub(super) fn swap_nonblocking(&self, enabled: bool) -> Result<u32> {
        if self.fixed & O_PATH != 0 {
            return Err(Errno(9));
        }
        Ok(if enabled {
            self.mutable.bits.fetch_or(O_NONBLOCK, Ordering::Relaxed)
        } else {
            self.mutable.bits.fetch_and(!O_NONBLOCK, Ordering::Relaxed)
        })
    }
}

#[derive(Clone)]
pub(super) struct DescriptorFlags {
    pub(super) status: StatusFlags,
    pub(super) cloexec: CloseOnExec,
}
impl FdFlags {
    pub fn descriptor_control(&self, fd: u32) -> Result<DescriptorControl> {
        self.1
            .as_ref()
            .ok_or(Errno(9))?
            .observation_descriptor(fd)
            .map(DescriptorControl)
    }
    pub(super) fn with_flags<T>(
        &self,
        fd: u32,
        access: impl Fn(&StatusFlags, &CloseOnExec) -> Result<T>,
    ) -> Result<T> {
        if let Some(result) = self
            .1
            .as_ref()
            .and_then(|files| files.with_flags(fd, &access))
        {
            return result;
        }
        let descriptor = self
            .0
            .get(fd as usize)
            .and_then(Option::as_ref)
            .ok_or(Errno(9))?;
        access(&descriptor.status, &descriptor.cloexec)
    }
    pub fn get(&self, fd: u32) -> Result<u32> {
        self.with_flags(fd, |status, cloexec| {
            Ok(status.get() | if cloexec.get() { O_CLOEXEC } else { 0 })
        })
    }
    pub fn fcntl(&self, fd: u32, command: u64, argument: u64) -> Result<u64> {
        self.with_flags(fd, |status, cloexec| {
            if command == 2 {
                cloexec.set(argument & 1 != 0);
                Ok(0)
            } else if command == 4 {
                if status.fixed & O_PATH != 0 {
                    return Err(Errno(9));
                }
                status.set(argument as u32)?;
                Ok(0)
            } else {
                query_fd_flags(
                    status.get() | if cloexec.get() { O_CLOEXEC } else { 0 },
                    command,
                )
            }
        })
    }
    pub fn set_nonblocking(&self, fd: u32, enabled: bool) -> Result<u64> {
        self.with_flags(fd, |status, _| status.nonblocking(enabled).map(|()| 0))
    }
    pub fn cloexec_range(&self, first: u32, last: u32) -> Result<u64> {
        if let Some(files) = &self.1 {
            return files.cloexec_range(first, last);
        }
        mark_cloexec_range(
            first,
            last,
            self.0
                .iter()
                .enumerate()
                .filter_map(|(fd, d)| d.as_ref().map(|d| (fd as u32, &d.cloexec))),
        )?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pipe_capacity_is_shared_and_resizing_preserves_queued_bytes() {
        let mut v = Vfs::default();
        let [read, write] = v.pipe(O_NONBLOCK).unwrap();
        let alias = v.dup(write, 0, false).unwrap();
        let control = v.descriptor_control(alias).unwrap();
        let user = Credentials::user(1000, 1000);
        assert_eq!(control.short(alias, 1031, 70000, &user), Ok(131072));
        assert_eq!(
            v.descriptor_control(read)
                .unwrap()
                .short(read, 1032, 0, &user),
            Ok(131072)
        );
        assert_eq!(v.write(write, &vec![3; 70000]), Ok(70000));
        assert_eq!(control.short(alias, 1031, 4096, &user), Err(Errno(16)));
        assert_eq!(v.read(read, 70000).unwrap(), vec![3; 70000]);
        assert_eq!(control.short(alias, 1031, 0, &user), Ok(4096));
        assert_eq!(
            control.short(alias, 1031, 2 * 1024 * 1024, &user),
            Err(Errno(1))
        );
        assert_eq!(
            control.short(alias, 1031, u32::MAX as u64, &user),
            Err(Errno(22))
        );
    }
    #[test]
    fn accepted_status_control_uses_live_inode_permission_and_survives_fd_reuse() {
        let mut v = Vfs::default();
        v.import_file(b"/owned", b"original".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/owned", 2, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let control = v.descriptor_control(fd).unwrap();
        let owner = Credentials::user(1000, 1000);
        assert_eq!(
            control.short(fd, 4, O_NOATIME as u64, &owner),
            Err(Errno(1))
        );
        assert_eq!(v.flags(fd).unwrap(), 2 | O_LARGEFILE);
        // The accepted OFD observes a subsequent owner change on its original
        // inode; it never substitutes a cached opener identity.
        v.chown_fd(fd, 1000, u32::MAX).unwrap();
        assert_eq!(control.short(fd, 4, O_NOATIME as u64, &owner), Ok(0));
        let stranger = Credentials::user(2000, 2000);
        assert_eq!(control.short(fd, 4, O_NOATIME as u64, &stranger), Ok(0));
        assert_eq!(control.short(fd, 4, 0, &stranger), Ok(0));
        assert_eq!(
            control.short(fd, 4, O_NOATIME as u64, &stranger),
            Err(Errno(1))
        );
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), fd);
        assert_eq!(
            control.short(fd, 4, (O_NOATIME | O_NONBLOCK) as u64, &owner),
            Ok(0)
        );
        assert_eq!(
            v.flags(alias).unwrap(),
            2 | O_NOATIME | O_NONBLOCK | O_LARGEFILE
        );
        assert_eq!(v.flags(fd).unwrap(), 2);
        assert_eq!(control.short(fd, 2, 1, &owner), Ok(0));
        assert_eq!(v.flags(fd).unwrap() & O_CLOEXEC, 0);
        assert_eq!(v.flags(alias).unwrap() & O_CLOEXEC, 0);
    }
    #[test]
    fn short_control_preserves_path_invalid_command_and_validation_precedence() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/", O_PATH, 0).unwrap();
        let path = v.descriptor_control(fd).unwrap();
        let user = Credentials::user(1000, 1000);
        for command in [4, 12, 1033, 1034, u64::MAX] {
            assert_eq!(path.short(fd, command, 0x80040000, &user), Err(Errno(9)));
        }
        assert_eq!(path.short(fd, 1, 0, &user), Ok(0));
        assert_eq!(path.short(fd, 2, 1, &user), Ok(0));
        assert_eq!(path.short(fd, 1, 0, &user), Ok(1));
        let file = v.open_at(AT_FDCWD, b"/regular", 0x42, 0o600).unwrap();
        let control = v.descriptor_control(file).unwrap();
        assert_eq!(control.short(file, 4, 0x80040000, &user), Err(Errno(1)));
        assert_eq!(control.short(file, 4, 0x80000000, &user), Ok(0));
        assert_eq!(
            control.short(file, u64::MAX, u64::MAX, &user),
            Err(Errno(22))
        );
        assert_eq!(
            control.short(file, 4, O_NOATIME as u64, &Credentials::default()),
            Ok(0)
        );
    }
    #[test]
    fn existing_flag_capture_resolves_new_socket_aliases_and_reuse() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let flags = v.fd_flags_snapshot();
        let network = v.direct_network();
        let fd = v.socket(2, 1, 0).unwrap();
        assert!(network.is_socket(fd));
        let alias = v.dup(fd, 0, false).unwrap();
        let shared = flags.clone();
        std::thread::spawn(move || {
            shared.fcntl(fd, 4, (2 | O_NONBLOCK) as u64).unwrap();
            shared.fcntl(fd, 2, 1).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(v.flags(fd).unwrap(), 2 | O_NONBLOCK | O_CLOEXEC);
        assert_eq!(v.flags(alias).unwrap(), 2 | O_NONBLOCK);
        assert_eq!(flags.fcntl(fd, 1, 0), Ok(1));
        assert_eq!(flags.fcntl(alias, 3, 0), Ok((2 | O_NONBLOCK) as u64));
        v.close(fd).unwrap();
        let replacement = v.socket(2, 1 | O_CLOEXEC, 0).unwrap();
        assert_eq!(replacement, fd);
        assert_eq!(flags.get(fd).unwrap(), 2 | O_CLOEXEC);
        assert_eq!(flags.get(alias).unwrap(), 2 | O_NONBLOCK);
        v.close(replacement).unwrap();
        assert_eq!(flags.get(fd), Err(Errno(9)));
        v.close(alias).unwrap();
        assert_eq!(v.live_sockets(), 0);
    }
    #[test]
    fn aliases_and_fork_share_status_without_changing_membership_or_cloexec() {
        let mut parent = Vfs::default();
        let [fd, _writer] = parent.pipe(O_CLOEXEC).unwrap();
        let alias = parent.dup(fd, 0, false).unwrap();
        let mut child = parent.clone();
        let flags = parent.fd_flags_snapshot();
        let bytes = parent.direct_descriptors();
        assert!(!bytes.get(fd).unwrap().nonblocking());
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    flags
                        .fcntl(alias, 4, (O_NONBLOCK | 0x400 | 2) as u64)
                        .unwrap()
                })
                .join()
                .unwrap();
        });
        assert_eq!(parent.flags(fd).unwrap(), O_CLOEXEC | O_NONBLOCK | 0x400);
        assert_eq!(child.flags(alias).unwrap(), O_NONBLOCK | 0x400);
        assert!(bytes.get(fd).unwrap().nonblocking());
        child.set_cloexec(fd, false).unwrap();
        assert_eq!(child.flags(fd).unwrap() & O_CLOEXEC, 0);
        assert_ne!(parent.flags(fd).unwrap() & O_CLOEXEC, 0);
        flags.set_nonblocking(fd, false).unwrap();
        assert_eq!(child.flags(alias).unwrap(), 0x400);
        assert!(!bytes.get(fd).unwrap().nonblocking());
    }
    #[test]
    fn concurrent_status_updates_preserve_fixed_authority_and_fionbio_keeps_append() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<FdFlags>();
        let status = StatusFlags::from(2 | O_DIRECTORY | 0x1000);
        std::thread::scope(|scope| {
            for i in 0..4 {
                let flags = &status;
                scope.spawn(move || {
                    for _ in 0..2048 {
                        flags
                            .set(((i & 1) * O_NONBLOCK) | (((i >> 1) & 1) * 0x400))
                            .unwrap();
                        assert_eq!(flags.get() & !CHANGEABLE, 2 | O_DIRECTORY | 0x1000);
                    }
                });
            }
        });
        status.set(0x400).unwrap();
        std::thread::scope(|scope| {
            for enabled in [true, false, true, false] {
                let flags = &status;
                scope.spawn(move || {
                    for _ in 0..2048 {
                        flags.nonblocking(enabled).unwrap();
                        assert_ne!(flags.get() & 0x400, 0);
                    }
                });
            }
        });
    }
    #[test]
    fn live_flags_resolve_reused_fd_without_retaining_old_pipe_endpoints() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let retained = v.fd_flags_snapshot();
        let alias = v.dup(reader, 0, false).unwrap();
        v.close(reader).unwrap();
        let [replacement, _] = v.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        retained.set_nonblocking(reader, true).unwrap();
        assert_eq!(v.flags(alias).unwrap(), 0);
        assert_eq!(v.flags(replacement).unwrap(), O_NONBLOCK);
        v.close(writer).unwrap();
        assert!(v.read(alias, 1).unwrap().is_empty());
    }
    #[test]
    fn captured_file_observes_append_changes_before_effects_without_recapture() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"abcd".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let flags = v.fd_flags_snapshot();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&v, true);
        let file = files.get(fd).unwrap();
        let mut cache = DiskReadCache::default();
        flags.fcntl(fd, 4, 0x400).unwrap();
        assert_eq!(file.write(b"X", None, &mut cache), Some(Ok(1)));
        assert_eq!(file.seek(0, 1), Some(Ok(5)));
        assert_eq!(
            file.read(4, Some(0), &mut cache),
            Some(Ok(b"abcd".to_vec()))
        );
        flags.fcntl(fd, 4, 0).unwrap();
        assert_eq!(file.seek(0, 0), Some(Ok(0)));
        assert_eq!(file.write(b"X", None, &mut cache), Some(Ok(1)));
        epoch.finish();
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 4).unwrap(), b"Xbcd");
    }
    #[test]
    fn ignored_status_bits_and_path_descriptors_preserve_original_errors() {
        let mut v = Vfs::default();
        let [reader, _] = v.pipe(0).unwrap();
        let path = v.open_at(AT_FDCWD, b"/", O_PATH, 0).unwrap();
        let flags = v.fd_flags_snapshot();
        assert_eq!(flags.fcntl(reader, 4, 0x80000000), Ok(0));
        assert_eq!(flags.fcntl(path, 4, O_NONBLOCK as u64), Err(Errno(9)));
        assert_eq!(flags.set_nonblocking(path, true), Err(Errno(9)));
        assert_eq!(flags.fcntl(u32::MAX, 4, 0), Err(Errno(9)));
        assert_eq!(v.flags(reader).unwrap(), 0);
    }
}
