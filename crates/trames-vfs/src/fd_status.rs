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
    mutable: Arc<AtomicU32>,
}
const CHANGEABLE: u32 = 0x400 | O_NONBLOCK | O_NOATIME;
impl From<u32> for StatusFlags {
    fn from(flags: u32) -> Self {
        Self {
            fixed: flags & !CHANGEABLE,
            mutable: Arc::new(AtomicU32::new(flags & CHANGEABLE)),
        }
    }
}
impl StatusFlags {
    pub(super) fn get(&self) -> u32 {
        self.fixed | self.mutable.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, flags: u32) -> Result<()> {
        if flags & !(CHANGEABLE | 3 | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | 0x101000) != 0 {
            return Err(Errno(22));
        }
        // Immutable authority is stored separately. Replacing the complete
        // mutable word needs one store, not a CAS loop or a resource lock.
        // This flag word publishes no guest bytes or descriptor membership.
        self.mutable.store(flags & CHANGEABLE, Ordering::Relaxed);
        Ok(())
    }
    pub(super) fn nonblocking(&self, enabled: bool) -> Result<()> {
        if self.fixed & O_PATH != 0 {
            return Err(Errno(9));
        }
        if enabled {
            self.mutable.fetch_or(O_NONBLOCK, Ordering::Relaxed);
        } else {
            self.mutable.fetch_and(!O_NONBLOCK, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct DescriptorFlags {
    pub(super) status: StatusFlags,
    pub(super) cloexec: CloseOnExec,
}
impl FdFlags {
    fn with_flags<T>(
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
        assert_eq!(file.write(b"X", None, &mut cache), None);
        assert_eq!(file.seek(0, 1), Some(Ok(0)));
        assert_eq!(
            file.read(4, Some(0), &mut cache),
            Some(Ok(b"abcd".to_vec()))
        );
        flags.fcntl(fd, 4, 0).unwrap();
        assert_eq!(file.write(b"X", None, &mut cache), Some(Ok(1)));
        epoch.finish();
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 4).unwrap(), b"Xbcd");
    }
    #[test]
    fn invalid_status_flags_and_path_descriptors_preserve_original_errors() {
        let mut v = Vfs::default();
        let [reader, _] = v.pipe(0).unwrap();
        let path = v.open_at(AT_FDCWD, b"/", O_PATH, 0).unwrap();
        let flags = v.fd_flags_snapshot();
        assert_eq!(flags.fcntl(reader, 4, 0x2000), Err(Errno(22)));
        assert_eq!(flags.fcntl(path, 4, O_NONBLOCK as u64), Err(Errno(9)));
        assert_eq!(flags.set_nonblocking(path, true), Err(Errno(9)));
        assert_eq!(flags.fcntl(u32::MAX, 4, 0), Err(Errno(9)));
        assert_eq!(v.flags(reader).unwrap(), 0);
    }
}
