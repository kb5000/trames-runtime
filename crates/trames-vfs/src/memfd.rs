// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
pub const MEMFD_BYTES: u64 = 128 * 1024 * 1024;
impl Vfs {
    pub(super) fn memfd_available(&self) -> u64 {
        self.fs.borrow().shared_budget.available() as u64
    }
    /// Mode-zero allocation reserves the virtual inode's storage quota and
    /// extends logical EOF without changing existing bytes or the fd position.
    /// KEEP_SIZE is supported for shared files; guest hole punching is separate.
    pub fn allocate_fd(&mut self, fd: u32, mode: u64, offset: u64, length: u64) -> Result<()> {
        if length == 0 || offset > i64::MAX as u64 || length > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let end = offset
            .checked_add(length)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Errno(27))?;
        let (old, shared) = {
            let o = self.descriptor(fd)?.open.borrow();
            if o.flags & O_PATH != 0 || o.flags & 3 == 0 {
                return Err(Errno(9));
            }
            if o.pipe.is_some() {
                return Err(Errno(29));
            }
            let n = o.node.as_ref().ok_or(Errno(19))?.borrow();
            let Content::File(data) = &n.content else {
                return Err(Errno(19));
            };
            (data.len(), data.shared_file())
        };
        if mode > 1 {
            return Err(Errno(95));
        }
        self.fd_writable(fd)?;
        if let Some(file) = shared {
            let n = self
                .descriptor(fd)?
                .open
                .borrow()
                .node
                .clone()
                .ok_or(Errno(19))?;
            if n.borrow()
                .seals
                .is_some_and(|s| s & 8 != 0 || mode == 0 && s & 4 != 0 && end > old)
            {
                return Err(Errno(1));
            }
            if mode == 0 && end > self.file_size_limit {
                return Err(Errno(27));
            }
            file.reserve_range(
                usize::try_from(offset).map_err(|_| Errno(27))?,
                usize::try_from(length).map_err(|_| Errno(27))?,
            )
            .map_err(storage::host_errno)?;
        } else if mode != 0 {
            return Err(Errno(95));
        }
        self.truncate_fd(fd, if mode == 0 { old.max(end) } else { old })
    }
    pub fn memfd_create(&mut self, name: &[u8], flags: u32) -> Result<u32> {
        if name.len() > 249 {
            return Err(Errno(22));
        }
        if flags & !3 != 0 {
            return Err(Errno(22));
        }
        let fd = self.available(0)?;
        let mut fs = self.fs.borrow_mut();
        fs.inodes.retain(|n| n.strong_count() != 0);
        if fs.inodes.len() >= fs.limits.nodes {
            return Err(Errno(28));
        }
        let inode = fs.next_inode;
        fs.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
        let node = Rc::new(RefCell::new(Node {
            notifications: inotify::Marks::default(),
            device: 16,
            content: Content::File(storage::FileData::Shared(
                trames_shared::SharedFile::anonymous_in(fs.shared_budget.clone())
                    .map_err(storage::host_errno)?,
            )),
            mode: 0o100777,
            uid: self.credentials.fsuid,
            gid: self.credentials.fsgid,
            volatile: false,
            inode,
            links: 0,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: Some(if flags & 2 != 0 { 0 } else { 1 }),
        }));
        fs.inodes.push(Rc::downgrade(&node));
        drop(fs);
        let mut target = b"/memfd:".to_vec();
        target.extend_from_slice(name);
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(OpenDescription {
                    id: self.open_id(),
                    owner: (self.credentials.fsuid, self.credentials.fsgid),
                    kind: FdKind::Node(target),
                    flags: 2,
                    position: 0,
                    node: Some(node),
                    pipe: None,
                    socket: None,
                    bridge: None,
                    kernel_log: None,
                    anonymous: None,
                    notification: None,
                    local: None,
                    pty: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: None,
                })),
                cloexec: flags & 1 != 0,
            },
        );
        Ok(fd)
    }
    /// A managed shared inode capability for native protocol FD translation.
    /// Guest descriptor numbers and guest-selected host paths never cross here.
    pub fn shared_file(&self, fd: u32) -> Result<trames_shared::SharedFile> {
        let open = self.descriptor(fd)?.open.borrow();
        if open.flags & O_PATH != 0 || open.flags & 3 == 1 {
            return Err(Errno(9));
        }
        let node = open.node.as_ref().ok_or(Errno(19))?.borrow();
        let Content::File(data) = &node.content else {
            return Err(Errno(19));
        };
        data.shared_file().ok_or(Errno(95))
    }
    pub fn seals(&self, fd: u32, add: Option<u32>) -> Result<u32> {
        let o = self.descriptor(fd)?.open.borrow();
        let node = o.node.as_ref().ok_or(Errno(22))?;
        let mut n = node.borrow_mut();
        let current = n.seals.ok_or(Errno(22))?;
        let Some(add) = add else { return Ok(current) };
        if add & !15 != 0 {
            return Err(Errno(22));
        }
        if o.flags & 3 != 2 || current & 1 != 0 {
            return Err(Errno(1));
        }
        if add & 8 != 0 {
            if let Content::File(storage::FileData::Mapped(data)) = &n.content {
                if data.has_writers() {
                    return Err(Errno(16));
                }
                data.sync(false)?;
            }
        }
        n.seals = Some(current | add);
        Ok(0)
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    #[test]
    fn allocation_preserves_bytes_position_and_shared_quota() {
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"buffer", 2).unwrap();
        v.write(fd, b"existing").unwrap();
        v.allocate_fd(fd, 0, 4096, 4096).unwrap();
        assert_eq!(v.pread(fd, 8, 0).unwrap(), b"existing");
        assert_eq!(v.seek(fd, 0, 1).unwrap(), 8);
        assert_eq!(v.pread(fd, 4, 4096).unwrap(), [0; 4]);
        assert_eq!(v.allocate_fd(fd, 0, 0, 0), Err(Errno(22)));
        assert_eq!(v.allocate_fd(fd, 1, 0, 1), Ok(()));
        assert_eq!(v.seek(fd, 0, 2).unwrap(), 8192);
        assert_eq!(v.allocate_fd(fd, 0, 0, MEMFD_BYTES + 1), Err(Errno(28)));
        assert_eq!(v.pread(fd, 8, 0).unwrap(), b"existing");
    }
    #[test]
    fn foot_sparse_pool_probe_falls_back_without_charging_512_mib() {
        let mut v = Vfs::default();
        for _ in 0..4 {
            let fd = v.memfd_create(b"foot-shm", 3).unwrap();
            let before = v.memfd_available();
            v.truncate_fd(fd, 512 * 1024 * 1024).unwrap();
            assert_eq!(v.memfd_available(), before);
            assert_eq!(v.allocate_fd(fd, 3, 0, 1), Err(Errno(95)));
            v.truncate_fd(fd, 8192).unwrap();
            let pages = v.mapping_pages(fd, 0, 8192, true, true).unwrap();
            assert!(v.memfd_available() < before);
            v.pwrite(fd, b"pixels", 4096).unwrap();
            assert_eq!(v.pread(fd, 6, 4096).unwrap(), b"pixels");
            v.close(fd).unwrap();
            drop(pages);
            assert_eq!(v.memfd_available(), before);
        }
    }
}
