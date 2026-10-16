// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
pub const MEMFD_BYTES: u64 = 128 * 1024 * 1024;
impl Vfs {
    pub(super) fn memfd_available(&self) -> u64 {
        self.fs.borrow().shared_budget.available() as u64
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
