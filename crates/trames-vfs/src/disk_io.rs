// SPDX-License-Identifier: GPL-3.0-or-later
//! Coordinator capabilities and Send-only host work are deliberately distinct.
use super::*;
use std::io::{Read, Seek, SeekFrom};

/// Retained only by the coordinator until the submitted read is completed.
pub struct DiskRead {
    open: Rc<RefCell<OpenDescription>>,
    node: Rc<RefCell<Node>>,
    backing: Arc<storage::DiskBacking>,
    positioned: bool,
    count: usize,
}
/// Contains no guest memory, VFS Rc, descriptor table, or borrowed page.
pub struct DiskReadJob {
    backing: Arc<storage::DiskBacking>,
    offset: u64,
    count: usize,
}
impl DiskReadJob {
    pub fn run(self) -> Result<Vec<u8>> {
        // Identical confinement, errno mapping, transfer cap and single-read
        // short-read semantics to FileData::read_at; open itself is off-thread.
        let mut file = self.backing.open(false)?;
        file.seek(SeekFrom::Start(self.offset))
            .map_err(storage::host_errno)?;
        let mut bytes = vec![0; self.count];
        let count = file.read(&mut bytes).map_err(storage::host_errno)?;
        bytes.truncate(count);
        Ok(bytes)
    }
}
impl DiskRead {
    /// While this read is outstanding, offset-changing operations on the same
    /// OFD and writes/sync on the same backing must wait. Positioned reads on
    /// independent OFDs can overlap, including through hard links.
    pub fn conflicts(&self, vfs: &Vfs, fd: u32, number: u32) -> bool {
        let Ok(d) = vfs.descriptor(fd) else {
            return false;
        };
        if Rc::ptr_eq(&self.open, &d.open) && matches!(number, 62..=66) {
            return true;
        }
        if !matches!(number, 64 | 66 | 68 | 70 | 82 | 83) {
            return false;
        }
        let o = d.open.borrow();
        let Some(node) = &o.node else { return false };
        // Retained inode identity also covers a mapped wrapper, if present.
        Rc::ptr_eq(&self.node, node)
            || matches!(&node.borrow().content, Content::File(data)
                if data.disk_source().is_some_and(|(b,_)| Arc::ptr_eq(&b, &self.backing)))
    }
    pub fn finish(self, result: Result<Vec<u8>>) -> Result<Vec<u8>> {
        let mut o = self.open.borrow_mut();
        if !self.positioned {
            if let Ok(bytes) = &result {
                o.position += bytes.len() as u64;
            }
        }
        Vfs::complete_file_read(&o, &self.node, &result, self.count != 0);
        result
    }
}
impl Vfs {
    pub fn disk_read_candidate(&self, fd: u32) -> bool {
        self.descriptor(fd).is_ok_and(|d| {
            Self::ordinary_file(&d.open.borrow(), false).is_some_and(|node|
                matches!(&node.borrow().content, Content::File(data) if data.disk_source().is_some()))
        })
    }
    /// Call only in an epoch, before changing this inode/OFD or mapping state.
    /// All outstanding reads must finish before the epoch is joined.
    pub fn prepare_disk_read(
        &self,
        fd: u32,
        count: usize,
        offset: Option<u64>,
    ) -> Result<Option<(DiskRead, DiskReadJob)>> {
        let descriptor = self.descriptor(fd)?;
        let o = descriptor.open.borrow();
        let Some(node) = Self::ordinary_file(&o, false) else {
            return Ok(None);
        };
        let n = node.borrow();
        let Content::File(data) = &n.content else {
            return Ok(None);
        };
        if !data.epoch_io_safe(false) {
            return Ok(None);
        }
        let Some((backing, length)) = data.disk_source() else {
            return Ok(None);
        };
        if offset.is_some_and(|offset| offset > i64::MAX as u64) {
            return Err(Errno(22));
        }
        if o.flags & O_PATH != 0 || o.flags & 3 == 1 {
            return Err(Errno(9));
        }
        let position = offset.unwrap_or(o.position);
        let size = count
            .min(storage::MAX_TRANSFER)
            .min(usize::try_from(length.saturating_sub(position)).unwrap_or(usize::MAX));
        // Preserve zero/EOF reads without spawning work or opening a host file.
        if size == 0 {
            return Ok(None);
        }
        let job = DiskReadJob {
            backing: backing.clone(),
            offset: position,
            count: size,
        };
        let read = DiskRead {
            open: descriptor.open.clone(),
            node: node.clone(),
            backing,
            positioned: offset.is_some(),
            count,
        };
        Ok(Some((read, job)))
    }
    pub(super) fn complete_file_read(
        o: &OpenDescription,
        node: &Rc<RefCell<Node>>,
        result: &Result<Vec<u8>>,
        access: bool,
    ) {
        if access && result.is_ok() {
            mounts::accessed(&mut node.borrow_mut(), o.mount.as_ref());
        }
        let notification_node = o.node.as_ref().unwrap_or(node);
        if !Rc::ptr_eq(notification_node, node) && result.is_ok() {
            mounts::accessed(&mut notification_node.borrow_mut(), o.mount.as_ref());
        }
        if result.as_ref().is_ok_and(|b| !b.is_empty())
            && !(node.borrow().seals.is_some() && o.notification.is_none())
        {
            inotify::notify(
                notification_node,
                inotify::ACCESS,
                o.notification.as_ref().and_then(|c| c.link.as_ref()),
            );
        }
    }
}
