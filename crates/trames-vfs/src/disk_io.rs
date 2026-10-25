// SPDX-License-Identifier: GPL-3.0-or-later
//! Coordinator capabilities and Send-only host work are deliberately distinct.
use super::*;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::FileExt;

/// Worker-local, bounded host handles. Weak identities neither retain an
/// unlinked object nor keep a store locked after its last guest/job reference.
#[derive(Default)]
pub struct DiskReadCache {
    entries: Vec<(std::sync::Weak<storage::DiskBacking>, bool, File)>,
}
impl DiskReadCache {
    pub(super) fn file(
        &mut self,
        backing: &Arc<storage::DiskBacking>,
        write: bool,
    ) -> Result<&File> {
        // Do not leave dead/orphan handles behind a frequently hit live entry.
        self.entries.retain(|(key, _, _)| key.strong_count() != 0);
        if let Some(index) = self.entries.iter().position(|(key, writable, _)| {
            key.as_ptr() == Arc::as_ptr(backing) && (!write || *writable)
        }) {
            // The retained Weak prevents address reuse while an entry exists.
            let entry = self.entries.remove(index);
            self.entries.push(entry);
        } else {
            let file = backing.open(write)?;
            if self.entries.len() == 16 {
                self.entries.remove(0);
            }
            self.entries.push((Arc::downgrade(backing), write, file));
        }
        Ok(&self.entries.last().expect("opened disk handle").2)
    }
}

/// Retained only by the coordinator until the submitted read is completed.
pub struct DiskRead {
    open: OpenHandle,
    node: NodeRef,
    backing: Arc<storage::DiskBacking>,
    positioned: bool,
    position: Arc<std::sync::Mutex<file_data::FilePosition>>,
    _lease: Option<file_data::ReadLease>,
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
        self.run_cached(&mut DiskReadCache::default(), Vec::new())
    }
    pub fn run_cached(self, cache: &mut DiskReadCache, mut bytes: Vec<u8>) -> Result<Vec<u8>> {
        // Revalidate guest admission each time; only the private object handle
        // is cached. First open keeps regular/O_NOFOLLOW/metadata confinement.
        let file = cache.file(&self.backing, false)?;
        bytes.resize(self.count, 0);
        #[cfg(unix)]
        let count = file
            .read_at(&mut bytes, self.offset)
            .map_err(storage::host_errno)?;
        #[cfg(not(unix))]
        let count = {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = file;
            file.seek(SeekFrom::Start(self.offset))
                .map_err(storage::host_errno)?;
            file.read(&mut bytes).map_err(storage::host_errno)?
        };
        bytes.truncate(count);
        Ok(bytes)
    }
}
impl Drop for DiskRead {
    fn drop(&mut self) {
        if !self.positioned {
            self.position.lock().unwrap().pending -= 1;
        }
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
        if !self.positioned && OpenHandle::ptr_eq(&self.open, &d.open) && matches!(number, 62..=66)
        {
            return true;
        }
        if !matches!(number, 64 | 66 | 68 | 70 | 82 | 83) {
            return false;
        }
        let o = d.open.borrow();
        let Some(node) = &o.node else { return false };
        // Retained inode identity also covers a mapped wrapper, if present.
        Arc::ptr_eq(&self.node, node)
            || matches!(&node.borrow().content, Content::File(data)
                if data.disk_source().is_some_and(|(b,_)| Arc::ptr_eq(&b, &self.backing)))
    }
    pub fn finish(self, result: Result<Vec<u8>>) -> Result<Vec<u8>> {
        let o = self.open.borrow();
        if !self.positioned {
            if let Ok(bytes) = &result {
                self.position.lock().unwrap().value += bytes.len() as u64;
            }
        }
        Vfs::complete_file_read(&o, &self.node, &result, self.count != 0);
        result
    }
}
impl Vfs {
    pub fn disk_read_candidate(&self, fd: u32) -> bool {
        self.descriptor(fd).is_ok_and(|d| {
            Self::ordinary_file(&d.open.borrow(), false).is_some_and(
                |node| matches!(&node.borrow().content, Content::File(data) if data.disk_backed()),
            )
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
        if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 1 {
            return Err(Errno(9));
        }
        let mut file_position = o.file_position.lock().unwrap();
        let position = offset.unwrap_or(file_position.value);
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
        if offset.is_none() {
            file_position.pending += 1;
        }
        let lease = if let Content::File(storage::FileData::Plain(data)) = &n.content {
            Some(data.register_read())
        } else {
            None
        };
        let read = DiskRead {
            position: o.file_position.clone(),
            _lease: lease,
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
        node: &NodeRef,
        result: &Result<Vec<u8>>,
        access: bool,
    ) {
        if access && result.is_ok() {
            mounts::accessed(&mut node.borrow_mut(), o.mount.as_deref());
        }
        let notification_node = o.node.as_ref().unwrap_or(node);
        if !Arc::ptr_eq(notification_node, node) && result.is_ok() {
            mounts::accessed(&mut notification_node.borrow_mut(), o.mount.as_deref());
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
