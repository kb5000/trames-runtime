// SPDX-License-Identifier: GPL-3.0-or-later
//! A copy-up owns its unpublished provider and completed byte prefixes.
use super::*;
use std::sync::{Mutex, Weak};

pub(super) type Copies = BTreeMap<usize, Weak<Mutex<Copy>>>;
pub(super) struct Copy {
    copies: Weak<SharedCell<Copies>>,
    owner: Weak<Mutex<Copy>>,
    node: NodeRef,
    truncate: bool,
    resources: Option<CgroupResourceContext>,
    stage: Option<Stage>,
    result: Option<Result<()>>,
}
impl Drop for Copy {
    fn drop(&mut self) {
        if let Some(copies) = self.copies.upgrade() {
            let mut copies = copies.borrow_mut();
            let id = pointer(&self.node);
            if copies
                .get(&id)
                .is_some_and(|copy| Weak::ptr_eq(copy, &self.owner))
            {
                copies.remove(&id);
            }
        }
    }
}
struct Stage {
    inode: u64,
    length: u64,
    caps: Option<file_caps::FileCaps>,
    sparse: Option<(Arc<file_data::PlainFile>, Arc<file_accounting::FileQuota>)>,
    source_sync: Option<mapped::DataSync>,
    copy: Option<storage::FileData>,
    offset: u64,
    bytes: Vec<u8>,
    written: usize,
    caps_done: bool,
    synced: bool,
}
impl Copy {
    fn prepare(&self, overlay: &Overlay) -> Result<Option<Stage>> {
        let upper = overlay.upper.as_ref().ok_or(Errno(30))?;
        let inode = overlay.allocate_inode()?;
        // Preserve upper-fs -> inode ordering. In particular, do not pin the
        // merged inode while waiting for an independently held upper namespace.
        let fs = upper.fs.borrow();
        let available = Vfs::filesystem_bytes(&fs).2;
        let node = self.node.borrow();
        let ids = mounts::idmap::Ids::from_mount(&upper.at.identity);
        if node.uid == u32::MAX || node.gid == u32::MAX {
            return Err(Errno(75));
        }
        ids.stored(false, node.uid)?;
        ids.stored(true, node.gid)?;
        ids.creator(&overlay.creator)?;
        projected_attrs(&node.xattrs, ids, true)?;
        if let Some(caps) = node.file_caps() {
            caps.translate(|id| ids.stored(false, id))?;
        }
        let Content::File(data) = &node.content else {
            return Ok(None);
        };
        let caps = node.file_caps();
        let length = if self.truncate { 0 } else { data.len() };
        if length != 0 {
            if let (Some(source), Some(mount)) = (data.source_node(), data.layer_mount()) {
                if !overlay.creator.allows_mapped(
                    &source.borrow(),
                    4,
                    mounts::idmap::Ids::from_mount(&mount),
                ) {
                    return Err(Errno(13));
                }
            }
        }
        let sparse = fs.quota.tmpfs.then(|| data.tmpfs_file()).flatten();
        if sparse.is_none() && length > available {
            return Err(Errno(28));
        }
        let (sparse, source_sync, copy) = if let Some(file) = sparse.filter(|_| !self.truncate) {
            (
                Some((file, fs.quota.clone())),
                Some(mapped::DataSync::capture(data, false)?),
                None,
            )
        } else {
            let copy = if let Some(disk) = &fs.disk {
                let copy = disk.create(inode)?;
                copy.bind_quota(fs.quota)?;
                copy
            } else {
                Vfs::ram_file(fs.quota)?
            };
            (None, None, Some(copy))
        };
        Ok(Some(Stage {
            inode,
            length,
            caps,
            sparse,
            source_sync,
            copy,
            offset: 0,
            bytes: Vec::new(),
            written: 0,
            caps_done: false,
            synced: false,
        }))
    }
    fn step(&mut self, overlay: &Overlay) -> Result<()> {
        if let Some(result) = self.result {
            return result;
        }
        if self.stage.is_none() {
            self.stage = self.prepare(overlay)?;
            if self.stage.is_none() {
                return Ok(());
            }
        }
        let stage = self.stage.as_mut().unwrap();
        if let Some((file, quota)) = &stage.sparse {
            if stage.copy.is_none() {
                if let Some(sync) = &mut stage.source_sync {
                    sync.run()?;
                }
                stage.copy = Some(file.copy_up_tmpfs(quota)?);
                stage.offset = stage.length;
            }
        }
        while stage.offset < stage.length {
            let goal = (stage.length - stage.offset).min(65536) as usize;
            while stage.bytes.len() < goal {
                let before = stage.bytes.len();
                let node = self.node.borrow();
                let Content::File(data) = &node.content else {
                    return Err(Errno(5));
                };
                data.read_into(
                    stage.offset + before as u64,
                    goal - before,
                    &mut stage.bytes,
                )?;
                if stage.bytes.len() == before {
                    return Err(Errno(5));
                }
            }
            while stage.written < stage.bytes.len() {
                let scope = resource_io::Scope::enter();
                let result = stage.copy.as_mut().unwrap().write_at(
                    stage.offset + stage.written as u64,
                    &stage.bytes[stage.written..],
                );
                let pending = scope.finish();
                let progress = match &result {
                    Ok(count) => *count,
                    Err(_) => pending.as_ref().map_or(0, |pending| pending.progress),
                };
                assert!(
                    progress <= stage.bytes.len() - stage.written,
                    "copy-up write progress"
                );
                stage.written += progress;
                if let Some(pending) = pending {
                    return Err(resource_io::memory_error(pending.wait.fault(0)));
                }
                if result? == 0 {
                    return Err(Errno(5));
                }
            }
            stage.offset += stage.bytes.len() as u64;
            stage.bytes.clear();
            stage.written = 0;
        }
        let copy = stage.copy.as_mut().unwrap();
        if !stage.caps_done {
            if stage.caps.is_some() {
                copy.edit_capabilities(stage.caps, 0)?;
            } else {
                copy.revoke_capabilities()?;
            }
            stage.caps_done = true;
        }
        if !stage.synced {
            copy.sync(false)?;
            stage.synced = true;
        }
        let mut node = self.node.borrow_mut();
        node.inode = stage.inode;
        node.content = Content::File(stage.copy.take().unwrap());
        Ok(())
    }
}

pub(super) fn run(overlay: &Overlay, node: &NodeRef, truncate: bool) -> Result<()> {
    let id = pointer(node);
    if !overlay.uncopied.borrow().contains(&id) {
        return Ok(());
    }
    let copy = {
        let mut copies = overlay.copying.borrow_mut();
        if let Some(copy) = copies.get(&id).and_then(Weak::upgrade) {
            copy
        } else {
            // No filesystem, node, byte or quota callback under this weak map.
            let copy = Arc::new_cyclic(|owner| {
                Mutex::new(Copy {
                    copies: Arc::downgrade(&overlay.copying),
                    owner: owner.clone(),
                    node: node.clone(),
                    truncate,
                    resources: Some(CgroupResourceContext::capture()),
                    stage: None,
                    result: None,
                })
            });
            copies.insert(id, Arc::downgrade(&copy));
            copy
        }
    };
    let (result, pending, notifications, retired) = {
        let mut cursor = copy.lock().unwrap();
        let _resources = cursor.resources.as_ref().map(|resources| resources.enter());
        let scope = resource_io::Scope::enter();
        let result = cursor.step(overlay);
        let pending = scope.finish();
        let notifications = cursor
            .stage
            .as_mut()
            .and_then(|stage| stage.source_sync.as_mut())
            .map(|sync| sync.take_notifications());
        let retired = if pending.is_none() {
            cursor.result = Some(result);
            Some((cursor.stage.take(), cursor.resources.take()))
        } else {
            None
        };
        (result, pending, notifications, retired)
    };
    // Ticket notifications, source pins, staged bytes and captured origins are
    // all retired outside the per-copy progress mutex and provider byte locks.
    drop(notifications);
    drop(retired);
    if let Some(pending) = pending {
        return Err(resource_io::memory_error(
            resource_io::holding(pending.wait, copy).fault(0),
        ));
    }
    if result.is_ok() {
        overlay.uncopied.borrow_mut().remove(&id);
        overlay.dirty.borrow_mut().insert(id);
    }
    let mut copies = overlay.copying.borrow_mut();
    if copies
        .get(&id)
        .and_then(Weak::upgrade)
        .is_some_and(|current| Arc::ptr_eq(&current, &copy))
    {
        copies.remove(&id);
    }
    result
}
