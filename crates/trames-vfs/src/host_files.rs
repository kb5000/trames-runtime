// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted host export retains its original inode across namespace changes.
use super::*;
use std::io::{Read, Write};

pub struct HostEdit {
    node: NodeRef,
    path: ResolvedPath,
    filesystem: fs_data::FsHandle,
}

pub struct HostExport {
    node: NodeRef,
}
impl Vfs {
    /// Conditional editor saves are restricted to the same private filesystem
    /// as before. Retain its original inode/path and mapping admission once.
    pub fn host_edit(&self, path: &[u8]) -> Result<HostEdit> {
        let path = self.resolve_final(AT_FDCWD, path, false)?;
        let filesystem = path.filesystem(self);
        if !filesystem.same_data(&self.fs) {
            return Err(Errno(18));
        }
        let node = self.node(&path)?;
        if !matches!(node.borrow().content, Content::File(_)) {
            return Err(Errno(21));
        }
        Ok(HostEdit {
            node,
            path,
            filesystem,
        })
    }
    pub fn host_export(&self, path: &[u8]) -> Result<HostExport> {
        let canonical = self.resolve(AT_FDCWD, path)?;
        let node = self.node(&canonical)?;
        {
            let n = node.borrow();
            if !self.allowed(&n, 4) {
                return Err(Errno(13));
            }
            if !matches!(n.content, Content::File(_)) {
                return Err(Errno(21));
            }
        }
        Ok(HostExport { node })
    }
}
impl HostEdit {
    pub fn layout(&self) -> Arc<trames_memory::layout::Layout> {
        self.node.layout.get_or_init(Default::default).clone()
    }
    /// Stage outside the transaction. The original namespace, inode and plain
    /// byte locks then protect validation through the path swap. Mapped bytes
    /// require the caller's original LayoutExclusive. No new I/O lock is added.
    /// Return true from validate for an already-applied retry, false to replace.
    pub fn replace(
        self,
        vfs: &mut Vfs,
        admission: &trames_memory::layout::LayoutExclusive,
        reader: &mut impl Read,
        validate: impl FnOnce(u64, &mut dyn Read) -> Result<bool>,
    ) -> Result<u64> {
        assert!(
            Arc::ptr_eq(&self.layout(), admission.layout()),
            "original edit admission"
        );
        match vfs.stage_import(reader) {
            Ok((data, _)) => self.commit(vfs, Some(data), true, validate),
            // A successful prior save needs no new staging quota to retry.
            Err(Errno(28)) => self.commit(vfs, None, true, validate),
            Err(error) => Err(error),
        }
    }
    pub(super) fn replace_unchecked(self, vfs: &mut Vfs, reader: &mut impl Read) -> Result<u64> {
        let (data, count) = vfs.stage_import(reader)?;
        self.commit(vfs, Some(data), false, |_, _| Ok(false))?;
        Ok(count)
    }
    fn commit(
        &self,
        vfs: &Vfs,
        staged_data: Option<storage::FileData>,
        checked: bool,
        validate: impl FnOnce(u64, &mut dyn Read) -> Result<bool>,
    ) -> Result<u64> {
        let _namespace = self.filesystem.namespace.lock().unwrap();
        vfs.check_parent_write(&self.path)?;
        if vfs.node(&self.path).is_ok() {
            vfs.check_remove(&self.path)?;
        }
        // FS -> inode -> bytes is the existing checkpoint lock order. This
        // cold explicit compare-and-replace transaction can block namespace
        // observers, but never asks unrelated CPUs to return their execution.
        let mut fs = self.filesystem.borrow_mut();
        let current = fs.paths.get(&self.path.key).cloned();
        if checked
            && !current
                .as_ref()
                .is_some_and(|node| Arc::ptr_eq(node, &self.node))
        {
            return Err(Errno(116));
        }
        if current
            .as_ref()
            .is_some_and(|node| matches!(node.borrow().content, Content::Directory))
        {
            return Err(Errno(21));
        }
        let previous_next = fs.next_inode;
        let previous_inodes = fs.inodes.len();
        let mut old = self.node.borrow_mut();
        let Content::File(data) = &old.content else {
            return Err(Errno(21));
        };
        let inode = old.inode;
        let replace = |bytes: &mut dyn Read| {
            if validate(inode, bytes)? {
                return Ok(None);
            }
            let data = staged_data.ok_or(Errno(28))?;
            fs.admit_inode()?;
            let inode = match data.inode() {
                Some(inode) => inode,
                None => match &fs.overlay {
                    Some(overlay) => overlay.allocate_inode()?,
                    None => fs.next_inode,
                },
            };
            if inode == fs.next_inode {
                fs.next_inode = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
            }
            let staged = Arc::new(Inode::new(Node {
                identity: 0,
                record_locks: Default::default(),
                whole_locks: Default::default(),
                notifications: Default::default(),
                path_hint: Default::default(),
                device: old.device,
                content: Content::File(data),
                mode: old.file_metadata().mode,
                uid: old.uid,
                gid: old.gid,
                volatile: false,
                inode,
                links: 1,
                times: [storage::Timestamp::now(); 3],
                seals: None,
                xattrs: old.xattrs.clone(),
            }));
            fs.track_inode(&staged)?;
            fs.paths.insert(self.path.key.clone(), staged.clone());
            Ok(Some(staged))
        };
        let replaced = if !checked {
            // Rename replacement does not consume old mapped bytes and never
            // requests their layout ticket or blocks unrelated mapped writers.
            replace(&mut std::io::empty())?
        } else if let storage::FileData::Plain(plain) = data {
            plain.with_reader(replace)?
        } else {
            // Node custody excludes regular mapped I/O; the accepted backing
            // ticket excludes CPU/native mapped writers. Plain fast-path OFDs
            // have already relinquished byte authority when mapping appeared.
            struct Reader<'a> {
                data: &'a storage::FileData,
                offset: u64,
            }
            impl Read for Reader<'_> {
                fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                    let bytes = self
                        .data
                        .read_at(self.offset, out.len())
                        .map_err(|e| std::io::Error::from_raw_os_error(e.0 as i32))?;
                    out[..bytes.len()].copy_from_slice(&bytes);
                    self.offset += bytes.len() as u64;
                    Ok(bytes.len())
                }
            }
            replace(&mut Reader { data, offset: 0 })?
        };
        let Some(staged) = replaced else {
            return Ok(inode);
        };
        let replacing_original = current
            .as_ref()
            .is_some_and(|node| Arc::ptr_eq(node, &self.node));
        if replacing_original {
            old.links -= 1;
        }
        drop(old); // Namespace already swapped; old OFDs now write old inode.
        if !replacing_original {
            if let Some(target) = &current {
                target.borrow_mut().links -= 1;
            }
        }
        if let Err(error) = fs.checkpoint() {
            if let Some(target) = &current {
                fs.paths.insert(self.path.key.clone(), target.clone());
                target.borrow_mut().links += 1;
            } else {
                fs.paths.remove(&self.path.key);
            }
            fs.next_inode = previous_next;
            fs.inodes.truncate(previous_inodes);
            return Err(error);
        }
        let inode = staged.borrow().inode;
        if let Content::File(data) = &mut staged.borrow_mut().content {
            data.orphan(false);
        }
        drop(fs);
        if let Some(target) = current {
            vfs.notification_link(&self.path, &target, false);
            inotify::notify(&target, inotify::ATTRIB, None);
            let mut old = target.borrow_mut();
            if old.links == 0 {
                if let Content::File(data) = &mut old.content {
                    data.orphan(true);
                }
            }
        }
        let cookie = (vfs.open_id() as u32).max(1);
        vfs.notification_entry(&self.path, inotify::MOVED_TO, cookie, false);
        if let Some((parent, name)) = vfs.notification_parent(&self.path) {
            inotify::link(&staged, &parent, &name);
        }
        Ok(inode)
    }
}
impl HostExport {
    pub fn layout(&self) -> Arc<trames_memory::layout::Layout> {
        self.node.layout.get_or_init(Default::default).clone()
    }
    pub fn len(&self) -> u64 {
        self.node.logical_size().load(Ordering::Relaxed)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The caller retains original backing admission while consuming mapped
    /// bytes. No pathname or guest descriptor lookup is repeated after waiting.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<u64> {
        let node = self.node.borrow();
        let Content::File(data) = &node.content else {
            return Err(Errno(21));
        };
        let mut offset = 0;
        while offset < data.len() {
            let bytes = data.read_at(offset, 65536)?;
            if bytes.is_empty() {
                return Err(Errno(5));
            }
            writer.write_all(&bytes).map_err(storage::host_errno)?;
            offset += bytes.len() as u64;
        }
        writer.flush().map_err(storage::host_errno)?;
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicBool, mpsc};
    fn read(v: &Vfs, path: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        v.export_writer(path, &mut bytes).unwrap();
        bytes
    }
    fn admit(edit: &HostEdit) -> trames_memory::layout::LayoutExclusive {
        edit.layout().write().try_enter().ok().unwrap()
    }
    #[test]
    fn completed_edit_retry_needs_no_staging_quota() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"done".to_vec()).unwrap();
        v.set_storage_limits(StorageLimits {
            file_bytes: 4,
            nodes: 128,
        })
        .unwrap();
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        edit.replace(&mut v, &admission, &mut &b"done"[..], |_, reader| {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"done");
            Ok(true)
        })
        .unwrap();
        assert_eq!(read(&v, b"/file"), b"done");
        assert_eq!(v.capacity().used_bytes, 4);
    }
    #[test]
    fn failed_manifest_commit_retains_original_file_and_releases_anonymous_stage() {
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let path = Temp(std::env::temp_dir().join(format!(
                "trames-host-edit-fault-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        std::fs::create_dir(&path.0).unwrap();
        let mut v = Vfs::open_disk(&path.0, DiskOptions::default()).unwrap();
        v.import_file(b"/file", b"old".to_vec()).unwrap();
        let used = v.capacity().used_bytes;
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        let result = edit.replace(&mut v, &admission, &mut &b"replacement"[..], |_, _| {
            std::fs::create_dir(path.0.join("manifest.new")).unwrap();
            Ok(false)
        });
        assert!(result.is_err());
        assert_eq!(read(&v, b"/file"), b"old");
        assert_eq!(v.capacity().used_bytes, used);
        assert!(!v
            .fs
            .borrow()
            .paths
            .keys()
            .any(|p| p.starts_with(b"/.trames-")));
        std::fs::remove_dir(path.0.join("manifest.new")).unwrap();
        drop(v);
        let reopened = Vfs::open_disk(&path.0, DiskOptions::default()).unwrap();
        assert_eq!(read(&reopened, b"/file"), b"old");
    }
    #[test]
    fn accepted_context_observes_pending_bindings_without_retiring_or_consuming_them() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/live", 0x42, 0o644).unwrap();
        let mut state = v.task_namespaces();
        state.with_credentials(|credentials, _| credentials.euid = 1000);
        state.publish_credentials();
        let accepted = v.host_files_context();
        assert_eq!(accepted.credentials.euid, 1000);
        assert_eq!(v.credentials.euid, 0);
        drop(accepted);
        assert!(v.shared_files().lookup(fd).unwrap().is_ok());
        assert!(v.sync_task_namespaces());
        assert_eq!(v.credentials.euid, 1000);
        let accepted = v.host_files_context();
        state.with_credentials(|credentials, _| credentials.euid = 1001);
        state.publish_credentials();
        assert_eq!(accepted.credentials.euid, 1000);
        assert_eq!(v.host_files_context().credentials.euid, 1001);
        assert!(v.sync_task_namespaces());
        v.close(fd).unwrap();
    }
    #[test]
    fn accepted_export_survives_replacement_and_namespace_alias_removal() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"old".to_vec()).unwrap();
        let export = v.host_export(b"/file").unwrap();
        let _admission = export.layout().write().try_enter().ok().unwrap();
        v.import_reader_replace(b"/file", &mut &b"new"[..]).unwrap();
        let mut bytes = Vec::new();
        export.write_to(&mut bytes).unwrap();
        assert_eq!(bytes, b"old");
        assert_eq!(read(&v, b"/file"), b"new");
    }
    #[test]
    fn checked_commit_preserves_old_descriptors_hardlinks_and_metadata() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"old".to_vec()).unwrap();
        v.link_at(AT_FDCWD, b"/file", AT_FDCWD, b"/alias").unwrap();
        v.chmod_at(AT_FDCWD, b"/file", 0o640).unwrap();
        v.set_xattr(
            AT_FDCWD,
            Some(b"/file"),
            true,
            b"user.edit",
            Some(b"kept"),
            0,
        )
        .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 0, 0).unwrap();
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        let inode = edit
            .replace(&mut v, &admission, &mut &b"new"[..], |_, reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"old");
                Ok(false)
            })
            .unwrap();
        assert_eq!(read(&v, b"/file"), b"new");
        assert_eq!(read(&v, b"/alias"), b"old");
        assert_eq!(v.read(fd, 100).unwrap(), b"old");
        let stat = v.stat_at(AT_FDCWD, b"/file").unwrap();
        assert_eq!(u64::from_le_bytes(stat[8..16].try_into().unwrap()), inode);
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o777,
            0o640
        );
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/file"), true, b"user.edit")
                .unwrap(),
            b"kept"
        );
        assert!(!v
            .fs
            .borrow()
            .paths
            .keys()
            .any(|p| p.starts_with(b"/.trames-edit-")));
    }
    #[test]
    fn checked_commit_retains_same_inode_changes_retry_and_cancellation() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"changed".to_vec()).unwrap();
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        assert_eq!(
            edit.replace(&mut v, &admission, &mut &b"new"[..], |_, reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"changed");
                Err(Errno(116))
            }),
            Err(Errno(116))
        );
        assert_eq!(read(&v, b"/file"), b"changed");
        drop(admission);
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        let before = v.stat_at(AT_FDCWD, b"/file").unwrap();
        edit.replace(&mut v, &admission, &mut &b"changed"[..], |_, _| Ok(true))
            .unwrap();
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/file").unwrap()[8..16],
            &before[8..16]
        );
        drop(admission);
        struct Cancel;
        impl Read for Cancel {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::Interrupted.into())
            }
        }
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        assert_eq!(
            edit.replace(&mut v, &admission, &mut Cancel, |_, _| panic!(
                "cancelled staging cannot commit"
            )),
            Err(Errno(4))
        );
        assert!(!v
            .fs
            .borrow()
            .paths
            .keys()
            .any(|p| p.starts_with(b"/.trames-edit-")));
    }
    #[test]
    fn checked_commit_excludes_plain_fast_writes_through_the_path_swap() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"old".to_vec()).unwrap();
        let node = v.node(b"/file").unwrap();
        let plain = match &node.borrow().content {
            Content::File(storage::FileData::Plain(p)) => p.clone(),
            _ => unreachable!(),
        };
        let edit = v.host_edit(b"/file").unwrap();
        let admission = admit(&edit);
        let (start, wait) = mpsc::sync_channel(0);
        let (attempt, began) = mpsc::sync_channel(0);
        let done = Arc::new(AtomicBool::new(false));
        let writer_done = done.clone();
        let writer = std::thread::spawn(move || {
            wait.recv().unwrap();
            attempt.send(()).unwrap();
            plain.write_at(0, b"late").unwrap();
            writer_done.store(true, Ordering::Release);
        });
        edit.replace(&mut v, &admission, &mut &b"new"[..], |_, reader| {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"old");
            start.send(()).unwrap();
            began.recv().unwrap();
            assert!(!done.load(Ordering::Acquire));
            Ok(false)
        })
        .unwrap();
        writer.join().unwrap();
        assert!(done.load(Ordering::Acquire));
        assert_eq!(read(&v, b"/file"), b"new");
        assert_eq!(
            match &node.borrow().content {
                Content::File(d) => d.read_at(0, 100).unwrap(),
                _ => unreachable!(),
            },
            b"late"
        );
    }
}
