// SPDX-License-Identifier: GPL-3.0-or-later
//! Real anonymous regular inodes. No temporary pathname enters the namespace.
use super::*;
pub(super) const BIT: u32 = 0x400000;
impl Vfs {
    pub(super) fn open_tmpfile<const PATH_TRUNCATE: bool>(
        &mut self,
        entry: ResolvedEntry,
        flags: u32,
        mode: u32,
        publication: Option<&DirectFiles>,
        reservation: fd_table::ReservedFd,
    ) -> Result<u32> {
        let (directory, parent) = self.directory_resolved(entry)?;
        directory.writable()?;
        if !self.allowed_on(&parent.borrow(), 3, &directory) {
            return Err(Errno(13));
        }
        let fs = directory.filesystem(self);
        #[cfg(all(feature = "hostfs", unix))]
        if fs.host.is_some() {
            return Err(Errno(95));
        }
        if !directory.mount.as_ref().is_some_and(|m| {
            matches!(
                m.kind,
                mounts::Kind::Root
                    | mounts::Kind::Tmpfs
                    | mounts::Kind::Ramfs
                    | mounts::Kind::Overlay
            )
        }) {
            return Err(Errno(95));
        }
        if fs.borrow().overlay.as_ref().is_some_and(|o| !o.has_upper()) {
            return Err(Errno(30));
        }
        let ids = directory.ids(self);
        let (uid, gid) = ids.creator(&self.credentials)?;
        let mut file_mode = 0o100000 | (mode & 0o7777);
        let (gid, attrs) = {
            let n = parent.borrow();
            let group = if n.mode & 0o2000 != 0 { n.gid } else { gid };
            if n.mode & 0o2000 != 0 && file_mode & 0o2010 == 0o2010 {
                let (owner, group) = ids.owner(n.uid, n.gid);
                if !self.credentials.in_group(group)
                    && !self
                        .credentials
                        .inode_cap(capabilities::FSETID, owner, group)
                {
                    file_mode &= !0o2000;
                }
            }
            let attrs = acl::inherit(Some(&n), &Content::Null, &mut file_mode, self.umask(), true);
            (group, attrs)
        };
        let content = Content::File(self.empty_data_at(&directory)?);
        let _namespace = fs.namespace.lock().unwrap();
        let mut data = fs.borrow_mut();
        data.admit_inode()?;
        let inode = if let Some(o) = &data.overlay {
            o.allocate_inode()?
        } else {
            let inode = data.next_inode;
            data.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
            inode
        };
        let mut node = Inode::new(Node {
            identity: 0,
            record_locks: Default::default(),
            whole_locks: Default::default(),
            notifications: Default::default(),
            path_hint: Default::default(),
            device: directory.mount.as_ref().map_or(0xfd01, |m| m.device),
            content,
            mode: file_mode,
            uid,
            gid,
            volatile: false,
            inode,
            links: 0,
            times: [storage::Timestamp::now(); 3],
            xattrs: attrs,
            seals: None,
        });
        node.tmpfile = (1 | if flags & 0x80 == 0 { 2 } else { 0 }).into();
        let node = Arc::new(node);
        data.track_inode(&node)?;
        drop(data);
        drop(_namespace);
        if let Some(o) = fs.overlay_handle() {
            o.prepare_tmpfile(&node)?;
        }
        if let Content::File(data) = &mut node.borrow_mut().content {
            data.orphan(true);
        }
        let mut label = directory.key.clone();
        if label != b"/" {
            label.push(b'/');
        }
        label.extend_from_slice(format!("#{inode}").as_bytes());
        let mut path = directory.clone();
        path.key = label.clone();
        path.directory_inode = None;
        path.indexed_position = None;
        path.retained_directory = None;
        let file = ResolvedInode {
            node,
            label,
            mount: path.mount.clone(),
            file: None,
            #[cfg(all(feature = "hostfs", unix))]
            host_file: None,
            _image: None,
            _directory: path
                .mount
                .as_ref()
                .map(|m| Arc::new(mounts::MountUse::new(m.identity.clone()))),
        };
        self.landlock_check_parent(&path, None, landlock::MAKE_REG)?;
        self.open_resolved::<PATH_TRUNCATE>(
            (path, Some(ResolvedTarget::Inode(file))),
            flags,
            mode,
            publication,
            reservation,
        )
    }
}
