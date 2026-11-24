// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(super) const RENAME_NOREPLACE: u32 = 1;
pub(super) const RENAME_EXCHANGE: u32 = 2;

// Accepted source identity, independent of a later pathname or numeric FD.
pub(crate) struct LinkSource {
    pub(super) path: ResolvedPath,
    pub(super) node: NodeRef,
    pub(super) policy: Arc<sysctl::NameiPolicy>,
    _usage: Option<mounts::MountUse>,
    _original: Option<ResolvedInode>,
}
fn link_resource_path(key: Vec<u8>, mount: Option<Arc<Mount>>) -> ResolvedPath {
    ResolvedPath {
        key,
        mount,
        directory_inode: None,
        indexed_position: None,
        #[cfg(all(feature = "hostfs", unix))]
        host_position: None,
        retained_directory: None,
        proc_binding: None,
    }
}
pub(super) fn link_permission(
    c: &Credentials,
    policy: u32,
    source: &Node,
    delegated: bool,
) -> Result<()> {
    if c.fsuid == source.uid
        || policy == 0
        || c.inode_cap(capabilities::FOWNER, source.uid, source.gid)
    {
        return Ok(());
    }
    let safe = source.mode & 0o170000 == 0o100000
        && source.mode & 0o4000 == 0
        && source.mode & 0o2010 != 0o2010
        && (delegated && matches!(source.content, Content::Fuse) || c.allows_node(source, 6));
    if safe {
        Ok(())
    } else {
        Err(Errno(1))
    }
}

fn sticky_create_permission(c: &Credentials, level: u32, owner: u32, dir: &Node) -> Result<()> {
    if level != 0
        && owner != c.fsuid
        && owner != dir.uid
        && dir.mode & 0o1000 != 0
        && (dir.mode & 2 != 0 || level == 2 && dir.mode & 0o020 != 0)
    {
        return Err(Errno(13));
    }
    Ok(())
}

impl Vfs {
    pub fn link_at(&mut self, oldfd: i32, old: &[u8], newfd: i32, new: &[u8]) -> Result<()> {
        self.link_at_follow(oldfd, old, newfd, new, false, false)
    }
    pub(super) fn link_at_follow(
        &mut self,
        oldfd: i32,
        old: &[u8],
        newfd: i32,
        new: &[u8],
        follow: bool,
        empty_path: bool,
    ) -> Result<()> {
        let accepted = if empty_path && oldfd != AT_FDCWD && !old.starts_with(b"/") {
            let descriptor = self.descriptor(oldfd as u32)?;
            let open = descriptor.open.borrow();
            let Some((identity, namespace)) = &open.link_credentials else {
                return Err(Errno(2));
            };
            if self.credentials.open_identity().0 != *identity
                && !self
                    .credentials
                    .has_ns_cap(namespace, capabilities::DAC_READ_SEARCH)
            {
                return Err(Errno(2));
            }
            drop(open);
            Some(descriptor)
        } else {
            None
        };
        let source = if old.is_empty() && empty_path {
            match &accepted {
                Some(descriptor) => self.accept_link_source((
                    link_resource_path(Vec::new(), None),
                    Some(ResolvedTarget::Descriptor(descriptor.open.clone())),
                ))?,
                None => {
                    let path = self.base(oldfd)?;
                    self.accept_link_source((path, None))?
                }
            }
        } else {
            let entry = self.resolve_entry_operation(
                oldfd,
                old,
                follow,
                true,
                0,
                true,
                None,
                accepted.as_ref(),
            )?;
            self.accept_link_source(entry)?
        };
        let (dest, fuse) = self.capture_fuse_path(newfd, new, false)?;
        if let Some(plan) = fuse {
            let rights = landlock::make(source.node.borrow().mode);
            return self.defer_fuse_namespace(
                plan,
                fuse::NamespaceAction::Link(Box::new(source)),
                None,
                rights,
            );
        }
        if self.proc_directory_tree(&dest) {
            self.node(&dest)?;
            return Err(Errno(17));
        }
        self.link_resolved(&source.path, &dest, Some(&source.node), None)
    }
    fn accept_link_source(&self, (mut path, magic): ResolvedEntry) -> Result<LinkSource> {
        let original = match magic {
            Some(ResolvedTarget::Descriptor(open)) => Some(self.proc_open_node(&open, &path)?),
            Some(ResolvedTarget::Inode(file)) => Some(file),
            None => None,
        };
        let node = if let Some(file) = &original {
            path = link_resource_path(file.label.clone(), file.mount.clone());
            #[cfg(all(feature = "hostfs", unix))]
            {
                path.host_position = file
                    .host_file
                    .as_ref()
                    .map(|f| hostfs::Position::inode(file.node.clone(), f.clone()));
            }
            file.node.clone()
        } else {
            self.node(&path)?
        };
        path.directory_inode = Some(node.clone());
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &path.filesystem(self).host {
            if let Some(file) = host.lease_path(&path.filesystem(self), &path, &node, O_PATH)? {
                path.host_position = Some(hostfs::Position::inode(node.clone(), file));
            }
        }
        let usage = path
            .mount
            .as_ref()
            .map(|m| mounts::MountUse::new(m.identity.clone()));
        Ok(LinkSource {
            path,
            node,
            policy: self.namei_policy.clone(),
            _usage: usage,
            _original: original,
        })
    }
    pub(super) fn check_link_source(&self, source: &Node) -> Result<()> {
        link_permission(
            &self.credentials,
            self.namei_policy.get(sysctl::Protection::Hardlinks),
            source,
            true,
        )
    }
    pub(super) fn check_sticky_create(&self, path: &ResolvedPath, node: &NodeRef) -> Result<()> {
        let n = node.borrow();
        if n.uid == self.credentials.fsuid {
            return Ok(());
        }
        let level = match n.content {
            Content::File(_) => self.namei_policy.get(sysctl::Protection::Regular),
            Content::Fifo(_) => self.namei_policy.get(sysctl::Protection::Fifos),
            _ => 0,
        };
        if level == 0 {
            return Ok(());
        }
        let owner = n.uid;
        drop(n);
        let parent = self.node(&path.parent())?;
        let dir = parent.borrow();
        sticky_create_permission(&self.credentials, level, owner, &dir)
    }
    pub(super) fn check_sticky_create_in(
        &self,
        mode: u32,
        owner: u32,
        parent: &NodeRef,
    ) -> Result<()> {
        let level = match mode & 0o170000 {
            0o100000 => self.namei_policy.get(sysctl::Protection::Regular),
            0o010000 => self.namei_policy.get(sysctl::Protection::Fifos),
            _ => 0,
        };
        if level == 0 || owner == self.credentials.fsuid {
            return Ok(());
        }
        sticky_create_permission(&self.credentials, level, owner, &parent.borrow())
    }
    /// Move or exchange complete subtrees under one namespace transaction.
    pub fn rename_at(
        &mut self,
        oldfd: i32,
        old: &[u8],
        newfd: i32,
        new: &[u8],
        flags: u32,
    ) -> Result<()> {
        if !matches!(flags, 0 | RENAME_NOREPLACE | RENAME_EXCHANGE) {
            return Err(Errno(22));
        }
        let special_final = |path: &[u8]| {
            matches!(
                path.rsplit(|b| *b == b'/').find(|part| !part.is_empty()),
                None | Some(b"." | b"..")
            )
        };
        let (source, source_fuse) = self.capture_fuse_path(oldfd, old, false)?;
        if let Some(source_plan) = source_fuse {
            // Capture only the destination's original base/root here. Its
            // actual mount/parent traversal starts after the source parent.
            let dest = fuse::NamespaceTarget::unresolved(self, newfd, new)?;
            if special_final(old) {
                return Err(Errno(16));
            }
            if special_final(new) {
                return Err(Errno(if flags == RENAME_NOREPLACE { 17 } else { 16 }));
            }
            return self.defer_fuse_namespace(
                source_plan,
                fuse::NamespaceAction::Rename { flags },
                Some(dest),
                landlock::REMOVE_FILE | landlock::REMOVE_DIR | landlock::REFER,
            );
        }
        let (dest, dest_fuse) = self.capture_fuse_path(newfd, new, false)?;
        if special_final(old) {
            return Err(Errno(16));
        }
        if special_final(new) {
            return Err(Errno(if flags == RENAME_NOREPLACE { 17 } else { 16 }));
        }
        if self.is_mount_root(&source) || self.is_mount_root(&dest) {
            return Err(Errno(16));
        }
        if let Some(dest_plan) = dest_fuse {
            let source = fuse::NamespaceTarget::ordinary(source, old.ends_with(b"/"));
            return self.defer_fuse_namespace(
                source,
                fuse::NamespaceAction::Rename { flags },
                Some(dest_plan.into()),
                landlock::REMOVE_FILE | landlock::REMOVE_DIR | landlock::REFER,
            );
        }
        self.rename_resolved(
            source,
            dest,
            flags,
            old.ends_with(b"/"),
            new.ends_with(b"/"),
        )
    }
    pub(super) fn rename_resolved(
        &mut self,
        source: ResolvedPath,
        dest: ResolvedPath,
        flags: u32,
        source_trailing: bool,
        dest_trailing: bool,
    ) -> Result<()> {
        if source.mount.as_ref().map(|m| m.id) != dest.mount.as_ref().map(|m| m.id) {
            return Err(Errno(18));
        }
        source.writable()?;
        let filesystem = source.filesystem(self);
        let _namespace = filesystem.namespace.lock().unwrap();
        let source = self.rebase_indexed(source)?;
        let dest = self.rebase_indexed(dest)?;
        let exchange = flags == RENAME_EXCHANGE;
        let src = self.node(&source)?;
        if source_trailing && !matches!(src.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let target = match self.node(&dest) {
            Ok(node) => Some(node),
            Err(Errno(2)) if !exchange && !self.proc_directory_tree(&dest) => None,
            Err(error) => return Err(error),
        };
        if flags == RENAME_NOREPLACE && target.is_some() {
            return Err(Errno(17));
        }
        if dest_trailing
            && (!matches!(src.borrow().content, Content::Directory)
                || target
                    .as_ref()
                    .is_some_and(|node| !matches!(node.borrow().content, Content::Directory)))
        {
            return Err(Errno(20));
        }
        if target.as_ref().is_some_and(|n| Arc::ptr_eq(n, &src)) {
            return Ok(());
        }
        let old_parent = self.check_parent_write(&source)?;
        let new_parent = self.check_parent_write(&dest)?;
        self.check_remove(&source)?;
        if target.is_some() {
            self.check_remove(&dest)?;
        }
        let is_dir = matches!(src.borrow().content, Content::Directory);
        let target_dir = target
            .as_ref()
            .is_some_and(|n| matches!(n.borrow().content, Content::Directory));
        if self.credentials.landlock.fs_mask() != 0 {
            let source_parent = source.parent();
            let dest_parent = dest.parent();
            self.landlock_check(
                &source_parent,
                Some(&old_parent),
                if is_dir {
                    landlock::REMOVE_DIR
                } else {
                    landlock::REMOVE_FILE
                },
            )?;
            let mut dest_rights = landlock::make(src.borrow().mode);
            if target.is_some() {
                dest_rights |= if target_dir {
                    landlock::REMOVE_DIR
                } else {
                    landlock::REMOVE_FILE
                };
            }
            self.landlock_check(&dest_parent, Some(&new_parent), dest_rights)?;
            if exchange {
                let target = target.as_ref().expect("exchange destination");
                self.landlock_check(
                    &source_parent,
                    Some(&old_parent),
                    landlock::make(target.borrow().mode),
                )?;
                self.landlock_reparent(&dest_parent, &source_parent, target)?;
            }
            self.landlock_reparent(&source_parent, &dest_parent, &src)?;
        }
        if exchange && target_dir && mounts::below(&source, &dest) {
            return Err(Errno(22));
        }
        if (is_dir || exchange && target_dir)
            && filesystem.borrow().overlay.as_ref().is_some_and(|o| {
                is_dir && o.lower_directory(&source)
                    || exchange && target_dir && o.lower_directory(&dest)
            })
        {
            // redirect_dir=off: Linux asks userspace to copy a lower/merged
            // directory tree rather than silently changing lower dentries.
            return Err(Errno(18));
        }
        if is_dir && mounts::below(&dest, &source) {
            return Err(Errno(22));
        }
        if !exchange && target.is_some() {
            if is_dir != target_dir {
                return Err(Errno(if is_dir { 20 } else { 21 }));
            }
            if target_dir {
                #[cfg(all(feature = "hostfs", unix))]
                let check_cached_children = filesystem.host.is_none();
                #[cfg(not(all(feature = "hostfs", unix)))]
                let check_cached_children = true;
                let mut dest_prefix = dest.clone();
                dest_prefix.push(b'/');
                if check_cached_children
                    && filesystem
                        .borrow()
                        .paths
                        .range(dest_prefix.key.clone()..)
                        .next()
                        .is_some_and(|(p, _)| p.starts_with(&dest_prefix))
                {
                    return Err(Errno(39));
                }
            }
        }
        let _change = self.path_change();
        let parent_times = directory::EntryTimes::lock(Some(&old_parent), Some(&new_parent));
        let mut fs = filesystem.borrow_mut();
        let mut moves = Vec::new();
        let mut plan = |from: &ResolvedPath,
                        to: &ResolvedPath,
                        node: &NodeRef,
                        directory: bool|
         -> Result<()> {
            moves.push((from.key.clone(), to.key.clone(), node.clone()));
            if directory {
                let mut prefix = from.key.clone();
                prefix.push(b'/');
                for (path, child) in fs
                    .paths
                    .range(prefix.clone()..)
                    .take_while(|(p, _)| p.starts_with(&prefix))
                {
                    let mut new_path = to.key.clone();
                    new_path.extend_from_slice(&path[from.len()..]);
                    if new_path.len() >= MAX_PATH {
                        return Err(Errno(36));
                    }
                    moves.push((path.clone(), new_path, child.clone()));
                }
            }
            Ok(())
        };
        plan(&source, &dest, &src, is_dir)?;
        let exchanged = target.as_ref().filter(|_| exchange);
        let overwritten = target.as_ref().filter(|_| !exchange);
        if let Some(n) = exchanged {
            plan(&dest, &source, n, target_dir)?;
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            host.rename(&filesystem, &source, &dest, flags)?;
        }
        if let Some(n) = overwritten {
            n.borrow_mut().links -= 1;
        }
        for (from, _, _) in &moves {
            fs.paths.remove(from);
        }
        for (_, to, n) in &moves {
            fs.paths.insert(to.clone(), n.clone());
        }
        let now = storage::Timestamp::now();
        let src_ctime = std::mem::replace(&mut src.borrow_mut().times[2], now);
        let other_ctime = exchanged.map(|n| std::mem::replace(&mut n.borrow_mut().times[2], now));
        if let Err(e) = parent_times.commit(now, || fs.checkpoint()) {
            for (_, to, _) in &moves {
                fs.paths.remove(to);
            }
            for (from, _, n) in moves {
                fs.paths.insert(from, n);
            }
            src.borrow_mut().times[2] = src_ctime;
            if let Some((n, time)) = exchanged.zip(other_ctime) {
                n.borrow_mut().times[2] = time;
            }
            if let Some(n) = overwritten {
                n.borrow_mut().links += 1;
                fs.paths.insert(dest.key.clone(), n.clone());
            }
            return Err(e);
        }
        drop(fs);
        drop(parent_times);
        if let Some(n) = overwritten {
            self.notification_link(&dest, n, false);
            inotify::notify(n, inotify::ATTRIB, None);
            let mut n = n.borrow_mut();
            if n.links == 0 {
                if matches!(n.content, Content::Directory) {
                    n.notifications.destroy(true);
                }
                if let Content::File(b) = &mut n.content {
                    b.orphan(true);
                }
            }
        }
        let old_entry = self.notification_parent(&source);
        let new_entry = self.notification_parent(&dest);
        if let (Some((old_parent, old_name)), Some((new_parent, new_name))) =
            (&old_entry, &new_entry)
        {
            inotify::move_link(&src, old_parent, old_name, new_parent, new_name);
            if let Some(other) = exchanged {
                inotify::move_link(other, new_parent, new_name, old_parent, old_name);
            }
        }
        let notify_move = |from: &Option<(NodeRef, Vec<u8>)>,
                           to: &Option<(NodeRef, Vec<u8>)>,
                           node: &NodeRef,
                           directory| {
            let cookie = (self.open_id() as u32).max(1);
            let kind = if directory { inotify::ISDIR } else { 0 };
            for (entry, mask) in [(from, inotify::MOVED_FROM), (to, inotify::MOVED_TO)] {
                if let Some((parent, name)) = entry {
                    parent
                        .borrow()
                        .notifications
                        .send(mask | kind, cookie, name, false);
                }
            }
            node.borrow()
                .notifications
                .send(inotify::MOVE_SELF, 0, b"", false);
        };
        notify_move(&old_entry, &new_entry, &src, is_dir);
        if let Some(other) = exchanged {
            notify_move(&new_entry, &old_entry, other, target_dir);
        }
        Ok(())
    }
    fn chmod_node(
        &self,
        node: NodeRef,
        mode: u32,
        persistent: bool,
        link: Option<&Arc<inotify::Link>>,
    ) -> Result<()> {
        let _metadata = node.metadata.lock().unwrap();
        self.pseudo_metadata_mutable(&node)?;
        let mut n = node.borrow_mut();
        if !self
            .credentials
            .inode_cap(capabilities::FOWNER, n.uid, n.gid)
            && self.credentials.fsuid != n.uid
        {
            return Err(Errno(1));
        }
        let old_mode = n.mode;
        let old_time = n.times[2];
        let old_acl = n.xattrs.get(acl::ACCESS).cloned();
        #[cfg(all(feature = "hostfs", unix))]
        {
            drop(n);
            if let Some(host) = self.host_for_node(&node) {
                host.chmod(&node, mode)?;
            }
            n = node.borrow_mut();
        }
        n.mode = (n.mode & !0o7777) | (mode & 0o7777);
        if !self
            .credentials
            .inode_cap(capabilities::FSETID, n.uid, n.gid)
            && !self.credentials.in_group(n.gid)
        {
            n.mode &= !0o2000;
        }
        let acl_mode = n.mode;
        if let Some(value) = n.xattrs.get_mut(acl::ACCESS) {
            acl::chmod(value, acl_mode, false);
        }
        n.times[2] = storage::Timestamp::now();
        drop(n);
        if let Err(e) = if persistent && !node.borrow().volatile && node.borrow().links != 0 {
            self.checkpoint()
        } else {
            Ok(())
        } {
            let mut n = node.borrow_mut();
            n.mode = old_mode;
            n.times[2] = old_time;
            if let Some(value) = old_acl {
                n.xattrs.insert(acl::ACCESS.to_vec(), value);
            }
            return Err(e);
        }
        inotify::notify(&node, inotify::ATTRIB, link);
        Ok(())
    }
    pub fn chmod_at(&mut self, dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
        let target = self.metadata_target(dirfd, path, true)?;
        if let Some(result) = self.fuse_path_attributes(&target, fuse::AttributeChange::Mode(mode))
        {
            return result;
        }
        let MetadataTarget { path, node, _magic } = target;
        path.writable()?;
        let link = self.event_link(&path, &node);
        self.chmod_node(node, mode, true, link.as_ref())
    }
    pub fn chmod_at_flags(
        &mut self,
        dirfd: i32,
        path: &[u8],
        mode: u32,
        nofollow: bool,
    ) -> Result<()> {
        let target = self.metadata_target(dirfd, path, !nofollow)?;
        if let Some(result) = self.fuse_path_attributes(&target, fuse::AttributeChange::Mode(mode))
        {
            return result;
        }
        let MetadataTarget { path, node, _magic } = target;
        path.writable()?;
        if matches!(node.borrow().content, Content::Symlink(_)) {
            return Err(Errno(95));
        }
        let link = self.event_link(&path, &node);
        self.chmod_node(node, mode, true, link.as_ref())
    }
    pub fn chmod_fd(&mut self, fd: u32, mode: u32) -> Result<()> {
        if self.flags(fd)? & O_PATH != 0 {
            return Err(Errno(9));
        }
        self.chmod_fd_at(fd, mode)
    }
    /// AT_EMPTY_PATH operates on an inode reference, including O_PATH.
    pub fn chmod_fd_at(&mut self, fd: u32, mode: u32) -> Result<()> {
        if let Some(result) = self.fuse_fd_attributes(fd, fuse::AttributeChange::Mode(mode)) {
            return result;
        }
        self.fd_writable(fd)?;
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        if let Some(socket) = &open.local {
            let (uid, gid) = open.owner;
            if self.credentials.fsuid != uid
                && !self.credentials.inode_cap(capabilities::FOWNER, uid, gid)
            {
                return Err(Errno(1));
            }
            let mut mode = mode & 0o7777;
            if !self.credentials.in_group(gid)
                && !self.credentials.inode_cap(capabilities::FSETID, uid, gid)
            {
                mode &= !0o2000;
            }
            socket.inode_permissions.store(mode, Ordering::Relaxed);
            return Ok(());
        }
        let n = open.metadata_node().ok_or(Errno(22))?;
        if matches!(n.borrow().content, Content::Symlink(_)) {
            return Err(Errno(95));
        }
        self.chmod_node(
            n,
            mode,
            open.node.is_some(),
            open.notification
                .as_ref()
                .and_then(|lease| lease.link.as_ref()),
        )
    }
    pub fn set_times(
        &mut self,
        dirfd: i32,
        path: Option<&[u8]>,
        times: Option<[[i64; 2]; 2]>,
    ) -> Result<()> {
        self.set_times_flags(dirfd, path, times, 0)
    }
    pub fn set_times_flags(
        &mut self,
        dirfd: i32,
        path: Option<&[u8]>,
        times: Option<[[i64; 2]; 2]>,
        flags: u32,
    ) -> Result<()> {
        if times.is_some_and(|t| t.iter().all(|pair| pair[1] == UTIME_OMIT)) {
            return Ok(());
        }
        if flags & !0x1100 != 0 || path.is_none() && dirfd != AT_FDCWD && flags != 0 {
            return Err(Errno(22));
        }
        let now = storage::Timestamp::now();
        let mut values = [Some(now); 2];
        if let Some(times) = times {
            for i in 0..2 {
                values[i] = match times[i][1] {
                    UTIME_NOW => Some(now),
                    UTIME_OMIT => None,
                    nanos if (0..1_000_000_000).contains(&nanos) => Some(storage::Timestamp {
                        seconds: times[i][0],
                        nanos: nanos as u32,
                    }),
                    _ => return Err(Errno(22)),
                };
            }
        }
        let empty_path = path == Some(&[][..]) && flags & 0x1000 != 0;
        let path = if dirfd == AT_FDCWD && flags & 0x1000 != 0 && path.is_none_or(|p| p.is_empty())
        {
            Some(b".".as_slice())
        } else if empty_path {
            None
        } else {
            path
        };
        if path.is_none() {
            if dirfd == AT_FDCWD {
                return Err(Errno(14));
            }
            if !empty_path && self.flags(dirfd as u32)? & O_PATH != 0 {
                return Err(Errno(9));
            }
            if let Some(result) =
                self.fuse_fd_attributes(dirfd as u32, fuse::AttributeChange::Times(times))
            {
                return result;
            }
            self.fd_writable(dirfd as u32)?;
        }
        let (node, link) = match path {
            Some(p) => {
                let target = self.metadata_target(dirfd, p, flags & 0x100 == 0)?;
                if let Some(result) =
                    self.fuse_path_attributes(&target, fuse::AttributeChange::Times(times))
                {
                    return result;
                }
                target.path.writable()?;
                let link = target
                    ._magic
                    .as_ref()
                    .and_then(|m| m.file.as_ref()?.notification.as_ref()?.link.clone())
                    .or_else(|| self.event_link(&target.path, &target.node));
                (target.node, link)
            }
            None => {
                let descriptor = self.descriptor(dirfd as u32)?;
                let open = descriptor.open.borrow();
                (
                    open.metadata_node().ok_or(Errno(22))?,
                    open.notification
                        .as_ref()
                        .and_then(|lease| lease.link.clone()),
                )
            }
        };
        let _metadata = node.metadata.lock().unwrap();
        self.pseudo_immutable(&node)?;
        {
            let n = node.borrow();
            let owner = self.credentials.fsuid == n.uid
                || self
                    .credentials
                    .inode_cap(capabilities::FOWNER, n.uid, n.gid);
            if !owner {
                if times.is_some_and(|t| !t.iter().all(|pair| pair[1] == UTIME_NOW)) {
                    return Err(Errno(1));
                }
                if !self.allowed(&n, 2) {
                    return Err(Errno(13));
                }
            }
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = self.host_for_node(&node) {
            host.times(&node, values)?;
        }
        let mut n = node.borrow_mut();
        let old = n.times;
        for (i, value) in values.into_iter().enumerate() {
            if let Some(value) = value {
                n.times[i] = value;
            }
        }
        n.times[2] = now;
        drop(n);
        if let Err(e) = if node.borrow().links != 0 {
            self.checkpoint()
        } else {
            Ok(())
        } {
            node.borrow_mut().times = old;
            return Err(e);
        }
        let mask = match (values[0].is_some(), values[1].is_some()) {
            (true, false) => inotify::ACCESS,
            (false, true) => inotify::MODIFY,
            _ => inotify::ATTRIB,
        };
        inotify::notify(&node, mask, link.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod namei_tests {
    use super::*;

    #[test]
    fn scoped_parent_walk_retries_until_all_path_changes_finish() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        let first = v.path_change();
        let second = v.path_change();
        drop(first);
        for policy in [8, 16] {
            assert_eq!(
                v.open_at_resolve(AT_FDCWD, b"a/..", O_DIRECTORY, 0, policy),
                Err(Errno(11))
            );
            let fd = v
                .open_at_resolve(AT_FDCWD, b"a", O_DIRECTORY, 0, policy)
                .unwrap();
            v.close(fd).unwrap();
        }
        let fd = v.open_at(AT_FDCWD, b"a/..", O_DIRECTORY, 0).unwrap();
        v.close(fd).unwrap();
        drop(second);
        let fd = v
            .open_at_resolve(AT_FDCWD, b"a/..", O_DIRECTORY, 0, 8)
            .unwrap();
        v.close(fd).unwrap();
    }
    fn setting(v: &mut Vfs, name: &str, value: &[u8]) -> Result<usize> {
        let path = format!("/proc/sys/fs/protected_{name}");
        let fd = v.open_at(AT_FDCWD, path.as_bytes(), 1, 0)?;
        let result = v.write(fd, value);
        v.close(fd)?;
        result
    }

    #[test]
    fn shared_link_policy_uses_filesystem_credentials_and_original_inode() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/public", 0o777).unwrap();
        v.chmod_at(AT_FDCWD, b"/public", 0o1777).unwrap();
        v.import_file(b"/target", Vec::new()).unwrap();
        v.symlink_at(b"/target", AT_FDCWD, b"/public/link").unwrap();
        v.chown_at(AT_FDCWD, b"/public/link", 1000, 1000, true)
            .unwrap();
        let mut user = v.clone();
        user.credentials = Credentials::user(1001, 1001);
        let link = |v: &mut Vfs| v.link_at(AT_FDCWD, b"/target", AT_FDCWD, b"/public/alias");
        assert_eq!(link(&mut user), Err(Errno(1)));
        assert_eq!(user.stat_at(AT_FDCWD, b"/public/link"), Err(Errno(13)));
        assert_eq!(
            user.readlink_at(AT_FDCWD, b"/public/link").unwrap(),
            b"/target"
        );
        assert_eq!(setting(&mut user, "hardlinks", b"0"), Err(Errno(13)));
        assert_eq!(setting(&mut v, "hardlinks", b"2"), Err(Errno(22)));
        setting(&mut v, "hardlinks", b"0").unwrap();
        link(&mut user).unwrap();
        setting(&mut v, "symlinks", b"0").unwrap();
        assert!(user.stat_at(AT_FDCWD, b"/public/link").is_ok());
        setting(&mut v, "hardlinks", b"1").unwrap();
        v.chmod_at(AT_FDCWD, b"/target", 0o666).unwrap();
        user.link_at(AT_FDCWD, b"/target", AT_FDCWD, b"/public/rw")
            .unwrap();
        v.chmod_at(AT_FDCWD, b"/target", 0o2776).unwrap();
        assert_eq!(
            user.link_at(AT_FDCWD, b"/target", AT_FDCWD, b"/public/sgid"),
            Err(Errno(1))
        );
        v.chmod_at(AT_FDCWD, b"/target", 0o2666).unwrap();
        user.link_at(AT_FDCWD, b"/target", AT_FDCWD, b"/public/sgid-data")
            .unwrap();
    }

    #[test]
    fn protected_create_checks_existing_files_and_fifos_in_sticky_directories() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.mkdir_at(AT_FDCWD, b"/group", 0o770).unwrap();
        v.chmod_at(AT_FDCWD, b"/group", 0o1770).unwrap();
        v.import_file(b"/group/file", Vec::new()).unwrap();
        v.mknod_at(AT_FDCWD, b"/group/fifo", 0o10644, 0).unwrap();
        for (name, path) in [("regular", b"/group/file"), ("fifos", b"/group/fifo")] {
            v.chown_at(AT_FDCWD, path, 1001, 1001, false).unwrap();
            let flags = O_CREAT | 0x800; // O_NONBLOCK, including for the FIFO.
            assert_eq!(setting(&mut v, name, b"3"), Err(Errno(22)));
            setting(&mut v, name, b"1").unwrap();
            let fd = v.open_at(AT_FDCWD, path, flags, 0).unwrap();
            v.close(fd).unwrap();
            setting(&mut v, name, b"2").unwrap();
            assert_eq!(v.open_at(AT_FDCWD, path, flags, 0), Err(Errno(13)));
            assert_eq!(v.open_at(AT_FDCWD, path, flags | 0x80, 0), Err(Errno(17)));
            let fd = v.open_at(AT_FDCWD, path, 0x800, 0).unwrap();
            v.close(fd).unwrap();
            v.chmod_at(AT_FDCWD, b"/group", 0o1777).unwrap();
            setting(&mut v, name, b"1").unwrap();
            assert_eq!(v.open_at(AT_FDCWD, path, flags, 0), Err(Errno(13)));
            v.chown_at(AT_FDCWD, path, 0, 0, false).unwrap();
            let fd = v.open_at(AT_FDCWD, path, flags, 0).unwrap();
            v.close(fd).unwrap();
            v.chmod_at(AT_FDCWD, b"/group", 0o1770).unwrap();
        }
    }

    #[test]
    fn link_timestamps_follow_access_mount_and_empty_path_descriptor() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/src", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/view", 0o755).unwrap();
        v.import_file(b"/target", Vec::new()).unwrap();
        v.symlink_at(b"/target", AT_FDCWD, b"/src/link").unwrap();
        v.mount(Some(b"/src"), b"/view", None, 4096, None).unwrap();
        let atime = |v: &Vfs| {
            let bytes = v.stat_at_flags(AT_FDCWD, b"/src/link", true).unwrap();
            i64::from_le_bytes(bytes[72..80].try_into().unwrap())
        };
        for flags in [mounts::MS_NOATIME, mounts::MS_RDONLY, mounts::MS_RELATIME] {
            v.mount(None, b"/view", None, 4096 | 32 | flags, None)
                .unwrap();
            v.set_times_flags(AT_FDCWD, Some(b"/src/link"), Some([[1, 0], [2, 0]]), 0x100)
                .unwrap();
            assert_eq!(atime(&v), 1);
            let fd = v
                .open_at(AT_FDCWD, b"/view/link", O_PATH | O_NOFOLLOW, 0)
                .unwrap();
            assert_eq!(v.readlink_at(fd as i32, b"").unwrap(), b"/target");
            v.close(fd).unwrap();
            v.stat_at(AT_FDCWD, b"/view/link").unwrap();
            assert_eq!(atime(&v) > 1, flags == mounts::MS_RELATIME);
        }
    }
}
