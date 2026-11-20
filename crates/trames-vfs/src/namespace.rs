// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(super) const RENAME_NOREPLACE: u32 = 1;
pub(super) const RENAME_EXCHANGE: u32 = 2;

impl Vfs {
    pub fn link_at(&mut self, oldfd: i32, old: &[u8], newfd: i32, new: &[u8]) -> Result<()> {
        self.link_at_follow(oldfd, old, newfd, new, false)
    }
    pub(super) fn link_at_follow(
        &mut self,
        oldfd: i32,
        old: &[u8],
        newfd: i32,
        new: &[u8],
        follow: bool,
    ) -> Result<()> {
        let source = self.resolve_final(oldfd, old, follow)?;
        let dest = self.resolve_final(newfd, new, false)?;
        if self.proc_directory_tree(&dest) {
            self.node(&source)?;
            self.node(&dest)?;
            return Err(Errno(17));
        }
        self.check_parent_write(&dest)?;
        self.link_resolved(&source, &dest, false)
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
        let source = self.resolve_final(oldfd, old, false)?;
        let dest = self.resolve_final(newfd, new, false)?;
        let special_final = |path: &[u8]| {
            matches!(
                path.rsplit(|b| *b == b'/').find(|part| !part.is_empty()),
                None | Some(b"." | b"..")
            )
        };
        if special_final(old) {
            return Err(Errno(16));
        }
        if special_final(new) {
            return Err(Errno(if flags == RENAME_NOREPLACE { 17 } else { 16 }));
        }
        if self.is_mount_root(&source) || self.is_mount_root(&dest) {
            return Err(Errno(16));
        }
        if source.mount.as_ref().map(|m| m.id) != dest.mount.as_ref().map(|m| m.id) {
            return Err(Errno(18));
        }
        source.writable()?;
        let filesystem = source.filesystem(self);
        let _namespace = filesystem.namespace.lock().unwrap();
        let exchange = flags == RENAME_EXCHANGE;
        let src = self.node(&source)?;
        let target = match self.node(&dest) {
            Ok(node) => Some(node),
            Err(Errno(2)) if !exchange && !self.proc_directory_tree(&dest) => None,
            Err(error) => return Err(error),
        };
        if flags == RENAME_NOREPLACE && target.is_some() {
            return Err(Errno(17));
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
            host.rename(&source.key, &dest.key, flags)?;
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
        let MetadataTarget { path, node, _magic } = self.metadata_target(dirfd, path, true)?;
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
        let MetadataTarget { path, node, _magic } = self.metadata_target(dirfd, path, !nofollow)?;
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
        self.fd_writable(fd)?;
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
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
            self.fd_writable(dirfd as u32)?;
        }
        let (node, link) = match path {
            Some(p) => {
                let target = self.metadata_target(dirfd, p, flags & 0x100 == 0)?;
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
