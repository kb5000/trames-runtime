// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
impl Vfs {
    pub fn link_at(&mut self, oldfd: i32, old: &[u8], newfd: i32, new: &[u8]) -> Result<()> {
        let source = self.resolve_final(oldfd, old, false)?;
        let dest = self.resolve_final(newfd, new, false)?;
        self.check_parent_write(&dest)?;
        self.link_resolved(&source, &dest, false)
    }
    /// Rename a file or subtree with one manifest replacement. Only NOREPLACE is
    /// supported in addition to the ordinary overwrite semantics.
    pub fn rename_at(
        &mut self,
        oldfd: i32,
        old: &[u8],
        newfd: i32,
        new: &[u8],
        flags: u32,
    ) -> Result<()> {
        if flags & !1 != 0 {
            return Err(Errno(22));
        }
        let source = self.resolve_final(oldfd, old, false)?;
        let dest = self.resolve_final(newfd, new, false)?;
        if self.is_mount_root(&source) || self.is_mount_root(&dest) {
            return Err(Errno(16));
        }
        if source.mount.as_ref().map(|m| m.id) != dest.mount.as_ref().map(|m| m.id) {
            return Err(Errno(18));
        }
        let filesystem = source.filesystem(self);
        let src = self.node(&source)?;
        self.check_parent_write(&source)?;
        self.check_parent_write(&dest)?;
        self.check_remove(&source)?;
        let target = self.node(&dest).ok();
        if target.is_some() {
            self.check_remove(&dest)?;
        }
        if target.is_some() && flags == 1 {
            return Err(Errno(17));
        }
        if target.as_ref().is_some_and(|n| Arc::ptr_eq(n, &src)) {
            return Ok(());
        }
        let is_dir = matches!(src.borrow().content, Content::Directory);
        if is_dir
            && filesystem
                .borrow()
                .overlay
                .as_ref()
                .is_some_and(|o| o.lower_directory(&source))
        {
            // redirect_dir=off: Linux asks userspace to copy a lower/merged
            // directory tree rather than silently changing lower dentries.
            return Err(Errno(18));
        }
        let mut prefix = source.clone();
        prefix.push(b'/');
        if is_dir && dest.starts_with(&prefix) {
            return Err(Errno(22));
        }
        if let Some(n) = &target {
            let target_dir = matches!(n.borrow().content, Content::Directory);
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
                        .keys()
                        .any(|p| p.starts_with(&dest_prefix))
                {
                    return Err(Errno(39));
                }
            }
        }
        let mut fs = filesystem.borrow_mut();
        let mut replacements = Vec::new();
        for (path, n) in &fs.paths {
            if *path == source.key || (is_dir && path.starts_with(&prefix)) {
                let mut new_path = dest.clone();
                new_path.extend_from_slice(&path[source.len()..]);
                if new_path.len() >= MAX_PATH {
                    return Err(Errno(36));
                }
                replacements.push((path.clone(), new_path, n.clone()));
            }
        }
        let old_paths = fs.paths.clone();
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            host.rename(&source.key, &dest.key, flags == 1)?;
        }
        if let Some(n) = &target {
            n.borrow_mut().links -= 1;
            fs.paths.remove(&dest.key);
        }
        for (path, _, _) in &replacements {
            fs.paths.remove(path);
        }
        for (_, path, n) in replacements {
            fs.paths.insert(path.key, n);
        }
        let old_time = src.borrow().times[2];
        src.borrow_mut().times[2] = storage::Timestamp::now();
        if let Err(e) = fs.checkpoint() {
            fs.paths = old_paths;
            src.borrow_mut().times[2] = old_time;
            if let Some(n) = &target {
                n.borrow_mut().links += 1;
            }
            return Err(e);
        }
        drop(fs);
        if let Some(n) = &target {
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
        let cookie = (self.open_id() as u32).max(1);
        self.notification_entry(&source, inotify::MOVED_FROM, cookie, is_dir);
        self.notification_entry(&dest, inotify::MOVED_TO, cookie, is_dir);
        if let (Some((old_parent, old_name)), Some((new_parent, new_name))) = (
            self.notification_parent(&source),
            self.notification_parent(&dest),
        ) {
            inotify::move_link(&src, &old_parent, &old_name, &new_parent, &new_name);
        }
        src.borrow_mut()
            .notifications
            .send(inotify::MOVE_SELF, 0, b"", false);
        Ok(())
    }
    fn chmod_node(&self, node: NodeRef, mode: u32, persistent: bool) -> Result<()> {
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        if !self.credentials.has_cap(capabilities::FOWNER) && self.credentials.fsuid != n.uid {
            return Err(Errno(1));
        }
        let old_mode = n.mode;
        let old_time = n.times[2];
        #[cfg(all(feature = "hostfs", unix))]
        {
            drop(n);
            if let Some(host) = self.host_for_node(&node) {
                host.chmod(&node, mode)?;
            }
            n = node.borrow_mut();
        }
        n.mode = (n.mode & !0o7777) | (mode & 0o7777);
        if !self.credentials.has_cap(capabilities::FSETID) && !self.credentials.in_group(n.gid) {
            n.mode &= !0o2000;
        }
        n.times[2] = storage::Timestamp::now();
        drop(n);
        if let Err(e) = if persistent && node.borrow().links != 0 {
            self.checkpoint()
        } else {
            Ok(())
        } {
            let mut n = node.borrow_mut();
            n.mode = old_mode;
            n.times[2] = old_time;
            return Err(e);
        }
        inotify::notify(&node, inotify::ATTRIB, None);
        Ok(())
    }
    pub fn chmod_at(&mut self, dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
        let (path, node) = self.metadata_target(dirfd, path, true)?;
        path.writable()?;
        self.chmod_node(node, mode, true)
    }
    pub fn chmod_at_flags(
        &mut self,
        dirfd: i32,
        path: &[u8],
        mode: u32,
        nofollow: bool,
    ) -> Result<()> {
        let (path, node) = self.metadata_target(dirfd, path, !nofollow)?;
        path.writable()?;
        if matches!(node.borrow().content, Content::Symlink(_)) {
            return Err(Errno(95));
        }
        self.chmod_node(node, mode, true)
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
        self.chmod_node(n, mode, open.node.is_some())
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
        if flags & !0x100 != 0 || path.is_none() && flags != 0 {
            return Err(Errno(22));
        }
        let now = storage::Timestamp::now();
        let mut values = [Some(now); 2];
        if let Some(times) = times {
            for i in 0..2 {
                values[i] = match times[i][1] {
                    1_073_741_823 => Some(now),
                    1_073_741_822 => None,
                    nanos if (0..1_000_000_000).contains(&nanos) => Some(storage::Timestamp {
                        seconds: times[i][0],
                        nanos: nanos as u32,
                    }),
                    _ => return Err(Errno(22)),
                };
            }
        }
        if path.is_none() {
            self.fd_writable(dirfd as u32)?;
        }
        let node = match path {
            Some(p) => {
                let p = self.resolve_final(dirfd, p, flags & 0x100 == 0)?;
                p.writable()?;
                self.node(&p)?
            }
            None => self
                .descriptor(dirfd as u32)?
                .open
                .borrow()
                .node
                .clone()
                .ok_or(Errno(22))?,
        };
        self.pseudo_immutable(&node)?;
        if values.iter().all(Option::is_none) {
            return Ok(());
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
        inotify::notify(&node, inotify::ATTRIB, None);
        Ok(())
    }
}
