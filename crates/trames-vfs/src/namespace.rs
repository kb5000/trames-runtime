// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
impl Vfs {
    pub fn flock(&mut self, fd: u32, operation: u32) -> Result<()> {
        if operation & !15 != 0 || !matches!(operation & !4, 1 | 2 | 8) {
            return Err(Errno(22));
        }
        let open = self.descriptor(fd)?.open.clone();
        let inode = open.borrow().node.as_ref().ok_or(Errno(9))?.borrow().inode;
        let mut fs = self.fs.borrow_mut();
        fs.flock.retain(|_, owners| {
            owners.retain(|(owner, _)| owner.strong_count() != 0);
            !owners.is_empty()
        });
        let owners = fs.flock.entry(inode).or_default();
        let kind = operation & !4;
        // Linux conversion drops this description's old lock before competing
        // for the new one; it is not an atomic lock upgrade.
        owners.retain(|(owner, _)| {
            !owner
                .upgrade()
                .is_some_and(|other| Rc::ptr_eq(&other, &open))
        });
        if kind != 8
            && owners.iter().any(|(owner, lock)| {
                owner
                    .upgrade()
                    .is_some_and(|other| !Rc::ptr_eq(&other, &open) && (kind == 2 || *lock == 2))
            })
        {
            return Err(Errno(11));
        }
        owners.retain(|(owner, _)| {
            !owner
                .upgrade()
                .is_some_and(|other| Rc::ptr_eq(&other, &open))
        });
        if kind != 8 {
            owners.push((Rc::downgrade(&open), kind));
        }
        Ok(())
    }

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
        if target.as_ref().is_some_and(|n| Rc::ptr_eq(n, &src)) {
            return Ok(());
        }
        let is_dir = matches!(src.borrow().content, Content::Directory);
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
                let mut dest_prefix = dest.clone();
                dest_prefix.push(b'/');
                if filesystem
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
        if let Some(n) = &target {
            let mut n = n.borrow_mut();
            if n.links == 0 {
                if let Content::File(b) = &mut n.content {
                    b.orphan(true);
                }
            }
        }
        Ok(())
    }
    fn chmod_node(&self, node: Rc<RefCell<Node>>, mode: u32) -> Result<()> {
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        if !self.credentials.has_cap(capabilities::FOWNER) && self.credentials.fsuid != n.uid {
            return Err(Errno(1));
        }
        let old_mode = n.mode;
        let old_time = n.times[2];
        n.mode = (n.mode & !0o7777) | (mode & 0o7777);
        if !self.credentials.has_cap(capabilities::FSETID) && !self.credentials.in_group(n.gid) {
            n.mode &= !0o2000;
        }
        n.times[2] = storage::Timestamp::now();
        drop(n);
        if let Err(e) = self.checkpoint() {
            let mut n = node.borrow_mut();
            n.mode = old_mode;
            n.times[2] = old_time;
            return Err(e);
        }
        Ok(())
    }
    pub fn chmod_at(&mut self, dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
        let (path, node) = self.metadata_target(dirfd, path, true)?;
        path.writable()?;
        self.chmod_node(node, mode)
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
        self.chmod_node(node, mode)
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
        let n = self
            .descriptor(fd)?
            .open
            .borrow()
            .node
            .clone()
            .ok_or(Errno(22))?;
        if matches!(n.borrow().content, Content::Symlink(_)) {
            return Err(Errno(95));
        }
        self.chmod_node(n, mode)
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
        let mut n = node.borrow_mut();
        let old = n.times;
        for (i, value) in values.into_iter().enumerate() {
            if let Some(value) = value {
                n.times[i] = value;
            }
        }
        n.times[2] = now;
        drop(n);
        if let Err(e) = self.checkpoint() {
            node.borrow_mut().times = old;
            return Err(e);
        }
        Ok(())
    }
}
