// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest identities only. They never change the containing app's host identity.
use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub groups: Vec<u32>,
    pub caps: capabilities::Capabilities,
}
impl Credentials {
    pub fn user(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            euid: uid,
            suid: uid,
            gid,
            egid: gid,
            sgid: gid,
            fsuid: uid,
            fsgid: gid,
            groups: Vec::new(),
            caps: capabilities::Capabilities::for_uid(uid),
        }
    }
    pub fn has_cap(&self, cap: u32) -> bool {
        self.caps.has(cap)
    }
    pub fn in_group(&self, gid: u32) -> bool {
        self.fsgid == gid || self.groups.contains(&gid)
    }
    pub fn set_res_ids(&mut self, group: bool, values: [u32; 3]) -> Result<()> {
        let current = if group {
            [self.gid, self.egid, self.sgid]
        } else {
            [self.uid, self.euid, self.suid]
        };
        if !self.has_cap(if group {
            capabilities::SETGID
        } else {
            capabilities::SETUID
        }) && values
            .iter()
            .any(|v| *v != u32::MAX && !current.contains(v))
        {
            return Err(Errno(1));
        }
        let mut next = current;
        for i in 0..3 {
            if values[i] != u32::MAX {
                next[i] = values[i];
            }
        }
        if group {
            [self.gid, self.egid, self.sgid] = next;
            self.fsgid = self.egid;
        } else {
            self.caps.uids_changed(current, next);
            [self.uid, self.euid, self.suid] = next;
            self.fsuid = self.euid;
        }
        Ok(())
    }
    pub fn set_id(&mut self, group: bool, value: u32) -> Result<()> {
        if value == u32::MAX {
            return Err(Errno(22));
        }
        if self.has_cap(if group {
            capabilities::SETGID
        } else {
            capabilities::SETUID
        }) {
            self.set_res_ids(group, [value; 3])
        } else {
            self.set_res_ids(group, [u32::MAX, value, u32::MAX])
        }
    }
}
impl Vfs {
    /// Metadata lookup remains public; dereferencing sensitive links and opening
    /// protected data use the ptrace-style check, as procfs does on Linux.
    pub(super) fn check_proc_inspection(&self, at: &ResolvedPath, link: bool) -> Result<()> {
        if !self.uses_pseudo(at) {
            return Ok(());
        }
        let Some(rest) = at.strip_prefix(b"/proc/") else {
            return Ok(());
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let parse = |s: &[u8]| {
            std::str::from_utf8(s)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        };
        let (pid, group, key) = match parts.as_slice() {
            [group, b"task", pid, key, ..] => (parse(pid), parse(group), *key),
            [pid, key, ..] => (parse(pid), None, *key),
            _ => return Ok(()),
        };
        let protected = if link {
            matches!(key, b"cwd" | b"root" | b"exe" | b"fd" | b"ns")
        } else {
            matches!(key, b"maps" | b"environ" | b"auxv" | b"fdinfo")
        };
        if protected {
            let pseudo = self.pseudo.borrow();
            let runtime = self.proc_runtime(at, &pseudo.runtime);
            if let Some(target) = runtime
                .processes
                .iter()
                .find(|p| Some(p.pid) == pid && group.is_none_or(|g| p.tgid == g))
            {
                if !self.may_inspect(at, &runtime, target) {
                    return Err(Errno(13));
                }
            }
        }
        Ok(())
    }
    pub fn dumpable(&self) -> u64 {
        u64::from(self.dumpable.get())
    }
    pub fn set_dumpable(&self, value: u64) -> Result<()> {
        if value > 1 {
            return Err(Errno(22));
        }
        self.dumpable.set(value != 0);
        Ok(())
    }
    pub fn unshare_dumpable(&mut self) {
        self.dumpable = Rc::new(Cell::new(self.dumpable.get()));
    }
    pub fn fs_identity(&self) -> [u32; 4] {
        let c = &self.credentials;
        [c.euid, c.egid, c.fsuid, c.fsgid]
    }
    pub fn reset_dumpable_after_ids(&self, old: [u32; 4]) {
        if self.fs_identity() != old {
            self.dumpable.set(false);
        }
    }
    /// Selected ptrace READ_FSCREDS policy for sensitive proc objects.
    /// Same thread group and CAP_SYS_PTRACE bypass the ordinary ID/dump checks.
    pub(super) fn may_inspect<P: PathArg + ?Sized>(
        &self,
        at: &P,
        runtime: &RuntimeInfo,
        target: &ProcessInfo,
    ) -> bool {
        let own = self.proc_namespace(at).local(self.pid);
        if runtime
            .processes
            .iter()
            .any(|p| p.pid == own && p.tgid == target.tgid)
            || self.credentials.has_cap(capabilities::SYS_PTRACE)
        {
            return true;
        }
        let c = &self.credentials;
        let t = &target.credentials;
        !target.nondumpable
            && [t.uid, t.euid, t.suid].iter().all(|id| *id == c.fsuid)
            && [t.gid, t.egid, t.sgid].iter().all(|id| *id == c.fsgid)
            && t.caps.permitted & !c.caps.effective == 0
    }

    pub fn apply_exec_credentials(&mut self, path: &[u8]) -> Result<()> {
        let file = self.executable_file_at(AT_FDCWD, path, 0)?;
        self.apply_exec_file_credentials(&file)
    }
    pub fn apply_exec_file_credentials(&mut self, file: &ExecutableFile) -> Result<()> {
        let n = file.node.borrow();
        let readable = self.allowed(&n, 4);
        let old_permitted = self.credentials.caps.permitted;
        let nosuid = file
            .mount
            .as_ref()
            .is_some_and(|m| m.flags.get() & mounts::MS_NOSUID != 0);
        if !nosuid && !self.credentials.caps.no_new_privs && n.mode & 0o4000 != 0 {
            self.credentials.euid = n.uid;
            self.credentials.fsuid = n.uid;
        }
        if !nosuid && !self.credentials.caps.no_new_privs && n.mode & 0o2010 == 0o2010 {
            self.credentials.egid = n.gid;
            self.credentials.fsgid = n.gid;
        }
        let c = &mut self.credentials;
        c.caps
            .exec(c.uid, c.euid, c.uid != c.euid || c.gid != c.egid);
        // NNP also prevents a pre-existing effective-ID mismatch from
        // surviving exec. Capability computation uses the pre-downgrade IDs.
        if c.caps.no_new_privs && (c.uid != c.euid || c.gid != c.egid) {
            c.euid = c.uid;
            c.egid = c.gid;
        }
        self.dumpable = Rc::new(Cell::new(
            readable
                && c.uid == c.euid
                && c.gid == c.egid
                && c.caps.permitted & !old_permitted == 0,
        ));
        c.fsuid = c.euid;
        c.fsgid = c.egid;
        self.credentials.suid = self.credentials.euid;
        self.credentials.sgid = self.credentials.egid;
        Ok(())
    }
    pub fn access_at(
        &self,
        dirfd: i32,
        path: &[u8],
        mode: u32,
        effective: bool,
        nofollow: bool,
    ) -> Result<()> {
        if mode & !7 != 0 {
            return Err(Errno(22));
        }
        let mut view = self.clone();
        if !effective {
            view.credentials.fsuid = self.credentials.uid;
            view.credentials.fsgid = self.credentials.gid;
            if self.credentials.caps.securebits & capabilities::NO_SETUID_FIXUP == 0 {
                view.credentials.caps.effective = if self.credentials.uid == 0 {
                    self.credentials.caps.permitted
                } else {
                    0
                };
            }
        }
        let path = view.resolve_final(dirfd, path, !nofollow)?;
        if mode & 2 != 0 {
            path.writable()?;
        }
        let node = view.node(&path)?;
        if view.allowed(&node.borrow(), mode) {
            Ok(())
        } else {
            Err(Errno(13))
        }
    }
    pub(super) fn check_remove(&self, path: &ResolvedPath) -> Result<()> {
        if self.is_mount_root(path) {
            return Err(Errno(16));
        }
        let parent = self.node(&path.parent())?;
        let p = parent.borrow();
        let uid = self.credentials.fsuid;
        if p.mode & 0o1000 != 0
            && !self.credentials.has_cap(capabilities::FOWNER)
            && uid != p.uid
            && uid != self.node(path)?.borrow().uid
        {
            return Err(Errno(1));
        }
        Ok(())
    }
    pub(super) fn allowed(&self, node: &Node, bits: u32) -> bool {
        let c = &self.credentials;
        let shift = if c.fsuid == node.uid {
            6
        } else if c.in_group(node.gid) {
            3
        } else {
            0
        };
        (node.mode >> shift) & bits == bits
            || c.has_cap(capabilities::DAC_OVERRIDE)
                && (bits & 1 == 0
                    || matches!(node.content, Content::Directory)
                    || node.mode & 0o111 != 0)
            || c.has_cap(capabilities::DAC_READ_SEARCH)
                && bits & 2 == 0
                && (bits & 1 == 0 || matches!(node.content, Content::Directory))
    }
    fn chown_node(&self, node: NodeRef, uid: u32, gid: u32, persistent: bool) -> Result<()> {
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        let c = &self.credentials;
        if !c.has_cap(capabilities::CHOWN)
            && (c.fsuid != n.uid
                || (uid != u32::MAX && uid != n.uid)
                || (gid != u32::MAX && gid != n.gid && !c.in_group(gid)))
        {
            return Err(Errno(1));
        }
        let old = (n.uid, n.gid, n.mode, n.times[2]);
        #[cfg(all(feature = "hostfs", unix))]
        {
            drop(n);
            if let Some(host) = self.host_for_node(&node) {
                host.chown(&node, uid, gid)?;
            }
            n = node.borrow_mut();
        }
        if uid != u32::MAX {
            n.uid = uid;
        }
        if gid != u32::MAX {
            n.gid = gid;
        }
        if matches!(n.content, Content::File(_)) && (uid != u32::MAX || gid != u32::MAX) {
            n.mode &= !0o6000;
        }
        n.times[2] = storage::Timestamp::now();
        drop(n);
        if let Err(error) = if persistent && node.borrow().links != 0 {
            self.checkpoint()
        } else {
            Ok(())
        } {
            let mut n = node.borrow_mut();
            (n.uid, n.gid, n.mode, n.times[2]) = old;
            return Err(error);
        }
        inotify::notify(&node, inotify::ATTRIB, None);
        Ok(())
    }
    pub fn chown_at(
        &mut self,
        dirfd: i32,
        path: &[u8],
        uid: u32,
        gid: u32,
        nofollow: bool,
    ) -> Result<()> {
        let (path, node) = self.metadata_target(dirfd, path, !nofollow)?;
        path.writable()?;
        self.chown_node(node, uid, gid, true)
    }
    pub fn chown_fd(&mut self, fd: u32, uid: u32, gid: u32) -> Result<()> {
        if self.flags(fd)? & O_PATH != 0 {
            return Err(Errno(9));
        }
        self.chown_fd_at(fd, uid, gid)
    }
    /// AT_EMPTY_PATH operates on an inode reference, including O_PATH.
    pub fn chown_fd_at(&mut self, fd: u32, uid: u32, gid: u32) -> Result<()> {
        self.fd_writable(fd)?;
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        let node = open.metadata_node().ok_or(Errno(22))?;
        self.chown_node(node, uid, gid, open.node.is_some())
    }
}
