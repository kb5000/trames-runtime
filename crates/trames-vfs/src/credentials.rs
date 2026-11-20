// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest identities only. They never change the containing app's host identity.
use super::*;

/// One original task's objective credentials. Observers take one coherent
/// record; ordinary caller-side file/network checks use their retained value.
#[derive(Default)]
pub struct CredentialState {
    current: std::sync::RwLock<Credentials>,
    pidfd: std::sync::Mutex<Option<PidfdResources>>,
}
struct PidfdResources {
    namespaces: SharedNamespaceSnapshot,
    table: std::sync::Weak<fd_table::Membership>,
    dumpable: Dumpable,
}
impl CredentialState {
    pub fn new(credentials: Credentials) -> Self {
        Self {
            current: std::sync::RwLock::new(credentials),
            pidfd: Default::default(),
        }
    }
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, Credentials> {
        self.current.read().unwrap()
    }
    pub fn publish(&self, credentials: &Credentials) {
        self.current.write().unwrap().clone_from(credentials);
    }
    /// Publish Files, namespace membership and mm at the same credential boundary as
    /// exec/unshare. A pidfd does not own the target table or keep it alive.
    pub fn publish_pidfd_resources(
        &self,
        credentials: &Credentials,
        files: &SharedFiles,
        dumpable: Dumpable,
        namespaces: SharedNamespaceSnapshot,
    ) {
        let mut target = self.current.write().unwrap();
        target.clone_from(credentials);
        *self.pidfd.lock().unwrap() = Some(PidfdResources {
            namespaces,
            table: Arc::downgrade(&files.0),
            dumpable,
        });
    }
    pub fn receive_pidfd_file(
        &self,
        caller: &Credentials,
        same_group: bool,
        fd: u32,
        into: &SharedFiles,
    ) -> Result<u32> {
        self.with_pidfd_resources(caller, same_group, |resources| {
            let files = resources.table.upgrade().ok_or(Errno(3))?;
            into.receive_pidfd_slot(&files, fd)
        })
    }
    pub fn pidfd_namespaces(
        &self,
        caller: &Credentials,
        same_group: bool,
        flags: u64,
    ) -> Result<PidfdNamespaces> {
        self.with_pidfd_resources(caller, same_group, |resources| {
            resources.namespaces.select(flags)
        })
    }
    fn with_pidfd_resources<T>(
        &self,
        caller: &Credentials,
        same_group: bool,
        accept: impl FnOnce(&PidfdResources) -> Result<T>,
    ) -> Result<T> {
        let target = self.current.read().unwrap();
        let binding = self.pidfd.lock().unwrap();
        let resources = binding.as_ref().ok_or(Errno(3))?;
        // Both READ_REALCREDS (setns) and ATTACH_REALCREDS (getfd) compare real IDs and permitted capabilities.
        if !same_group
            && !caller.has_ns_cap(&target.user_namespace, capabilities::SYS_PTRACE)
            && (!resources.dumpable.get()
                || caller.user_namespace != target.user_namespace
                || [target.uid, target.euid, target.suid]
                    .iter()
                    .any(|id| *id != caller.uid)
                || [target.gid, target.egid, target.sgid]
                    .iter()
                    .any(|id| *id != caller.gid)
                || target.caps.permitted & !caller.caps.permitted != 0)
        {
            return Err(Errno(1));
        }
        accept(resources)
    }
    /// Directory/bootstrap compatibility; both signal target IDs change together.
    pub fn publish_signal_ids(&self, uid: u32, suid: u32) {
        let mut credentials = self.current.write().unwrap();
        credentials.uid = uid;
        credentials.suid = suid;
    }
    pub fn publish_kill_permission(&self, allowed: bool) {
        let mut credentials = self.current.write().unwrap();
        let bit = 1 << capabilities::KILL;
        if allowed {
            credentials.caps.effective |= bit;
        } else {
            credentials.caps.effective &= !bit;
        }
    }
}

/// Original mm dumpability, shared by CLONE_VM tasks and retained proc views.
#[derive(Clone)]
pub struct Dumpable(Arc<std::sync::atomic::AtomicBool>);
impl Default for Dumpable {
    fn default() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(true)))
    }
}
impl Dumpable {
    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    pub fn set(&self, value: bool) {
        self.0.store(value, Ordering::Relaxed);
    }
    pub fn fork(&self) -> Self {
        let copy = Self::default();
        copy.set(self.get());
        copy
    }
}

/// Accepted executable metadata and original credentials. A late TSYNC may
/// change only the task's monotonic NNP flag, without re-looking-up the file.
pub struct ExecCredentials {
    original: Credentials,
    uid: u32,
    gid: u32,
    mode: u32,
    nosuid: bool,
    readable: bool,
}
impl ExecCredentials {
    pub fn include_interpreter(&mut self, view: &Vfs, file: &ExecutableFile) {
        self.readable &= view.allowed(&file.node.borrow(), 4);
    }
    pub fn no_new_privs(&self) -> bool {
        self.original.caps.no_new_privs.get()
    }
    pub fn apply(&self, view: &mut Vfs) -> bool {
        let no_new_privs = self.no_new_privs();
        let old_permitted = self.original.caps.permitted;
        let mut c = self.original.clone();
        if !self.nosuid && !no_new_privs {
            if self.mode & 0o4000 != 0 && c.user_namespace.from_global(false, self.uid).is_some() {
                c.euid = self.uid;
            }
            if self.mode & 0o2010 == 0o2010
                && c.user_namespace.from_global(true, self.gid).is_some()
            {
                c.egid = self.gid;
            }
        }
        c.caps.exec_with_nnp(
            c.privilege_uid(c.uid),
            c.privilege_uid(c.euid),
            c.uid != c.euid || c.gid != c.egid,
            no_new_privs,
        );
        // Preserve the established pre-existing effective-ID downgrade rule.
        if no_new_privs && (c.uid != c.euid || c.gid != c.egid) {
            c.euid = c.uid;
            c.egid = c.gid;
        }
        view.dumpable = Dumpable::default();
        view.dumpable.set(
            self.readable
                && c.uid == c.euid
                && c.gid == c.egid
                && c.caps.permitted & !old_permitted == 0,
        );
        c.fsuid = c.euid;
        c.fsgid = c.egid;
        c.suid = c.euid;
        c.sgid = c.egid;
        view.credentials = c;
        no_new_privs
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credentials {
    pub user_namespace: UserNamespace,
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
    pub fn fs_identity(&self) -> [u32; 4] {
        [self.euid, self.egid, self.fsuid, self.fsgid]
    }
    pub(super) fn allows_node(&self, node: &Node, bits: u32) -> bool {
        let c = self;
        let shift = if c.fsuid == node.uid {
            6
        } else if c.in_group(node.gid) {
            3
        } else {
            0
        };
        let mode = node.file_metadata().mode;
        let permitted = if c.fsuid != node.uid {
            node.xattrs
                .get(acl::ACCESS)
                .map_or((mode >> shift) & bits == bits, |value| {
                    acl::allows(value, node, c, bits)
                })
        } else {
            (mode >> shift) & bits == bits
        };
        permitted
            || c.inode_cap(capabilities::DAC_OVERRIDE, node.uid, node.gid)
                && (bits & 1 == 0
                    || matches!(node.content, Content::Directory)
                    || mode & 0o111 != 0)
            || c.inode_cap(capabilities::DAC_READ_SEARCH, node.uid, node.gid)
                && bits & 2 == 0
                && (bits & 1 == 0 || matches!(node.content, Content::Directory))
    }
    pub fn user(uid: u32, gid: u32) -> Self {
        Self {
            user_namespace: UserNamespace::default(),
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
        self.user_namespace.is_initial() && self.caps.has(cap)
    }
    pub fn has_local_cap(&self, cap: u32) -> bool {
        self.caps.has(cap)
    }
    pub fn has_ns_cap(&self, namespace: &UserNamespace, cap: u32) -> bool {
        namespace.capable(self, cap)
    }
    // Capability rules compare mapped IDs. The configurable display value for
    // an unmapped UID can itself be zero.
    fn privilege_uid(&self, id: u32) -> u32 {
        self.user_namespace
            .from_global(false, id)
            .unwrap_or(u32::MAX)
    }
    pub fn local_id(&self, group: bool, id: u32) -> u32 {
        self.user_namespace.visible(group, id)
    }
    pub fn mapped_id(&self, group: bool, id: u32) -> Result<u32> {
        self.user_namespace.to_global(group, id).ok_or(Errno(22))
    }
    pub fn enter_user_namespace(&mut self, namespace: UserNamespace) {
        let nnp = self.caps.no_new_privs.clone();
        self.user_namespace = namespace;
        self.caps = capabilities::Capabilities::default();
        self.caps.no_new_privs = nnp;
    }
    pub fn inode_cap(&self, cap: u32, uid: u32, gid: u32) -> bool {
        self.has_local_cap(cap)
            && (self.user_namespace.is_initial()
                || self.user_namespace.from_global(false, uid).is_some()
                    && (cap == capabilities::FOWNER
                        || self.user_namespace.from_global(true, gid).is_some()))
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
        let fs = if group { self.fsgid } else { self.fsuid };
        if values
            .iter()
            .zip(current)
            .enumerate()
            .all(|(i, (new, old))| *new == u32::MAX || *new == old && (i != 1 || *new == fs))
        {
            return Ok(());
        }
        if !self.has_local_cap(if group {
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
            self.caps.uids_changed(
                current.map(|id| self.privilege_uid(id)),
                next.map(|id| self.privilege_uid(id)),
            );
            [self.uid, self.euid, self.suid] = next;
            self.fsuid = self.euid;
        }
        Ok(())
    }
    pub fn set_id(&mut self, group: bool, value: u32) -> Result<()> {
        if value == u32::MAX {
            return Err(Errno(22));
        }
        if self.has_local_cap(if group {
            capabilities::SETGID
        } else {
            capabilities::SETUID
        }) {
            self.set_res_ids(group, [value; 3])
        } else {
            let allowed = if group {
                [self.gid, self.sgid]
            } else {
                [self.uid, self.suid]
            };
            if !allowed.contains(&value) {
                return Err(Errno(1));
            }
            self.set_res_ids(group, [u32::MAX, value, u32::MAX])
        }
    }
    pub fn set_re_ids(&mut self, group: bool, real: u32, effective: u32) -> Result<()> {
        let ids = if group {
            [self.gid, self.egid, self.sgid]
        } else {
            [self.uid, self.euid, self.suid]
        };
        if !self.has_local_cap(if group {
            capabilities::SETGID
        } else {
            capabilities::SETUID
        }) && (real != u32::MAX && !ids[..2].contains(&real)
            || effective != u32::MAX && !ids.contains(&effective))
        {
            return Err(Errno(1));
        }
        let next = if effective == u32::MAX {
            ids[1]
        } else {
            effective
        };
        let saved = if real != u32::MAX || effective != u32::MAX && effective != ids[0] {
            next
        } else {
            u32::MAX
        };
        self.set_res_ids(group, [real, effective, saved])?;
        // Unlike the setres* no-op rule, setre* always resets the filesystem ID.
        if group {
            self.fsgid = self.egid;
        } else {
            self.fsuid = self.euid;
        }
        Ok(())
    }
    pub fn set_fs_id(&mut self, group: bool, value: u32) -> u32 {
        let old = if group { self.fsgid } else { self.fsuid };
        let ids = if group {
            [self.gid, self.egid, self.sgid, old]
        } else {
            [self.uid, self.euid, self.suid, old]
        };
        if value != u32::MAX
            && (ids.contains(&value)
                || self.has_local_cap(if group {
                    capabilities::SETGID
                } else {
                    capabilities::SETUID
                }))
        {
            if group {
                self.fsgid = value;
            } else {
                self.caps
                    .fsuid_changed(self.privilege_uid(old), self.privilege_uid(value));
                self.fsuid = value;
            }
        }
        old
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
                if link
                    && key == b"ns"
                    && parts.last().is_some_and(|kind| {
                        *kind != b"ns" && Self::namespace_target_released(target, kind)
                    })
                {
                    return Err(Errno(2));
                }
            }
        }
        Ok(())
    }
    pub fn dumpable(&self) -> u64 {
        u64::from(self.dumpable.get())
    }
    pub fn dumpable_state(&self) -> Dumpable {
        self.dumpable.clone()
    }
    pub fn set_dumpable(&self, value: u64) -> Result<()> {
        if value > 1 {
            return Err(Errno(22));
        }
        self.dumpable.set(value != 0);
        Ok(())
    }
    pub fn unshare_dumpable(&mut self) {
        self.dumpable = self.dumpable.fork();
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
            || self
                .credentials
                .has_ns_cap(&target.credentials.user_namespace, capabilities::SYS_PTRACE)
        {
            return true;
        }
        let c = &self.credentials;
        let t = &target.credentials;
        !target.nondumpable
            && [t.uid, t.euid, t.suid].iter().all(|id| *id == c.fsuid)
            && [t.gid, t.egid, t.sgid].iter().all(|id| *id == c.fsgid)
            && (c.user_namespace == t.user_namespace && t.caps.permitted & !c.caps.effective == 0
                || c.has_ns_cap(&t.user_namespace, capabilities::SYS_PTRACE))
    }

    pub fn apply_exec_credentials(&mut self, path: &[u8]) -> Result<()> {
        let file = self.executable_file_at(AT_FDCWD, path, 0)?;
        self.apply_exec_file_credentials(&file)
    }
    pub fn exec_credentials(&self, file: &ExecutableFile) -> ExecCredentials {
        let node = file.node.borrow();
        ExecCredentials {
            original: self.credentials.clone(),
            readable: self.allowed(&node, 4),
            uid: node.uid,
            gid: node.gid,
            mode: node.file_metadata().mode,
            nosuid: file
                .mount
                .as_ref()
                .is_some_and(|m| m.flags.get() & mounts::MS_NOSUID != 0),
        }
    }
    pub fn apply_exec_file_credentials(&mut self, file: &ExecutableFile) -> Result<()> {
        self.exec_credentials(file).apply(self);
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
                view.credentials.caps.effective =
                    if self.credentials.privilege_uid(self.credentials.uid) == 0 {
                        self.credentials.caps.permitted
                    } else {
                        0
                    };
            }
        }
        let path = view.resolve_final(dirfd, path, !nofollow)?;
        let node = view.node(&path)?;
        if mode & 2 != 0 {
            if let Some(mount) = &path.mount {
                mount.writable_data(Some(&node))?;
            }
        }
        if mode & 2 != 0 && view.proc_task_directory(&path) {
            return Err(Errno(1));
        }
        if mode & 1 != 0
            && matches!(node.borrow().content, Content::File(_))
            && path
                .mount
                .as_ref()
                .is_some_and(|m| m.flags.get() & mounts::MS_NOEXEC != 0)
        {
            return Err(Errno(13));
        }
        if mode & 2 != 0 && path.as_ref() == sysctl::MAX_USER_NAMESPACES && view.uses_pseudo(&path)
        {
            if mode & 1 == 0 && view.credentials.has_local_cap(capabilities::SYS_RESOURCE) {
                return Ok(());
            }
            return Err(Errno(13));
        }
        if view.allowed(&node.borrow(), mode) {
            Ok(())
        } else {
            Err(Errno(13))
        }
    }
    pub(super) fn check_remove(&self, path: &ResolvedPath) -> Result<NodeRef> {
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
        drop(p);
        Ok(parent)
    }
    pub(super) fn allowed(&self, node: &Node, bits: u32) -> bool {
        self.credentials.allows_node(node, bits)
    }
    fn chown_node(&self, node: NodeRef, uid: u32, gid: u32, persistent: bool) -> Result<()> {
        let _metadata = node.metadata.lock().unwrap();
        self.pseudo_metadata_mutable(&node)?;
        let mut n = node.borrow_mut();
        let c = &self.credentials;
        if !c.inode_cap(capabilities::CHOWN, n.uid, n.gid)
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
            n.mode &= !0o4000;
            if n.mode & 0o0010 != 0 {
                n.mode &= !0o2000;
            }
        }
        n.times[2] = storage::Timestamp::now();
        drop(n);
        if let Err(error) = if persistent && !node.borrow().volatile && node.borrow().links != 0 {
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
        let uid = if uid == u32::MAX {
            uid
        } else {
            self.credentials.mapped_id(false, uid)?
        };
        let gid = if gid == u32::MAX {
            gid
        } else {
            self.credentials.mapped_id(true, gid)?
        };
        let MetadataTarget { path, node, _magic } = self.metadata_target(dirfd, path, !nofollow)?;
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
        let uid = if uid == u32::MAX {
            uid
        } else {
            self.credentials.mapped_id(false, uid)?
        };
        let gid = if gid == u32::MAX {
            gid
        } else {
            self.credentials.mapped_id(true, gid)?
        };
        self.fd_writable(fd)?;
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        if let Some(socket) = &open.socket {
            let c = &self.credentials;
            return socket
                .chown(uid, gid, |[current_uid, current_gid]| {
                    if !c.inode_cap(capabilities::CHOWN, current_uid, current_gid)
                        && (c.fsuid != current_uid
                            || uid != u32::MAX && uid != current_uid
                            || gid != u32::MAX && gid != current_gid && !c.in_group(gid))
                    {
                        return Err(trames_net::NetError(1));
                    }
                    Ok(())
                })
                .map_err(|e| Errno(e.0));
        }
        let node = open.metadata_node().ok_or(Errno(22))?;
        self.chown_node(node, uid, gid, open.node.is_some())
    }
}
