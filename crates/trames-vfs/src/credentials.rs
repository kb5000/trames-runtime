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
    memory: Option<trames_memory::TransferTarget>,
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
        self.publish_resources(credentials, files, dumpable, namespaces, None);
    }
    pub fn publish_image_resources(
        &self,
        credentials: &Credentials,
        files: &SharedFiles,
        dumpable: Dumpable,
        namespaces: SharedNamespaceSnapshot,
        memory: trames_memory::TransferTarget,
    ) {
        self.publish_resources(credentials, files, dumpable, namespaces, Some(memory));
    }
    fn publish_resources(
        &self,
        credentials: &Credentials,
        files: &SharedFiles,
        dumpable: Dumpable,
        namespaces: SharedNamespaceSnapshot,
        memory: Option<trames_memory::TransferTarget>,
    ) {
        let mut target = self.current.write().unwrap();
        target.clone_from(credentials);
        let mut binding = self.pidfd.lock().unwrap();
        // A namespace/Files-only update retains the original mm. An image
        // replacement publishes its memory and objective credentials together.
        let memory = memory.or_else(|| {
            binding
                .as_mut()
                .filter(|old| Arc::ptr_eq(&old.dumpable.0, &dumpable.0))
                .and_then(|old| old.memory.take())
        });
        *binding = Some(PidfdResources {
            memory,
            namespaces,
            table: Arc::downgrade(&files.0),
            dumpable,
        });
    }
    pub fn admit_process_memory(
        &self,
        caller: &Credentials,
        observed: &trames_memory::MemoryReport,
        require_cap: bool,
    ) -> Result<trames_memory::TransferTarget> {
        self.with_pidfd_resources(caller, false, require_cap, |resources| {
            resources
                .memory
                .as_ref()
                .filter(|mm| mm.matches(observed))
                .cloned()
                .ok_or(Errno(3))
        })
    }
    pub fn check_proc_memory(
        &self,
        caller: &Credentials,
        same_group: bool,
        mm: &trames_memory::MemoryReport,
        require_cap: bool,
    ) -> Result<()> {
        self.open_proc_memory(caller, same_group, mm, require_cap)
            .map(|_| ())
    }
    pub fn open_proc_memory(
        &self,
        caller: &Credentials,
        same_group: bool,
        mm: &trames_memory::MemoryReport,
        require_cap: bool,
    ) -> Result<trames_memory::TransferTarget> {
        let target = self.current.read().unwrap();
        let binding = self.pidfd.lock().unwrap();
        let resources = binding.as_ref().ok_or(Errno(3))?;
        if require_cap && !caller.has_ns_cap(&target.user_namespace, capabilities::SYS_PTRACE)
            || !same_group
                && (!caller.landlock.contains(&target.landlock)
                    || !resources.dumpable.may_inspect(caller))
            || !caller.can_inspect_credentials(same_group, &target, resources.dumpable.get())
        {
            return Err(Errno(13));
        }
        if !resources
            .memory
            .as_ref()
            .is_some_and(|image| image.matches(mm))
        {
            return Err(Errno(3));
        }
        Ok(resources.memory.as_ref().expect("matched image").clone())
    }
    pub fn receive_pidfd_file(
        &self,
        caller: &Credentials,
        same_group: bool,
        fd: u32,
        into: &SharedFiles,
        require_cap: bool,
    ) -> Result<u32> {
        self.with_pidfd_resources(caller, same_group, require_cap, |resources| {
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
        self.with_pidfd_resources(caller, same_group, false, |resources| {
            resources.namespaces.select(flags)
        })
    }
    /// PTRACE_ATTACH uses the same objective credentials and dumpability
    /// transaction as pidfd_getfd. The caller has already excluded its own group.
    pub fn check_trace_attach(&self, caller: &Credentials, require_cap: bool) -> Result<()> {
        self.with_pidfd_resources(caller, false, require_cap, |_| Ok(()))
    }
    /// perf task monitoring uses real credentials without Yama ATTACH policy.
    /// CAP_PERFMON/SYS_ADMIN apply in the initial user namespace.
    pub fn check_perf(&self, caller: &Credentials, same_group: bool) -> Result<()> {
        if caller.has_cap(capabilities::PERFMON) || caller.has_cap(capabilities::SYS_ADMIN) {
            return Ok(());
        }
        self.with_pidfd_resources(caller, same_group, false, |_| Ok(()))
            .map_err(|error| if error == Errno(1) { Errno(13) } else { error })
    }
    fn with_pidfd_resources<T>(
        &self,
        caller: &Credentials,
        same_group: bool,
        require_cap: bool,
        accept: impl FnOnce(&PidfdResources) -> Result<T>,
    ) -> Result<T> {
        let target = self.current.read().unwrap();
        let binding = self.pidfd.lock().unwrap();
        let resources = binding.as_ref().ok_or(Errno(3))?;
        if require_cap && !caller.has_ns_cap(&target.user_namespace, capabilities::SYS_PTRACE)
            || !same_group && !resources.dumpable.may_inspect(caller)
        {
            return Err(Errno(1));
        }
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
pub struct Dumpable(Arc<DumpPolicy>);
struct DumpPolicy {
    namespace: UserNamespace,
    enabled: std::sync::atomic::AtomicBool,
    filter: std::sync::atomic::AtomicU32,
}
impl Default for Dumpable {
    fn default() -> Self {
        Self(Arc::new(DumpPolicy {
            namespace: UserNamespace::default(),
            enabled: true.into(),
            filter: 0x33.into(),
        }))
    }
}
impl Dumpable {
    pub fn get(&self) -> bool {
        self.0.enabled.load(Ordering::Relaxed)
    }
    pub fn set(&self, value: bool) {
        self.0.enabled.store(value, Ordering::Relaxed);
    }
    pub(super) fn filter(&self) -> u32 {
        self.0.filter.load(Ordering::Relaxed)
    }
    pub(super) fn set_filter(&self, value: u32) {
        self.0.filter.store(value & 0x1ff, Ordering::Relaxed);
    }
    pub fn fork(&self) -> Self {
        self.in_namespace(self.0.namespace.clone())
    }
    fn in_namespace(&self, namespace: UserNamespace) -> Self {
        Self(Arc::new(DumpPolicy {
            namespace,
            enabled: self.get().into(),
            filter: self.filter().into(),
        }))
    }
    fn may_inspect(&self, caller: &Credentials) -> bool {
        self.get() || caller.has_ns_cap(&self.0.namespace, capabilities::SYS_PTRACE)
    }
}

/// Accepted executable metadata and original credentials. A late TSYNC may
/// change only the task's monotonic NNP flag, without re-looking-up the file.
pub struct ExecCredentials {
    original: Credentials,
    uid: u32,
    gid: u32,
    mode: u32,
    file_caps: Option<file_caps::FileCaps>,
    nosuid: bool,
    readable: bool,
    mm_namespace: UserNamespace,
}
impl ExecCredentials {
    pub fn include_interpreter(&mut self, view: &Vfs, file: &ExecutableFile) {
        let node = file.node.borrow();
        let ids = file.mount.as_ref().map_or_else(
            || mounts::idmap::Ids::plain(&view.fs.owner),
            |m| mounts::idmap::Ids::from_mount(&m.identity),
        );
        if !view.credentials.allows_mapped(&node, 4, ids) {
            self.readable = false;
            let (uid, gid) = ids.owner(node.uid, node.gid);
            Self::include_owner(&mut self.mm_namespace, uid, gid);
        }
    }
    fn include_owner(namespace: &mut UserNamespace, uid: u32, gid: u32) {
        while namespace.from_global(false, uid).is_none()
            || namespace.from_global(true, gid).is_none()
        {
            let Some(parent) = namespace.parent() else {
                break;
            };
            *namespace = parent;
        }
    }
    pub fn no_new_privs(&self) -> bool {
        self.original.caps.no_new_privs.get()
    }
    pub fn apply(&self, view: &mut Vfs) -> bool {
        self.apply_for_exec(view, false)
    }
    pub fn apply_for_exec(&self, view: &mut Vfs, externally_shared_fs: bool) -> bool {
        self.apply_observed_exec(view, externally_shared_fs, false)
    }
    pub fn apply_observed_exec(
        &self,
        view: &mut Vfs,
        externally_shared_fs: bool,
        traced: bool,
    ) -> bool {
        let no_new_privs = self.no_new_privs() || traced;
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
            no_new_privs || externally_shared_fs,
            self.file_caps,
        );
        // Preserve the established pre-existing effective-ID downgrade rule.
        if (no_new_privs
            || externally_shared_fs && !self.original.has_local_cap(capabilities::SETUID))
            && (c.uid != c.euid || c.gid != c.egid)
        {
            c.euid = c.uid;
            c.egid = c.gid;
        }
        c.file_secure_exec = c.privilege_uid(c.euid) != 0
            && self.file_caps.is_some()
            && (self.file_caps.is_some_and(|f| f.effective)
                || c.caps.permitted & !c.caps.ambient != 0);
        view.dumpable = view.dumpable.in_namespace(self.mm_namespace.clone());
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
        c.renew_open_identity();
        view.credentials = c;
        no_new_privs
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credentials {
    file_secure_exec: bool,
    open_identity: u64,
    pub landlock: landlock::Domain,
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
    pub fn renew_open_identity(&mut self) {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        self.open_identity = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn open_identity(&self) -> (u64, UserNamespace) {
        (self.open_identity, self.user_namespace.clone())
    }
    pub fn secure_exec(&self) -> bool {
        self.file_secure_exec || self.uid != self.euid || self.gid != self.egid
    }
    pub fn fs_identity(&self) -> [u32; 4] {
        [self.euid, self.egid, self.fsuid, self.fsgid]
    }
    fn mode_class(&self, uid: u32, gid: u32) -> u32 {
        if self.fsuid == uid {
            6
        } else if self.in_group(gid) {
            3
        } else {
            0
        }
    }
    fn allows_dac(
        &self,
        owner: (u32, u32),
        mode: u32,
        directory: bool,
        bits: u32,
        permitted: bool,
    ) -> bool {
        permitted
            || self.inode_cap(capabilities::DAC_OVERRIDE, owner.0, owner.1)
                && (bits & 1 == 0 || directory || mode & 0o111 != 0)
            || self.inode_cap(capabilities::DAC_READ_SEARCH, owner.0, owner.1)
                && bits & 2 == 0
                && (bits & 1 == 0 || directory)
    }
    pub(super) fn allows_mode(
        &self,
        uid: u32,
        gid: u32,
        mode: u32,
        directory: bool,
        bits: u32,
    ) -> bool {
        self.allows_dac(
            (uid, gid),
            mode,
            directory,
            bits,
            (mode >> self.mode_class(uid, gid)) & bits == bits,
        )
    }
    pub(super) fn allows_node(&self, node: &Node, bits: u32) -> bool {
        self.allows_mapped(node, bits, mounts::idmap::Ids::plain(&self.user_namespace))
    }
    pub(super) fn allows_mapped(
        &self,
        node: &Node,
        bits: u32,
        ids: mounts::idmap::Ids<'_>,
    ) -> bool {
        let mode = node.file_metadata().mode;
        let directory = matches!(node.content, Content::Directory);
        let (uid, gid) = ids.owner(node.uid, node.gid);
        if bits & 2 != 0 && (uid == u32::MAX || gid == u32::MAX) {
            return false;
        }
        if self.fsuid != uid {
            if let Some(value) = node.xattrs.get(acl::ACCESS) {
                return self.allows_dac(
                    (uid, gid),
                    mode,
                    directory,
                    bits,
                    acl::allows_mapped(value, node, self, bits, ids),
                );
            }
        }
        self.allows_mode(uid, gid, mode, directory, bits)
    }
    pub(super) fn allows_acl(&self, node: &Node, bits: u32, access: Option<&[u8]>) -> Result<bool> {
        let mode = node.file_metadata().mode;
        let directory = matches!(node.content, Content::Directory);
        if self.fsuid != node.uid {
            if let Some(value) = access {
                return Ok(self.allows_dac(
                    (node.uid, node.gid),
                    mode,
                    directory,
                    bits,
                    acl::permission(value, node, self, bits)?,
                ));
            }
        }
        Ok(self.allows_mode(node.uid, node.gid, mode, directory, bits))
    }
    pub fn can_read_proc_task(&self, same_group: bool, target: &ProcessInfo) -> bool {
        self.can_inspect_credentials(same_group, &target.credentials, !target.nondumpable)
    }
    fn can_inspect_credentials(&self, same_group: bool, t: &Credentials, dumpable: bool) -> bool {
        same_group
            || self.landlock.contains(&t.landlock)
                && (self.has_ns_cap(&t.user_namespace, capabilities::SYS_PTRACE)
                    || dumpable
                        && [t.uid, t.euid, t.suid].iter().all(|id| *id == self.fsuid)
                        && [t.gid, t.egid, t.sgid].iter().all(|id| *id == self.fsgid)
                        && self.user_namespace == t.user_namespace
                        && t.caps.permitted & !self.caps.effective == 0)
    }
    pub fn user(uid: u32, gid: u32) -> Self {
        let mut credentials = Self {
            file_secure_exec: false,
            open_identity: 0,
            landlock: Default::default(),
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
        };
        credentials.renew_open_identity();
        credentials
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
        self.renew_open_identity();
    }
    pub fn inode_cap(&self, cap: u32, uid: u32, gid: u32) -> bool {
        uid != u32::MAX
            && (cap == capabilities::FOWNER || gid != u32::MAX)
            && self.has_local_cap(cap)
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
            matches!(
                key,
                b"maps" | b"smaps" | b"smaps_rollup" | b"environ" | b"auxv" | b"fdinfo"
            )
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
    pub fn install_exec_dumpable(&mut self, prepared: Dumpable) {
        prepared.set_filter(self.dumpable.filter());
        self.dumpable = prepared;
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
        self.may_inspect_pid(self.proc_namespace(at).local(self.pid), runtime, target)
    }

    /// proc_fd_permission permits a task's own thread group after setuid
    /// made the proc directory root-owned. The FD target still has its usual
    /// ptrace, mount and inode authorization checks.
    #[cold]
    pub(super) fn proc_fd_search_allowed(&self, at: &ResolvedPath) -> bool {
        if !self.uses_pseudo(at) {
            return false;
        }
        let Some(rest) = at.strip_prefix(b"/proc/") else {
            return false;
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let (target, group) = match parts.as_slice() {
            [pid, b"fd"] => (proc_source::proc_task_id(pid), None),
            [group, b"task", pid, b"fd"] => (
                proc_source::proc_task_id(pid),
                proc_source::proc_task_id(group),
            ),
            _ => return false,
        };
        let pseudo = self.pseudo.borrow();
        let runtime = self.proc_runtime(at, &pseudo.runtime);
        let own = self.proc_namespace(at).local(self.pid);
        let Some(own) = runtime.processes.iter().find(|p| p.pid == own) else {
            return false;
        };
        runtime.processes.iter().any(|p| {
            Some(p.pid) == target && p.tgid == own.tgid && group.is_none_or(|g| p.tgid == g)
        })
    }

    pub(super) fn may_inspect_pid(
        &self,
        own: u32,
        runtime: &RuntimeInfo,
        target: &ProcessInfo,
    ) -> bool {
        self.credentials.can_read_proc_task(
            runtime
                .processes
                .iter()
                .any(|p| p.pid == own && p.tgid == target.tgid),
            target,
        )
    }

    pub fn apply_exec_credentials(&mut self, path: &[u8]) -> Result<()> {
        let file = self.executable_file_at(AT_FDCWD, path, 0)?;
        self.apply_exec_file_credentials(&file)
    }
    pub fn exec_credentials(&self, file: &ExecutableFile) -> Result<ExecCredentials> {
        let node = file.node.borrow();
        let ids = file.mount.as_ref().map_or_else(
            || mounts::idmap::Ids::plain(&self.fs.owner),
            |m| mounts::idmap::Ids::from_mount(&m.identity),
        );
        let (uid, gid) = ids.owner(node.uid, node.gid);
        let nosuid = file
            .mount
            .as_ref()
            .is_some_and(|m| m.flags.get() & mounts::MS_NOSUID != 0);
        let file_caps = if nosuid {
            None
        } else {
            node.file_caps()
                .and_then(|caps| caps.mapped(ids))
                .filter(|caps| caps.applies(&self.credentials.user_namespace))
        };
        if let Some(file) = file_caps {
            let caps = &self.credentials.caps;
            if file.effective
                && file.permitted
                    & capabilities::ALL
                    & !(caps.bounding | (caps.inheritable & file.inheritable))
                    != 0
            {
                return Err(Errno(1));
            }
        }
        let readable = self.credentials.allows_mapped(&node, 4, ids);
        let mut mm_namespace = self.credentials.user_namespace.clone();
        if !readable {
            ExecCredentials::include_owner(&mut mm_namespace, uid, gid);
        }
        Ok(ExecCredentials {
            original: self.credentials.clone(),
            readable,
            mm_namespace,
            uid,
            gid,
            mode: node.file_metadata().mode,
            file_caps,
            nosuid,
        })
    }
    pub fn apply_exec_file_credentials(&mut self, file: &ExecutableFile) -> Result<()> {
        self.exec_credentials(file)?.apply(self);
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
        self.access_at_empty(dirfd, path, mode, effective, nofollow, false)
    }
    pub fn access_at_empty(
        &self,
        dirfd: i32,
        path: &[u8],
        mode: u32,
        effective: bool,
        nofollow: bool,
        empty: bool,
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
        if empty && path.is_empty() {
            if dirfd == AT_FDCWD {
                let (node, mount) = {
                    let paths = view.context.paths.borrow();
                    (
                        paths.cwd_node.clone().ok_or(Errno(2))?,
                        paths.cwd_mount.clone(),
                    )
                };
                let path = ResolvedPath {
                    key: view.cwd().unwrap_or_default(),
                    mount,
                    directory_inode: Some(node.clone()),
                    proc_binding: None,
                    fuse_entry: None,
                    indexed_position: None,
                    retained_directory: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                };
                return view.access_node(path, &node, mode);
            }
            let description = view.descriptor(dirfd as u32)?.open;
            let path = ResolvedPath {
                key: Vec::new(),
                mount: None,
                directory_inode: None,
                proc_binding: None,
                fuse_entry: None,
                indexed_position: None,
                retained_directory: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_position: None,
            };
            return view
                .access_resolved((path, Some(ResolvedTarget::Descriptor(description))), mode);
        }
        let entry = view.resolve_entry_operation(
            dirfd,
            path,
            !nofollow,
            !nofollow,
            0,
            !nofollow,
            Some(ResolveOperation::Fuse(fuse::PathOperation::Access(mode))),
            None,
        )?;
        let result = view.access_resolved(entry, mode);
        fuse::PathRetry::arm(
            &view,
            dirfd,
            path,
            !nofollow,
            !nofollow,
            0,
            !nofollow,
            fuse::PathOperation::Access(mode),
            None,
            true,
        );
        result
    }
    pub(super) fn access_resolved(&self, (path, target): ResolvedEntry, mode: u32) -> Result<()> {
        match target {
            Some(ResolvedTarget::Descriptor(open)) => {
                let open = open.borrow();
                if let Some(events::SharedControl::FuseFile(file)) = &open.control {
                    let query = self.query.as_ref().ok_or(Errno(95))?;
                    if let Some(pending) = fuse::Metadata::access_file(self, file, mode)? {
                        query.prepared.borrow_mut().fuse = Some(Box::new(pending));
                        return query.defer();
                    }
                    return Ok(());
                }
                let actual = ResolvedPath {
                    key: if let FdKind::Node(label) = &open.kind {
                        label.clone()
                    } else {
                        path.key
                    },
                    mount: self.mount_for_path(open.mount.as_ref()),
                    proc_binding: None,
                    directory_inode: None,
                    fuse_entry: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                };
                if let Some(node) = open.metadata_node() {
                    #[cfg(all(feature = "hostfs", unix))]
                    if let Some(file) = &open.host_file {
                        // This final inode was retained before native dispatch;
                        // refresh through its fd even after unlink/replacement.
                        file.refresh_permissions(&node)?;
                    }
                    return self.access_node(actual, &node, mode);
                }
                // Anonymous inodes have no filesystem ACL object. Read their
                // original metadata and use the same DAC/capability decision.
                let stat = self.stat_open(&open)?;
                let value =
                    |offset| u32::from_le_bytes(stat[offset..offset + 4].try_into().unwrap());
                let inode_mode = value(16);
                let kind = inode_mode & 0o170000;
                if let Some(mount) = &actual.mount {
                    if mode & 2 != 0 && !matches!(kind, 0o010000 | 0o020000 | 0o060000 | 0o140000) {
                        mount.writable()?;
                    }
                    if mode & 1 != 0
                        && kind == 0o100000
                        && mount.flags.get() & mounts::MS_NOEXEC != 0
                    {
                        return Err(Errno(13));
                    }
                }
                if self.credentials.allows_mode(
                    value(24),
                    value(28),
                    inode_mode,
                    kind == 0o040000,
                    mode,
                ) {
                    Ok(())
                } else {
                    Err(Errno(13))
                }
            }
            Some(ResolvedTarget::Inode(file)) => {
                #[cfg(all(feature = "hostfs", unix))]
                if let Some(host) = &file.host_file {
                    host.refresh_permissions(&file.node)?;
                }
                let actual = ResolvedPath {
                    key: file.label.clone(),
                    mount: file.mount.clone(),
                    proc_binding: None,
                    directory_inode: None,
                    fuse_entry: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                };
                self.access_node(actual, &file.node, mode)
            }
            None => {
                let node = self.node(&path)?;
                #[cfg(all(feature = "hostfs", unix))]
                if let Some(position) = &path.host_position {
                    let fs = path.filesystem(self);
                    position
                        .pin(fs.host.as_ref().ok_or(Errno(5))?, &fs, &path.key)?
                        .file
                        .refresh_permissions(&node)?;
                }
                self.access_node(path, &node, mode)
            }
        }
    }
    fn access_node(&self, path: ResolvedPath, node: &NodeRef, mode: u32) -> Result<()> {
        if let Some((m, fs)) = path
            .mount
            .as_ref()
            .and_then(|m| m.fs.fuse.as_ref().map(|fs| (m, fs)))
        {
            let query = self.query.as_ref().ok_or(Errno(95))?;
            if let Some(request) = fuse::Metadata::access_inode(self, m, fs, node.clone(), mode)? {
                query.prepared.borrow_mut().fuse = Some(Box::new(request));
                return query.defer();
            }
            return Ok(());
        }
        if mode & 2 != 0 {
            if let Some(mount) = &path.mount {
                mount.writable_data(Some(node))?;
            }
        }
        if mode & 2 != 0 && self.proc_task_directory(&path) {
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
        if mode & 2 != 0 && path.as_ref() == sysctl::MAX_USER_NAMESPACES && self.uses_pseudo(&path)
        {
            if mode & 1 == 0 && self.credentials.has_local_cap(capabilities::SYS_RESOURCE) {
                return Ok(());
            }
            return Err(Errno(13));
        }
        if self.allowed_on(&node.borrow(), mode, &path) {
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
        let ids = path.ids(self);
        let target = self.node(path)?;
        let (owner, group) = {
            let node = target.borrow();
            ids.valid_owner(node.uid, node.gid)?
        };
        if p.mode & 0o1000 != 0
            && uid != ids.visible(false, p.uid)
            && uid != owner
            && !self
                .credentials
                .inode_cap(capabilities::FOWNER, owner, group)
        {
            return Err(Errno(1));
        }
        drop(p);
        Ok(parent)
    }
    pub(super) fn allowed(&self, node: &Node, bits: u32) -> bool {
        self.credentials.allows_node(node, bits)
    }
    fn chown_node(
        &self,
        node: NodeRef,
        uid: u32,
        gid: u32,
        filesystem: Option<&FsHandle>,
        ids: mounts::idmap::Ids<'_>,
    ) -> Result<()> {
        let _metadata = node.metadata.lock().unwrap();
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = node.host.get() {
            host.metadata_file()?.refresh_permissions(&node)?;
        }
        self.pseudo_metadata_mutable(&node)?;
        let n = node.borrow_mut();
        let c = &self.credentials;
        let (owner, group) = ids.owner(n.uid, n.gid);
        if uid == u32::MAX && owner == u32::MAX || gid == u32::MAX && group == u32::MAX {
            return Err(Errno(75));
        }
        let capable = c.inode_cap(capabilities::CHOWN, owner, group);
        if uid != u32::MAX
            && !(c.fsuid == owner && uid == n.uid
                || capable
                || owner == u32::MAX && ids.fs_capable(c, capabilities::CHOWN))
        {
            return Err(Errno(1));
        }
        if gid != u32::MAX
            && !(c.fsuid == owner && (gid == n.gid || c.in_group(ids.visible(true, gid)))
                || capable
                || group == u32::MAX && ids.fs_capable(c, capabilities::CHOWN))
        {
            return Err(Errno(1));
        }
        drop(n);
        if let Some(fs) = filesystem {
            fs.prepare_metadata(&node)?;
        }
        let mut n = node.borrow_mut();
        let old = (n.uid, n.gid, n.mode, n.times[2]);
        if uid != u32::MAX || gid != u32::MAX {
            n.revoke_file_caps()?;
        }
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
        if let Err(error) = filesystem.map_or(Ok(()), |fs| fs.checkpoint_metadata(&node)) {
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
        if self.host_resources() {
            return self.host_namespace_work(NamespaceCall::Chown {
                fd: dirfd,
                path: Some(path.to_vec()),
                uid,
                gid,
                nofollow,
                empty: false,
            });
        }
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
        let target = self.metadata_target(dirfd, path, !nofollow)?;
        if let Some(result) =
            self.fuse_path_attributes(&target, fuse::AttributeChange::Owner(uid, gid))
        {
            return result;
        }
        let retry = self.metadata_retry(Some(target));
        let target = retry.target();
        target.path.writable()?;
        let ids = target.path.ids(self);
        self.chown_node(
            target.node.clone(),
            ids.stored(false, uid)?,
            ids.stored(true, gid)?,
            Some(&target.path.filesystem(self)),
            ids,
        )
    }
    pub fn chown_fd(&mut self, fd: u32, uid: u32, gid: u32) -> Result<()> {
        if self.flags(fd)? & O_PATH != 0 {
            return Err(Errno(9));
        }
        self.chown_fd_at(fd, uid, gid)
    }
    /// AT_EMPTY_PATH operates on an inode reference, including O_PATH.
    pub fn chown_fd_at(&mut self, fd: u32, uid: u32, gid: u32) -> Result<()> {
        if self.host_resources() {
            return self.host_namespace_work(NamespaceCall::Chown {
                fd: fd as i32,
                path: None,
                uid,
                gid,
                nofollow: false,
                empty: true,
            });
        }
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
        if let Some(result) = self.fuse_fd_attributes(fd, fuse::AttributeChange::Owner(uid, gid)) {
            return result;
        }
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
        let ids = self.open_ids(open.mount.as_ref());
        self.chown_node(
            node,
            ids.stored(false, uid)?,
            ids.stored(true, gid)?,
            open.node
                .as_ref()
                .map(|_| open.mount.as_ref().map_or(&self.fs, |m| &m.fs)),
            ids,
        )
    }
}

#[cfg(test)]
mod process_transfer_tests {
    use super::*;
    #[test]
    fn nondumpable_proc_fd_search_keeps_the_same_thread_group_exception() {
        let mut v = Vfs::default();
        v.import_file(b"/data", b"x".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
        v.credentials = Credentials::user(1000, 1000);
        let process = |pid, tgid| ProcessInfo {
            pid,
            tgid,
            nondumpable: true,
            credentials: v.credentials.clone(),
            fds: v.fd_snapshot(),
            ..ProcessInfo::default()
        };
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![process(1, 1), process(2, 1), process(3, 3)],
                ..RuntimeInfo::default()
            },
        );
        for directory in ["/proc/1/fd", "/proc/1/task/2/fd"] {
            let path = format!("{directory}/{fd}");
            assert!(v.stat_at(AT_FDCWD, path.as_bytes()).is_ok(), "{path}");
            let fd = v
                .open_at(AT_FDCWD, directory.as_bytes(), O_DIRECTORY, 0)
                .unwrap();
            v.close(fd).unwrap();
        }
        for directory in ["/proc/3/fd", "/proc/1/fdinfo"] {
            let path = format!("{directory}/{fd}");
            assert_eq!(
                v.stat_at(AT_FDCWD, path.as_bytes()),
                Err(Errno(13)),
                "{path}"
            );
        }
    }
    #[test]
    fn nondumpable_mm_requires_a_capability_in_the_executable_owners_namespace() {
        let mut vfs = Vfs::default();
        let initial = vfs.credentials.clone();
        vfs.unshare_user().unwrap();
        let nested = &vfs.credentials;
        assert!(nested.has_ns_cap(&nested.user_namespace, capabilities::SYS_PTRACE));
        let mut owner = nested.user_namespace.clone();
        ExecCredentials::include_owner(&mut owner, initial.uid, initial.gid);
        assert!(owner == initial.user_namespace);
        let mm = Dumpable::default().in_namespace(owner);
        mm.set(false);
        for policy in [mm.clone(), mm.fork()] {
            assert!(!policy.may_inspect(nested));
            assert!(policy.may_inspect(&initial));
        }
        assert!(mm
            .in_namespace(nested.user_namespace.clone())
            .may_inspect(nested));
    }

    #[test]
    fn accepted_target_matches_the_image_checked_with_real_credentials() {
        let vfs = Vfs::default();
        let creds = Credentials::user(1200, 1200);
        let state = CredentialState::new(creds.clone());
        let old = trames_memory::Memory::default();
        let new = trames_memory::Memory::default();
        let policy = Dumpable::default();
        let publish = |mm: &trames_memory::Memory, policy: &Dumpable| {
            state.publish_image_resources(
                &creds,
                &vfs.shared_files(),
                policy.clone(),
                vfs.pidfd_namespace_source(),
                mm.transfer_target(),
            );
        };
        publish(&old, &policy);
        let mut fs_caller = Credentials::user(1300, 1300);
        fs_caller.fsuid = creds.uid;
        fs_caller.fsgid = creds.gid;
        assert_eq!(
            state.check_proc_memory(&fs_caller, false, &old.memory_report(), false),
            Ok(())
        );
        fs_caller.fsuid = 1300;
        assert_eq!(
            state.check_proc_memory(&fs_caller, false, &old.memory_report(), false),
            Err(Errno(13))
        );
        let retained = state
            .admit_process_memory(&creds, &old.memory_report(), false)
            .unwrap();
        assert!(matches!(
            state.admit_process_memory(&Credentials::user(1300, 1300), &old.memory_report(), false),
            Err(Errno(1))
        ));
        state.publish_pidfd_resources(
            &creds,
            &vfs.shared_files(),
            policy.clone(),
            vfs.pidfd_namespace_source(),
        );
        assert!(state
            .admit_process_memory(&creds, &old.memory_report(), false)
            .is_ok());
        policy.set(false);
        assert!(matches!(
            state.admit_process_memory(&creds, &old.memory_report(), false),
            Err(Errno(1))
        ));
        publish(&new, &Dumpable::default());
        assert!(matches!(
            state.admit_process_memory(&creds, &old.memory_report(), false),
            Err(Errno(3))
        ));
        assert!(state
            .admit_process_memory(&creds, &new.memory_report(), false)
            .is_ok());
        assert_eq!(
            state.check_proc_memory(&creds, false, &old.memory_report(), false),
            Err(Errno(3))
        );
        assert!(!retained.matches(&new.memory_report()));
    }
}
