// SPDX-License-Identifier: GPL-3.0-or-later
//! Attribute changes retain the accepted inode and mount through daemon waits.
use super::*;

#[derive(Clone)]
pub(crate) enum AttributeChange {
    Mode(u32),
    Owner(u32, u32),
    Times(Option<[[i64; 2]; 2]>),
    Size { length: u64, opening: bool },
}
#[derive(Clone, Copy)]
enum Phase {
    Lock,
    Permission,
    Capabilities,
    RemoveCapabilities,
    Refresh,
    Set,
}
pub(super) struct Attributes {
    change: AttributeChange,
    node: NodeRef,
    fs: Arc<Mounted>,
    caller: Caller,
    credentials: Credentials,
    phase: Phase,
    check: Option<posix::Check>,
    transaction: Option<inode::Write>,
    waiting: Option<inode::WriteWait>,
    _file: Option<Arc<File>>,
    lock_owner: u64,
    _writer: mapped::MountWrite,
    link: Option<Arc<inotify::Link>>,
}
impl Attributes {
    pub(super) fn node(&self) -> &NodeRef {
        &self.node
    }
    pub(super) fn waiting_lock(&self) -> bool {
        matches!(self.phase, Phase::Lock)
    }
    pub(super) fn lock_ready(&self) -> bool {
        inode::attr(&self.node).write_ready()
    }
    pub(super) fn subscribe_lock(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        inode::attr(&self.node).subscribe_write(signal)
    }
    fn begin(&mut self, node: u64) -> Result<Option<Arc<Request>>> {
        let Some(transaction) = inode::attr(&self.node).enter_write(&mut self.waiting) else {
            self.phase = Phase::Lock;
            return Ok(None);
        };
        self.transaction = Some(transaction);
        let by_file = matches!(self.change, AttributeChange::Size { .. }) && self._file.is_some();
        if self.fs.local_permissions() && !by_file {
            let now = matches!(self.change, AttributeChange::Times(None))
                || matches!(self.change, AttributeChange::Times(Some(t)) if t.iter().all(|p| p[1] == UTIME_NOW));
            let mut check = posix::Check::new(
                self.node.clone(),
                self.credentials.clone(),
                if now || matches!(self.change, AttributeChange::Size { .. }) {
                    2
                } else {
                    0
                },
            );
            if now {
                check = check.times();
            }
            if let Some(request) = check.next(&self.fs, self.caller)? {
                self.check = Some(check);
                self.phase = Phase::Permission;
                return Ok(Some(request));
            }
            self.permission()?;
        }
        self.phase = self.start_phase();
        self.request(node).map(Some)
    }
    fn start_phase(&self) -> Phase {
        if matches!(
            self.change,
            AttributeChange::Owner(..) | AttributeChange::Size { .. }
        ) && !self.node.directory
        {
            if self.fs.xattr_unsupported.load(Ordering::Relaxed) & 2 == 0 {
                Phase::Capabilities
            } else {
                Phase::Refresh
            }
        } else {
            Phase::Set
        }
    }
    fn permission(&self) -> Result<()> {
        if !self.fs.local_permissions() {
            return Ok(());
        }
        let node = self.node.borrow();
        let c = &self.credentials;
        let owner = c.fsuid == node.uid || c.inode_cap(capabilities::FOWNER, node.uid, node.gid);
        match self.change {
            AttributeChange::Mode(_) if !owner => Err(Errno(1)),
            AttributeChange::Owner(uid, gid)
                if !c.inode_cap(capabilities::CHOWN, node.uid, node.gid)
                    && (c.fsuid != node.uid
                        || uid != u32::MAX && uid != node.uid
                        || gid != u32::MAX && gid != node.gid && !c.in_group(gid)) =>
            {
                Err(Errno(1))
            }
            AttributeChange::Times(times) if !owner => {
                if times.is_some_and(|t| !t.iter().all(|p| p[1] == UTIME_NOW)) {
                    return Err(Errno(1));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn request(&self, node: u64) -> Result<Arc<Request>> {
        self.fs.check_inode(&self.node)?;
        let (opcode, body) = match self.phase {
            Phase::Lock => unreachable!("inode write admission precedes a daemon request"),
            Phase::Capabilities => {
                let mut body = vec![0; 8];
                body.extend(file_caps::NAME);
                body.push(0);
                (22, body)
            }
            Phase::RemoveCapabilities => {
                let mut body = file_caps::NAME.to_vec();
                body.push(0);
                (24, body)
            }
            Phase::Permission | Phase::Refresh => {
                let mut body = vec![0; 16];
                if matches!(self.change, AttributeChange::Size { opening: false, .. }) {
                    if let Some(fh) = self._file.as_ref().and_then(|file| file.fh) {
                        body[..4].copy_from_slice(&1u32.to_le_bytes());
                        body[8..16].copy_from_slice(&fh.to_le_bytes());
                    }
                }
                (3, body)
            }
            Phase::Set => (4, self.body()?.to_vec()),
        };
        if opcode == 3 {
            self.fs.invalidate_acl(&self.node);
        }
        Ok(Arc::new(self.fs.connection.request(
            opcode,
            node,
            self.caller,
            &body,
        )?))
    }

    fn body(&self) -> Result<[u8; 88]> {
        let mut body = [0; 88];
        let mut valid = 0u32;
        match self.change {
            AttributeChange::Mode(mode) => {
                valid = 1;
                let node = self.node.borrow();
                let mut mode = node.mode & !0o7777 | mode & 0o7777;
                if self.fs.local_permissions()
                    && !self.credentials.in_group(node.gid)
                    && !self
                        .credentials
                        .inode_cap(capabilities::FSETID, node.uid, node.gid)
                {
                    mode &= !0o2000;
                }
                body[68..72].copy_from_slice(&mode.to_le_bytes());
            }
            AttributeChange::Owner(uid, gid) => {
                for (value, group, flag, offset) in [(uid, false, 2, 76), (gid, true, 4, 80)] {
                    if value != u32::MAX {
                        valid |= flag;
                        let id = self
                            .fs
                            .namespace
                            .from_global(group, value)
                            .ok_or(Errno(75))?;
                        body[offset..offset + 4].copy_from_slice(&id.to_le_bytes());
                    }
                }
                // Without negotiated HANDLE_KILLPRIV Linux refreshes the inode
                // before calculating the mode removed by non-directory chown.
                if !self.node.directory {
                    let mode = self.node.borrow().mode;
                    let kill = (mode & 0o4000) | if mode & 0o2010 == 0o2010 { 0o2000 } else { 0 };
                    if kill != 0 {
                        valid |= 1;
                        body[68..72].copy_from_slice(&(mode & !kill).to_le_bytes());
                    }
                }
            }
            AttributeChange::Times(times) => {
                let now = storage::Timestamp::now();
                for (i, [seconds, nanos]) in
                    times.unwrap_or([[0, UTIME_NOW]; 2]).into_iter().enumerate()
                {
                    if nanos == UTIME_OMIT {
                        continue;
                    }
                    valid |= 16 << i;
                    let stamp = if nanos == UTIME_NOW {
                        valid |= 128 << i;
                        now
                    } else {
                        storage::Timestamp {
                            seconds,
                            nanos: nanos as u32,
                        }
                    };
                    let offset = 32 + i * 8;
                    body[offset..offset + 8].copy_from_slice(&stamp.seconds.to_le_bytes());
                    let offset = 56 + i * 4;
                    body[offset..offset + 4].copy_from_slice(&stamp.nanos.to_le_bytes());
                }
            }
            AttributeChange::Size { length, .. } => {
                valid = 8 | 512; // SIZE | LOCKOWNER
                body[16..24].copy_from_slice(&length.to_le_bytes());
                body[24..32].copy_from_slice(&self.lock_owner.to_le_bytes());
                if !self.credentials.has_cap(capabilities::FSETID) {
                    let mode = self.node.borrow().mode;
                    let kill = (mode & 0o4000) | if mode & 0o2010 == 0o2010 { 0o2000 } else { 0 };
                    if kill != 0 {
                        valid |= 1;
                        body[68..72].copy_from_slice(&(mode & !kill).to_le_bytes());
                    }
                }
            }
        }
        if matches!(self.change, AttributeChange::Size { opening: false, .. }) {
            if let Some(fh) = self._file.as_ref().and_then(|file| file.fh) {
                valid |= 64;
                body[8..16].copy_from_slice(&fh.to_le_bytes());
            }
        }
        body[..4].copy_from_slice(&valid.to_le_bytes());
        Ok(body)
    }
    fn refresh(&self, bytes: &mut [u8], version: u64, set: bool) -> Result<()> {
        if set
            && bytes.len() == 104
            && self.fs.connection.option(1 << 16)
            && inode::attr(&self.node).kind_is_regular()
        {
            let attr = inode::attr(&self.node).lock().unwrap();
            if !matches!(self.change, AttributeChange::Size { .. }) {
                bytes[24..32].copy_from_slice(&attr[8..16]);
            }
            if !matches!(
                self.change,
                AttributeChange::Size { .. } | AttributeChange::Times(_)
            ) {
                bytes[48..56].copy_from_slice(&attr[32..40]);
                bytes[68..72].copy_from_slice(&attr[52..56]);
            }
        }
        self.fs
            .refresh_permission_attr(&self.node, bytes, version, set)
    }
    fn mask(&self) -> u32 {
        match self.change {
            AttributeChange::Size { .. } => inotify::MODIFY,
            AttributeChange::Times(Some(t)) if t[1][1] == UTIME_OMIT => inotify::ACCESS,
            AttributeChange::Times(Some(t)) if t[0][1] == UTIME_OMIT => inotify::MODIFY,
            _ => inotify::ATTRIB,
        }
    }
}
impl Metadata {
    pub(crate) fn path_size(
        v: &Vfs,
        mount: &mounts::MountData,
        fs: &Arc<Mounted>,
        node: NodeRef,
        length: u64,
        link: Option<Arc<inotify::Link>>,
    ) -> Result<Self> {
        fs.check_inode(&node)?;
        let kind = node.borrow().mode & 0o170000;
        if kind == 0o040000 {
            return Err(Errno(21));
        }
        if kind != 0o100000 || length > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let current = u64::from_le_bytes(
            inode::attr(&node).lock().unwrap()[8..16]
                .try_into()
                .unwrap(),
        );
        if length > current && length > v.file_size_limit.get() {
            v.file_size_signal.set(true);
            return Err(Errno(27));
        }
        Self::attributes(
            v,
            mount,
            fs,
            node,
            None,
            AttributeChange::Size {
                length,
                opening: false,
            },
            link,
        )
    }
    pub(super) fn file_size(v: &Vfs, file: Arc<File>, length: u64, opening: bool) -> Result<Self> {
        file.attr.check()?;
        if file.fh.is_none() {
            return Err(Errno(9));
        }
        if !opening && !fd_can_write(file.flags) {
            return Err(Errno(22));
        }
        let node = file.inode().ok_or(Errno(5))?;
        if node.borrow().mode & 0o170000 != 0o100000 {
            return Err(Errno(22));
        }
        if length > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let current = u64::from_le_bytes(file.attr.lock().unwrap()[8..16].try_into().unwrap());
        if length > current && length > v.file_size_limit.get() {
            v.file_size_signal.set(true);
            return Err(Errno(27));
        }
        let mount = file.mount.clone();
        let fs = file.reference.fs.clone();
        Self::attributes(
            v,
            &mount,
            &fs,
            node,
            Some(file),
            AttributeChange::Size { length, opening },
            None,
        )
    }
    pub(crate) fn attributes(
        v: &Vfs,
        mount: &mounts::MountData,
        fs: &Arc<Mounted>,
        node: NodeRef,
        file: Option<Arc<File>>,
        change: AttributeChange,
        link: Option<Arc<inotify::Link>>,
    ) -> Result<Self> {
        fs.check(&v.credentials)?;
        if matches!(change, AttributeChange::Mode(_)) && node.borrow().mode & 0o170000 == 0o120000 {
            return Err(Errno(95));
        }
        let reference = LookupRef::retained(fs, node.clone());
        let mut operation = Attributes {
            phase: Phase::Set,
            check: None,
            transaction: None,
            waiting: None,
            change,
            node,
            fs: fs.clone(),
            caller: fs.caller(v),
            credentials: v.credentials.clone(),
            _file: file,
            lock_owner: u64::from(v.lock_owner),
            _writer: mapped::MountWrite::new(&mount.identity)?,
            link,
        };
        // An accepted writable OFD retains write authority after chmod/chown.
        // O_TRUNC has already passed the open permission check on this inode.
        let request = operation.begin(reference.node)?;
        Ok(Self {
            request,
            kind: ResultKind::Attributes(Box::new(operation)),
            _usage: Some(mounts::MountUse::new(mount.identity.clone())),
            resolved: None,
            resolved_entry: None,
            reference: Some(reference),
            open: None,
            mount: StatMount::mounted(mount.id, false),
            dev: mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
            retry: None,
        })
    }
    pub(super) fn advance_attributes(
        &mut self,
        result: Result<Vec<u8>>,
    ) -> Result<Option<FileValue>> {
        let version = self.request.as_ref().map_or(0, |r| r.attr_version);
        let ResultKind::Attributes(operation) = &mut self.kind else {
            unreachable!()
        };
        match operation.phase {
            Phase::Lock => unreachable!("lock wait has no daemon reply"),
            Phase::Permission => {
                let check = operation.check.as_mut().unwrap();
                check.accept(&operation.fs, result)?;
                if let Some(request) = check.next(&operation.fs, operation.caller)? {
                    self.request = Some(request);
                    return Ok(None);
                }
                operation.check = None;
                operation.permission()?;
                operation.phase = operation.start_phase();
            }
            Phase::Capabilities => {
                let present = killpriv::capabilities_present(&operation.fs, result);
                operation.phase =
                    if present && operation.fs.xattr_unsupported.load(Ordering::Relaxed) & 8 == 0 {
                        Phase::RemoveCapabilities
                    } else {
                        Phase::Refresh
                    };
            }
            Phase::RemoveCapabilities => {
                killpriv::removed_capabilities(&operation.fs, result)?;
                operation.phase = Phase::Refresh;
            }
            Phase::Refresh => {
                operation.refresh(&mut result?, version, false)?;
                operation.phase = Phase::Set;
            }
            Phase::Set => {
                operation.refresh(&mut result?, version, true)?;
                operation.fs.invalidate_acl(&operation.node);
                inotify::notify(&operation.node, operation.mask(), operation.link.as_ref());
                let opening = matches!(
                    operation.change,
                    AttributeChange::Size { opening: true, .. }
                );
                let file = opening.then(|| {
                    operation
                        ._file
                        .take()
                        .expect("unpublished original FUSE open")
                });
                return if let Some(file) = file {
                    self.publish_file(file).map(Some)
                } else {
                    Ok(Some(FileValue::Count(0)))
                };
            }
        }
        self.request = Some(operation.request(self.reference.as_ref().unwrap().node)?);
        Ok(None)
    }
    pub(super) fn resume_attributes(&mut self) -> Result<Option<FileValue>> {
        let ResultKind::Attributes(operation) = &mut self.kind else {
            unreachable!()
        };
        self.request = operation.begin(self.reference.as_ref().unwrap().node)?;
        Ok(None)
    }
}
impl Vfs {
    fn defer_fuse_attributes(
        &self,
        mount: &mounts::MountData,
        node: NodeRef,
        file: Option<Arc<File>>,
        change: AttributeChange,
        link: Option<Arc<inotify::Link>>,
    ) -> Result<()> {
        let query = self.query.as_ref().ok_or(Errno(95))?;
        let fs = mount.fs.fuse.as_ref().unwrap();
        let operation = Metadata::attributes(self, mount, fs, node, file, change, link)?;
        query.prepared.borrow_mut().fuse = Some(Box::new(operation));
        query.defer()
    }
    pub(crate) fn fuse_path_attributes(
        &self,
        target: &MetadataTarget,
        change: AttributeChange,
    ) -> Option<Result<()>> {
        let mount = target.path.mount.as_ref()?;
        mount.fs.fuse.as_ref()?;
        Some(self.defer_fuse_attributes(
            &mount.shared,
            target.node.clone(),
            None,
            change,
            self.event_link(&target.path, &target.node),
        ))
    }
    pub(crate) fn fuse_fd_attributes(
        &self,
        fd: u32,
        change: AttributeChange,
    ) -> Option<Result<()>> {
        let descriptor = match self.descriptor(fd) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let open = descriptor.open.borrow();
        let mount = open.mount.as_ref()?;
        mount.fs.fuse.as_ref()?;
        let file = match &open.control {
            Some(events::SharedControl::FuseFile(f)) => Some(f.clone()),
            _ => None,
        };
        let node = open.node.clone().or_else(|| file.as_ref()?.inode());
        let Some(node) = node else {
            return Some(Err(Errno(95)));
        };
        Some(self.defer_fuse_attributes(
            mount,
            node,
            file,
            change,
            open.notification.as_ref().and_then(|n| n.link.clone()),
        ))
    }
}
