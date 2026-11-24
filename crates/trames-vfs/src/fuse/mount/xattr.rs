// SPDX-License-Identifier: GPL-3.0-or-later
//! Daemon xattrs use the final inode and the caller's actual buffer capacity.
use super::*;
#[derive(Clone, Copy)]
pub(crate) enum XattrCall<'a> {
    Read {
        name: Option<&'a [u8]>,
        capacity: u64,
    },
    Write {
        name: &'a [u8],
        value: Option<&'a [u8]>,
        flags: u32,
    },
}
impl XattrCall<'_> {
    fn opcode(self) -> u32 {
        match self {
            Self::Read { name: Some(_), .. } => 22,
            Self::Read { name: None, .. } => 23,
            Self::Write { value: Some(_), .. } => 21,
            Self::Write { value: None, .. } => 24,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flavor {
    Plain,
    Acl,
    Capabilities,
}
pub(super) struct Xattr {
    opcode: u32,
    capacity: u32,
    wire_capacity: u32,
    flavor: Flavor,
    querying: bool,
    permission: Option<(posix::Check, Vec<u8>)>,
    body: Option<Vec<u8>>,
    generic_permission: bool,
    credentials: Credentials,
    transaction: Option<inode::Write>,
    waiting_lock: bool,
    acl: Option<posix::Claim>,
    cached_acl: Option<Option<Arc<Vec<u8>>>>,
    fs: Arc<Mounted>,
    reader: UserNamespace,
    caller: Caller,
    node: NodeRef,
    _file: Option<Arc<File>>,
    _writer: Option<mapped::MountWrite>,
    link: Option<Arc<inotify::Link>>,
}
impl Drop for Xattr {
    fn drop(&mut self) {
        if let Some(claim) = self.acl.take() {
            self.fs.acl_cache(&self.node).cancel(claim);
        }
    }
}
fn map_acl(mut bytes: Vec<u8>, from: &UserNamespace, to: &UserNamespace) -> Result<Vec<u8>> {
    acl::decode(&bytes)?;
    acl::normalize(&mut bytes);
    for entry in bytes[4..].chunks_exact_mut(8) {
        let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
        if matches!(tag, 2 | 8) {
            let group = tag == 8;
            let id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            let global = from.to_global(group, id).ok_or(Errno(22))?;
            let mapped = to.from_global(group, global);
            entry[4..8].copy_from_slice(&mapped.unwrap_or(u32::MAX).to_le_bytes());
        }
    }
    Ok(bytes)
}
impl Xattr {
    pub(super) fn waiting_lock(&self) -> bool {
        self.waiting_lock
    }
    pub(super) fn lock_ready(&self) -> bool {
        !inode::attr(&self.node).writing()
    }
    pub(super) fn subscribe_lock(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        inode::attr(&self.node).subscribe_write(signal)
    }
    fn begin(&mut self, node: u64) -> Result<Option<Arc<Request>>> {
        if self._writer.is_some() && self.transaction.is_none() {
            let Some(transaction) = inode::attr(&self.node).try_write() else {
                self.waiting_lock = true;
                return Ok(None);
            };
            self.transaction = Some(transaction);
            self.waiting_lock = false;
            // The accepted inode can have changed owner while waiting behind
            // chmod/chown or a data writer. Recheck under its transaction.
            let value = self.node.borrow();
            let credentials = &self.credentials;
            if self.flavor == Flavor::Acl
                && credentials.fsuid != value.uid
                && !credentials.inode_cap(capabilities::FOWNER, value.uid, value.gid)
                || self.flavor == Flavor::Capabilities
                    && !credentials.inode_cap(capabilities::SETFCAP, value.uid, value.gid)
            {
                return Err(Errno(1));
            }
        }
        let body = self.body.take().expect("unsubmitted xattr body");
        let mask = if self._writer.is_some() { 2 } else { 4 };
        if self.fs.local_permissions()
            && self.generic_permission
            && self
                .fs
                .permission_refresh(&self.node, &self.credentials, mask)
        {
            let mut check = posix::Check::new(self.node.clone(), self.credentials.clone(), mask);
            if let Some(request) = check.next(&self.fs, self.caller)? {
                self.permission = Some((check, body));
                return Ok(Some(request));
            }
        }
        self.send(node, &body).map(Some)
    }
    fn finish_acl(&self, value: Option<&Vec<u8>>) -> Result<FileValue> {
        let mut bytes = value.ok_or(Errno(61))?.clone();
        for entry in bytes[4..].chunks_exact_mut(8) {
            let tag = u16::from_le_bytes(entry[..2].try_into().unwrap());
            if matches!(tag, 2 | 8) {
                let global = u32::from_le_bytes(entry[4..8].try_into().unwrap());
                let id = self
                    .reader
                    .from_global(tag == 8, global)
                    .unwrap_or(u32::MAX);
                entry[4..8].copy_from_slice(&id.to_le_bytes());
            }
        }
        self.read_value(bytes)
    }
    fn send(&self, node: u64, body: &[u8]) -> Result<Arc<Request>> {
        self.fs.check_inode(&self.node)?;
        let unsupported = self.fs.xattr_unsupported.load(Ordering::Relaxed);
        if self.flavor == Flavor::Acl && self._writer.is_some() && unsupported & 1 != 0 {
            return Err(Errno(95));
        }
        if unsupported & (1 << (self.opcode - 21)) != 0 {
            return Err(Errno(if self.flavor == Flavor::Acl && self.opcode == 22 {
                61
            } else {
                95
            }));
        }
        let mut adjusted;
        let body = if self.opcode == 21 && self.fs.connection.option(1 << 29) {
            adjusted = body.to_vec();
            let inode = self.node.borrow();
            let kill = self.flavor == Flavor::Acl
                && self.fs.posix_acl()
                && !self.credentials.in_group(inode.gid)
                && !self
                    .credentials
                    .inode_cap(capabilities::FSETID, inode.uid, inode.gid);
            adjusted[8..12].copy_from_slice(&u32::from(kill).to_le_bytes());
            &adjusted[..]
        } else {
            body
        };
        Ok(Arc::new(self.fs.connection.request(
            self.opcode,
            node,
            self.caller,
            body,
        )?))
    }
    fn response(&self, result: Result<Vec<u8>>) -> Result<Vec<u8>> {
        match result {
            Err(Errno(38)) => {
                self.fs
                    .xattr_unsupported
                    .fetch_or(1 << (self.opcode - 21), Ordering::Relaxed);
                Err(Errno(if self.flavor == Flavor::Acl && self.opcode == 22 {
                    61
                } else {
                    95
                }))
            }
            Err(Errno(34))
                if matches!(self.opcode, 22 | 23)
                    && (self.capacity == 65536 || self.flavor == Flavor::Acl) =>
            {
                Err(Errno(7))
            }
            other => other,
        }
    }
    fn read_value(&self, mut bytes: Vec<u8>) -> Result<FileValue> {
        if bytes.len() > self.wire_capacity as usize {
            return Err(Errno(5));
        }
        if self.flavor == Flavor::Capabilities && !bytes.is_empty() {
            bytes =
                file_caps::FileCaps::decode(&bytes, &self.fs.namespace)?.encode(&self.reader)?;
        }
        if self.opcode == 23 {
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                let n = rest.iter().position(|&c| c == 0).ok_or(Errno(5))?;
                if n == 0 {
                    return Err(Errno(5));
                }
                rest = &rest[n + 1..];
            }
        }
        if self.capacity == 0 {
            return Ok(FileValue::Count(bytes.len() as u64));
        }
        if bytes.len() > self.capacity as usize {
            return Err(Errno(34));
        }
        Ok(FileValue::Bytes(bytes))
    }
    fn finish(&self, bytes: Vec<u8>) -> Result<FileValue> {
        if matches!(self.opcode, 21 | 24) {
            if !bytes.is_empty() {
                return Err(Errno(5));
            }
            let now = storage::Timestamp::now();
            let mut value = self.node.borrow_mut();
            value.times[2] = now;
            let attr = self
                .node
                .fuse_leaf
                .get()
                .map(|n| &n.attr)
                .or_else(|| self.node.fuse_directory.get().map(|n| &n.attr));
            if let Some(attr) = attr {
                let mut a = attr.lock().unwrap();
                a[40..48].copy_from_slice(&now.seconds.to_le_bytes());
                a[56..60].copy_from_slice(&now.nanos.to_le_bytes());
            }
            drop(value);
            self.fs.invalidate_permission_attr(&self.node);
            inotify::notify(&self.node, inotify::ATTRIB, self.link.as_ref());
            return Ok(FileValue::Count(0));
        }
        if self.flavor == Flavor::Plain && self.capacity == 0 {
            if bytes.len() != 8 {
                return Err(Errno(5));
            }
            return Ok(FileValue::Count(
                u32::from_le_bytes(bytes[..4].try_into().unwrap()).min(65536) as u64,
            ));
        }
        self.read_value(bytes)
    }
}
impl Metadata {
    pub(crate) fn xattr(
        v: &Vfs,
        mount: &mounts::MountData,
        node: NodeRef,
        file: Option<Arc<File>>,
        call: XattrCall<'_>,
        link: Option<Arc<inotify::Link>>,
    ) -> Result<Option<Self>> {
        let fs = mount.fs.fuse.as_ref().unwrap();
        fs.check(&v.credentials)?;
        let writer = matches!(call, XattrCall::Write { .. })
            .then(|| mapped::MountWrite::new(&mount.identity))
            .transpose()?;
        let name = match call {
            XattrCall::Read { name, .. } => name,
            XattrCall::Write { name, .. } => Some(name),
        };
        let flavor = if name.is_some_and(acl::name) {
            Flavor::Acl
        } else if name == Some(file_caps::NAME) {
            Flavor::Capabilities
        } else {
            Flavor::Plain
        };
        let mut converted = None;
        if let Some(name) = name {
            let value = node.borrow();
            if name.starts_with(b"trusted.") && !v.credentials.has_cap(capabilities::SYS_ADMIN) {
                return Err(Errno(if writer.is_some() { 1 } else { 61 }));
            }
            if name.starts_with(b"user.") {
                if !matches!(value.mode & 0o170000, 0o100000 | 0o040000) {
                    return Err(Errno(if writer.is_some() { 1 } else { 61 }));
                }
                if writer.is_some()
                    && value.mode & 0o170000 == 0o040000
                    && value.mode & 0o1000 != 0
                    && v.credentials.fsuid != value.uid
                    && !v
                        .credentials
                        .inode_cap(capabilities::FOWNER, value.uid, value.gid)
                {
                    return Err(Errno(1));
                }
            }
            if flavor == Flavor::Acl {
                if value.mode & 0o170000 == 0o120000
                    || !fs.namespace.is_initial() && !fs.posix_acl()
                {
                    return Err(Errno(95));
                }
                if let XattrCall::Write { value: bytes, .. } = call {
                    if let Some(bytes) = bytes.filter(|b| !b.is_empty()) {
                        converted = Some(map_acl(
                            bytes.to_vec(),
                            &v.credentials.user_namespace,
                            &fs.namespace,
                        )?);
                    }
                    if converted.as_ref().is_some_and(|b| b.len() == 4) {
                        converted = None;
                    }
                    if name == acl::DEFAULT && !node.directory {
                        if converted.is_some() {
                            return Err(Errno(13));
                        }
                        return Ok(None);
                    }
                    if v.credentials.fsuid != value.uid
                        && !v
                            .credentials
                            .inode_cap(capabilities::FOWNER, value.uid, value.gid)
                    {
                        return Err(Errno(1));
                    }
                    if let Some(bytes) = &converted {
                        acl::validate(bytes)?;
                    }
                    if converted.as_ref().is_some_and(|b| b.len() > 4096) {
                        return Err(Errno(7));
                    }
                }
            }
            if flavor == Flavor::Capabilities && writer.is_some() {
                if !v
                    .credentials
                    .inode_cap(capabilities::SETFCAP, value.uid, value.gid)
                {
                    return Err(Errno(1));
                }
                if let XattrCall::Write {
                    value: Some(bytes), ..
                } = call
                {
                    converted = Some(
                        file_caps::FileCaps::parse(bytes, &v.credentials.user_namespace)?
                            .encode(&fs.namespace)?,
                    );
                }
            }
        }
        let call = match call {
            XattrCall::Write { name, .. } if flavor == Flavor::Acl => XattrCall::Write {
                name,
                flags: 0,
                value: converted.as_deref(),
            },
            XattrCall::Write { name, flags, .. }
                if flavor == Flavor::Capabilities && converted.is_some() =>
            {
                XattrCall::Write {
                    name,
                    flags,
                    value: converted.as_deref(),
                }
            }
            call => call,
        };
        let opcode = call.opcode();
        let mut body = Vec::new();
        let capacity;
        let wire_capacity;
        match call {
            XattrCall::Read {
                name,
                capacity: limit,
            } => {
                capacity = limit.min(65536) as u32;
                wire_capacity = match flavor {
                    Flavor::Acl => 4096,
                    Flavor::Capabilities => 0,
                    _ => capacity,
                };
                body.extend(wire_capacity.to_le_bytes());
                body.extend([0; 4]);
                if let Some(name) = name {
                    body.extend(name);
                    body.push(0);
                }
            }
            XattrCall::Write { name, value, flags } => {
                capacity = 0;
                wire_capacity = 0;
                if let Some(value) = value {
                    body.extend((value.len() as u32).to_le_bytes());
                    body.extend(flags.to_le_bytes());
                    if fs.connection.option(1 << 29) {
                        let inode = node.borrow();
                        let kill = flavor == Flavor::Acl
                            && fs.posix_acl()
                            && !v.credentials.in_group(inode.gid)
                            && !v
                                .credentials
                                .inode_cap(capabilities::FSETID, inode.uid, inode.gid);
                        drop(inode);
                        body.extend(u32::from(kill).to_le_bytes());
                        body.extend([0; 4]);
                    }
                    body.extend(name);
                    body.push(0);
                    body.extend(value);
                } else {
                    body.extend(name);
                    body.push(0);
                }
            }
        }
        let reference = LookupRef::retained(fs, node.clone());
        let caller = fs.caller(v);
        fs.check_inode(&node)?;
        let (mut acl, mut cached_acl) = (None, None);
        if flavor == Flavor::Acl && opcode == 22 && fs.posix_acl() {
            let kind = if name == Some(acl::DEFAULT) {
                posix::Kind::Default
            } else {
                posix::Kind::Access
            };
            match fs.acl_cache(&node).begin(kind) {
                posix::Read::Cached(value) => cached_acl = Some(value),
                posix::Read::Pending(claim) => acl = Some(claim),
            }
        }
        let generic_permission = name.is_some_and(|name| {
            !name.starts_with(b"trusted.")
                && !name.starts_with(b"security.")
                && !name.starts_with(b"system.")
        });
        let mut operation = Xattr {
            opcode,
            capacity,
            wire_capacity,
            flavor,
            permission: None,
            body: Some(body),
            generic_permission,
            credentials: v.credentials.clone(),
            transaction: None,
            waiting_lock: false,
            acl,
            cached_acl,
            querying: flavor == Flavor::Capabilities && opcode == 22,
            fs: fs.clone(),
            reader: v.credentials.user_namespace.clone(),
            caller,
            node,
            _file: file,
            _writer: writer,
            link,
        };
        let request = if operation.cached_acl.is_some() {
            None
        } else {
            operation.begin(reference.node)?
        };
        Ok(Some(Self {
            request,
            kind: ResultKind::Xattr(Box::new(operation)),
            _usage: Some(mounts::MountUse::new(mount.identity.clone())),
            resolved: None,
            resolved_entry: None,
            reference: Some(reference),
            open: None,
            mount: StatMount::mounted(mount.id, false),
            dev: mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        }))
    }
    pub(super) fn cached_xattr(&mut self) -> Result<FileValue> {
        let ResultKind::Xattr(operation) = &mut self.kind else {
            unreachable!()
        };
        let value = operation.cached_acl.take().expect("cached ACL phase");
        operation.finish_acl(value.as_deref())
    }
    pub(super) fn resume_xattr(&mut self) -> Result<Option<FileValue>> {
        let ResultKind::Xattr(operation) = &mut self.kind else {
            unreachable!()
        };
        self.request = operation.begin(self.reference.as_ref().unwrap().node)?;
        Ok(None)
    }
    pub(super) fn advance_xattr(&mut self, result: Result<Vec<u8>>) -> Result<Option<FileValue>> {
        let ResultKind::Xattr(operation) = &mut self.kind else {
            unreachable!()
        };
        if let Some((mut check, body)) = operation.permission.take() {
            check.accept(&operation.fs, result)?;
            if let Some(request) = check.next(&operation.fs, operation.caller)? {
                operation.permission = Some((check, body));
                self.request = Some(request);
            } else {
                self.request = Some(operation.send(self.reference.as_ref().unwrap().node, &body)?);
            }
            return Ok(None);
        }
        if operation.flavor == Flavor::Acl
            && matches!(operation.opcode, 21 | 24)
            && operation.fs.posix_acl()
        {
            operation.fs.invalidate_acl(&operation.node);
            operation.fs.invalidate_permission_attr(&operation.node);
        }
        if operation.flavor == Flavor::Acl && operation.opcode == 22 {
            let value = operation.fs.decode_acl(operation.response(result));
            if let Some(claim) = operation.acl.take() {
                operation
                    .fs
                    .acl_cache(&operation.node)
                    .complete(claim, &value);
            }
            return operation.finish_acl(value?.as_deref()).map(Some);
        }
        let bytes = operation.response(result)?;
        if operation.querying {
            if bytes.len() != 8 {
                return Err(Errno(5));
            }
            let size = u32::from_le_bytes(bytes[..4].try_into().unwrap()).min(65536);
            if size == 0 {
                return operation.read_value(Vec::new()).map(Some);
            }
            operation.querying = false;
            operation.wire_capacity = size;
            let mut body = Vec::new();
            body.extend(size.to_le_bytes());
            body.extend([0; 4]);
            body.extend(file_caps::NAME);
            body.push(0);
            self.request = Some(Arc::new(operation.fs.connection.request(
                22,
                self.reference.as_ref().unwrap().node,
                operation.caller,
                &body,
            )?));
            return Ok(None);
        }
        operation.finish(bytes).map(Some)
    }
}
impl Vfs {
    pub(crate) fn defer_fuse_xattr(
        &self,
        mount: &mounts::MountData,
        node: NodeRef,
        file: Option<Arc<File>>,
        call: XattrCall<'_>,
        link: Option<Arc<inotify::Link>>,
    ) -> Result<()> {
        let query = self.query.as_ref().ok_or(Errno(95))?;
        let Some(pending) = Metadata::xattr(self, mount, node, file, call, link)? else {
            return Ok(());
        };
        query.prepared.borrow_mut().fuse = Some(Box::new(pending));
        query.defer()
    }
}
