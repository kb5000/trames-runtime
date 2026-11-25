// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted namespace operands and daemon-owned directory mutations.
use super::*;
pub(super) mod locks;

pub(crate) struct PathPlan {
    pub(super) mount: Arc<mounts::MountData>,
    pub(super) fs: Arc<Mounted>,
    pub(super) start: u64,
    pub(super) start_directory: NodeRef,
    pub(super) anchor: Option<SharedFd>,
    pub(super) names: VecDeque<Vec<u8>>,
    pub(super) trailing: bool,
    pub(super) walk: Option<Box<PathWalk>>,
    pub(super) link: Option<(NodeRef, ResolvedPath)>,
    pub(super) _usage: mounts::MountUse,
}
impl PathPlan {
    pub(crate) fn root(
        mount: &Arc<mounts::Mount>,
        fs: &Arc<Mounted>,
        names: VecDeque<Vec<u8>>,
        trailing: bool,
    ) -> Self {
        Self {
            mount: mount.shared.clone(),
            fs: fs.clone(),
            start: 1,
            start_directory: fs.root_directory(),
            anchor: None,
            names,
            trailing,
            walk: None,
            link: None,
            _usage: mounts::MountUse::new(mount.identity.clone()),
        }
    }
    pub(crate) fn with_walk(mut self, walk: PathWalk) -> Self {
        self.walk = Some(Box::new(walk));
        self
    }
    pub(crate) fn at_link(mut self, node: NodeRef, parent: ResolvedPath) -> Self {
        self.link = Some((node, parent));
        self
    }
    pub(crate) fn at_directory(mut self, directory: NodeRef) -> Self {
        self.start = directory.fuse_directory.get().unwrap().id();
        self.start_directory = directory;
        self
    }
}

pub(crate) enum Action {
    Mkdir { mode: u32 },
    Mknod { mode: u32, device: u32 },
    Symlink(Vec<u8>),
    Link(Box<crate::namespace::LinkSource>),
    Unlink { directory: bool },
    Rename { flags: u32 },
}
struct Frame {
    node: u64,
    attr: [u8; 88],
    generation: u64,
    validity: (u64, u32),
    version: u64,
    directory: Option<NodeRef>,
    _reference: Option<LookupRef>,
}
impl Frame {
    fn entry(
        fs: &Arc<Mounted>,
        caller: Caller,
        bytes: &[u8],
        version: u64,
        kind: Option<u32>,
    ) -> Result<Self> {
        if kind.is_none() && bytes.len() == 128 && bytes[..8] == 1u64.to_le_bytes() {
            let mut raw: [u8; 88] = bytes[40..].try_into().unwrap();
            fs.apply_root_lookup(
                &mut raw,
                version,
                (
                    u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
                    u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
                ),
            )?;
            return Err(Errno(5));
        }
        let node = transport::entry_id(bytes, kind).ok_or(Errno(5))?;
        let reference = LookupRef::new(fs, caller, node);
        Ok(Self {
            node,
            version,
            attr: bytes[40..].try_into().unwrap(),
            generation: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            validity: (
                u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
                u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            ),
            directory: None,
            _reference: Some(reference),
        })
    }
    fn lookup(
        fs: &Arc<Mounted>,
        caller: Caller,
        bytes: &[u8],
        version: u64,
        parent: (&NodeRef, &[u8]),
    ) -> Result<Self> {
        if bytes.len() == 128 && bytes[..8] == [0; 8] {
            return Err(Errno(2));
        }
        let mut frame = Self::entry(fs, caller, bytes, version, None)?;
        frame.retain_inode(fs, parent.0, parent.1)?;
        Ok(frame)
    }
    fn retain_directory(&mut self, fs: &Mounted, parent: &NodeRef, name: &[u8]) -> Result<NodeRef> {
        if let Some(node) = &self.directory {
            return Ok(node.clone());
        }
        let node = fs.directory(
            self._reference.as_ref().unwrap(),
            self.generation,
            (parent, name),
            &mut self.attr,
            self.version,
            self.validity,
        )?;
        self.directory = Some(node.clone());
        Ok(node)
    }
    fn retain_inode(&mut self, fs: &Mounted, parent: &NodeRef, name: &[u8]) -> Result<NodeRef> {
        if self.kind() == 0o040000 {
            return self.retain_directory(fs, parent, name);
        }
        if let Some(node) = &self.directory {
            return Ok(node.clone());
        }
        let node = fs.leaf_inode(
            self._reference.as_ref().unwrap(),
            self.generation,
            parent,
            &mut self.attr,
            self.version,
            self.validity,
        )?;
        let reference = self._reference.as_mut().unwrap();
        reference.leaf = Some(node.clone());
        reference.entry = Some(fs.entries.bind(&node, parent, name));
        self.directory = Some(node.clone());
        Ok(node)
    }
    fn kind(&self) -> u32 {
        u32::from_le_bytes(self.attr[60..64].try_into().unwrap()) & 0o170000
    }
}
// Both operands already name original, fully resolved directories. This
// driver owns only their final LOOKUP and mutation protocol, never a second
// parent pathname algorithm.
struct MutationParent {
    path: PathPlan,
    name: Vec<u8>,
    caller: Caller,
    current: Option<Frame>,
    refreshed: bool,
}
impl MutationParent {
    fn new(mut path: PathPlan, caller: Caller) -> Self {
        debug_assert!(path.walk.is_none());
        let name = path.names.pop_back().expect("resolved mutation leaf");
        debug_assert!(path.names.is_empty());
        Self {
            path,
            name,
            caller,
            current: None,
            refreshed: false,
        }
    }
    fn start(&mut self) -> Result<Option<Arc<Request>>> {
        self.path.fs.check_inode(&self.path.start_directory)?;
        if self.path.fs.connection.initialized()
            && self
                .path
                .fs
                .permission_attr_fresh(&self.path.start_directory)
        {
            let attr = inode::attr(&self.path.start_directory).lock().unwrap();
            self.current = Some(Frame {
                node: self.path.start,
                attr: **attr,
                version: attr.version,
                generation: 0,
                validity: (0, 0),
                directory: Some(self.path.start_directory.clone()),
                _reference: None,
            });
            return Ok(None);
        }
        let mut body = [0; 16];
        if let Some(anchor) = &self.path.anchor {
            if let Some(events::SharedControl::FuseFile(file)) = &anchor.open.control {
                if let Some(fh) = file.fh {
                    body[..4].copy_from_slice(&1u32.to_le_bytes());
                    body[8..].copy_from_slice(&fh.to_le_bytes());
                }
            }
        }
        self.path.fs.invalidate_acl(&self.path.start_directory);
        Ok(Some(Arc::new(self.path.fs.connection.request(
            3,
            self.path.start,
            self.caller,
            &body,
        )?)))
    }
    fn frame(&self) -> &Frame {
        self.current.as_ref().unwrap()
    }
    fn accept(&mut self, bytes: &[u8], version: u64) -> Result<()> {
        if bytes.len() != 104 {
            return Err(Errno(5));
        }
        let mut frame = Frame {
            node: self.path.start,
            version,
            attr: bytes[16..].try_into().unwrap(),
            generation: 0,
            validity: (
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            ),
            directory: Some(self.path.start_directory.clone()),
            _reference: None,
        };
        self.path.fs.refresh_inode_at(
            &self.path.start_directory,
            &mut frame.attr,
            version,
            frame.validity,
            inode::Update::Read,
        )?;
        frame.attr = **inode::attr(&self.path.start_directory).lock().unwrap();
        self.current = Some(frame);
        self.refreshed = true;
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum ParentAfter {
    SourceReady,
    Create,
    SourceFound,
    DestReady,
    Rename,
}
#[derive(Clone, Copy)]
enum Phase {
    Lock(AfterLock),
    ParentPermission(bool, u32, ParentAfter),
    LinkPermission,
    MovePermission(bool),
    SourceParent,
    CreateEntry,
    SourceEntry,
    DestParent,
    DestEntry,
    EmptyReply,
    EntryReply(u32),
}
#[derive(Clone, Copy)]
enum AfterLock {
    Start,
    Create,
    SourceFound,
    Rename,
}
pub(super) enum Step {
    Blocked,
    Waiting(Arc<Request>),
    Complete(FileValue),
}
pub(super) struct Mutation {
    locks: locks::Locks,
    _writer: mapped::MountWrite,
    source: MutationParent,
    dest: Option<MutationParent>,
    source_entry: Option<Frame>,
    dest_entry: Option<Frame>,
    credentials: Credentials,
    umask: Umask,
    action: Action,
    phase: Phase,
    link_checked: bool,
    link_error: bool,
    move_checked: u8,
    parent_grants: u8,
    pending_check: Option<posix::Check>,
}
impl Mutation {
    pub(super) fn stale_retry(&self) -> bool {
        match self.action {
            Action::Unlink { .. } | Action::Rename { .. } => true,
            // filename_create errors leave mkdir/mknod/symlink/link before
            // their outer retry label. Only the admitted mutation may retry.
            _ => matches!(
                self.phase,
                Phase::EmptyReply
                    | Phase::EntryReply(_)
                    | Phase::LinkPermission
                    | Phase::ParentPermission(_, _, ParentAfter::Create)
            ),
        }
    }
    fn blocked(&mut self, after: AfterLock) -> Step {
        self.phase = Phase::Lock(after);
        Step::Blocked
    }
    pub(super) fn waiting_lock(&self) -> bool {
        matches!(self.phase, Phase::Lock(_))
    }
    pub(super) fn lock_ready(&self) -> bool {
        self.locks.ready()
    }
    pub(super) fn subscribe_lock(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        self.locks.subscribe(signal)
    }
    pub(super) fn resume_lock(&mut self) -> Result<Step> {
        let Phase::Lock(after) = self.phase else {
            unreachable!()
        };
        match after {
            AfterLock::Start => self.start(),
            AfterLock::Create => self.create(),
            AfterLock::SourceFound => self.source_found(),
            AfterLock::Rename => self.rename(),
        }
    }
    fn start(&mut self) -> Result<Step> {
        if !self.locks.parents(
            &self.source.path.fs,
            &self.source.path.start_directory,
            self.dest.as_ref().map(|dest| &dest.path.start_directory),
        )? {
            return Ok(self.blocked(AfterLock::Start));
        }
        self.phase = Phase::SourceParent;
        match self.source.start()? {
            Some(request) => Ok(Step::Waiting(request)),
            None => self.source_ready(),
        }
    }
    pub(super) fn reply_inode(&self, id: u64) -> Option<NodeRef> {
        self.source
            .path
            .fs
            .attribute_target(id)
            .or_else(|| self.dest.as_ref()?.path.fs.attribute_target(id))
    }
    fn frame_permission(&self, frame: &Frame, mask: u32) -> Result<bool> {
        let word = |i| u32::from_le_bytes(frame.attr[i..i + 4].try_into().unwrap());
        let ns = &self.source.path.fs.namespace;
        let uid = ns.to_global(false, word(68)).unwrap_or(u32::MAX);
        let gid = ns.to_global(true, word(72)).unwrap_or(u32::MAX);
        Ok(self
            .credentials
            .allows_mode(uid, gid, word(60), frame.kind() == 0o040000, mask))
    }
    fn move_permission(&mut self, target: bool) -> Result<Option<Step>> {
        let bit = if target { 2 } else { 1 };
        let frame = if target {
            self.dest_entry.as_ref().unwrap()
        } else {
            self.source_entry.as_ref().unwrap()
        };
        if frame.kind() != 0o040000 || self.move_checked & bit != 0 {
            return Ok(None);
        }
        if !self.source.path.fs.posix_acl() && self.frame_permission(frame, 2)? {
            return Ok(None);
        }
        let parent = if target {
            self.dest.as_ref().unwrap()
        } else {
            &self.source
        };
        let frame = if target {
            self.dest_entry.as_mut().unwrap()
        } else {
            self.source_entry.as_mut().unwrap()
        };
        let node = frame.retain_directory(
            &self.source.path.fs,
            &parent.path.start_directory,
            &parent.name,
        )?;
        let mut check = posix::Check::new(node, self.credentials.clone(), 2);
        if let Some(request) = check.next(&self.source.path.fs, self.source.caller)? {
            self.pending_check = Some(check);
            self.phase = Phase::MovePermission(target);
            return Ok(Some(Step::Waiting(request)));
        }
        self.move_checked |= bit;
        Ok(None)
    }
    fn parent_permission(
        &mut self,
        dest: bool,
        mask: u32,
        after: ParentAfter,
    ) -> Result<Option<Step>> {
        let bit = (if dest { 4 } else { 1 }) * if mask == 3 { 2 } else { 1 };
        if self.parent_grants & bit != 0 {
            return Ok(None);
        }
        let parent = if dest {
            self.dest.as_ref().unwrap()
        } else {
            &self.source
        };
        let check = posix::Check::new(
            parent.path.start_directory.clone(),
            self.credentials.clone(),
            mask,
        );
        let mut check = if parent.refreshed {
            check.refreshed()
        } else {
            check
        };
        if let Some(request) = check.next(&parent.path.fs, parent.caller)? {
            self.pending_check = Some(check);
            self.phase = Phase::ParentPermission(dest, mask, after);
            return Ok(Some(Step::Waiting(request)));
        }
        self.parent_grants |= bit;
        Ok(None)
    }
    fn dest_ready(&mut self) -> Result<Step> {
        if let Some(step) = self.parent_permission(true, 1, ParentAfter::DestReady)? {
            return Ok(step);
        }
        self.phase = Phase::DestEntry;
        self.lookup(self.dest.as_ref().unwrap())
    }
    fn request(&self, opcode: u32, node: u64, body: &[u8]) -> Result<Step> {
        let connection = &self.source.path.fs.connection;
        let request = if let Phase::EntryReply(kind) = self.phase {
            connection.request_entry(opcode, node, self.source.caller, body, kind)?
        } else {
            connection.request(opcode, node, self.source.caller, body)?
        };
        Ok(Step::Waiting(Arc::new(request)))
    }
    fn lookup(&self, walker: &MutationParent) -> Result<Step> {
        Metadata::lookup_request(
            &walker.path.fs,
            walker.frame().node,
            walker.caller,
            walker.name.clone(),
        )
        .map(Step::Waiting)
    }
    fn sticky(&self, parent: &Frame, target: &Frame) -> Result<()> {
        let mode = u32::from_le_bytes(parent.attr[60..64].try_into().unwrap());
        if !self.source.path.fs.local_permissions() || mode & 0o1000 == 0 {
            return Ok(());
        }
        let namespace = &self.source.path.fs.namespace;
        let owner = |frame: &Frame, group: bool| {
            let at = if group { 72 } else { 68 };
            namespace
                .to_global(
                    group,
                    u32::from_le_bytes(frame.attr[at..at + 4].try_into().unwrap()),
                )
                .unwrap_or(u32::MAX)
        };
        if self.credentials.fsuid == owner(parent, false)
            || self.credentials.fsuid == owner(target, false)
            || self.credentials.inode_cap(
                capabilities::FOWNER,
                owner(target, false),
                owner(target, true),
            )
        {
            Ok(())
        } else {
            Err(Errno(1))
        }
    }
    fn source_ready(&mut self) -> Result<Step> {
        if let Some(step) = self.parent_permission(false, 1, ParentAfter::SourceReady)? {
            return Ok(step);
        }
        self.phase = if matches!(
            self.action,
            Action::Mkdir { .. } | Action::Mknod { .. } | Action::Symlink(_) | Action::Link(_)
        ) {
            Phase::CreateEntry
        } else {
            Phase::SourceEntry
        };
        self.lookup(&self.source)
    }
    fn create(&mut self) -> Result<Step> {
        if let Some(step) = self.parent_permission(false, 3, ParentAfter::Create)? {
            return Ok(step);
        }
        if self.source.path.trailing && !matches!(self.action, Action::Mkdir { .. }) {
            return Err(Errno(2));
        }
        let name = &self.source.name;
        let mut body = Vec::new();
        // Linux FUSE defers VFS umask stripping, then its callback masks mode
        // and reports a separate live fs_struct read. A daemon wait must not
        // freeze the caller's earlier mask.
        let callback_mask = if self.source.path.fs.dont_mask() {
            0
        } else {
            self.umask.get()
        };
        let umask = self.umask.get();
        let (opcode, kind) = match &self.action {
            Action::Mkdir { mode } => {
                let parent_mode =
                    u32::from_le_bytes(self.source.frame().attr[60..64].try_into().unwrap());
                body.extend(
                    ((mode & 0o1777 & !callback_mask) | (parent_mode & 0o2000)).to_le_bytes(),
                );
                body.extend(umask.to_le_bytes());
                (9, 0o040000)
            }
            Action::Mknod { mode, device } => {
                body.extend((mode & !callback_mask).to_le_bytes());
                body.extend(device.to_le_bytes());
                body.extend(umask.to_le_bytes());
                body.extend([0; 4]);
                (8, mode & 0o170000)
            }
            Action::Symlink(_) => (6, 0o120000),
            Action::Link(source) => {
                if source.path.mount.as_ref().map(|m| m.id) != Some(self.source.path.mount.id) {
                    return Err(Errno(18));
                }
                let node = source.node.borrow();
                if node.mode & 0o170000 == 0o040000 || node.volatile {
                    return Err(Errno(1));
                }
                if !self.link_checked
                    && self.source.path.fs.local_permissions()
                    && source.policy.get(sysctl::Protection::Hardlinks) != 0
                    && node.mode & 0o170000 == 0o100000
                    && node.mode & 0o4000 == 0
                    && node.mode & 0o2010 != 0o2010
                    && (self.source.path.fs.posix_acl()
                        || self.source.path.fs.permission_refresh(
                            &source.node,
                            &self.credentials,
                            6,
                        ))
                {
                    drop(node);
                    let mut check =
                        posix::Check::new(source.node.clone(), self.credentials.clone(), 6);
                    match check.next(&self.source.path.fs, self.source.caller) {
                        Ok(Some(request)) => {
                            self.pending_check = Some(check);
                            self.phase = Phase::LinkPermission;
                            return Ok(Step::Waiting(request));
                        }
                        Ok(None) => self.link_checked = true,
                        Err(_) => {
                            self.link_checked = true;
                            self.link_error = true;
                        }
                    }
                    return self.create();
                }
                if self.link_error
                    && source.policy.get(sysctl::Protection::Hardlinks) != 0
                    && self.credentials.fsuid != node.uid
                    && !self
                        .credentials
                        .inode_cap(capabilities::FOWNER, node.uid, node.gid)
                {
                    return Err(Errno(1));
                }
                crate::namespace::link_permission(
                    &self.credentials,
                    source.policy.get(sysctl::Protection::Hardlinks),
                    &node,
                    !self.source.path.fs.local_permissions()
                        || self.link_checked && !self.link_error,
                )?;
                if node.links == 0 {
                    return Err(Errno(2));
                }
                let id = source.node.fuse_leaf.get().ok_or(Errno(18))?.node;
                let kind = node.mode & 0o170000;
                let inode = source.node.clone();
                drop(node);
                if !self.locks.child(&inode) {
                    return Ok(self.blocked(AfterLock::Create));
                }
                // VFS source checks precede the daemon's cached capability.
                if self.source.path.fs.link_unsupported.load(Ordering::Relaxed) {
                    return Err(Errno(1));
                }
                body.extend(id.to_le_bytes());
                (13, kind)
            }
            Action::Unlink { .. } | Action::Rename { .. } => {
                unreachable!()
            }
        };
        body.extend(name);
        body.push(0);
        if let Action::Symlink(target) = &self.action {
            body.extend(target);
            body.push(0);
        }
        self.phase = Phase::EntryReply(kind);
        self.request(opcode, self.source.frame().node, &body)
    }
    fn source_found(&mut self) -> Result<Step> {
        let target = self.source_entry.as_ref().unwrap();
        if self.source.path.trailing && target.kind() != 0o040000 {
            return Err(Errno(20));
        }
        if let Some(step) = self.parent_permission(false, 3, ParentAfter::SourceFound)? {
            return Ok(step);
        }
        let target = self.source_entry.as_ref().unwrap();
        self.sticky(self.source.frame(), target)?;
        match self.action {
            Action::Unlink { directory } => {
                let is_directory = target.kind() == 0o040000;
                if directory != is_directory {
                    return Err(Errno(if is_directory { 21 } else { 20 }));
                }
                let parent = self.source.path.start_directory.clone();
                let name = self.source.name.clone();
                let target = self.source_entry.as_mut().unwrap().retain_inode(
                    &self.source.path.fs,
                    &parent,
                    &name,
                )?;
                if !self.locks.child(&target) {
                    return Ok(self.blocked(AfterLock::SourceFound));
                }
                let mut body = self.source.name.clone();
                body.push(0);
                self.phase = Phase::EmptyReply;
                self.request(
                    if directory { 11 } else { 10 },
                    self.source.frame().node,
                    &body,
                )
            }
            Action::Rename { .. } => {
                self.phase = Phase::DestParent;
                match self.dest.as_mut().unwrap().start()? {
                    Some(request) => Ok(Step::Waiting(request)),
                    None => self.dest_ready(),
                }
            }
            _ => unreachable!(),
        }
    }
    fn rename(&mut self) -> Result<Step> {
        let Action::Rename { flags } = self.action else {
            unreachable!()
        };
        if let Some(step) = self.parent_permission(true, 3, ParentAfter::Rename)? {
            return Ok(step);
        }
        let source = self.source_entry.as_ref().unwrap();
        let dest = self.dest.as_ref().unwrap();
        let dest_entry = self.dest_entry.as_ref();
        if flags == 1 && dest_entry.is_some() {
            return Err(Errno(17));
        }
        if flags == 2 && dest_entry.is_none() {
            return Err(Errno(2));
        }
        if dest.path.trailing
            && (source.kind() != 0o040000 || dest_entry.is_some_and(|f| f.kind() != 0o040000))
        {
            return Err(Errno(20));
        }
        if let Some(target) = dest_entry {
            if source.node == target.node {
                return Ok(Step::Complete(FileValue::Count(0)));
            }
            self.sticky(dest.frame(), target)?;
            if flags != 2 && (source.kind() == 0o040000) != (target.kind() == 0o040000) {
                return Err(Errno(if source.kind() == 0o040000 { 20 } else { 21 }));
            }
        }
        if self.source.path.fs.local_permissions() && self.source.frame().node != dest.frame().node
        {
            if let Some(step) = self.move_permission(false)? {
                return Ok(step);
            }
            if flags == 2 && self.dest_entry.is_some() {
                if let Some(step) = self.move_permission(true)? {
                    return Ok(step);
                }
            }
        }
        let source = self.source_entry.as_ref().unwrap();
        let dest = self.dest.as_ref().unwrap();
        let dest_entry = self.dest_entry.as_ref();
        if source.kind() == 0o040000
            && dest
                .frame()
                .directory
                .as_ref()
                .unwrap()
                .fuse_directory
                .get()
                .unwrap()
                .descendant_of(source.node)
        {
            return Err(Errno(22));
        }
        if flags == 2
            && dest_entry.is_some_and(|f| {
                f.kind() == 0o040000
                    && self
                        .source
                        .frame()
                        .directory
                        .as_ref()
                        .unwrap()
                        .fuse_directory
                        .get()
                        .unwrap()
                        .descendant_of(f.node)
            })
        {
            return Err(Errno(22));
        }
        if flags != 0
            && self
                .source
                .path
                .fs
                .rename_unsupported
                .load(Ordering::Relaxed)
        {
            return Err(Errno(22));
        }
        // Linux locks moved subdirectories source first, then regular inodes
        // in pointer order. A same-parent rename need not lock its source dir.
        let cross = !Arc::ptr_eq(
            &self.source.path.start_directory,
            &dest.path.start_directory,
        );
        let source_needed = source.kind() != 0o040000 || cross;
        let dest_needed =
            dest_entry.is_some_and(|entry| entry.kind() != 0o040000 || cross || flags != 2);
        let mut nodes = Vec::new();
        if source_needed {
            nodes.push(self.source_entry.as_mut().unwrap().retain_inode(
                &self.source.path.fs,
                &self.source.path.start_directory,
                &self.source.name,
            )?);
        }
        if dest_needed {
            let dest = self.dest.as_ref().unwrap();
            nodes.push(self.dest_entry.as_mut().unwrap().retain_inode(
                &self.source.path.fs,
                &dest.path.start_directory,
                &dest.name,
            )?);
        }
        nodes.sort_by_key(|node| {
            (
                !node.directory,
                if node.directory {
                    0
                } else {
                    Arc::as_ptr(node) as usize
                },
            )
        });
        for node in &nodes {
            if !self.locks.child(node) {
                return Ok(self.blocked(AfterLock::Rename));
            }
        }
        let dest = self.dest.as_ref().unwrap();
        let mut body = dest.frame().node.to_le_bytes().to_vec();
        if flags != 0 {
            body.extend(flags.to_le_bytes());
            body.extend([0; 4]);
        }
        body.extend(&self.source.name);
        body.push(0);
        body.extend(&dest.name);
        body.push(0);
        self.phase = Phase::EmptyReply;
        self.request(
            if flags == 0 { 12 } else { 45 },
            self.source.frame().node,
            &body,
        )
    }
    fn publish_directory_changes(&self) -> Result<()> {
        let Some(source) = &self.source_entry else {
            return Ok(());
        };
        let fs = &self.source.path.fs;
        fs.inode_changed(&self.source.path.start_directory);
        if let Some(dest) = &self.dest {
            if !Arc::ptr_eq(
                &self.source.path.start_directory,
                &dest.path.start_directory,
            ) {
                fs.inode_changed(&dest.path.start_directory);
            }
        }
        let source_node = fs.known_directory(source.node, source.generation);
        let unlink = |node: NodeRef, parent: &NodeRef| {
            let _ = node.removed_directory_parent.set(parent.clone());
            node.fuse_directory.get().unwrap().unlink();
            fs.entry_unlinked(&node);
        };
        match &self.action {
            Action::Unlink { directory: false } => {
                if let Some(node) = fs.known_leaf(source.node, source.generation) {
                    fs.entries.unlink(
                        self.source.frame().directory.as_ref().unwrap(),
                        &self.source.name,
                        &node,
                    );
                    fs.entry_unlinked(&node);
                }
            }
            Action::Unlink { directory: true } => {
                if let Some(node) = source_node {
                    unlink(node, self.source.frame().directory.as_ref().unwrap());
                }
            }
            Action::Rename { flags } => {
                let dest = self.dest.as_ref().unwrap();
                if let Some(node) = source
                    .directory
                    .as_ref()
                    .cloned()
                    .or_else(|| fs.known_directory(source.node, source.generation))
                {
                    fs.inode_changed(&node);
                }
                let dest_node = self
                    .dest_entry
                    .as_ref()
                    .and_then(|entry| fs.known_directory(entry.node, entry.generation));
                let source_hint = source_node
                    .as_ref()
                    .map(|node| node.fuse_directory.get().unwrap().entry.clone())
                    .or_else(|| {
                        fs.known_leaf(source.node, source.generation)
                            .and_then(|node| {
                                fs.entries.matching(
                                    self.source.frame().directory.as_ref().unwrap(),
                                    &self.source.name,
                                    &node,
                                )
                            })
                    });
                let dest_hint = dest_node
                    .as_ref()
                    .map(|node| node.fuse_directory.get().unwrap().entry.clone())
                    .or_else(|| {
                        self.dest_entry
                            .as_ref()
                            .and_then(|entry| fs.known_leaf(entry.node, entry.generation))
                            .and_then(|node| {
                                fs.entries.matching(
                                    dest.frame().directory.as_ref().unwrap(),
                                    &dest.name,
                                    &node,
                                )
                            })
                    });
                fs.entries.rename(
                    (
                        self.source.frame().directory.as_ref().unwrap(),
                        &self.source.name,
                        source_hint,
                    ),
                    (
                        dest.frame().directory.as_ref().unwrap(),
                        &dest.name,
                        dest_hint,
                    ),
                    *flags == 2,
                    false,
                )?;
                if let Some(node) = dest_node {
                    if *flags != 2 {
                        unlink(node, dest.frame().directory.as_ref().unwrap());
                    } else {
                        fs.inode_changed(&node);
                    }
                } else if let Some(node) = self
                    .dest_entry
                    .as_ref()
                    .and_then(|entry| fs.known_leaf(entry.node, entry.generation))
                {
                    if *flags != 2 {
                        fs.entry_unlinked(&node);
                    } else {
                        fs.inode_changed(&node);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) fn advance(&mut self, result: Result<Vec<u8>>, version: u64) -> Result<Step> {
        match self.phase {
            Phase::Lock(_) => unreachable!("inode admission has no daemon reply"),
            Phase::ParentPermission(dest, mask, after) => {
                let parent = if dest {
                    self.dest.as_ref().unwrap()
                } else {
                    &self.source
                };
                let check = self.pending_check.as_mut().unwrap();
                check.accept(&parent.path.fs, result)?;
                if let Some(request) = check.next(&parent.path.fs, parent.caller)? {
                    return Ok(Step::Waiting(request));
                }
                let refreshed = check.attributes_refreshed();
                let parent = if dest {
                    self.dest.as_mut().unwrap()
                } else {
                    &mut self.source
                };
                let attributes = inode::attr(&parent.path.start_directory).lock().unwrap();
                let frame = parent.current.as_mut().unwrap();
                frame.attr = **attributes;
                frame.version = attributes.version;
                parent.refreshed |= refreshed;
                drop(attributes);
                self.pending_check = None;
                let bit = (if dest { 4 } else { 1 }) * if mask == 3 { 2 } else { 1 };
                self.parent_grants |= bit;
                match after {
                    ParentAfter::SourceReady => self.source_ready(),
                    ParentAfter::Create => self.create(),
                    ParentAfter::SourceFound => self.source_found(),
                    ParentAfter::DestReady => self.dest_ready(),
                    ParentAfter::Rename => self.rename(),
                }
            }
            Phase::LinkPermission => {
                let check = self.pending_check.as_mut().unwrap();
                let step = check
                    .accept(&self.source.path.fs, result)
                    .and_then(|()| check.next(&self.source.path.fs, self.source.caller));
                match step {
                    Ok(Some(request)) => return Ok(Step::Waiting(request)),
                    Ok(None) => self.link_error = false,
                    Err(_) => self.link_error = true,
                }
                self.pending_check = None;
                self.link_checked = true;
                self.create()
            }
            Phase::MovePermission(target) => {
                let check = self.pending_check.as_mut().unwrap();
                check.accept(&self.source.path.fs, result)?;
                if let Some(request) = check.next(&self.source.path.fs, self.source.caller)? {
                    return Ok(Step::Waiting(request));
                }
                let attr = **check
                    .node
                    .fuse_directory
                    .get()
                    .unwrap()
                    .attr
                    .lock()
                    .unwrap();
                let frame = if target {
                    self.dest_entry.as_mut().unwrap()
                } else {
                    self.source_entry.as_mut().unwrap()
                };
                frame.attr = attr;
                self.pending_check = None;
                self.move_checked |= if target { 2 } else { 1 };
                self.rename()
            }
            Phase::SourceParent => {
                self.source.accept(&result?, version)?;
                self.source_ready()
            }
            Phase::SourceEntry => {
                self.source_entry = Some(Frame::lookup(
                    &self.source.path.fs,
                    self.source.caller,
                    &result?,
                    version,
                    (&self.source.path.start_directory, &self.source.name),
                )?);
                self.source_found()
            }
            Phase::CreateEntry => {
                match result {
                    Err(Errno(2)) => {}
                    Ok(bytes) if bytes.len() == 128 && bytes[..8] == [0; 8] => {}
                    Ok(bytes) => {
                        self.source_entry = Some(Frame::lookup(
                            &self.source.path.fs,
                            self.source.caller,
                            &bytes,
                            version,
                            (&self.source.path.start_directory, &self.source.name),
                        )?);
                        return Err(Errno(17));
                    }
                    Err(error) => return Err(error),
                }
                self.create()
            }
            Phase::DestParent => {
                let dest = self.dest.as_mut().unwrap();
                dest.accept(&result?, version)?;
                self.dest_ready()
            }
            Phase::DestEntry => {
                self.dest_entry = match result {
                    Ok(bytes) if bytes.len() == 128 && bytes[..8] == [0; 8] => None,
                    Ok(bytes) => Some(Frame::lookup(
                        &self.source.path.fs,
                        self.source.caller,
                        &bytes,
                        version,
                        (
                            &self.dest.as_ref().unwrap().path.start_directory,
                            &self.dest.as_ref().unwrap().name,
                        ),
                    )?),
                    Err(Errno(2)) => None,
                    Err(error) => return Err(error),
                };
                self.rename()
            }
            Phase::EmptyReply => {
                if matches!(result, Err(Errno(38)))
                    && matches!(self.action, Action::Rename { flags } if flags != 0)
                {
                    self.source
                        .path
                        .fs
                        .rename_unsupported
                        .store(true, Ordering::Relaxed);
                    return Err(Errno(22));
                }
                if !result?.is_empty() {
                    return Err(Errno(5));
                }
                self.publish_directory_changes()?;
                Ok(Step::Complete(FileValue::Count(0)))
            }
            Phase::EntryReply(kind) => {
                if matches!(self.action, Action::Link(_)) && matches!(result, Err(Errno(38))) {
                    self.source
                        .path
                        .fs
                        .link_unsupported
                        .store(true, Ordering::Relaxed);
                    return Err(Errno(1));
                }
                let mut entry = Frame::entry(
                    &self.source.path.fs,
                    self.source.caller,
                    &result?,
                    version,
                    Some(kind),
                )?;
                let parent = self.source.frame().directory.as_ref().unwrap();
                if kind == 0o040000 {
                    let _inode = self.source.path.fs.directory(
                        entry._reference.as_ref().unwrap(),
                        entry.generation,
                        (parent, &self.source.name),
                        &mut entry.attr,
                        0,
                        entry.validity,
                    )?;
                } else {
                    let _inode = self.source.path.fs.leaf_inode(
                        entry._reference.as_ref().unwrap(),
                        entry.generation,
                        parent,
                        &mut entry.attr,
                        0,
                        entry.validity,
                    )?;
                }
                self.source.path.fs.inode_changed(parent);
                Ok(Step::Complete(FileValue::Count(0)))
            }
        }
    }
}
impl Metadata {
    pub(crate) fn namespace(
        v: &Vfs,
        path: PathPlan,
        action: Action,
        dest: Option<PathPlan>,
    ) -> Result<Self> {
        path.fs.check(&v.credentials)?;
        if path.mount.readonly() || dest.as_ref().is_some_and(|d| d.mount.readonly()) {
            return Err(Errno(30));
        }
        if dest.as_ref().is_some_and(|d| d.mount.id != path.mount.id) {
            return Err(Errno(18));
        }
        let caller = path.fs.caller(v);
        let mount = StatMount::mounted(path.mount.id, false);
        let dev = path.mount.device();
        let owner_ns = path.fs.namespace.clone();
        let writer = mapped::MountWrite::new(&path.mount.identity)?;
        let source = MutationParent::new(path, caller);
        let mut mutation = Box::new(Mutation {
            locks: Default::default(),
            _writer: writer,
            source,
            dest: dest.map(|d| MutationParent::new(d, caller)),
            source_entry: None,
            dest_entry: None,
            credentials: v.credentials.clone(),
            umask: v.umask_capability(),
            action,
            phase: Phase::SourceParent,
            link_checked: false,
            link_error: false,
            move_checked: 0,
            parent_grants: 0,
            pending_check: None,
        });
        let request = match mutation.start()? {
            Step::Waiting(request) => Some(request),
            Step::Blocked => None,
            Step::Complete(_) => unreachable!("initial namespace stage must resolve its leaf"),
        };
        Ok(Self {
            request,
            kind: ResultKind::Mutation(mutation),
            _usage: None,
            resolved: None,
            resolved_entry: None,
            reference: None,
            open: None,
            mount,
            dev,
            owner_ns,
            reader_ns: v.credentials.user_namespace.clone(),
            retry: None,
        })
    }
}
impl Vfs {
    pub(crate) fn capture_fuse_path(
        &self,
        dirfd: i32,
        path: &[u8],
        follow: bool,
    ) -> Result<(ResolvedPath, Option<PathPlan>)> {
        if path.is_empty() {
            return Err(Errno(2));
        }
        if path.len() >= MAX_PATH || path.contains(&0) {
            return Err(Errno(36));
        }
        let captured = RefCell::new(None);
        let resolved = self
            .resolve_entry_operation(
                dirfd,
                path,
                follow,
                false,
                0,
                false,
                Some(ResolveOperation::CaptureFuse(&captured)),
                None,
            )?
            .0;
        let mut plan = captured.into_inner();
        if let Some(plan) = &mut plan {
            if dirfd != AT_FDCWD && !path.starts_with(b"/") {
                let descriptor = self.descriptor(dirfd as u32)?;
                let open = descriptor.open.borrow();
                if let Some(events::SharedControl::FuseFile(file)) = &open.control {
                    if file
                        .reference
                        .directory
                        .as_ref()
                        .is_some_and(|node| Arc::ptr_eq(node, &plan.start_directory))
                    {
                        plan.anchor = Some(SharedFd::new(open.shared.clone()));
                    }
                }
            }
        }
        Ok((resolved, plan))
    }
    pub(crate) fn defer_fuse_namespace(
        &self,
        path: impl Into<NamespaceTarget>,
        action: Action,
        dest: Option<NamespaceTarget>,
        rights: u64,
    ) -> Result<()> {
        let query = self.query.as_ref().ok_or(Errno(95))?;
        let pending = PendingNamespace::new(self, path.into(), action, dest, rights)?;
        query.prepared.borrow_mut().namespace = Some(Box::new(pending));
        query.defer()
    }
}
