// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest Landlock ruleset descriptions and immutable per-thread policy layers.
use super::*;
use std::{fmt, sync::Mutex};
use trames_memory::CpuMemory;

pub(super) const EXECUTE: u64 = 1 << 0;
pub(super) const WRITE_FILE: u64 = 1 << 1;
pub(super) const READ_FILE: u64 = 1 << 2;
pub(super) const READ_DIR: u64 = 1 << 3;
pub(super) const REMOVE_DIR: u64 = 1 << 4;
pub(super) const REMOVE_FILE: u64 = 1 << 5;
pub(super) const MAKE_CHAR: u64 = 1 << 6;
pub(super) const MAKE_DIR: u64 = 1 << 7;
pub(super) const MAKE_REG: u64 = 1 << 8;
pub(super) const MAKE_SOCK: u64 = 1 << 9;
pub(super) const MAKE_FIFO: u64 = 1 << 10;
pub(super) const MAKE_BLOCK: u64 = 1 << 11;
pub(super) const MAKE_SYM: u64 = 1 << 12;
pub(super) const REFER: u64 = 1 << 13;
pub(super) const TRUNCATE: u64 = 1 << 14;
pub(super) const IOCTL_DEV: u64 = 1 << 15;
pub const BIND_TCP: u64 = 1;
pub const CONNECT_TCP: u64 = 2;
pub(super) const ABSTRACT_UNIX_SOCKET: u64 = 1;
pub const SIGNAL: u64 = 2;

const FS_MASK: u64 = (IOCTL_DEV << 1) - 1;
const FILE_MASK: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
const MAX_LAYERS: u8 = 16;

pub(super) struct Ruleset {
    fs: u64,
    net: u64,
    scopes: u64,
    rules: Mutex<Rules>,
}

#[derive(Clone, Default)]
struct Rules {
    paths: BTreeMap<u64, u64>,
    ports: BTreeMap<u16, u64>,
}

struct Layer {
    parent: Domain,
    fs: u64,
    net: u64,
    scopes: u64,
    depth: u8,
    handled_fs: u64,
    handled_net: u64,
    handled_scopes: u64,
    rules: Rules,
}

#[derive(Clone, Default)]
pub struct Domain(Option<Arc<Layer>>);

impl PartialEq for Domain {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref().map(Arc::as_ptr) == other.0.as_ref().map(Arc::as_ptr)
    }
}
impl Eq for Domain {}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LandlockDomain")
            .field(&self.depth())
            .finish()
    }
}

impl Domain {
    fn layers(&self) -> impl Iterator<Item = &Layer> {
        std::iter::successors(self.0.as_deref(), |layer| layer.parent.0.as_deref())
    }

    fn depth(&self) -> u8 {
        self.0.as_ref().map_or(0, |layer| layer.depth)
    }

    fn restrict(&self, ruleset: &Ruleset) -> Result<Self> {
        if self.depth() == MAX_LAYERS {
            return Err(Errno(7));
        }
        let previous = self.0.as_deref();
        let layer = Layer {
            parent: self.clone(),
            fs: ruleset.fs | REFER,
            net: ruleset.net,
            scopes: ruleset.scopes,
            depth: self.depth() + 1,
            handled_fs: ruleset.fs | previous.map_or(0, |layer| layer.handled_fs),
            handled_net: ruleset.net | previous.map_or(0, |layer| layer.handled_net),
            handled_scopes: ruleset.scopes | previous.map_or(0, |layer| layer.handled_scopes),
            rules: ruleset.rules.lock().unwrap().clone(),
        };
        Ok(Self(Some(Arc::new(layer))))
    }

    pub fn contains(&self, target: &Self) -> bool {
        self.0
            .as_deref()
            .is_none_or(|ancestor| target.layers().any(|layer| std::ptr::eq(layer, ancestor)))
    }

    pub fn scoped(&self, scope: u64) -> bool {
        self.0
            .as_ref()
            .is_some_and(|layer| layer.handled_scopes & scope != 0)
    }

    pub fn allows_scope(&self, target: &Self, scope: u64) -> bool {
        if !self.scoped(scope) {
            return true;
        }
        self.layers()
            .find(|layer| layer.scopes & scope != 0)
            .is_none_or(|boundary| target.layers().any(|layer| std::ptr::eq(layer, boundary)))
    }

    pub(super) fn fs_mask(&self) -> u64 {
        self.0.as_ref().map_or(0, |layer| {
            if layer.handled_fs == 0 {
                0
            } else {
                layer.handled_fs | REFER
            }
        })
    }

    pub(super) fn handles_net(&self, right: u64) -> bool {
        self.0
            .as_ref()
            .is_some_and(|layer| layer.handled_net & right != 0)
    }

    pub fn check_tcp(
        &self,
        socket: &trames_net::Socket,
        address: &[u8],
        right: u64,
    ) -> std::result::Result<(), trames_net::NetError> {
        if !self.handles_net(BIND_TCP | CONNECT_TCP) || !socket.is_stream() {
            return Ok(());
        }
        let Some(info) = socket.info() else {
            return Ok(());
        };
        let port = match address {
            [] | [_] => return Err(trames_net::NetError(22)),
            [0 | 2, 0, ..] if address.len() < 16 => return Err(trames_net::NetError(22)),
            [10, 0, ..] if address.len() < 24 => return Err(trames_net::NetError(22)),
            [0, 0, ..] if right == CONNECT_TCP => return Ok(()),
            [0, 0, ..] if info.family == 2 => {
                if address[4..8] != [0; 4] {
                    return Err(trames_net::NetError(97));
                }
                &address[2..4]
            }
            [2, 0, ..] if info.family == 2 => &address[2..4],
            [10, 0, ..] if info.family == 10 => &address[2..4],
            [0 | 2 | 10, 0, ..] => return Err(trames_net::NetError(22)),
            _ => return Ok(()),
        };
        if !self.allows_port(u16::from_be_bytes([port[0], port[1]]), right) {
            return Err(trames_net::NetError(13));
        }
        Ok(())
    }

    pub(super) fn pty_peer_required(&self) -> bool {
        self.fs_mask() & (READ_FILE | WRITE_FILE | IOCTL_DEV) != 0
    }

    fn allows_port(&self, port: u16, right: u64) -> bool {
        if !self.handles_net(right) {
            return true;
        }
        self.layers().all(|layer| {
            layer.net & right == 0
                || layer
                    .rules
                    .ports
                    .get(&port)
                    .is_some_and(|mask| mask & right != 0)
        })
    }
}

impl Layer {
    fn denied(&self, ancestors: &[u64], requested: u64) -> u64 {
        let mut missing = requested & self.fs;
        for identity in ancestors {
            if missing == 0 {
                break;
            }
            missing &= !self.rules.paths.get(identity).copied().unwrap_or(0);
        }
        missing
    }
}

// Generic VFS commands that Linux permits on device files independently of IOCTL_DEV.
fn device_ioctl_gate(request: u32) -> bool {
    !matches!(
        request,
        0x5450
            ..=0x5452
                | 0x5421
                | 0x5460
                | 2
                | 0xc0045877
                | 0xc0045878
                | 0xc020660b
                | 0x40049409
                | 0x4020940d
                | 0xc0189436
                | 0x80111500
                | 0x80811501
    )
}

impl SharedOpenDescription {
    pub(super) fn check_device_ioctl(&self, request: u32) -> Result<()> {
        if self.landlock_denied & IOCTL_DEV != 0 && device_ioctl_gate(request) {
            return Err(Errno(13));
        }
        Ok(())
    }
}

impl Vfs {
    pub(super) fn landlock_check_mount(&self) -> Result<()> {
        if self.credentials.landlock.fs_mask() != 0 {
            return Err(Errno(1));
        }
        Ok(())
    }

    pub fn check_device_ioctl(&self, fd: u32, request: u32) -> Result<()> {
        self.descriptor(fd)?
            .open
            .borrow()
            .shared
            .check_device_ioctl(request)
    }

    pub(super) fn landlock_open<const PATH_TRUNCATE: bool>(
        &self,
        path: Option<&ResolvedPath>,
        node: &NodeRef,
        flags: u32,
    ) -> Result<u64> {
        if self.credentials.landlock.fs_mask() == 0 || flags & O_PATH != 0 {
            return Ok(0);
        }
        let n = node.borrow();
        let required = if PATH_TRUNCATE {
            TRUNCATE
        } else if matches!(n.content, Content::Directory) {
            READ_DIR
        } else {
            (if fd_can_read(flags) { READ_FILE } else { 0 })
                | (if fd_can_write(flags) { WRITE_FILE } else { 0 })
                | (if flags & O_TRUNC != 0 { TRUNCATE } else { 0 })
        };
        let deferred = if matches!(n.mode & 0o170000, 0o020000 | 0o060000) {
            IOCTL_DEV
        } else if matches!(n.content, Content::File(_)) {
            TRUNCATE
        } else {
            0
        };
        drop(n);
        let denied = self.landlock_file_denied(path, node, required | deferred)?;
        if denied & required != 0 {
            Err(Errno(13))
        } else {
            Ok(denied)
        }
    }

    pub(super) fn landlock_execute(
        &self,
        path: Option<&ResolvedPath>,
        node: &NodeRef,
    ) -> Result<()> {
        if self.landlock_file_denied(path, node, EXECUTE | READ_FILE)? != 0 {
            return Err(Errno(13));
        }
        Ok(())
    }

    fn landlock_file_denied(
        &self,
        path: Option<&ResolvedPath>,
        node: &NodeRef,
        requested: u64,
    ) -> Result<u64> {
        let domain = &self.credentials.landlock;
        if domain.fs_mask() & requested == 0 || node.borrow().seals.is_some() {
            return Ok(0);
        }
        if let Some(path) = path {
            return self.landlock_denied(path, Some(node), requested);
        }
        // An already open inode can outlive its directory entry. Inode rules
        // still apply, but a different hard link cannot supply its ancestors.
        Ok(domain.layers().fold(0, |denied, layer| {
            denied | layer.denied(&[node.identity], requested)
        }))
    }

    pub(super) fn landlock_retained_path(&self, file: &ResolvedInode) -> Option<ResolvedPath> {
        let key = file
            .file
            .as_ref()
            .and_then(|open| match &open.kind {
                FdKind::Node(key) if key.starts_with(b"/") => Some(key),
                _ => None,
            })
            .or_else(|| {
                file._image
                    .as_ref()
                    .and_then(|image| image.backing_key.as_ref())
            });
        if let Some(key) = key {
            let path = ResolvedPath {
                key: key.clone(),
                mount: file.mount.clone(),
                retained_directory: None,
                proc_binding: file
                    .node
                    .proc_node
                    .get()
                    .and_then(|proc| proc.binding.clone()),
            };
            if self
                .node(&path)
                .is_ok_and(|node| Arc::ptr_eq(&node, &file.node))
            {
                return Some(path);
            }
        }
        let path = self.location(&file.node, &file.mount).ok()?;
        if matches!(file.node.borrow().content, Content::Directory) {
            return Some(path);
        }
        let original = file
            .file
            .as_ref()
            .and_then(|open| open.notification.as_ref())
            .or_else(|| file._image.as_ref().map(|image| &image.notification))?
            .link
            .as_ref()?;
        let current = self.event_link(&path, &file.node)?;
        Arc::ptr_eq(original, &current).then_some(path)
    }

    pub fn landlock_call(
        &mut self,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Result<u64> {
        match number {
            444 => {
                let size = args[1];
                match args[2] as u32 {
                    1 if args[0] == 0 && size == 0 => return Ok(6),
                    0 => {}
                    _ => return Err(Errno(22)),
                }
                if args[0] == 0 {
                    return Err(Errno(14));
                }
                if size < 8 {
                    return Err(Errno(22));
                }
                if size > trames_memory::PAGE_SIZE {
                    return Err(Errno(7));
                }
                let mut bytes = [0; 24];
                let copied = (size as usize).min(bytes.len());
                memory
                    .read(args[0], &mut bytes[..copied])
                    .map_err(|_| Errno(14))?;
                if size > 24 {
                    let mut extension = vec![0; size as usize - 24];
                    let start = args[0].checked_add(24).ok_or(Errno(14))?;
                    memory.read(start, &mut extension).map_err(|_| Errno(14))?;
                    if extension.iter().any(|byte| *byte != 0) {
                        return Err(Errno(7));
                    }
                }
                let fs = word(&bytes);
                let net = word(&bytes[8..]);
                let scopes = word(&bytes[16..]);
                if fs & !FS_MASK != 0 || net & !3 != 0 || scopes & !3 != 0 {
                    return Err(Errno(22));
                }
                if fs | net | scopes == 0 {
                    return Err(Errno(42));
                }
                let rules = Ruleset {
                    fs,
                    net,
                    scopes,
                    rules: Default::default(),
                };
                self.anonymous(O_CLOEXEC | 2, events::Anonymous::Landlock(Arc::new(rules)))
                    .map(u64::from)
            }
            445 => {
                if args[3] as u32 != 0 {
                    return Err(Errno(22));
                }
                let ruleset = self.landlock_ruleset(args[0] as u32)?;
                match args[1] as u32 {
                    1 => {
                        let raw = memory.read_array::<12>(args[2]).map_err(|_| Errno(14))?;
                        let access = word(&raw);
                        Self::landlock_validate_rule(access, ruleset.fs)?;
                        let fd = u32::from_le_bytes(raw[8..12].try_into().unwrap());
                        let descriptor = self.descriptor(fd)?;
                        let open = descriptor.open.borrow();
                        let node = open.node.as_ref().ok_or(Errno(77))?;
                        if open.mount.is_none() || open.namespace_resource.is_some() {
                            return Err(Errno(77));
                        }
                        if !matches!(node.borrow().content, Content::Directory)
                            && access & !FILE_MASK != 0
                        {
                            return Err(Errno(22));
                        }
                        *ruleset
                            .rules
                            .lock()
                            .unwrap()
                            .paths
                            .entry(node.identity)
                            .or_default() |= access;
                    }
                    2 => {
                        let raw = memory.read_array::<16>(args[2]).map_err(|_| Errno(14))?;
                        let access = word(&raw);
                        Self::landlock_validate_rule(access, ruleset.net)?;
                        let port = u16::try_from(word(&raw[8..])).map_err(|_| Errno(22))?;
                        *ruleset.rules.lock().unwrap().ports.entry(port).or_default() |= access;
                    }
                    _ => return Err(Errno(22)),
                }
                Ok(0)
            }
            446 => {
                if !self.credentials.caps.no_new_privs.get()
                    && !self.credentials.has_local_cap(capabilities::SYS_ADMIN)
                {
                    return Err(Errno(1));
                }
                if args[1] as u32 != 0 {
                    return Err(Errno(22));
                }
                let ruleset = self.landlock_ruleset(args[0] as u32)?;
                self.credentials.landlock = self.credentials.landlock.restrict(&ruleset)?;
                self.credentials.renew_open_identity();
                Ok(0)
            }
            _ => Err(Errno(38)),
        }
    }

    fn landlock_validate_rule(access: u64, handled: u64) -> Result<()> {
        if access == 0 {
            return Err(Errno(42));
        }
        if access & !handled != 0 {
            return Err(Errno(22));
        }
        Ok(())
    }

    fn landlock_ruleset(&self, fd: u32) -> Result<Arc<Ruleset>> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        if open.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        match &open.control {
            Some(events::SharedControl::Landlock(ruleset)) => Ok(ruleset.clone()),
            _ => Err(Errno(77)),
        }
    }

    fn landlock_ancestors(&self, path: &ResolvedPath, first: Option<&NodeRef>) -> Result<Vec<u64>> {
        let sequence = self.path_sequence();
        if sequence as u32 != 0 {
            return Err(Errno(13));
        }
        let mut at = path.clone();
        let mut ancestors = Vec::new();
        let mut accepted = first.cloned();
        loop {
            let node = self.node(&at);
            let node = if let Some(original) = accepted.take() {
                if !node.as_ref().is_ok_and(|node| Arc::ptr_eq(node, &original)) {
                    return Ok(vec![original.identity]);
                }
                original
            } else {
                node?
            };
            ancestors.push(node.identity);
            let Some(parent) = self.landlock_parent(&at) else {
                break;
            };
            at = parent;
        }
        if self.path_sequence() != sequence {
            return Err(Errno(13));
        }
        Ok(ancestors)
    }

    pub(super) fn landlock_denied(
        &self,
        path: &ResolvedPath,
        first: Option<&NodeRef>,
        requested: u64,
    ) -> Result<u64> {
        let domain = &self.credentials.landlock;
        let requested = requested & domain.fs_mask();
        if requested == 0 {
            return Ok(0);
        }
        let ancestors = self.landlock_ancestors(path, first)?;
        Ok(domain.layers().fold(0, |denied, layer| {
            denied | layer.denied(&ancestors, requested)
        }))
    }

    pub(super) fn landlock_check(
        &self,
        path: &ResolvedPath,
        first: Option<&NodeRef>,
        requested: u64,
    ) -> Result<()> {
        if self.landlock_denied(path, first, requested)? != 0 {
            Err(Errno(13))
        } else {
            Ok(())
        }
    }

    pub(super) fn landlock_check_parent(
        &self,
        child: &ResolvedPath,
        parent: Option<&NodeRef>,
        access: u64,
    ) -> Result<()> {
        if self.credentials.landlock.fs_mask() & access == 0 {
            return Ok(());
        }
        self.landlock_check(&child.parent(), parent, access)
    }

    pub(super) fn landlock_reparent(
        &self,
        source: &ResolvedPath,
        dest: &ResolvedPath,
        inode: &NodeRef,
    ) -> Result<()> {
        let domain = &self.credentials.landlock;
        if domain.fs_mask() == 0 || source == dest {
            return Ok(());
        }
        let mut before = self.landlock_ancestors(source, None)?;
        let mut after = self.landlock_ancestors(dest, None)?;
        if domain
            .layers()
            .any(|layer| layer.denied(&before, REFER) | layer.denied(&after, REFER) != 0)
        {
            return Err(Errno(18));
        }
        before.insert(0, inode.identity);
        after.insert(0, inode.identity);
        let possible = if matches!(inode.borrow().content, Content::Directory) {
            FS_MASK
        } else {
            FILE_MASK
        };
        if domain
            .layers()
            .any(|layer| layer.denied(&before, possible) & !layer.denied(&after, possible) != 0)
        {
            return Err(Errno(18));
        }
        Ok(())
    }
}

pub(super) fn make(mode: u32) -> u64 {
    match mode & 0o170000 {
        0o010000 => MAKE_FIFO,
        0o020000 => MAKE_CHAR,
        0o040000 => MAKE_DIR,
        0o060000 => MAKE_BLOCK,
        0o120000 => MAKE_SYM,
        0o140000 => MAKE_SOCK,
        _ => MAKE_REG,
    }
}

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};

    fn ruleset(vfs: &mut Vfs, handled: u64) -> (Memory, u64) {
        let mut memory = Memory::default();
        memory
            .map(0x1000, trames_memory::PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory.write_array(0x1000, handled.to_le_bytes()).unwrap();
        let fd = vfs
            .landlock_call(444, [0x1000, 8, 0, 0, 0, 0], &memory)
            .unwrap();
        (memory, fd)
    }

    fn grant(vfs: &mut Vfs, memory: &mut Memory, fd: u64, path: &[u8], rights: u64) {
        let path_fd = vfs.open_at(AT_FDCWD, path, O_PATH, 0).unwrap();
        memory.write_array(0x1000, rights.to_le_bytes()).unwrap();
        memory.write_array(0x1008, path_fd.to_le_bytes()).unwrap();
        vfs.landlock_call(445, [fd, 1, 0x1000, 0, 0, 0], memory)
            .unwrap();
        vfs.close(path_fd).unwrap();
    }

    #[test]
    fn enforcing_a_ruleset_snapshots_rules_and_open_file_authority() {
        let mut vfs = Vfs::default();
        let old = vfs.open_at(AT_FDCWD, b"/file", O_CREAT | 2, 0o600).unwrap();
        let (mut memory, fd) = ruleset(&mut vfs, TRUNCATE);
        vfs.landlock_call(446, [fd, 0, 0, 0, 0, 0], &memory)
            .unwrap();
        let confined = vfs.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        grant(&mut vfs, &mut memory, fd, b"/file", TRUNCATE);
        assert_eq!(vfs.truncate_fd(old, 8), Ok(()));
        assert_eq!(vfs.truncate_fd(confined, 0), Err(Errno(13)));
        assert_eq!(vfs.truncate_at(b"/file", 0), Err(Errno(13)));
        assert_eq!(
            vfs.open_at(AT_FDCWD, b"/file", 2 | O_TRUNC, 0),
            Err(Errno(13))
        );
    }

    #[test]
    fn refer_cannot_import_authority_from_the_destination() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/readable", 0o755).unwrap();
        let original = vfs.open_at(AT_FDCWD, b"/file", O_CREAT | 2, 0o600).unwrap();
        let (mut memory, fd) = ruleset(&mut vfs, REFER | READ_FILE);
        grant(&mut vfs, &mut memory, fd, b"/", REFER);
        grant(&mut vfs, &mut memory, fd, b"/readable", READ_FILE);
        vfs.landlock_call(446, [fd, 0, 0, 0, 0, 0], &memory)
            .unwrap();
        assert_eq!(
            vfs.link_at(AT_FDCWD, b"/file", AT_FDCWD, b"/readable/alias"),
            Err(Errno(18))
        );
        assert_eq!(
            vfs.rename_at(AT_FDCWD, b"/file", AT_FDCWD, b"/readable/file", 0),
            Err(Errno(18))
        );
        assert_eq!(vfs.read(original, 1), Ok(Vec::new()));
    }

    #[test]
    fn filesystem_rules_prevent_mount_topology_changes_even_with_admin_capability() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/mount", 0o755).unwrap();
        vfs.mkdir_at(AT_FDCWD, b"/other", 0o755).unwrap();
        vfs.mount(None, b"/mount", Some(b"tmpfs"), 0, None).unwrap();
        let (memory, fd) = ruleset(&mut vfs, READ_FILE);
        vfs.landlock_call(446, [fd, 0, 0, 0, 0, 0], &memory)
            .unwrap();
        assert_eq!(
            vfs.mount(None, b"/other", Some(b"tmpfs"), 0, None),
            Err(Errno(1))
        );
        assert_eq!(vfs.umount(b"/mount", 0), Err(Errno(1)));
        assert_eq!(vfs.pivot_root(b"/mount", b"/other"), Err(Errno(1)));
    }

    #[test]
    fn network_only_rules_leave_filesystem_topology_available() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/mount", 0o755).unwrap();
        let mut memory = Memory::default();
        memory
            .map(0x1000, trames_memory::PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory.write_array(0x1008, BIND_TCP.to_le_bytes()).unwrap();
        let fd = vfs
            .landlock_call(444, [0x1000, 16, 0, 0, 0, 0], &memory)
            .unwrap();
        vfs.landlock_call(446, [fd, 0, 0, 0, 0, 0], &memory)
            .unwrap();
        assert_eq!(vfs.mount(None, b"/mount", Some(b"tmpfs"), 0, None), Ok(()));
    }

    #[test]
    fn executing_a_file_requires_its_read_access_when_handled() {
        let mut vfs = Vfs::default();
        let file = vfs
            .open_at(AT_FDCWD, b"/program", O_CREAT | 2, 0o755)
            .unwrap();
        vfs.close(file).unwrap();
        let (mut memory, fd) = ruleset(&mut vfs, EXECUTE | READ_FILE);
        grant(&mut vfs, &mut memory, fd, b"/program", EXECUTE);
        vfs.landlock_call(446, [fd, 0, 0, 0, 0, 0], &memory)
            .unwrap();
        assert_eq!(
            vfs.executable_file_at(AT_FDCWD, b"/program", 0).err(),
            Some(Errno(13))
        );
    }

    #[test]
    fn opening_a_proc_fd_and_executing_by_fd_use_the_original_hard_link() {
        let mut vfs = Vfs::default();
        vfs.mkdir_at(AT_FDCWD, b"/allowed", 0o755).unwrap();
        let fd = vfs
            .open_at(AT_FDCWD, b"/program", O_CREAT | 2, 0o755)
            .unwrap();
        vfs.close(fd).unwrap();
        vfs.link_at(AT_FDCWD, b"/program", AT_FDCWD, b"/allowed/program")
            .unwrap();
        let alias = vfs
            .open_at(AT_FDCWD, b"/allowed/program", O_PATH, 0)
            .unwrap();
        let denied = vfs.open_at(AT_FDCWD, b"/program", O_PATH, 0).unwrap();
        let (mut memory, rules) = ruleset(&mut vfs, READ_FILE | EXECUTE);
        grant(
            &mut vfs,
            &mut memory,
            rules,
            b"/allowed",
            READ_FILE | EXECUTE,
        );
        vfs.landlock_call(446, [rules, 0, 0, 0, 0, 0], &memory)
            .unwrap();
        assert!(vfs.executable_file_at(alias as i32, b"", 0x1000).is_ok());
        assert_eq!(
            vfs.executable_file_at(denied as i32, b"", 0x1000).err(),
            Some(Errno(13))
        );
        vfs.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    credentials: vfs.credentials.clone(),
                    fds: vfs.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let path = format!("/proc/self/fd/{denied}");
        assert_eq!(vfs.open_at(AT_FDCWD, path.as_bytes(), 0, 0), Err(Errno(13)));
    }
}
