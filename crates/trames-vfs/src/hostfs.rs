// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit directory capabilities. No host pathname is inferred from guest input.
use super::*;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{atomic::AtomicBool, Mutex};
mod private_map;
pub(super) use private_map::pages as private_pages;

fn errno(error: std::io::Error) -> Errno {
    let code = match error.raw_os_error() {
        Some(libc::ENOTDIR) => 20,
        Some(libc::EISDIR) => 21,
        Some(libc::ENOTEMPTY) => 39,
        Some(libc::ELOOP) => 40,
        Some(libc::EROFS) => 30,
        Some(libc::EXDEV) => 18,
        Some(libc::EOPNOTSUPP) => 95,
        Some(libc::EBUSY) => 16,
        Some(libc::EMLINK) => 31,
        Some(libc::EBADF) => 9,
        _ => return storage::host_errno(error),
    };
    Errno(code)
}
fn status(result: libc::c_int) -> Result<()> {
    if result < 0 {
        Err(errno(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
fn component(name: &[u8]) -> Result<CString> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(Errno(22));
    }
    CString::new(name).map_err(|_| Errno(22))
}
fn open_at(parent: &File, name: &CString, flags: i32, mode: u32) -> Result<File> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let nofollow = if flags & (libc::O_NOFOLLOW_ANY | libc::O_SYMLINK) != 0 {
        0
    } else {
        libc::O_NOFOLLOW
    };
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let nofollow = libc::O_NOFOLLOW;
    // SAFETY: a live directory capability and NUL-terminated component; the
    // resulting owned fd is CLOEXEC and never follows a native symbolic link.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | nofollow | libc::O_NONBLOCK,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(errno(std::io::Error::last_os_error()));
    }
    // SAFETY: openat returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn meta_at(parent: &File, name: &CString) -> Result<libc::stat> {
    let mut out = std::mem::MaybeUninit::uninit();
    // SAFETY: one initialized stat on success, retained directory, valid name.
    status(unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            out.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: successful fstatat initialized all fields.
    Ok(unsafe { out.assume_init() })
}
pub(super) struct Root {
    directory: File,
    readonly: bool,
    uid: (u32, u32),
    gid: (u32, u32),
}
enum Parent<'a> {
    Root(&'a File),
    Open(File),
}
impl std::ops::Deref for Parent<'_> {
    type Target = File;
    fn deref(&self) -> &File {
        match self {
            Self::Root(file) => file,
            Self::Open(file) => file,
        }
    }
}
impl Root {
    fn parent(&self, key: &[u8]) -> Result<(Parent<'_>, CString)> {
        let mut pieces = key
            .split(|&b| b == b'/')
            .filter(|part| !part.is_empty())
            .map(component)
            .collect::<Result<Vec<_>>>()?;
        let name = pieces.pop().unwrap_or_else(|| CString::new(".").unwrap());
        if pieces.is_empty() {
            return Ok((Parent::Root(&self.directory), name));
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let path = pieces
                .iter()
                .map(|part| part.as_bytes())
                .collect::<Vec<_>>()
                .join(&b'/');
            let path = CString::new(path).unwrap();
            // The native name resolver rejects symlinks at every component in
            // one lookup. No check-then-open or per-component descriptor churn.
            let directory = open_at(
                &self.directory,
                &path,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY,
                0,
            )?;
            Ok((Parent::Open(directory), name))
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let mut directory = Parent::Root(&self.directory);
            for part in pieces {
                directory = Parent::Open(open_at(
                    &directory,
                    &part,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?);
            }
            Ok((directory, name))
        }
    }
    fn open(&self, key: &[u8], access: u32, directory: bool) -> Result<File> {
        if access != 0 && self.readonly {
            return Err(Errno(30));
        }
        let (parent, name) = self.parent(key)?;
        let flags = match access {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
        open_at(
            &parent,
            &name,
            flags | if directory { libc::O_DIRECTORY } else { 0 },
            0,
        )
    }
    fn writable(&self) -> Result<()> {
        if self.readonly {
            Err(Errno(30))
        } else {
            Ok(())
        }
    }
}
pub(super) struct OpenFile {
    pub file: File,
    root: Arc<Root>,
}
impl OpenFile {
    pub fn stat(&self) -> Result<[u8; 128]> {
        let mut native = std::mem::MaybeUninit::uninit();
        // SAFETY: retained original fd and space for one initialized native stat.
        status(unsafe { libc::fstat(self.file.as_raw_fd(), native.as_mut_ptr()) })?;
        Ok(encode_stat(&self.root, &unsafe { native.assume_init() }))
    }
}
#[allow(clippy::unnecessary_cast)]
fn encode_stat(root: &Root, meta: &libc::stat) -> [u8; 128] {
    let mut out = [0; 128];
    for (offset, value) in [
        (0, meta.st_dev as u64),
        (8, meta.st_ino as u64),
        (48, meta.st_size.max(0) as u64),
        (64, meta.st_blocks as u64),
    ] {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (16, meta.st_mode as u32),
        (20, meta.st_nlink as u32),
        (
            24,
            if meta.st_uid == root.uid.0 {
                root.uid.1
            } else {
                meta.st_uid
            },
        ),
        (
            28,
            if meta.st_gid == root.gid.0 {
                root.gid.1
            } else {
                meta.st_gid
            },
        ),
        (56, 4096),
    ] {
        out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, time) in [72, 88, 104].into_iter().zip(stat_times(meta)) {
        out[offset..offset + 8].copy_from_slice(&time.seconds.to_le_bytes());
        out[offset + 8..offset + 16].copy_from_slice(&(time.nanos as u64).to_le_bytes());
    }
    out
}

struct FileState {
    key: Vec<u8>,
    handles: [Vec<std::sync::Weak<OpenFile>>; 3],
    metadata: std::sync::Weak<OpenFile>,
}
impl FileState {
    fn retained(&mut self, write: Option<bool>) -> Option<Arc<OpenFile>> {
        for access in [2, 0, 1] {
            if write.is_some_and(|write| if write { access == 0 } else { access == 1 }) {
                continue;
            }
            let handles = &mut self.handles[access];
            while let Some(handle) = handles.last() {
                if let Some(file) = handle.upgrade() {
                    return Some(file);
                }
                handles.pop();
            }
        }
        None
    }
}
pub(super) struct HostFile {
    root: Arc<Root>,
    identity: (u64, u64),
    directory: bool,
    state: Mutex<FileState>,
    length: AtomicU64,
    length_generation: AtomicU64,
}
impl HostFile {
    pub fn chmod(&self, _node: &NodeRef, mode: u32) -> Result<()> {
        self.root.writable()?;
        let file = self.any_file()?;
        // SAFETY: retained original native file, no path resolution.
        status(unsafe { libc::fchmod(file.file.as_raw_fd(), (mode & 0o7777) as libc::mode_t) })
    }
    pub fn chown(&self, node: &NodeRef, uid: u32, gid: u32) -> Result<()> {
        self.root.writable()?;
        let uid = if uid == self.root.uid.1 {
            self.root.uid.0
        } else {
            uid
        };
        let gid = if gid == self.root.gid.1 {
            self.root.gid.0
        } else {
            gid
        };
        if matches!(node.borrow().content, Content::Symlink(_)) {
            let (parent, name) = self.root.parent(&self.state.lock().unwrap().key)?;
            // SAFETY: retained parent; ownership of the link itself only.
            status(unsafe {
                libc::fchownat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    uid,
                    gid,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })
        } else {
            let file = self.any_file()?;
            // SAFETY: retained original inode and scalar ownership ids.
            status(unsafe { libc::fchown(file.file.as_raw_fd(), uid, gid) })
        }
    }
    pub fn times(&self, node: &NodeRef, values: [Option<storage::Timestamp>; 2]) -> Result<()> {
        self.root.writable()?;
        let times: [libc::timespec; 2] = values.map(|time| match time {
            Some(time) => libc::timespec {
                tv_sec: time.seconds,
                tv_nsec: time.nanos as _,
            },
            None => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        });
        if matches!(node.borrow().content, Content::Symlink(_)) {
            let (parent, name) = self.root.parent(&self.state.lock().unwrap().key)?;
            // SAFETY: two initialized timespecs and anchored link pathname.
            status(unsafe {
                libc::utimensat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })
        } else {
            let file = self.any_file()?;
            // SAFETY: two initialized timespecs and the retained file descriptor.
            status(unsafe { libc::futimens(file.file.as_raw_fd(), times.as_ptr()) })
        }
    }

    pub fn append(&self, bytes: &[u8]) -> Result<(usize, u64)> {
        let file = self.file(true)?;
        // PlainFile's existing data write guard excludes changes to these
        // private descriptor flags by other guest writes. The actual append is
        // one native write, atomic against independent host appenders too.
        let fd = file.file.as_raw_fd();
        // SAFETY: live owned descriptor, scalar fcntl commands.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        status(flags)?;
        status(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_APPEND) })?;
        // SAFETY: input lives through the call; the descriptor is retained.
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        let error = std::io::Error::last_os_error();
        let end = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        let restored = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        status(restored)?;
        if count < 0 {
            return Err(errno(error));
        }
        if end < 0 {
            return Err(Errno(5));
        }
        Ok((count as usize, end as u64))
    }
    // A new guest open always goes through native open admission. Retained
    // descriptors/mappings subsequently use the original native inode.
    pub fn acquire(&self, access: u32) -> Result<Arc<OpenFile>> {
        let key = self.state.lock().unwrap().key.clone();
        let file = self.root.open(&key, access, self.directory)?;
        self.retain(file, access)
    }
    fn retain(&self, file: File, access: u32) -> Result<Arc<OpenFile>> {
        let meta = file.metadata().map_err(errno)?;
        if (meta.dev(), meta.ino()) != self.identity {
            return Err(Errno(2));
        }
        if !meta.is_file() && !meta.is_dir() {
            return Err(Errno(95));
        }
        self.publish_length(meta.len());
        let handle = Arc::new(OpenFile {
            file,
            root: self.root.clone(),
        });
        let mut state = self.state.lock().unwrap();
        let handles = &mut state.handles[access as usize];
        handles.retain(|file| file.strong_count() != 0);
        handles.push(Arc::downgrade(&handle));
        Ok(handle)
    }
    pub fn file(&self, write: bool) -> Result<Arc<OpenFile>> {
        let found = self.state.lock().unwrap().retained(Some(write));
        match found {
            Some(file) => Ok(file),
            None => self.acquire(u32::from(write)),
        }
    }
    pub fn len(&self) -> u64 {
        if let Ok(meta) = self.metadata() {
            self.publish_length(meta.len());
        }
        self.length.load(Ordering::Relaxed)
    }
    pub(super) fn publish_length(&self, length: u64) {
        if self.length.load(Ordering::Relaxed) != length
            && self.length.swap(length, Ordering::Relaxed) != length
        {
            self.length_generation.fetch_add(1, Ordering::Relaxed);
            trames_memory::backing_changed();
        }
    }
    pub fn metadata(&self) -> Result<Metadata> {
        self.any_file()?.file.metadata().map_err(errno)
    }
    pub fn any_file(&self) -> Result<Arc<OpenFile>> {
        let mut state = self.state.lock().unwrap();
        let handle = state.retained(None).or_else(|| state.metadata.upgrade());
        drop(state);
        match handle {
            Some(handle) => Ok(handle),
            None => self.acquire(0),
        }
    }
    fn pin_path(&self) -> Result<Arc<OpenFile>> {
        let (parent, name) = self.root.parent(&self.state.lock().unwrap().key)?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let flags = libc::O_EVTONLY | libc::O_SYMLINK;
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        let flags = libc::O_PATH;
        let file = open_at(&parent, &name, flags, 0)?;
        let meta = file.metadata().map_err(errno)?;
        if (meta.dev(), meta.ino()) != self.identity {
            return Err(Errno(2));
        }
        let handle = Arc::new(OpenFile {
            file,
            root: self.root.clone(),
        });
        self.state.lock().unwrap().metadata = Arc::downgrade(&handle);
        Ok(handle)
    }
}
struct Entry {
    kind: u32,
    node: std::sync::Weak<Inode>,
    file: Arc<HostFile>,
}
pub(super) struct HostFs {
    root: Arc<Root>,
    entries: Mutex<BTreeMap<(u64, u64), Entry>>,
}
fn native_path(file: &File) -> Result<std::path::PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut path = vec![0; libc::MAXPATHLEN as usize];
        // SAFETY: F_GETPATH writes at most MAXPATHLEN bytes to this buffer.
        status(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) })?;
        path.truncate(path.iter().position(|&b| b == 0).ok_or(Errno(36))?);
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(path)))
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(errno)
    }
}
impl HostFs {
    pub fn stat_at(&self, key: &[u8]) -> Result<[u8; 128]> {
        let (parent, name) = self.root.parent(key)?;
        Ok(encode_stat(&self.root, &meta_at(&parent, &name)?))
    }
    pub fn key_of(&self, filesystem: &FsHandle, node: &NodeRef) -> Result<Vec<u8>> {
        let file = node.host.get().ok_or(Errno(2))?;
        let handle = file.any_file()?;
        if handle.file.metadata().map_err(errno)?.nlink() == 0 {
            return Err(Errno(2));
        }
        let root = native_path(&self.root.directory)?;
        let path = native_path(&handle.file)?;
        let relative = path.strip_prefix(&root).map_err(|_| Errno(2))?;
        let mut key = b"/".to_vec();
        key.extend_from_slice(relative.as_os_str().as_bytes());
        let previous = file.state.lock().unwrap().key.clone();
        if key != previous {
            let mut fs = filesystem.borrow_mut();
            if file.directory {
                fs.paths.remove(&previous);
            }
            fs.paths.insert(key.clone(), node.clone());
            drop(fs);
            file.state.lock().unwrap().key = key.clone();
        }
        Ok(key)
    }
    // libc's stat/statvfs scalar widths differ between Darwin and Linux.
    #[allow(clippy::unnecessary_cast)]
    pub fn statfs(&self, flags: u64) -> Result<[u8; 120]> {
        let mut native = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: retained directory and space for one initialized statvfs.
        status(unsafe { libc::fstatvfs(self.root.directory.as_raw_fd(), native.as_mut_ptr()) })?;
        let native = unsafe { native.assume_init() };
        let mut out = [0; 120];
        for (offset, value) in [
            (0, 0x686f7374),
            (8, native.f_frsize as u64),
            (16, native.f_blocks as u64),
            (24, native.f_bfree as u64),
            (32, native.f_bavail as u64),
            (40, native.f_files as u64),
            (48, native.f_ffree as u64),
            (64, native.f_namemax as u64),
            (72, native.f_frsize as u64),
            (80, flags & 15),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok(out)
    }
    fn new(path: &Path, readonly: bool, uid: u32, gid: u32) -> Result<Arc<Self>> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::fs::canonicalize(path).map_err(errno)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(errno)?;
        // SAFETY: getuid/getgid have no memory arguments or effects.
        let (native_uid, native_gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Ok(Arc::new(Self {
            root: Arc::new(Root {
                directory,
                readonly,
                uid: (native_uid, uid),
                gid: (native_gid, gid),
            }),
            entries: Mutex::new(BTreeMap::new()),
        }))
    }
    pub fn readonly(&self) -> bool {
        self.root.readonly
    }
    #[allow(clippy::unnecessary_cast)]
    pub fn lookup(&self, filesystem: &FsHandle, key: &[u8]) -> Result<NodeRef> {
        let (parent, name) = self.root.parent(key)?;
        let meta = match meta_at(&parent, &name) {
            Ok(meta) => meta,
            Err(error) => {
                filesystem.borrow_mut().paths.remove(key);
                return Err(error);
            }
        };
        let kind = meta.st_mode as u32 & 0o170000;
        if !matches!(kind, 0o100000 | 0o40000 | 0o120000) {
            return Err(Errno(95));
        }
        let identity = (meta.st_dev as u64, meta.st_ino);
        let existing = self
            .entries
            .lock()
            .unwrap()
            .get(&identity)
            .filter(|entry| entry.kind == kind)
            .and_then(|entry| entry.node.upgrade());
        let mut created = existing.is_none();
        let node = match existing {
            Some(node) => node,
            None => {
                let file = Arc::new(HostFile {
                    root: self.root.clone(),
                    identity,
                    directory: kind == 0o40000,
                    state: Mutex::new(FileState {
                        key: key.to_vec(),
                        handles: std::array::from_fn(|_| Vec::new()),
                        metadata: std::sync::Weak::new(),
                    }),
                    length: AtomicU64::new(meta.st_size.max(0) as u64),
                    length_generation: AtomicU64::new(0),
                });
                let content = match kind {
                    0o40000 => Content::Directory,
                    0o120000 => {
                        let mut target = vec![0; MAX_PATH];
                        // SAFETY: retained parent, valid name and writable output buffer.
                        let count = unsafe {
                            libc::readlinkat(
                                parent.as_raw_fd(),
                                name.as_ptr(),
                                target.as_mut_ptr().cast(),
                                target.len(),
                            )
                        };
                        if count < 0 {
                            return Err(errno(std::io::Error::last_os_error()));
                        }
                        if count as usize == target.len() {
                            return Err(Errno(36));
                        }
                        target.truncate(count as usize);
                        Content::Symlink(target)
                    }
                    _ => Content::File(storage::FileData::disk(storage::DiskObject {
                        length: meta.st_size.max(0) as u64,
                        backing: Arc::new(storage::DiskBacking {
                            files: std::sync::Mutex::default(),
                            charge: std::sync::OnceLock::new(),
                            path: Default::default(),
                            remove_on_drop: AtomicBool::new(false),
                            _store: None,
                            host: Some(file.clone()),
                            inode: meta.st_ino,
                        }),
                    })),
                };
                let node = Arc::new(Inode::new(Node {
                    identity: 0,
                    record_locks: std::sync::OnceLock::new(),
                    whole_locks: std::sync::OnceLock::new(),
                    notifications: inotify::Marks::default(),
                    path_hint: SharedCell::default(),
                    device: identity.0,
                    content,
                    mode: meta.st_mode as u32,
                    uid: 0,
                    gid: 0,
                    volatile: false,
                    inode: identity.1,
                    links: meta.st_nlink as u32,
                    times: [storage::Timestamp::default(); 3],
                    seals: None,
                    xattrs: BTreeMap::new(),
                }));
                node.host.set(file.clone()).ok().expect("new host inode");
                node
            }
        };
        // Candidate construction (including native readlink) occurs outside
        // the shared identity index. Reconcile concurrent first lookups here.
        let mut entries = self.entries.lock().unwrap();
        let node = if created {
            if let Some(existing) = entries
                .get(&identity)
                .filter(|entry| entry.kind == kind)
                .and_then(|entry| entry.node.upgrade())
            {
                created = false;
                existing
            } else {
                entries.insert(
                    identity,
                    Entry {
                        kind,
                        node: Arc::downgrade(&node),
                        file: node.host.get().unwrap().clone(),
                    },
                );
                node
            }
        } else {
            node
        };
        let file = &entries[&identity].file;
        file.state.lock().unwrap().key = key.to_vec();
        file.length
            .store(meta.st_size.max(0) as u64, Ordering::Relaxed);
        drop(entries);
        {
            let mut n = node.borrow_mut();
            n.mode = meta.st_mode as u32;
            n.uid = if meta.st_uid == self.root.uid.0 {
                self.root.uid.1
            } else {
                meta.st_uid
            };
            n.gid = if meta.st_gid == self.root.gid.0 {
                self.root.gid.1
            } else {
                meta.st_gid
            };
            n.links = meta.st_nlink as u32;
            n.times = stat_times(&meta);
        }
        // Never hold the identity index or file-key lock while acquiring the
        // namespace lock: rename already owns the namespace before those keys.
        let mut fs = filesystem.borrow_mut();
        fs.paths.insert(key.to_vec(), node.clone());
        let collect = if created {
            fs.inodes.push(Arc::downgrade(&node));
            fs.next_inode = fs.next_inode.wrapping_add(1);
            fs.next_inode.is_multiple_of(1024)
        } else {
            false
        };
        if collect {
            fs.inodes.retain(|node| node.strong_count() != 0);
        }
        drop(fs);
        if collect {
            self.entries
                .lock()
                .unwrap()
                .retain(|_, entry| entry.node.strong_count() != 0);
        }
        Ok(node)
    }
    pub fn lease(&self, node: &NodeRef, flags: u32) -> Result<Option<Arc<OpenFile>>> {
        let n = node.borrow();
        let file = self
            .entries
            .lock()
            .unwrap()
            .get(&(n.device, n.inode))
            .ok_or(Errno(2))?
            .file
            .clone();
        drop(n);
        if flags & O_PATH != 0 {
            file.pin_path().map(Some)
        } else {
            file.acquire(flags & 3).map(Some)
        }
    }
    pub fn create(
        &self,
        filesystem: &FsHandle,
        key: &[u8],
        content: &Content,
        mode: u32,
    ) -> Result<NodeRef> {
        self.root.writable()?;
        let (parent, name) = self.root.parent(key)?;
        match content {
            Content::Directory => {
                // SAFETY: retained directory capability, valid final component.
                status(unsafe {
                    libc::mkdirat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        (mode & 0o7777) as libc::mode_t,
                    )
                })?;
            }
            Content::Symlink(target) => {
                let target = CString::new(target.as_slice()).map_err(|_| Errno(22))?;
                // SAFETY: both strings valid; symlink contents are never resolved natively.
                status(unsafe {
                    libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr())
                })?;
            }
            Content::File(_) => {
                open_at(
                    &parent,
                    &name,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    mode & 0o7777,
                )?;
            }
            _ => return Err(Errno(95)),
        }
        self.lookup(filesystem, key)
    }
    pub fn create_open(
        &self,
        filesystem: &FsHandle,
        key: &[u8],
        flags: u32,
        mode: u32,
    ) -> Result<(NodeRef, Arc<OpenFile>)> {
        self.root.writable()?;
        let (parent, name) = self.root.parent(key)?;
        let access = flags & 3;
        let native = match access {
            0 => libc::O_RDONLY,
            1 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
        let file = open_at(
            &parent,
            &name,
            native | libc::O_CREAT | libc::O_EXCL,
            mode & 0o7777,
        )?;
        let node = self.lookup(filesystem, key)?;
        let lease = node.host.get().ok_or(Errno(2))?.retain(file, access)?;
        Ok((node, lease))
    }
    pub fn unlink(&self, key: &[u8], directory: bool) -> Result<()> {
        self.root.writable()?;
        let (parent, name) = self.root.parent(key)?;
        // SAFETY: anchored directory and one component, no native link traversal.
        status(unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        })
    }
    pub fn rename(&self, old: &[u8], new: &[u8], exclusive: bool) -> Result<()> {
        self.root.writable()?;
        let (old_dir, old_name) = self.root.parent(old)?;
        let (new_dir, new_name) = self.root.parent(new)?;
        // SAFETY: anchored parents and valid final components; exclusive rename
        // uses the native atomic flag rather than a check-then-overwrite race.
        let result = unsafe {
            if exclusive {
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                {
                    libc::renameatx_np(
                        old_dir.as_raw_fd(),
                        old_name.as_ptr(),
                        new_dir.as_raw_fd(),
                        new_name.as_ptr(),
                        libc::RENAME_EXCL,
                    )
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    libc::renameat2(
                        old_dir.as_raw_fd(),
                        old_name.as_ptr(),
                        new_dir.as_raw_fd(),
                        new_name.as_ptr(),
                        libc::RENAME_NOREPLACE,
                    )
                }
                #[cfg(not(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "linux",
                    target_os = "android"
                )))]
                {
                    return Err(Errno(95));
                }
            } else {
                libc::renameat(
                    old_dir.as_raw_fd(),
                    old_name.as_ptr(),
                    new_dir.as_raw_fd(),
                    new_name.as_ptr(),
                )
            }
        };
        status(result)?;
        let mut prefix = old.to_vec();
        prefix.push(b'/');
        for entry in self.entries.lock().unwrap().values() {
            let mut state = entry.file.state.lock().unwrap();
            if state.key == old || state.key.starts_with(&prefix) {
                let mut key = new.to_vec();
                key.extend_from_slice(&state.key[old.len()..]);
                state.key = key;
            }
        }
        Ok(())
    }
    pub fn link(&self, old: &[u8], new: &[u8]) -> Result<()> {
        self.root.writable()?;
        let (old_dir, old_name) = self.root.parent(old)?;
        let (new_dir, new_name) = self.root.parent(new)?;
        // SAFETY: both operations are relative to retained directory capabilities.
        status(unsafe {
            libc::linkat(
                old_dir.as_raw_fd(),
                old_name.as_ptr(),
                new_dir.as_raw_fd(),
                new_name.as_ptr(),
                0,
            )
        })
    }
    pub fn children(&self, key: &[u8]) -> Result<BTreeMap<Vec<u8>, (u64, u8)>> {
        let directory = self.root.open(key, 0, true)?;
        use std::os::fd::IntoRawFd;
        let fd = directory.into_raw_fd();
        // SAFETY: transfers ownership of this fresh fd on success.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = errno(std::io::Error::last_os_error());
            // SAFETY: fdopendir did not take ownership on failure.
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                // SAFETY: one owned directory stream, dropped exactly once.
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Directory(stream);
        let mut result = BTreeMap::new();
        loop {
            // SAFETY: exclusive access to this local stream; errno distinguishes EOF.
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(errno(error));
                }
                break;
            }
            // SAFETY: readdir's current dirent is valid until the next call.
            let entry = unsafe { &*entry };
            let name = unsafe { std::ffi::CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                result.insert(name.to_vec(), (entry.d_ino, entry.d_type));
            }
        }
        Ok(result)
    }
}
fn stat_times(meta: &libc::stat) -> [storage::Timestamp; 3] {
    [
        storage::Timestamp {
            seconds: meta.st_atime,
            nanos: meta.st_atime_nsec as u32,
        },
        storage::Timestamp {
            seconds: meta.st_mtime,
            nanos: meta.st_mtime_nsec as u32,
        },
        storage::Timestamp {
            seconds: meta.st_ctime,
            nanos: meta.st_ctime_nsec as u32,
        },
    ]
}

impl Vfs {
    pub(super) fn host_for_node(&self, node: &NodeRef) -> Option<Arc<HostFile>> {
        node.host.get().cloned()
    }
    pub(super) fn encode_host_directory(
        o: &mut OpenDescription,
        count: usize,
        children: BTreeMap<Vec<u8>, (u64, u8)>,
        inode: u64,
        parent: u64,
    ) -> Result<Vec<u8>> {
        let mut entries = vec![(b".".to_vec(), inode, 4u8), (b"..".to_vec(), parent, 4)];
        entries.extend(
            children
                .into_iter()
                .map(|(name, (inode, kind))| (name, inode, kind)),
        );
        let mut out = Vec::new();
        while let Some((name, inode, kind)) = entries.get(o.position as usize) {
            let size = (19 + name.len() + 1 + 7) & !7;
            if out.len() + size > count {
                if out.is_empty() {
                    return Err(Errno(22));
                }
                break;
            }
            let start = out.len();
            out.resize(start + size, 0);
            out[start..start + 8].copy_from_slice(&inode.to_le_bytes());
            out[start + 8..start + 16].copy_from_slice(&(o.position + 1).to_le_bytes());
            out[start + 16..start + 18].copy_from_slice(&(size as u16).to_le_bytes());
            out[start + 18] = *kind;
            out[start + 19..start + 19 + name.len()].copy_from_slice(name);
            o.position += 1;
        }
        Ok(out)
    }
    /// Embedding-only mount: Linux mount(2) cannot manufacture host authority.
    /// The selected directory already exists; mounts are session-local.
    pub fn mount_host(
        &mut self,
        target: &[u8],
        host: impl AsRef<Path>,
        readonly: bool,
    ) -> Result<()> {
        use mounts::{Attachment, Kind, MountInit, MS_NODEV, MS_NOSUID, MS_RDONLY};
        if self.mounts.is_none() {
            self.initialize_mounts()?;
        }
        let target = self.mount_location(target, true)?;
        let node = self.node(&target)?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let backend = HostFs::new(
            host.as_ref(),
            readonly,
            self.credentials.fsuid,
            self.credentials.fsgid,
        )?;
        let mut filesystem = FsHandle::new(Filesystem {
            shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
            paths: BTreeMap::new(),
            inodes: Vec::new(),
            next_inode: 1,
            limits: StorageLimits {
                file_bytes: i64::MAX as u64,
                nodes: usize::MAX,
            },
            disk: None,
            volume: None,
        });
        filesystem.host = Some(backend.clone());
        let root = backend.lookup(&filesystem, b"/")?;
        let mount = Rc::new(Mount::new(MountInit {
            id: mounts::new_mount_id()?,
            fs: filesystem,
            root,
            root_key: b"/".to_vec(),
            kind: Kind::Host,
            namespace: None,
            pid_namespace: None,
            devpts: None,
            flags: Cell::new(MS_NODEV | MS_NOSUID | if readonly { MS_RDONLY } else { 0 }),
            writers: Arc::default(),
            parent: RefCell::new(Some(Attachment {
                parent: target.mount.ok_or(Errno(22))?,
                node,
                fallback: target.key,
            })),
        }));
        self.register_mounts(std::slice::from_ref(&mount))?;
        self.mounts
            .as_ref()
            .unwrap()
            .0
            .borrow_mut()
            .mounts
            .push(mount);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let name = format!(
                "trames-hostfs-{}-{}",
                std::process::id(),
                trames_memory::new_backing_identity()
            );
            let path = std::env::temp_dir().join(name);
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn vfs(&self, readonly: bool) -> Vfs {
            let mut vfs = Vfs::default();
            vfs.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
            vfs.mount_host(b"/host", &self.0, readonly).unwrap();
            vfs
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn size(stat: [u8; 128]) -> u64 {
        u64::from_le_bytes(stat[48..56].try_into().unwrap())
    }
    #[test]
    fn bidirectional_bytes_live_size_and_retained_replacement() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), b"first").unwrap();
        let mut v = fixture.vfs(false);
        let fd = v.open_at(AT_FDCWD, b"/host/file", 2, 0).unwrap();
        assert_eq!(v.read(fd, 10).unwrap(), b"first");
        std::fs::write(fixture.0.join("file"), b"host extended").unwrap();
        assert_eq!(size(v.stat_fd(fd).unwrap()), 13);
        assert_eq!(v.pread(fd, 30, 0).unwrap(), b"host extended");
        v.pwrite(fd, b"guest", 0).unwrap();
        assert_eq!(
            std::fs::read(fixture.0.join("file")).unwrap(),
            b"guestextended"
        );
        std::fs::write(fixture.0.join("temp"), b"replacement").unwrap();
        std::fs::rename(fixture.0.join("temp"), fixture.0.join("file")).unwrap();
        let fresh = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        assert_eq!(v.read(fresh, 30).unwrap(), b"replacement");
        assert_eq!(v.pread(fd, 30, 0).unwrap(), b"guestextended");
        v.unlink_at(AT_FDCWD, b"/host/file", false).unwrap();
        assert_eq!(v.pread(fresh, 30, 0).unwrap(), b"replacement");
        assert!(!fixture.0.join("file").exists());
    }
    #[test]
    fn closing_the_newest_handle_does_not_lose_an_older_open_inode() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), b"original").unwrap();
        let mut v = fixture.vfs(false);
        let old = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let newest = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        v.close(newest).unwrap();
        v.unlink_at(AT_FDCWD, b"/host/file", false).unwrap();
        assert_eq!(v.pread(old, 8, 0).unwrap(), b"original");
        v.close(old).unwrap();
    }
    #[test]
    fn namespace_metadata_append_and_directory_refresh() {
        let fixture = Fixture::new();
        let mut v = fixture.vfs(false);
        v.mkdir_at(AT_FDCWD, b"/host/sub", 0o750).unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/host/sub/file", 0x442, 0o640)
            .unwrap();
        v.write(fd, b"a").unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(fixture.0.join("sub/file"))
            .unwrap()
            .write_all(b"h")
            .unwrap();
        v.pwrite(fd, b"b", 0).unwrap(); // Linux append also applies to pwrite.
        assert_eq!(std::fs::read(fixture.0.join("sub/file")).unwrap(), b"ahb");
        v.link_at(AT_FDCWD, b"/host/sub/file", AT_FDCWD, b"/host/sub/link")
            .unwrap();
        v.chdir(b"/host/sub").unwrap();
        v.rename_at(AT_FDCWD, b"/host/sub", AT_FDCWD, b"/host/moved", 0)
            .unwrap();
        assert_eq!(v.cwd().unwrap(), b"/host/moved");
        assert_eq!(v.pread(fd, 30, 0).unwrap(), b"ahb");
        v.chmod_fd(fd, 0o600).unwrap();
        assert_eq!(
            std::fs::metadata(fixture.0.join("moved/file"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        v.set_times(fd as i32, None, Some([[123, 0], [456, 0]]))
            .unwrap();
        assert_eq!(
            std::fs::metadata(fixture.0.join("moved/file"))
                .unwrap()
                .mtime(),
            456
        );
        let dir = v.open_at(AT_FDCWD, b"/host/moved", O_DIRECTORY, 0).unwrap();
        std::fs::write(fixture.0.join("moved/new"), b"new").unwrap();
        let names = v.getdents(dir, 4096).unwrap();
        assert!(names.windows(4).any(|n| n == b"new\0"));
        v.unlink_at(AT_FDCWD, b"/host/moved/new", false).unwrap();
        assert!(!fixture.0.join("moved/new").exists());
        assert_eq!(
            v.rename_at(
                AT_FDCWD,
                b"/host/moved/file",
                AT_FDCWD,
                b"/host/moved/link",
                1
            ),
            Err(Errno(17))
        );
    }
    #[test]
    fn creating_readonly_files_preserves_the_original_write_description() {
        let fixture = Fixture::new();
        let mut v = fixture.vfs(false);
        let fd = v.open_at(AT_FDCWD, b"/host/object", 0xc2, 0o444).unwrap();
        v.write(fd, b"git object").unwrap();
        assert_eq!(v.pread(fd, 10, 0).unwrap(), b"git object");
        assert_eq!(
            std::fs::metadata(fixture.0.join("object")).unwrap().mode() & 0o777,
            0o444
        );
        v.sync_fd(fd, false).unwrap();
        v.close(fd).unwrap();
        assert_eq!(
            std::fs::read(fixture.0.join("object")).unwrap(),
            b"git object"
        );
    }
    #[test]
    fn readonly_is_an_immutable_host_capability_and_shared_mmap_is_explicit() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), b"readonly").unwrap();
        let mut v = fixture.vfs(true);
        assert_eq!(v.open_at(AT_FDCWD, b"/host/file", 2, 0), Err(Errno(30)));
        assert_eq!(v.mkdir_at(AT_FDCWD, b"/host/new", 0o755), Err(Errno(30)));
        assert_eq!(v.unlink_at(AT_FDCWD, b"/host/file", false), Err(Errno(30)));
        assert_eq!(v.mount(None, b"/host", None, 32, None), Err(Errno(30)));
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        assert_eq!(
            v.mapping_pages(fd, 0, 4096, true, false).err(),
            Some(Errno(19))
        );
        assert_eq!(v.read(fd, 30).unwrap(), b"readonly");
    }
    #[test]
    fn private_mapping_is_lazy_cow_and_does_not_shadow_native_file_io() {
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), vec![7; PAGE_SIZE as usize * 2]).unwrap();
        let mut v = fixture.vfs(true);
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let pages = v
            .mapping_pages(fd, PAGE_SIZE, PAGE_SIZE, false, true)
            .unwrap();
        assert!(pages[0].shared_page().is_none());
        let mut memory = Memory::new(1 << 20);
        memory
            .map_backed(0x10000, pages, false, Permissions::RW, false)
            .unwrap();
        assert_eq!(memory.read_array::<4>(0x10000).unwrap(), [7; 4]);
        memory.write(0x10000, b"COW!").unwrap();
        assert_eq!(memory.read_array::<4>(0x10000).unwrap(), *b"COW!");
        std::fs::write(fixture.0.join("file"), vec![9; PAGE_SIZE as usize * 2]).unwrap();
        assert_eq!(v.pread(fd, 4, PAGE_SIZE).unwrap(), [9; 4]);
        assert_eq!(memory.read_array::<4>(0x10000).unwrap(), *b"COW!");
        assert_eq!(v.allocated_bytes(), 0);
        assert_eq!(
            &std::fs::read(fixture.0.join("file")).unwrap()[4096..4100],
            &[9; 4]
        );
    }
    #[test]
    fn private_mapping_and_exec_keep_the_original_inode_after_native_replacement() {
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), vec![5; 100]).unwrap();
        std::fs::set_permissions(
            fixture.0.join("file"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut v = fixture.vfs(false);
        let executable = v.executable_file_at(AT_FDCWD, b"/host/file", 0).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let pages = v.mapping_pages(fd, 0, 2 * PAGE_SIZE, false, false).unwrap();
        assert!(matches!(
            pages[1].check(0x11000),
            Err(trames_memory::MemoryError::Bus(0x11000))
        ));
        let first = pages[0].clone();
        let mut memory = Memory::new(1 << 20);
        memory
            .map_backed(0x10000, vec![first], false, Permissions::R, false)
            .unwrap();
        v.close(fd).unwrap();
        std::fs::write(fixture.0.join("new"), vec![8; 100]).unwrap();
        std::fs::rename(fixture.0.join("new"), fixture.0.join("file")).unwrap();
        assert_eq!(executable.bytes().unwrap(), vec![5; 100]);
        assert_eq!(memory.read_array::<4>(0x10000).unwrap(), [5; 4]);
        assert_eq!(memory.read_array::<4>(0x10000 + 100).unwrap(), [0; 4]);
        pages[0].sync().unwrap();
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        assert_eq!(v.read(fd, 4).unwrap(), [8; 4]);
    }
    #[test]
    fn private_mapping_faults_after_guest_truncates_a_resident_page() {
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), vec![3; PAGE_SIZE as usize]).unwrap();
        let mut v = fixture.vfs(false);
        let fd = v.open_at(AT_FDCWD, b"/host/file", 2, 0).unwrap();
        let pages = v.mapping_pages(fd, 0, PAGE_SIZE, false, true).unwrap();
        let mut memory = Memory::new(1 << 20);
        memory
            .map_backed(0x10000, pages, false, Permissions::RW, false)
            .unwrap();
        assert_eq!(memory.read_array::<4>(0x10000).unwrap(), [3; 4]);
        memory.write(0x10000, b"COW!").unwrap();
        v.truncate_fd(fd, 0).unwrap();
        assert!(matches!(
            memory.read_array::<4>(0x10000),
            Err(trames_memory::MemoryError::Bus(_))
        ));
    }
    #[test]
    fn symlinks_resolve_in_guest_and_native_ancestor_replacement_cannot_escape() {
        let fixture = Fixture::new();
        let outside = Fixture::new();
        std::fs::write(outside.0.join("secret"), b"host secret").unwrap();
        std::os::unix::fs::symlink(&outside.0, fixture.0.join("escape")).unwrap();
        std::os::unix::fs::symlink("/private", fixture.0.join("absolute")).unwrap();
        let mut v = fixture.vfs(false);
        v.import_file(b"/private", b"guest private".to_vec())
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/host/absolute", 0, 0).unwrap();
        assert_eq!(v.read(fd, 30).unwrap(), b"guest private");
        assert_eq!(
            v.open_at(AT_FDCWD, b"/host/escape/secret", 0, 0),
            Err(Errno(2))
        );
        std::fs::create_dir(fixture.0.join("parent")).unwrap();
        let resolved = v.resolve(AT_FDCWD, b"/host/parent/secret").unwrap();
        std::fs::remove_dir(fixture.0.join("parent")).unwrap();
        std::os::unix::fs::symlink(&outside.0, fixture.0.join("parent")).unwrap();
        let host = resolved.mount.as_ref().unwrap().fs.host.as_ref().unwrap();
        assert!(host.root.open(&resolved.key, 0, false).is_err());
    }
    #[test]
    fn bulk_disk_job_retains_the_original_host_file_after_close_and_reuse() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), vec![7; 128 * 1024]).unwrap();
        let mut v = fixture.vfs(false);
        let fd = v.open_at(AT_FDCWD, b"/host/file", 0, 0).unwrap();
        let (read, job) = v.prepare_disk_read(fd, 128 * 1024, None).unwrap().unwrap();
        v.close(fd).unwrap();
        v.unlink_at(AT_FDCWD, b"/host/file", false).unwrap();
        let replacement = v.open_at(AT_FDCWD, b"/host/new", 0x42, 0o600).unwrap();
        assert_eq!(fd, replacement);
        let bytes = read.finish(job.run()).unwrap();
        assert_eq!(bytes, vec![7; 128 * 1024]);
        v.write(replacement, b"new").unwrap();
        v.sync_fd(replacement, false).unwrap();
    }
    #[test]
    fn parallel_metadata_admission_and_rename_do_not_invert_cache_locks() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("left"), b"moving").unwrap();
        for i in 0..256 {
            std::fs::write(fixture.0.join(format!("side-{i}")), b"metadata").unwrap();
        }
        let mut v = fixture.vfs(false);
        let filesystem = v.resolve(AT_FDCWD, b"/host").unwrap().filesystem(&v);
        let host = filesystem.host.as_ref().unwrap().clone();
        let worker = std::thread::spawn(move || {
            for i in 0..256 {
                host.lookup(&filesystem, format!("/side-{i}").as_bytes())
                    .unwrap();
            }
        });
        for i in 0..256 {
            let (old, new) = if i % 2 == 0 {
                (b"/host/left".as_slice(), b"/host/right".as_slice())
            } else {
                (b"/host/right".as_slice(), b"/host/left".as_slice())
            };
            v.rename_at(AT_FDCWD, old, AT_FDCWD, new, 0).unwrap();
        }
        worker.join().unwrap();
    }
    #[test]
    fn a_later_guest_bind_mount_invalidates_the_no_child_shortcut() {
        let fixture = Fixture::new();
        let mut v = fixture.vfs(false);
        v.mkdir_at(AT_FDCWD, b"/source", 0o755).unwrap();
        v.import_file(b"/source/inside", b"bound".to_vec()).unwrap();
        v.mkdir_at(AT_FDCWD, b"/host/sub", 0o755).unwrap();
        v.mount(Some(b"/source"), b"/host/sub", None, 4096, None)
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/host/sub/inside", 0, 0).unwrap();
        assert_eq!(v.read(fd, 10).unwrap(), b"bound");
        v.close(fd).unwrap();
        v.umount(b"/host/sub", 0).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/host/sub/inside", 0, 0),
            Err(Errno(2))
        );
    }
    #[test]
    fn path_only_handles_retain_native_symlinks_after_replacement() {
        let fixture = Fixture::new();
        std::os::unix::fs::symlink("old target", fixture.0.join("link")).unwrap();
        let mut v = fixture.vfs(false);
        let fd = v
            .open_at(AT_FDCWD, b"/host/link", O_PATH | O_NOFOLLOW, 0)
            .unwrap();
        std::fs::remove_file(fixture.0.join("link")).unwrap();
        std::os::unix::fs::symlink("new target", fixture.0.join("link")).unwrap();
        assert_eq!(v.readlink_at(fd as i32, b"").unwrap(), b"old target");
        let stat = v.stat_fd(fd).unwrap();
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000,
            0o120000
        );
        assert_eq!(v.read(fd, 8), Err(Errno(9)));
    }
    #[test]
    fn native_directory_emptiness_is_not_inferred_from_a_stale_lookup_cache() {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.0.join("source")).unwrap();
        std::fs::create_dir(fixture.0.join("target")).unwrap();
        std::fs::write(fixture.0.join("target/deleted"), b"old").unwrap();
        let mut v = fixture.vfs(false);
        v.stat_at(AT_FDCWD, b"/host/target/deleted").unwrap();
        std::fs::remove_file(fixture.0.join("target/deleted")).unwrap();
        v.rename_at(AT_FDCWD, b"/host/source", AT_FDCWD, b"/host/target", 0)
            .unwrap();
        assert!(fixture.0.join("target").is_dir());
    }
    #[test]
    fn mount_marker_uses_the_visible_pseudo_inode_over_an_imported_directory() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/proc", 0o755).unwrap();
        v.initialize_mounts().unwrap();
        v.pseudo.borrow_mut().enabled = true;
        assert_eq!(
            v.resolve(AT_FDCWD, b"/proc").unwrap().mount.unwrap().kind,
            mounts::Kind::Proc
        );
    }
    #[test]
    fn cwd_and_directory_fd_follow_a_native_directory_rename() {
        let fixture = Fixture::new();
        std::fs::create_dir(fixture.0.join("sub")).unwrap();
        std::fs::write(fixture.0.join("sub/file"), b"live directory").unwrap();
        let mut v = fixture.vfs(false);
        let dir = v.open_at(AT_FDCWD, b"/host/sub", O_DIRECTORY, 0).unwrap();
        v.chdir_fd(dir).unwrap();
        v.close(dir).unwrap();
        std::fs::rename(fixture.0.join("sub"), fixture.0.join("moved")).unwrap();
        assert_eq!(v.cwd().unwrap(), b"/host/moved");
        let fd = v.open_at(AT_FDCWD, b"file", 0, 0).unwrap();
        assert_eq!(v.read(fd, 64).unwrap(), b"live directory");
    }
    #[test]
    fn mount_does_not_walk_the_host_tree_or_charge_native_bytes_to_guest_storage() {
        let fixture = Fixture::new();
        let file = File::create(fixture.0.join("sparse")).unwrap();
        file.set_len(8 << 30).unwrap();
        let v = fixture.vfs(false);
        let m = v.resolve(AT_FDCWD, b"/host").unwrap().mount.unwrap();
        assert_eq!(m.fs.host.as_ref().unwrap().entries.lock().unwrap().len(), 1);
        assert_eq!(size(v.stat_at(AT_FDCWD, b"/host/sparse").unwrap()), 8 << 30);
        assert_eq!(v.allocated_bytes(), 0);
        let fs = v.statfs_at(b"/host").unwrap();
        assert_ne!(u64::from_le_bytes(fs[16..24].try_into().unwrap()), 0);
    }
    use std::io::Write;
}
