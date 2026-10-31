// SPDX-License-Identifier: GPL-3.0-or-later
//! Native watch events are drained by an existing reader/poller, never a thread
//! or periodic tree scan. Directory snapshots cover immediate names only.
use super::*;
#[cfg(target_vendor = "apple")]
use crate::inotify;
use crate::inotify::Source;
use std::os::fd::{AsFd, OwnedFd};

pub(crate) const NATIVE_MASK: u32 = 2 | 4 | 64 | 128 | 256 | 512 | 1024 | 2048;
pub(crate) struct Event {
    pub wd: i32,
    pub mask: u32,
    pub cookie: u32,
    pub name: Vec<u8>,
}
pub(crate) struct Native(Mutex<backend::State>);
impl Native {
    pub fn new() -> Result<Self> {
        backend::State::new().map(|state| Self(Mutex::new(state)))
    }
    pub fn add(
        &self,
        wd: i32,
        host: &HostFile,
        source: Arc<Source>,
        directory: bool,
        mask: u32,
    ) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.contains(wd) {
            return state.configure(wd, mask);
        }
        let file = if directory {
            host.acquire(0)?
        } else {
            host.pin_path()?
        };
        state.add(wd, file, source, directory, mask)
    }
    pub fn remove(&self, wd: i32) {
        self.0.lock().unwrap().remove(wd);
    }
    pub fn close(&self) {
        self.0.lock().unwrap().close();
    }
    pub fn active(&self) -> bool {
        self.0.lock().unwrap().active()
    }
    pub fn fd(&self) -> Option<OwnedFd> {
        self.0.lock().unwrap().fd().ok()
    }
    pub fn drain(&self) -> Result<Vec<Event>> {
        self.0.lock().unwrap().drain()
    }
}

#[cfg(target_vendor = "apple")]
mod backend {
    use super::*;
    use std::os::fd::IntoRawFd;
    type Names = BTreeMap<Vec<u8>, ((u64, u64), u32)>;
    struct Child {
        identity: (u64, u64),
        mode: u32,
        native: Option<(File, usize)>,
    }
    struct Watch {
        file: Arc<OpenFile>,
        _source: Arc<Source>,
        directory: bool,
        child_data: bool,
        token: usize,
        children: BTreeMap<Vec<u8>, Child>,
    }
    pub(super) struct State {
        queue: Option<OwnedFd>,
        next: usize,
        cookie: u32,
        watches: BTreeMap<i32, Watch>,
        targets: BTreeMap<usize, (i32, Option<Vec<u8>>)>,
    }
    impl State {
        pub fn new() -> Result<Self> {
            // SAFETY: kqueue returns one fresh owned descriptor.
            let fd = unsafe { libc::kqueue() };
            if fd < 0 {
                return Err(errno(std::io::Error::last_os_error()));
            }
            Ok(Self {
                queue: Some(unsafe { OwnedFd::from_raw_fd(fd) }),
                next: 0,
                cookie: 0,
                watches: BTreeMap::new(),
                targets: BTreeMap::new(),
            })
        }
        pub fn contains(&self, wd: i32) -> bool {
            self.watches.contains_key(&wd)
        }
        pub fn active(&self) -> bool {
            !self.watches.is_empty()
        }
        pub fn fd(&self) -> Result<OwnedFd> {
            self.queue
                .as_ref()
                .ok_or(Errno(9))?
                .as_fd()
                .try_clone_to_owned()
                .map_err(errno)
        }
        fn register(&mut self, wd: i32, name: Option<Vec<u8>>, fd: i32) -> Result<usize> {
            self.next = self.next.checked_add(1).ok_or(Errno(28))?;
            let token = self.next;
            let event = libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE
                    | libc::NOTE_EXTEND
                    | libc::NOTE_ATTRIB
                    | libc::NOTE_LINK
                    | libc::NOTE_RENAME
                    | libc::NOTE_DELETE
                    | libc::NOTE_REVOKE,
                data: 0,
                udata: token as *mut libc::c_void,
            };
            // SAFETY: retained native fd, initialized event; udata is an ID only.
            status(unsafe {
                libc::kevent(
                    self.queue.as_ref().ok_or(Errno(9))?.as_raw_fd(),
                    &event,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            })?;
            self.targets.insert(token, (wd, name));
            Ok(token)
        }
        fn unregister(&mut self, token: usize, fd: i32) {
            self.targets.remove(&token);
            if let Some(queue) = &self.queue {
                let event = libc::kevent {
                    ident: fd as usize,
                    filter: libc::EVFILT_VNODE,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                };
                unsafe {
                    libc::kevent(
                        queue.as_raw_fd(),
                        &event,
                        1,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    );
                }
            }
        }
        pub fn add(
            &mut self,
            wd: i32,
            file: Arc<OpenFile>,
            source: Arc<Source>,
            directory: bool,
            mask: u32,
        ) -> Result<()> {
            let token = self.register(wd, None, file.file.as_raw_fd())?;
            let mut watch = Watch {
                file,
                _source: source,
                directory,
                child_data: mask & 6 != 0,
                token,
                children: BTreeMap::new(),
            };
            if directory {
                if let Err(error) = self.refresh(wd, &mut watch, false, &mut Vec::new()) {
                    self.retire(watch);
                    return Err(error);
                }
            }
            self.watches.insert(wd, watch);
            Ok(())
        }
        fn retire(&mut self, watch: Watch) {
            self.unregister(watch.token, watch.file.file.as_raw_fd());
            for child in watch.children.into_values() {
                if let Some((file, token)) = child.native {
                    self.unregister(token, file.as_raw_fd());
                }
            }
        }
        pub fn remove(&mut self, wd: i32) {
            if let Some(watch) = self.watches.remove(&wd) {
                self.retire(watch);
            }
        }
        pub fn close(&mut self) {
            let watches = std::mem::take(&mut self.watches);
            for watch in watches.into_values() {
                self.retire(watch);
            }
            self.queue = None;
        }
        fn names(file: &File) -> Result<Names> {
            let fd = file.try_clone().map_err(errno)?.into_raw_fd();
            // This watch owns its independent directory description; rewind
            // only that stream, never a guest getdents position.
            let stream = unsafe { libc::fdopendir(fd) };
            if stream.is_null() {
                unsafe { libc::close(fd) };
                return Err(errno(std::io::Error::last_os_error()));
            }
            struct Dir(*mut libc::DIR);
            impl Drop for Dir {
                fn drop(&mut self) {
                    unsafe {
                        libc::closedir(self.0);
                    }
                }
            }
            let stream = Dir(stream);
            unsafe { libc::rewinddir(stream.0) };
            let mut entries = BTreeMap::new();
            loop {
                unsafe {
                    *libc::__error() = 0;
                }
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(0) {
                        return Err(errno(error));
                    }
                    break;
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let meta = match meta_at(file, &component(name)?) {
                    Ok(meta) => meta,
                    Err(Errno(2)) => continue,
                    Err(e) => return Err(e),
                };
                entries.insert(
                    name.to_vec(),
                    ((meta.st_dev as u64, meta.st_ino), meta.st_mode as u32),
                );
            }
            Ok(entries)
        }
        fn event(wd: i32, mask: u32, cookie: u32, name: &[u8], mode: u32) -> Event {
            Event {
                wd,
                mask: mask
                    | if mode & 0o170000 == 0o40000 {
                        0x40000000
                    } else {
                        0
                    },
                cookie,
                name: name.to_vec(),
            }
        }
        fn refresh(
            &mut self,
            wd: i32,
            watch: &mut Watch,
            emit: bool,
            events: &mut Vec<Event>,
        ) -> Result<()> {
            let names = Self::names(&watch.file.file)?;
            let removed: Vec<_> = watch
                .children
                .iter()
                .filter(|(name, c)| names.get(*name).is_none_or(|(id, _)| *id != c.identity))
                .map(|(n, c)| (n.clone(), c.identity, c.mode))
                .collect();
            let added: Vec<_> = names
                .iter()
                .filter(|(name, (id, _))| {
                    watch.children.get(*name).is_none_or(|c| c.identity != *id)
                })
                .map(|(n, (id, mode))| (n.clone(), *id, *mode))
                .collect();
            let mut paired = std::collections::BTreeSet::new();
            if emit {
                for (name, id, mode) in &removed {
                    if let Some((new, _, _)) = added
                        .iter()
                        .find(|(n, other, _)| other == id && !paired.contains(n))
                    {
                        self.cookie = self.cookie.wrapping_add(1).max(1);
                        paired.insert(new.clone());
                        events.push(Self::event(
                            wd,
                            inotify::MOVED_FROM,
                            self.cookie,
                            name,
                            *mode,
                        ));
                        events.push(Self::event(wd, inotify::MOVED_TO, self.cookie, new, *mode));
                    } else {
                        events.push(Self::event(wd, inotify::DELETE, 0, name, *mode));
                    }
                }
                for (name, _, mode) in &added {
                    if !paired.contains(name) {
                        events.push(Self::event(wd, inotify::CREATE, 0, name, *mode));
                    }
                }
            }
            for (name, _, _) in removed {
                if let Some(child) = watch.children.remove(&name) {
                    if let Some((file, token)) = child.native {
                        self.unregister(token, file.as_raw_fd());
                    }
                }
            }
            for (name, id, mode) in added {
                watch.children.insert(
                    name,
                    Child {
                        identity: id,
                        mode,
                        native: None,
                    },
                );
            }
            self.child_interests(wd, watch)?;
            Ok(())
        }
        fn child_interests(&mut self, wd: i32, watch: &mut Watch) -> Result<()> {
            for (name, child) in &mut watch.children {
                if !watch.child_data {
                    if let Some((file, token)) = child.native.take() {
                        self.unregister(token, file.as_raw_fd());
                    }
                } else if child.native.is_none() {
                    let file = match open_at(
                        &watch.file.file,
                        &component(name)?,
                        libc::O_EVTONLY | libc::O_SYMLINK,
                        0,
                    ) {
                        Ok(file) => file,
                        Err(Errno(2)) => continue,
                        Err(error) => return Err(error),
                    };
                    let token = self.register(wd, Some(name.clone()), file.as_raw_fd())?;
                    child.native = Some((file, token));
                }
            }
            Ok(())
        }
        pub fn configure(&mut self, wd: i32, mask: u32) -> Result<()> {
            let Some(mut watch) = self.watches.remove(&wd) else {
                return Err(Errno(22));
            };
            watch.child_data = mask & 6 != 0;
            let result = self.child_interests(wd, &mut watch);
            self.watches.insert(wd, watch);
            result
        }
        pub fn drain(&mut self) -> Result<Vec<Event>> {
            let Some(queue) = &self.queue else {
                return Ok(Vec::new());
            };
            let fd = queue.as_raw_fd();
            let mut events = Vec::new();
            let mut native: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            loop {
                let count = unsafe {
                    libc::kevent(
                        fd,
                        std::ptr::null(),
                        0,
                        native.as_mut_ptr(),
                        native.len() as i32,
                        &timeout,
                    )
                };
                if count < 0 {
                    return Err(errno(std::io::Error::last_os_error()));
                }
                if count == 0 {
                    break;
                }
                for event in &native[..count as usize] {
                    let Some((wd, name)) = self.targets.get(&(event.udata as usize)).cloned()
                    else {
                        continue;
                    };
                    let Some(mut watch) = self.watches.remove(&wd) else {
                        continue;
                    };
                    let flags = event.fflags;
                    if let Some(name) = name {
                        if let Some(child) = watch.children.get(&name) {
                            if flags & (libc::NOTE_WRITE | libc::NOTE_EXTEND) != 0
                                && child.mode & 0o170000 != 0o40000
                            {
                                events.push(Self::event(wd, inotify::MODIFY, 0, &name, child.mode));
                            }
                            if flags & (libc::NOTE_ATTRIB | libc::NOTE_LINK) != 0 {
                                events.push(Self::event(wd, inotify::ATTRIB, 0, &name, child.mode));
                            }
                        }
                    } else {
                        let mode = if watch.directory { 0o40000 } else { 0o100000 };
                        if flags & (libc::NOTE_DELETE | libc::NOTE_REVOKE) != 0 {
                            events.push(Self::event(wd, 1024, 0, b"", mode));
                            events.push(Event {
                                wd,
                                mask: 0x8000,
                                cookie: 0,
                                name: Vec::new(),
                            });
                        } else if watch.directory && flags & libc::NOTE_WRITE != 0 {
                            if self.refresh(wd, &mut watch, true, &mut events).is_err() {
                                events.push(Event {
                                    wd: -1,
                                    mask: 0x4000,
                                    cookie: 0,
                                    name: Vec::new(),
                                });
                            }
                        } else if !watch.directory
                            && flags & (libc::NOTE_WRITE | libc::NOTE_EXTEND) != 0
                        {
                            events.push(Self::event(wd, inotify::MODIFY, 0, b"", mode));
                        }
                        if flags & libc::NOTE_ATTRIB != 0 {
                            events.push(Self::event(wd, inotify::ATTRIB, 0, b"", mode));
                        }
                        if flags & libc::NOTE_RENAME != 0 {
                            events.push(Self::event(wd, inotify::MOVE_SELF, 0, b"", mode));
                        }
                    }
                    self.watches.insert(wd, watch);
                }
                if events.len() >= 16384 {
                    events.push(Event {
                        wd: -1,
                        mask: 0x4000,
                        cookie: 0,
                        name: Vec::new(),
                    });
                    break;
                }
            }
            Ok(events)
        }
    }
}

#[cfg(target_os = "linux")]
mod backend {
    use super::*;
    struct Watch {
        native: i32,
        _file: Arc<OpenFile>,
        _source: Arc<Source>,
    }
    pub(super) struct State {
        fd: Option<OwnedFd>,
        watches: BTreeMap<i32, Watch>,
    }
    impl State {
        pub fn new() -> Result<Self> {
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if fd < 0 {
                return Err(errno(std::io::Error::last_os_error()));
            }
            Ok(Self {
                fd: Some(unsafe { OwnedFd::from_raw_fd(fd) }),
                watches: BTreeMap::new(),
            })
        }
        pub fn configure(&mut self, _: i32, _: u32) -> Result<()> {
            Ok(())
        }
        pub fn contains(&self, wd: i32) -> bool {
            self.watches.contains_key(&wd)
        }
        pub fn active(&self) -> bool {
            !self.watches.is_empty()
        }
        pub fn fd(&self) -> Result<OwnedFd> {
            self.fd
                .as_ref()
                .ok_or(Errno(9))?
                .as_fd()
                .try_clone_to_owned()
                .map_err(errno)
        }
        pub fn add(
            &mut self,
            wd: i32,
            file: Arc<OpenFile>,
            source: Arc<Source>,
            _: bool,
            _: u32,
        ) -> Result<()> {
            let path = CString::new(format!("/proc/self/fd/{}", file.file.as_raw_fd())).unwrap();
            let fd = self.fd.as_ref().ok_or(Errno(9))?.as_raw_fd();
            let native = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), NATIVE_MASK) };
            if native < 0 {
                return Err(errno(std::io::Error::last_os_error()));
            }
            self.watches.insert(
                wd,
                Watch {
                    native,
                    _file: file,
                    _source: source,
                },
            );
            Ok(())
        }
        pub fn remove(&mut self, wd: i32) {
            if let Some(watch) = self.watches.remove(&wd) {
                if !self
                    .watches
                    .values()
                    .any(|other| other.native == watch.native)
                {
                    if let Some(fd) = &self.fd {
                        // SAFETY: live inotify descriptor and watch ID returned by it.
                        unsafe {
                            libc::inotify_rm_watch(fd.as_raw_fd(), watch.native);
                        }
                    }
                }
            }
        }
        pub fn close(&mut self) {
            self.watches.clear();
            self.fd = None;
        }
        pub fn drain(&mut self) -> Result<Vec<Event>> {
            let Some(fd) = &self.fd else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            let mut bytes = [0u8; 65536];
            loop {
                let count =
                    unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
                if count < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(errno(error));
                }
                if count == 0 {
                    break;
                }
                let mut pos = 0;
                while pos + 16 <= count as usize {
                    let native = i32::from_ne_bytes(bytes[pos..pos + 4].try_into().unwrap());
                    let mask = u32::from_ne_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
                    let cookie = u32::from_ne_bytes(bytes[pos + 8..pos + 12].try_into().unwrap());
                    let len =
                        u32::from_ne_bytes(bytes[pos + 12..pos + 16].try_into().unwrap()) as usize;
                    let watched: Vec<_> = if native < 0 {
                        vec![-1]
                    } else {
                        self.watches
                            .iter()
                            .filter(|(_, w)| w.native == native)
                            .map(|(&wd, _)| wd)
                            .collect()
                    };
                    for wd in watched {
                        let name = bytes[pos + 16..pos + 16 + len]
                            .split(|b| *b == 0)
                            .next()
                            .unwrap_or_default()
                            .to_vec();
                        out.push(Event {
                            wd,
                            mask,
                            cookie,
                            name,
                        });
                    }
                    pos += 16 + len;
                }
            }
            Ok(out)
        }
    }
}
