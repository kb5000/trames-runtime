// SPDX-License-Identifier: GPL-3.0-or-later
//! Original host-console byte resources. No task, VFS control callback or guest
//! pointer crosses this boundary; waits use the existing execution notification.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleStream {
    Input,
    Output,
    Error,
}

pub trait ConsoleIo: Send + Sync {
    fn read(&self, count: usize) -> Result<Vec<u8>>;
    fn write(&self, stream: ConsoleStream, bytes: &[u8]) -> Result<usize>;
    fn poll(&self, stream: ConsoleStream, events: u16) -> (u16, [u64; 2]);
    fn subscribe(&self, _signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        Vec::new()
    }
    fn native_wait_fds(&self, _stream: ConsoleStream) -> Vec<HostFd> {
        Vec::new()
    }
    /// Potentially blocking host I/O belongs on the existing bounded disk pool.
    fn host_work(&self) -> bool {
        false
    }
}

type ConsoleWrite = dyn Fn(ConsoleStream, &[u8]) -> Result<usize> + Send + Sync;

pub struct ConsoleCallbacks {
    read: Box<dyn Fn(usize) -> Result<Vec<u8>> + Send + Sync>,
    write: Box<ConsoleWrite>,
    poll: Box<dyn Fn(ConsoleStream, u16) -> (u16, [u64; 2]) + Send + Sync>,
    readiness: Option<Arc<Readiness>>,
    host: bool,
}
impl ConsoleCallbacks {
    pub fn new(
        read: impl Fn(usize) -> Result<Vec<u8>> + Send + Sync + 'static,
        write: impl Fn(ConsoleStream, &[u8]) -> Result<usize> + Send + Sync + 'static,
        poll: impl Fn(ConsoleStream, u16) -> (u16, [u64; 2]) + Send + Sync + 'static,
    ) -> Self {
        Self {
            read: Box::new(read),
            write: Box::new(write),
            poll: Box::new(poll),
            readiness: None,
            host: false,
        }
    }
    pub fn readiness(mut self, readiness: Arc<Readiness>) -> Self {
        self.readiness = Some(readiness);
        self
    }
    pub fn host(mut self) -> Self {
        self.host = true;
        self
    }
}
impl ConsoleIo for ConsoleCallbacks {
    fn read(&self, count: usize) -> Result<Vec<u8>> {
        (self.read)(count)
    }
    fn write(&self, stream: ConsoleStream, bytes: &[u8]) -> Result<usize> {
        (self.write)(stream, bytes)
    }
    fn poll(&self, stream: ConsoleStream, events: u16) -> (u16, [u64; 2]) {
        (self.poll)(stream, events)
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.readiness.iter().map(|r| r.subscribe(signal)).collect()
    }
    fn host_work(&self) -> bool {
        self.host
    }
}

#[derive(Default)]
struct Bytes {
    bytes: Vec<u8>,
    consumed: usize,
}
#[derive(Clone, Default)]
pub struct CapturedBytes(Arc<std::sync::Mutex<Bytes>>);
impl CapturedBytes {
    pub fn snapshot(&self) -> Vec<u8> {
        self.0.lock().unwrap().bytes.clone()
    }
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn append(&self, bytes: &[u8]) {
        self.0.lock().unwrap().bytes.extend_from_slice(bytes);
    }
    pub fn read(&self, count: usize) -> Vec<u8> {
        let mut state = self.0.lock().unwrap();
        let start = state.consumed.min(state.bytes.len());
        let end = start + count.min(state.bytes.len() - start);
        let bytes = state.bytes[start..end].to_vec();
        state.consumed = end;
        bytes
    }
}
impl From<Vec<u8>> for CapturedBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Bytes {
            bytes,
            consumed: 0,
        })))
    }
}
impl std::fmt::Debug for CapturedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.lock().unwrap().bytes.fmt(f)
    }
}
impl<const N: usize> PartialEq<[u8; N]> for CapturedBytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0.lock().unwrap().bytes.as_slice() == other
    }
}
impl<const N: usize> PartialEq<&[u8; N]> for CapturedBytes {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.0.lock().unwrap().bytes.as_slice() == *other
    }
}
impl PartialEq<Vec<u8>> for CapturedBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0.lock().unwrap().bytes == *other
    }
}

#[derive(Clone, Default)]
pub struct CapturedConsole {
    pub input: CapturedBytes,
    pub output: CapturedBytes,
    pub error: CapturedBytes,
}
impl ConsoleIo for CapturedConsole {
    fn read(&self, count: usize) -> Result<Vec<u8>> {
        Ok(self.input.read(count))
    }
    fn write(&self, stream: ConsoleStream, bytes: &[u8]) -> Result<usize> {
        match stream {
            ConsoleStream::Input => return Err(Errno(9)),
            ConsoleStream::Output => &self.output,
            ConsoleStream::Error => &self.error,
        }
        .append(bytes);
        Ok(bytes.len())
    }
    fn poll(&self, stream: ConsoleStream, events: u16) -> (u16, [u64; 2]) {
        (
            events & if stream == ConsoleStream::Input { 1 } else { 4 },
            [0; 2],
        )
    }
}

#[derive(Clone)]
pub(super) struct ConsoleEndpoint {
    pub io: Arc<dyn ConsoleIo>,
    pub stream: ConsoleStream,
}
impl ConsoleEndpoint {
    pub fn read(&self, count: usize) -> Result<Vec<u8>> {
        if self.stream != ConsoleStream::Input {
            return Err(Errno(9));
        }
        self.io.read(count)
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        self.io.write(self.stream, bytes)
    }
}
impl Vfs {
    pub fn bind_console(&self, io: Arc<dyn ConsoleIo>) {
        if self.fds.cache().console_bound {
            return;
        }
        let mut changed = false;
        for descriptor in self.fds.entries().values() {
            let open = descriptor.open.borrow();
            let stream = match open.kind {
                FdKind::Stdin => ConsoleStream::Input,
                FdKind::Stdout => ConsoleStream::Output,
                FdKind::Stderr => ConsoleStream::Error,
                _ => continue,
            };
            if open
                .console
                .set(ConsoleEndpoint {
                    io: io.clone(),
                    stream,
                })
                .is_ok()
            {
                changed = true;
            }
        }
        self.fds.cache().console_bound = true;
        if changed {
            FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(unix)]
pub struct NativeConsole {
    files: [std::result::Result<Arc<std::fs::File>, u32>; 3],
    input: std::sync::Mutex<()>,
    revision: [AtomicU64; 3],
}
#[cfg(unix)]
impl NativeConsole {
    pub fn stdio() -> Self {
        use std::os::fd::FromRawFd;
        Self {
            files: std::array::from_fn(|index| {
                // SAFETY: duplicate an existing process descriptor; the resulting
                // File owns only this new descriptor and never changes host flags.
                let fd = unsafe { libc::fcntl(index as i32, libc::F_DUPFD_CLOEXEC, 3) };
                if fd < 0 {
                    Err(storage::host_errno(std::io::Error::last_os_error()).0)
                } else {
                    Ok(Arc::new(unsafe { std::fs::File::from_raw_fd(fd) }))
                }
            }),
            input: Default::default(),
            revision: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    fn index(stream: ConsoleStream) -> usize {
        match stream {
            ConsoleStream::Input => 0,
            ConsoleStream::Output => 1,
            ConsoleStream::Error => 2,
        }
    }
    fn file(&self, stream: ConsoleStream) -> Result<&Arc<std::fs::File>> {
        self.files[Self::index(stream)]
            .as_ref()
            .map_err(|errno| Errno(*errno))
    }
}
#[cfg(unix)]
impl ConsoleIo for NativeConsole {
    fn read(&self, count: usize) -> Result<Vec<u8>> {
        use std::io::Read;
        if count == 0 {
            return Ok(Vec::new());
        }
        let _reader = self.input.lock().unwrap();
        if self.poll(ConsoleStream::Input, 1).0 == 0 {
            return Err(Errno(11));
        }
        let mut bytes = vec![0; count];
        let mut file = &**self.file(ConsoleStream::Input)?;
        let count = file.read(&mut bytes).map_err(storage::host_errno)?;
        bytes.truncate(count);
        self.revision[0].fetch_add(1, Ordering::Relaxed);
        Ok(bytes)
    }
    fn write(&self, stream: ConsoleStream, bytes: &[u8]) -> Result<usize> {
        use std::io::Write;
        if stream == ConsoleStream::Input {
            return Err(Errno(9));
        }
        let mut file = &**self.file(stream)?;
        let count = file.write(bytes).map_err(storage::host_errno)?;
        self.revision[Self::index(stream)].fetch_add(1, Ordering::Relaxed);
        Ok(count)
    }
    fn poll(&self, stream: ConsoleStream, events: u16) -> (u16, [u64; 2]) {
        use std::os::fd::AsRawFd;
        let index = Self::index(stream);
        let epoch = self.revision[index].load(Ordering::Relaxed);
        let Ok(file) = self.file(stream) else {
            return (32, [epoch; 2]);
        };
        let mut fd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: events as i16,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, synchronous zero-timeout query.
        let ready = unsafe { libc::poll(&mut fd, 1, 0) };
        (if ready > 0 { fd.revents as u16 } else { 0 }, [epoch; 2])
    }
    fn native_wait_fds(&self, stream: ConsoleStream) -> Vec<HostFd> {
        self.file(stream)
            .ok()
            .and_then(|file| {
                file.try_clone()
                    .ok()
                    .map(|fd| HostFd::retained(fd.into(), file.clone()))
            })
            .into_iter()
            .collect()
    }
    fn host_work(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_epoll_alias_and_fork_retain_complete_legacy_and_nested_watch_graphs() {
        let mut v = Vfs::default();
        let inner = v.descriptor_factory().epoll_create(0).unwrap();
        let outer = v.descriptor_factory().epoll_create(0).unwrap();
        v.epoll_ctl(inner, 1, 0, 1, 42).unwrap();
        v.epoll_ctl(outer, 1, inner, 1, 77).unwrap();
        let alias = v.dup(outer, 100, false).unwrap();
        let child = v.clone();
        assert_eq!(v.shared_files().close(outer, 1), Some(Ok(())));
        assert_eq!(
            child
                .epoll_wait(alias, 4, |kind, events| Ok(
                    matches!(kind, FdKind::Stdin).then_some(events & 1)
                ))
                .unwrap(),
            vec![(1, 77)]
        );
        assert_eq!(
            v.epoll_wait(inner, 4, |kind, events| Ok(
                matches!(kind, FdKind::Stdin).then_some(events & 1)
            ))
            .unwrap(),
            vec![(1, 42)]
        );
    }
}
