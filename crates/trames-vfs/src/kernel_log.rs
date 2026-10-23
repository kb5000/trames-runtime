// SPDX-License-Identifier: GPL-3.0-or-later
//! Session-scoped log shared by virtual processes, never stored in the disk manifest.
use super::*;
use std::time::{Duration, Instant};

pub const LOG_CAPACITY: usize = 256 * 1024;
const MAX_MESSAGE: usize = 1024;
const RECORDS_PER_SECOND: u32 = 64;
/// A session resource, independently shared by VFS handles, kmsg descriptors
/// and executing workers. The mutex covers only this bounded log, not the VFS.
#[derive(Default)]
pub(super) struct KernelLog {
    state: std::sync::Mutex<LogState>,
    readiness: Arc<readiness::Readiness>,
}
#[derive(Clone, Default)]
pub struct KernelLogAccess {
    log: Arc<KernelLog>,
    authorized: bool,
}
impl KernelLogAccess {
    pub fn syslog(&self, action: u32, count: usize) -> Result<Vec<u8>> {
        self.log.syslog(action, count, self.authorized)
    }
    pub fn size(&self, action: u32) -> Result<u64> {
        self.log.size(action, self.authorized)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.log.readiness.subscribe(signal)
    }
}
impl KernelLog {
    pub(super) fn append(&self, priority: u32, message: &str) {
        let mut state = self.state.lock().unwrap();
        let before = state.next;
        state.append(priority, message);
        let changed = state.next != before;
        drop(state);
        if changed {
            self.readiness.notify_locked();
        }
    }
    pub(super) fn oldest(&self) -> u64 {
        self.state.lock().unwrap().oldest()
    }
    #[cfg(test)]
    fn kmsg_read(&self, cursor: &mut u64, count: usize) -> Result<Vec<u8>> {
        self.state.lock().unwrap().kmsg_read(cursor, count)
    }
    fn syslog(&self, action: u32, count: usize, authorized: bool) -> Result<Vec<u8>> {
        if action > 10 {
            return Err(Errno(22));
        }
        if !authorized {
            return Err(Errno(1));
        }
        if matches!(action, 0 | 1) {
            return Ok(Vec::new());
        }
        let mut log = self.state.lock().unwrap();
        match action {
            2 => log.stream_read(count),
            3 => Ok(log.snapshot(count)),
            4 => {
                // Snapshot and clear form one transaction with concurrent
                // writers; no record arriving afterwards is cleared unseen.
                let data = log.snapshot(count);
                log.clear();
                Ok(data)
            }
            5 => {
                log.clear();
                Ok(Vec::new())
            }
            _ => Err(Errno(22)),
        }
    }
    fn size(&self, action: u32, authorized: bool) -> Result<u64> {
        if !authorized {
            return Err(Errno(1));
        }
        match action {
            9 => Ok(self.state.lock().unwrap().unread() as u64),
            10 => Ok(LOG_CAPACITY as u64),
            _ => Err(Errno(22)),
        }
    }
}
/// Per-open kmsg cursor. Dup/fork share this object, independent opens do not.
/// Cursor transactions use the log lock, including overrun recovery and seek;
/// the atomic supplies shared storage, not a second synchronization protocol.
pub(super) struct Kmsg {
    log: Arc<KernelLog>,
    cursor: AtomicU64,
    seek_epoch: AtomicU64,
}
impl Kmsg {
    pub(super) fn new(log: Arc<KernelLog>) -> Arc<Self> {
        let cursor = AtomicU64::new(log.oldest());
        Arc::new(Self {
            log,
            cursor,
            seek_epoch: AtomicU64::new(0),
        })
    }
    pub(super) fn same_log(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.log, &other.log)
    }
    pub(super) fn position(&self) -> u64 {
        self.cursor.load(Ordering::Relaxed)
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.log.readiness.subscribe(signal)
    }
    pub(super) fn read(&self, count: usize) -> Result<Vec<u8>> {
        let state = self.log.state.lock().unwrap();
        let mut cursor = self.cursor.load(Ordering::Relaxed);
        let result = state.kmsg_read(&mut cursor, count);
        self.cursor.store(cursor, Ordering::Relaxed);
        result
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<usize> {
        if bytes.len() > 1024 {
            return Err(Errno(22));
        }
        if !bytes.is_empty() {
            self.log.append(14, &String::from_utf8_lossy(bytes));
        }
        Ok(bytes.len())
    }
    pub(super) fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        let state = self.log.state.lock().unwrap();
        let cursor = state.seek(offset, whence)?;
        let changed = self.cursor.swap(cursor, Ordering::Relaxed) != cursor;
        if changed {
            self.seek_epoch.fetch_add(1, Ordering::Relaxed);
        }
        drop(state);
        if changed {
            self.log.readiness.notify_locked();
        }
        Ok(0)
    }
    pub(super) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let state = self.log.state.lock().unwrap();
        (
            state.poll(self.cursor.load(Ordering::Relaxed), events),
            [
                state
                    .next
                    .wrapping_add(self.seek_epoch.load(Ordering::Relaxed)),
                0,
            ],
        )
    }
}
struct Record {
    sequence: u64,
    text: Vec<u8>,
    kmsg: Vec<u8>,
}
struct LogState {
    started: Instant,
    window: Instant,
    emitted: u32,
    suppressed: u64,
    records: VecDeque<Record>,
    bytes: usize,
    next: u64,
    cleared: u64,
    stream: u64,
    stream_offset: usize,
}
impl Default for LogState {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            window: Instant::now(),
            emitted: 0,
            suppressed: 0,
            records: VecDeque::new(),
            bytes: 0,
            next: 0,
            cleared: 0,
            stream: 0,
            stream_offset: 0,
        }
    }
}
impl LogState {
    pub(super) fn oldest(&self) -> u64 {
        self.records.front().map_or(self.next, |r| r.sequence)
    }
    pub(super) fn append(&mut self, priority: u32, message: &str) {
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.emitted = 0;
            if self.suppressed != 0 {
                let message = format!("log rate limit: suppressed {} messages", self.suppressed);
                self.suppressed = 0;
                self.insert(4, &message);
            }
        }
        if self.emitted >= RECORDS_PER_SECOND {
            self.suppressed = self.suppressed.saturating_add(1);
            return;
        }
        self.emitted += 1;
        self.insert(priority, message);
    }
    fn insert(&mut self, priority: u32, message: &str) {
        let mut escaped = String::new();
        for c in message.chars() {
            let piece = if c.is_control() {
                format!("\\u{{{:x}}}", c as u32)
            } else {
                c.to_string()
            };
            if escaped.len() + piece.len() > MAX_MESSAGE {
                break;
            }
            escaped.push_str(&piece);
        }
        let micros = self.started.elapsed().as_micros();
        let text = format!(
            "<{priority}>[{}.{:06}] {escaped}\n",
            micros / 1_000_000,
            micros % 1_000_000
        )
        .into_bytes();
        let kmsg = format!("{priority},{},{micros},-;{escaped}\n", self.next).into_bytes();
        self.bytes += text.len() + kmsg.len();
        self.records.push_back(Record {
            sequence: self.next,
            text,
            kmsg,
        });
        self.next += 1;
        while self.bytes > LOG_CAPACITY {
            let r = self.records.pop_front().expect("nonempty log");
            self.bytes -= r.text.len() + r.kmsg.len();
        }
    }
    pub(super) fn kmsg_read(&self, cursor: &mut u64, count: usize) -> Result<Vec<u8>> {
        if *cursor < self.oldest() {
            *cursor = self.oldest();
            return Err(Errno(32));
        }
        let r = self
            .records
            .iter()
            .find(|r| r.sequence == *cursor)
            .ok_or(Errno(11))?;
        if count < r.kmsg.len() {
            return Err(Errno(22));
        }
        *cursor += 1;
        Ok(r.kmsg.clone())
    }
    pub(super) fn seek(&self, offset: i64, whence: u32) -> Result<u64> {
        if offset != 0 {
            return Err(Errno(22));
        }
        match whence {
            0 => Ok(self.oldest()),
            2 => Ok(self.next),
            3 => Ok(self.cleared.max(self.oldest())),
            _ => Err(Errno(22)),
        }
    }
    pub(super) fn poll(&self, cursor: u64, events: u16) -> u16 {
        (if cursor < self.next { events & 1 } else { 0 })
            | (if cursor < self.oldest() { 8 } else { 0 })
            | (events & 4)
    }
    pub(super) fn snapshot(&self, count: usize) -> Vec<u8> {
        let bytes: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.sequence >= self.cleared)
            .flat_map(|r| r.text.iter().copied())
            .collect();
        bytes[bytes.len().saturating_sub(count)..].to_vec()
    }
    pub(super) fn clear(&mut self) {
        self.cleared = self.next;
    }
    fn normalize_stream(&mut self) {
        if self.stream < self.oldest() {
            self.stream = self.oldest();
            self.stream_offset = 0;
        }
    }
    pub(super) fn unread(&mut self) -> usize {
        self.normalize_stream();
        self.records
            .iter()
            .filter(|r| r.sequence >= self.stream)
            .map(|r| r.text.len())
            .sum::<usize>()
            .saturating_sub(self.stream_offset)
    }
    pub(super) fn stream_read(&mut self, count: usize) -> Result<Vec<u8>> {
        self.normalize_stream();
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.unread() == 0 {
            return Err(Errno(11));
        }
        let mut bytes = Vec::new();
        let start = self.stream;
        for r in self.records.iter().filter(|r| r.sequence >= start) {
            let take = (count - bytes.len()).min(r.text.len() - self.stream_offset);
            bytes.extend_from_slice(&r.text[self.stream_offset..self.stream_offset + take]);
            self.stream_offset += take;
            if self.stream_offset == r.text.len() {
                self.stream = r.sequence + 1;
                self.stream_offset = 0;
            }
            if bytes.len() == count {
                break;
            }
        }
        Ok(bytes)
    }
}
impl Vfs {
    /// Cold scheduling hint for a legacy stream waiter without a kmsg FD.
    /// Merely sharing a session log must not divert unrelated solo CPU work.
    pub fn can_write_kernel_log_for(&self, reader: &Self) -> bool {
        Arc::ptr_eq(&self.kernel_log, &reader.kernel_log)
            && self.fds.entries().values().any(|d| {
                let open = d.open.borrow();
                open.kernel_log.is_some() && open.flags.get() & 3 != 0
            })
    }
    pub fn log(&self, priority: u32, message: &str) {
        self.kernel_log.append(priority, message);
    }
    pub fn log_syscall(&self, number: u64, pc: u64, args: [u64; 6], errno: u32, comm: &[u8]) {
        self.log(
            4,
            &format!(
                "pid={} syscall={}({}) pc={:#x} args={:x?} unsupported errno={errno} comm={:?}",
                self.pid,
                number,
                syscall_names::name(number),
                pc,
                args,
                String::from_utf8_lossy(&comm[..comm.len().min(15)])
            ),
        );
    }
    /// Authority is sampled only for an immutable worker epoch; credential or
    /// namespace changes still join before a replacement capability is issued.
    pub fn kernel_log_capability(&self) -> KernelLogAccess {
        KernelLogAccess {
            log: self.kernel_log.clone(),
            authorized: self.credentials.has_cap(capabilities::SYSLOG),
        }
    }
    /// syscall 116 klogctl: reading and clearing require guest CAP_SYSLOG.
    pub fn syslog(&self, action: u32, count: usize) -> Result<Vec<u8>> {
        self.kernel_log.syslog(
            action,
            count,
            self.credentials.has_cap(capabilities::SYSLOG),
        )
    }
    pub fn syslog_size(&self, action: u32) -> Result<u64> {
        self.kernel_log
            .size(action, self.credentials.has_cap(capabilities::SYSLOG))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kmsg_cursor_transactions_are_shared_with_owner_and_epoll() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        let fd = v.open_at(AT_FDCWD, b"/dev/kmsg", O_NONBLOCK, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let independent = v.open_at(AT_FDCWD, b"/dev/kmsg", O_NONBLOCK, 0).unwrap();
        let ep = v.epoll_create(0).unwrap();
        v.epoll_ctl(ep, 1, fd, 0x80000001, 42).unwrap();
        let fds = v.direct_descriptors();
        for i in 0..32 {
            v.log(4, &format!("cursor-{i}"));
        }
        let first = v.read(independent, 2048).unwrap();
        let records = std::thread::scope(|scope| {
            let mut readers = Vec::new();
            for reader in [fd, alias] {
                let resource = fds.get(reader).unwrap().clone();
                readers.push(scope.spawn(move || {
                    let mut records = Vec::new();
                    loop {
                        match resource.read(2048) {
                            Ok(record) => records.push(record),
                            Err(Errno(11)) => break,
                            other => panic!("unexpected kmsg result: {other:?}"),
                        }
                    }
                    records
                }));
            }
            readers
                .into_iter()
                .flat_map(|r| r.join().unwrap())
                .collect::<Vec<_>>()
        });
        let unique: std::collections::BTreeSet<_> = records.iter().collect();
        assert_eq!((records.len(), unique.len()), (32, 32));
        assert!(unique.contains(&first));
        assert_eq!(v.read(fd, 2048), Err(Errno(11)));
        assert_eq!(v.poll(independent, 1), 1);
        assert!(fds.get(ep).unwrap().epoll_wait(1).unwrap().is_empty());
        assert_eq!(fds.get(alias).unwrap().kmsg_seek(0, 0), Ok(0));
        assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), vec![(1, 42)]);
        assert!(fds.get(ep).unwrap().epoll_wait(1).unwrap().is_empty());
        assert_eq!(v.read(fd, 2048).unwrap(), first);
        v.log(4, "new-edge-without-draining");
        assert_eq!(fds.get(ep).unwrap().epoll_wait(1).unwrap(), vec![(1, 42)]);
        assert!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
        assert_eq!(fds.get(fd).unwrap().write(b"forbidden"), Err(Errno(9)));
        assert_eq!(fds.get(fd).unwrap().kmsg_seek(1, 0), Err(Errno(22)));
        let mut observer = v.clone();
        observer.close(fd).unwrap();
        observer.close(alias).unwrap();
        let _old = observer.direct_descriptors();
        v.close(fd).unwrap();
        v.close(alias).unwrap();
        v.log(4, "closed-watch");
        assert!(observer
            .direct_descriptors()
            .get(ep)
            .unwrap()
            .epoll_wait(1)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn concurrent_append_and_read_clear_do_not_lose_or_duplicate_records() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<KernelLogAccess>();
        let log = Arc::new(KernelLog::default());
        let gate = Arc::new(std::sync::Barrier::new(3));
        let mut received = std::thread::scope(|scope| {
            for writer in 0..2 {
                let log = log.clone();
                let gate = gate.clone();
                scope.spawn(move || {
                    gate.wait();
                    for i in 0..16 {
                        log.append(4, &format!("record-{writer}-{i}"));
                    }
                });
            }
            gate.wait();
            let mut received = Vec::new();
            for _ in 0..16 {
                received.extend(log.syslog(4, LOG_CAPACITY, true).unwrap());
            }
            // All writers are joined before the last collection below.
            received
        });
        received.extend(log.syslog(4, LOG_CAPACITY, true).unwrap());
        let text = String::from_utf8(received).unwrap();
        let records: Vec<_> = text
            .lines()
            .map(|line| line.split_once("] ").unwrap().1)
            .collect();
        let unique: std::collections::BTreeSet<_> = records.iter().copied().collect();
        assert_eq!(records.len(), 32);
        assert_eq!(unique.len(), 32);
        for writer in 0..2 {
            for i in 0..16 {
                assert!(unique.contains(format!("record-{writer}-{i}").as_str()));
            }
        }
        assert!(log.syslog(3, LOG_CAPACITY, true).unwrap().is_empty());
        // READ_CLEAR does not consume the separate legacy stream or kmsg.
        assert!(log.size(9, true).unwrap() > 0);
        assert!(log.kmsg_read(&mut 0, 2048).is_ok());
    }
    #[test]
    fn worker_log_capability_survives_vfs_drop_with_epoch_authority() {
        let mut v = Vfs::default();
        v.log(4, "retained worker diagnostic");
        let authorized = v.kernel_log_capability();
        v.credentials = Credentials::user(1000, 1000);
        let denied = v.kernel_log_capability();
        let weak = Arc::downgrade(&v.kernel_log);
        drop(v);
        std::thread::spawn(move || {
            assert_eq!(denied.syslog(5, 0), Err(Errno(1)));
            assert_eq!(denied.size(10), Err(Errno(1)));
            let bytes = authorized.syslog(4, LOG_CAPACITY).unwrap();
            assert!(String::from_utf8(bytes)
                .unwrap()
                .contains("retained worker diagnostic"));
            assert!(authorized.syslog(3, LOG_CAPACITY).unwrap().is_empty());
        })
        .join()
        .unwrap();
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn independent_readers_dup_clear_and_user_permissions() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v.log(4, "diagnostic\nforged line");
        let fd = v.open_at(AT_FDCWD, b"/dev/kmsg", O_NONBLOCK, 0).unwrap();
        let other = v.open_at(AT_FDCWD, b"/dev/kmsg", O_NONBLOCK, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        assert_eq!(v.read(fd, 1), Err(Errno(22)));
        let record = v.read(alias, 2048).unwrap();
        assert!(record.windows(8).any(|w| w == b"\\u{a}for"));
        assert_eq!(v.read(fd, 2048), Err(Errno(11)));
        assert_eq!(v.read(other, 2048).unwrap(), record);
        assert_eq!(v.poll(fd, 1), 0);
        let child = v.clone();
        child.log(4, "child log");
        assert_eq!(v.poll(fd, 1), 1);
        assert!(!v.syslog(4, LOG_CAPACITY).unwrap().is_empty());
        assert!(v.syslog(3, LOG_CAPACITY).unwrap().is_empty());
        // Clear only affects snapshots, not independent kmsg readers or legacy stream.
        assert!(!v.read(fd, 2048).unwrap().is_empty());
        assert!(v.syslog_size(9).unwrap() > 0);
        v.seek(fd, 0, 2).unwrap();
        assert_eq!(v.read(fd, 2048), Err(Errno(11)));
        assert_eq!(v.pread(fd, 10, 0), Err(Errno(29)));
        assert_eq!(v.seek(fd, 1, 0), Err(Errno(22)));
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(v.syslog(3, 4096), Err(Errno(1)));
        assert_eq!(v.open_at(AT_FDCWD, b"/dev/kmsg", 0, 0), Err(Errno(13)));
    }
    #[test]
    fn bounded_log_overrun_stream_progress_and_rate_limit() {
        let mut log = LogState::default();
        for _ in 0..500 {
            log.insert(4, &"x".repeat(1024));
        }
        assert!(log.bytes <= LOG_CAPACITY);
        let mut cursor = 0;
        assert_eq!(log.kmsg_read(&mut cursor, 2048), Err(Errno(32)));
        assert_eq!(cursor, log.oldest());
        assert!(log.kmsg_read(&mut cursor, 2048).is_ok());
        let before = log.unread();
        assert_eq!(log.stream_read(3).unwrap().len(), 3);
        assert_eq!(log.unread(), before - 3);
        for _ in 0..100 {
            log.append(4, "repeated unsupported call");
        }
        assert_eq!(log.suppressed, 36);
        log.window -= Duration::from_secs(2);
        log.append(4, "next diagnostic");
        let text = String::from_utf8(log.snapshot(LOG_CAPACITY)).unwrap();
        assert!(text.contains("suppressed 36 messages"));
        assert_eq!(log.suppressed, 0);
    }
}
