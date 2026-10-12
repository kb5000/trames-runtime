// SPDX-License-Identifier: GPL-3.0-or-later
//! Session-scoped log shared by virtual processes, never stored in the disk manifest.
use super::*;
use std::time::{Duration, Instant};

pub const LOG_CAPACITY: usize = 256 * 1024;
const MAX_MESSAGE: usize = 1024;
const RECORDS_PER_SECOND: u32 = 64;
struct Record {
    sequence: u64,
    text: Vec<u8>,
    kmsg: Vec<u8>,
}
pub(super) struct KernelLog {
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
impl Default for KernelLog {
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
impl KernelLog {
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
    pub fn log(&self, priority: u32, message: &str) {
        self.kernel_log.borrow_mut().append(priority, message);
    }
    pub fn log_syscall(&self, number: u64, pc: u64, args: [u64; 6], errno: u32) {
        self.log(
            4,
            &format!(
                "pid={} syscall={}({}) pc={:#x} args={:x?} unsupported errno={errno}",
                self.pid,
                number,
                syscall_names::name(number),
                pc,
                args
            ),
        );
    }
    /// syscall 116 klogctl: reading and clearing require virtual root.
    pub fn syslog(&self, action: u32, count: usize) -> Result<Vec<u8>> {
        if action > 10 {
            return Err(Errno(22));
        }
        if self.credentials.euid != 0 {
            return Err(Errno(1));
        }
        let mut log = self.kernel_log.borrow_mut();
        match action {
            0 | 1 => Ok(Vec::new()),
            2 => log.stream_read(count),
            3 => Ok(log.snapshot(count)),
            4 => {
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
    pub fn syslog_size(&self, action: u32) -> Result<u64> {
        if self.credentials.euid != 0 {
            return Err(Errno(1));
        }
        match action {
            9 => Ok(self.kernel_log.borrow_mut().unread() as u64),
            10 => Ok(LOG_CAPACITY as u64),
            _ => Err(Errno(22)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut log = KernelLog::default();
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
