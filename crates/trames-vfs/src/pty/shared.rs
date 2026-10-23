// SPDX-License-Identifier: GPL-3.0-or-later
//! Only the terminal and endpoint state cross the worker boundary. Namespace,
//! devpts nodes, FD ownership and signal delivery stay with their owners.
use super::*;
use crate::readiness::Readiness;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU8},
    Mutex, MutexGuard,
};

/// Frozen process authority; session/group and controlling-TTY changes join.
#[derive(Clone, Copy)]
pub struct TerminalAccess {
    pub session: u32,
    pub group: u32,
    pub controlling: Option<u32>,
    pub ignore_ttou: bool,
}

pub struct TerminalLock {
    data: Mutex<Terminal>,
    pub(super) readiness: Arc<Readiness>,
}
pub struct TerminalGuard<'a> {
    guard: Option<MutexGuard<'a, Terminal>>,
    source: &'a TerminalLock,
    before: ([u64; 4], bool),
}
fn epochs(tty: &Terminal) -> ([u64; 4], bool) {
    (
        [
            tty.input_epoch,
            tty.input_space_epoch,
            tty.output_epoch,
            tty.output_space_epoch,
        ],
        tty.eof,
    )
}
impl TerminalLock {
    fn new(tty: Terminal) -> Self {
        Self {
            data: Mutex::new(tty),
            readiness: Arc::default(),
        }
    }
    pub fn borrow(&self) -> TerminalGuard<'_> {
        self.borrow_mut()
    }
    pub fn borrow_mut(&self) -> TerminalGuard<'_> {
        let guard = self.data.lock().unwrap();
        let before = epochs(&guard);
        TerminalGuard {
            guard: Some(guard),
            source: self,
            before,
        }
    }
}
impl std::ops::Deref for TerminalGuard<'_> {
    type Target = Terminal;
    fn deref(&self) -> &Terminal {
        self.guard.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for TerminalGuard<'_> {
    fn deref_mut(&mut self) -> &mut Terminal {
        self.guard.as_mut().unwrap()
    }
}
impl Drop for TerminalGuard<'_> {
    fn drop(&mut self) {
        let changed = epochs(self.guard.as_ref().unwrap()) != self.before;
        drop(self.guard.take());
        // A callback may poll/read this very PTY; never notify under its lock.
        if changed {
            self.source.readiness.notify_locked();
        }
    }
}

pub struct PtyIo {
    pub id: u32,
    pub terminal: TerminalLock,
    pub master_alive: AtomicBool,
    pub slaves: AtomicU32,
    pub(super) slave_opened: AtomicBool,
    pub packet: AtomicBool,
    pub packet_status: AtomicU8,
}

/// The real slave open, independent of its owner-side inode/mount projection.
/// Aliases clone this Arc; independently opening a slave creates another end.
/// Byte/poll snapshots keep only PtyIo and never count as slave opens.
pub struct PtySlaveEndpoint {
    io: Arc<PtyIo>,
}
impl PtySlaveEndpoint {
    pub(super) fn open(io: Arc<PtyIo>) -> Arc<Self> {
        io.slaves.fetch_add(1, Ordering::Relaxed);
        io.slave_opened.store(true, Ordering::Relaxed);
        io.notify();
        Arc::new(Self { io })
    }
}
impl Drop for PtySlaveEndpoint {
    fn drop(&mut self) {
        self.io.slaves.fetch_sub(1, Ordering::Relaxed);
        // No terminal, inode or namespace lock is held during notification.
        self.io.notify();
    }
}
impl PtyIo {
    pub(crate) fn new(id: u32, tty: Terminal) -> Self {
        Self {
            id,
            terminal: TerminalLock::new(tty),
            master_alive: AtomicBool::new(true),
            slaves: AtomicU32::new(0),
            slave_opened: AtomicBool::new(false),
            packet: AtomicBool::new(false),
            packet_status: AtomicU8::new(0),
        }
    }
    pub(crate) fn subscribe(&self, signal: &Arc<crate::IoSignal>) -> crate::IoSubscription {
        self.terminal.readiness.subscribe(signal)
    }
    pub(crate) fn notify(&self) {
        self.terminal.readiness.notify_locked();
    }
    pub fn master_read(&self, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let packet = self.packet.load(Ordering::Relaxed);
        if packet {
            let status = self.packet_status.swap(0, Ordering::Relaxed);
            if status != 0 {
                self.notify();
                return Ok(vec![status]);
            }
        }
        let mut tty = self.terminal.borrow_mut();
        if tty.output_queue.is_empty() {
            return Err(Errno(
                if self.slave_opened.load(Ordering::Relaxed)
                    && self.slaves.load(Ordering::Relaxed) == 0
                {
                    5
                } else {
                    11
                },
            ));
        }
        let mut bytes = Vec::new();
        if packet {
            bytes.push(0);
        }
        let take = (count - bytes.len()).min(tty.output_queue.len());
        bytes.extend(tty.drain_output(take));
        Ok(bytes)
    }
    fn poll_locked(&self, tty: &Terminal, master: bool, events: u16) -> u16 {
        if master {
            let status = self.packet.load(Ordering::Relaxed)
                && self.packet_status.load(Ordering::Relaxed) != 0;
            (if !tty.output_queue.is_empty() || status {
                events & 1
            } else {
                0
            }) | (if status { events & 2 } else { 0 })
                | (if tty.input_capacity() != 0 {
                    events & 4
                } else {
                    0
                })
                | (if self.slave_opened.load(Ordering::Relaxed)
                    && self.slaves.load(Ordering::Relaxed) == 0
                {
                    16
                } else {
                    0
                })
        } else {
            let alive = self.master_alive.load(Ordering::Relaxed);
            (if tty.readable() || !alive {
                events & 1
            } else {
                0
            }) | (if tty.output_queue.len() < PIPE_CAPACITY && alive {
                events & 4
            } else {
                0
            }) | (if !alive { 16 | 8 } else { 0 })
        }
    }
    pub fn poll(&self, master: bool, events: u16) -> u16 {
        self.poll_state(master, events).0
    }
    pub(crate) fn poll_state(&self, master: bool, events: u16) -> (u16, [u64; 2]) {
        let tty = self.terminal.borrow();
        (
            self.poll_locked(&tty, master, events),
            if master {
                [tty.output_epoch, tty.input_space_epoch]
            } else {
                [tty.input_epoch, tty.output_space_epoch]
            },
        )
    }
    pub(crate) fn poll_epoch(&self, master: bool) -> [u64; 2] {
        self.poll_state(master, 0).1
    }
    fn flush_echo_locked(tty: &mut Terminal) {
        let echo = std::mem::take(&mut tty.echo);
        let count = tty.queue_output(&echo).unwrap_or(0);
        tty.echo = echo[count..].to_vec();
    }
    pub fn flush_echo(&self) {
        Self::flush_echo_locked(&mut self.terminal.borrow_mut());
    }
    fn input_locked(&self, tty: &mut Terminal, bytes: &[u8]) -> Result<(usize, Vec<u32>)> {
        let count = bytes.len().min(tty.input_capacity());
        if count == 0 && !bytes.is_empty() {
            return Err(Errno(11));
        }
        let stopped = tty.flow_stopped;
        let signals = tty.input(&bytes[..count]);
        if stopped != tty.flow_stopped {
            tty.output_epoch = tty.output_epoch.wrapping_add(1);
            self.packet_status
                .fetch_or(if tty.flow_stopped { 4 } else { 8 }, Ordering::Relaxed);
        }
        Self::flush_echo_locked(tty);
        Ok((count, signals))
    }
    /// Owner input also uses this operation, then delivers the returned signals.
    pub fn master_write(&self, bytes: &[u8]) -> Result<(usize, Vec<u32>)> {
        self.input_locked(&mut self.terminal.borrow_mut(), bytes)
    }
    fn background(&self, tty: &Terminal, access: TerminalAccess) -> bool {
        access.controlling == Some(self.id)
            && access.session == tty.session
            && access.group != tty.foreground
    }
    pub(crate) fn read(
        &self,
        master: bool,
        count: usize,
        access: Option<TerminalAccess>,
    ) -> Option<Result<Vec<u8>>> {
        if master {
            return Some(self.master_read(count));
        }
        let mut tty = self.terminal.borrow_mut();
        if count == 0 || !self.master_alive.load(Ordering::Relaxed) {
            return Some(Ok(Vec::new()));
        }
        if self.background(&tty, access?) {
            return None;
        }
        Some(tty.read(count))
    }
    pub(crate) fn write(
        &self,
        master: bool,
        bytes: &[u8],
        access: Option<TerminalAccess>,
    ) -> Option<Result<usize>> {
        let mut tty = self.terminal.borrow_mut();
        if master {
            let count = bytes.len().min(tty.input_capacity());
            // Check the entire accepted prefix before modifying input or echo.
            // Control-C/Z and other terminal signals still use kernel authority.
            if tty.lflag() & 1 != 0
                && bytes[..count]
                    .iter()
                    .any(|&c| tty.input_signal(c).is_some())
            {
                return None;
            }
            return Some(self.input_locked(&mut tty, bytes).map(|(count, _)| count));
        }
        if !self.master_alive.load(Ordering::Relaxed) {
            return Some(Err(Errno(5)));
        }
        let access = access?;
        if tty.lflag() & 256 != 0 && !access.ignore_ttou && self.background(&tty, access) {
            return None;
        }
        Some(tty.queue_output(bytes))
    }
    pub(crate) fn readable_bytes(&self, master: bool) -> usize {
        let tty = self.terminal.borrow();
        if master {
            tty.output_queue.len()
        } else {
            tty.available()
        }
    }
    pub(crate) fn query(&self, request: u32) -> Option<Vec<u8>> {
        let tty = self.terminal.borrow();
        match request {
            0x5401 => Some(tty.attributes.to_vec()),
            0x5413 => Some(tty.window.to_vec()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    fn access(group: u32) -> TerminalAccess {
        TerminalAccess {
            session: 1,
            group,
            controlling: Some(17),
            ignore_ttou: false,
        }
    }
    #[test]
    fn background_terminal_calls_defer_without_consuming_bytes() {
        let io = PtyIo::new(17, Terminal::default());
        assert_eq!(io.write(true, b"line\n", None), Some(Ok(5)));
        assert_eq!(io.read(false, 16, Some(access(2))), None);
        assert_eq!(io.read(false, 0, Some(access(2))), Some(Ok(vec![])));
        assert_eq!(
            io.read(false, 16, Some(access(1))),
            Some(Ok(b"line\n".to_vec()))
        );
        io.terminal.borrow_mut().attributes[13] |= 1; // TOSTOP
        let before = io.terminal.borrow().output_queue.len();
        assert_eq!(io.write(false, b"background", Some(access(2))), None);
        assert_eq!(io.terminal.borrow().output_queue.len(), before);
        let mut ignored = access(2);
        ignored.ignore_ttou = true;
        assert_eq!(io.write(false, b"ignored", Some(ignored)), Some(Ok(7)));
        assert_eq!(io.write(false, b"no-authority", None), None);
        let mut foreign = access(2);
        foreign.session = 2;
        assert_eq!(io.write(false, b"foreign", Some(foreign)), Some(Ok(7)));
    }
    #[test]
    fn signal_input_defers_the_whole_prefix_then_owner_delivers_it_once() {
        let io = PtyIo::new(17, Terminal::default());
        assert_eq!(io.write(true, b"discard\x03after\n", None), None);
        let tty = io.terminal.borrow();
        assert_eq!(tty.input_epoch, 0);
        assert_eq!(tty.input_capacity(), 65536);
        assert!(tty.echo.is_empty() && tty.output_queue.is_empty());
        drop(tty);
        assert_eq!(io.master_write(b"discard\x03after\n"), Ok((14, vec![2])));
        assert_eq!(
            io.read(false, 16, Some(access(1))),
            Some(Ok(b"after\n".to_vec()))
        );
        // Flow control takes precedence if a signal character is remapped to it.
        io.terminal.borrow_mut().attributes[17] = 19;
        assert_eq!(io.write(true, &[19], None), Some(Ok(1)));
        io.terminal.borrow_mut().attributes[17] = b'\n';
        assert_eq!(io.write(true, b"\r", None), None); // ICRNL
    }
    #[test]
    fn worker_packet_flow_and_output_translation_use_the_original_discipline() {
        let io = PtyIo::new(17, Terminal::default());
        io.packet.store(true, Ordering::Relaxed);
        assert_eq!(io.write(true, &[19], None), Some(Ok(1)));
        assert_eq!(io.poll(true, 3) & 3, 3);
        assert_eq!(io.master_read(1), Ok(vec![4]));
        assert_eq!(io.write(true, &[17], None), Some(Ok(1)));
        assert_eq!(io.master_read(1), Ok(vec![8]));
        assert_eq!(io.write(false, b"a\nb", Some(access(1))), Some(Ok(3)));
        assert_eq!(io.master_read(16), Ok(b"\0a\r\nb".to_vec()));
        assert_eq!(io.master_read(1), Err(Errno(11)));
    }
    struct Target {
        io: Arc<PtyIo>,
        calls: AtomicUsize,
    }
    impl crate::IoWake for Target {
        fn wake_io(&self, _: &Arc<crate::IoSignal>) {
            // Re-enter the notifying terminal. A notification under lock hangs.
            self.io.poll(false, 5);
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn terminal_notifications_allow_reentry_and_wake_both_endpoints() {
        let io = Arc::new(PtyIo::new(17, Terminal::default()));
        let target = Arc::new(Target {
            io: io.clone(),
            calls: AtomicUsize::new(0),
        });
        let erased: Arc<dyn crate::IoWake> = target.clone();
        let signal = crate::IoSignal::new(1, Arc::downgrade(&erased));
        let _subscription = io.subscribe(&signal);
        io.write(true, b"x\n", None).unwrap().unwrap();
        assert!(signal.ready());
        signal.reset();
        io.read(false, 2, Some(access(1))).unwrap().unwrap();
        assert!(signal.ready());
        signal.reset();
        io.master_read(16).unwrap();
        assert!(signal.ready());
        assert_eq!(target.calls.load(Ordering::Relaxed), 3);
    }
}
