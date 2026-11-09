// SPDX-License-Identifier: GPL-3.0-or-later
//! Host transport for the original embedding PTY. No guest syscall executes here.
use std::{io, sync::Arc, time::Duration};
use trames_linux::{GuestOutput, HostMemoryInfo, HostSpawn, OutputFd, TerminalEvent};
pub use trames_vfs::terminal::Terminal;
use trames_vfs::{Errno, Pty, Vfs};

pub(crate) trait Executor: Send + Sync {
    fn write(&self, work: Write);
}
pub(crate) struct Write {
    pub source: Arc<dyn trames_vfs::ConsoleIo>,
    pub pair: Arc<Pty>,
    pub bytes: Vec<u8>,
    pub offset: usize,
    pub result: Arc<Pending>,
}
impl Write {
    pub(crate) fn run(mut self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.flush()))
            .unwrap_or(Err(Errno(5)));
        self.result
            .complete(self.bytes, self.offset, result.map(|()| 0));
    }
    fn flush(&mut self) -> Result<(), Errno> {
        // Continue on this original I/O worker, not through the host poller for
        // every 4 KiB. Bound one assignment so unrelated native files can run.
        for step in 0..16 {
            let n = self.source.write(
                trames_vfs::ConsoleStream::Output,
                &self.bytes[self.offset..],
            )?;
            if n > self.bytes.len() - self.offset {
                return Err(Errno(5));
            }
            self.offset += n;
            if self.offset != self.bytes.len() || step == 15 {
                return Ok(());
            }
            match self.pair.master_read(4096) {
                Ok(bytes) => {
                    self.bytes = bytes;
                    self.offset = 0;
                }
                Err(Errno(5 | 11)) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        unreachable!()
    }
}
type Reply = (Vec<u8>, usize, Result<usize, Errno>);
pub(crate) struct Pending(std::sync::Mutex<Option<Reply>>, std::thread::Thread);
impl Pending {
    pub(crate) fn complete(&self, bytes: Vec<u8>, offset: usize, result: Result<usize, Errno>) {
        *self.0.lock().unwrap() = Some((bytes, offset, result));
        self.1.unpark();
    }
}

pub(crate) struct Adapter<'a, T: GuestOutput> {
    inner: &'a mut T,
    terminal: Option<Arc<Pty>>,
    output: Vec<u8>,
    consumed: usize,
    console: Option<Arc<dyn trames_vfs::ConsoleIo>>,
    executor: Arc<dyn Executor>,
    pending: Option<Arc<Pending>>,
}
impl<'a, T: GuestOutput> Adapter<'a, T> {
    pub fn new(inner: &'a mut T, terminal: Option<Arc<Pty>>, executor: Arc<dyn Executor>) -> Self {
        let console = terminal.as_ref().map(|_| inner.source_console());
        Self {
            inner,
            terminal,
            output: Vec::new(),
            consumed: 0,
            console,
            executor,
            pending: None,
        }
    }
    fn collect_output(&mut self) -> io::Result<bool> {
        let Some(pending) = &self.pending else {
            return Ok(true);
        };
        let result = pending.0.lock().unwrap().take();
        let Some((bytes, offset, result)) = result else {
            return Ok(false);
        };
        self.pending = None;
        self.output = bytes;
        self.consumed = offset;
        match result {
            Ok(n) if n <= self.output.len() - offset => self.consumed += n,
            Err(Errno(11)) => {}
            Err(error) => return Err(io_error(error)),
            _ => return Err(io::Error::other("invalid terminal output count")),
        }
        Ok(true)
    }
    fn pump(&mut self) -> io::Result<()> {
        let Some(pair) = &self.terminal else {
            return Ok(());
        };
        let mut input = [0; 4096];
        let capacity = pair.terminal.borrow().input_capacity().min(input.len());
        if capacity != 0 {
            match self.inner.poll_stdin(&mut input[..capacity]) {
                Ok(0) => pair.terminal.borrow_mut().eof = true,
                Ok(n) if n <= capacity => {
                    let (written, signals) = pair.master_write(&input[..n]).map_err(io_error)?;
                    debug_assert_eq!(written, n);
                    pair.queue_host_signals(signals);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
                _ => return Err(io::Error::other("invalid terminal input count")),
            }
        }
        for _ in 0..16 {
            match self.inner.terminal_event() {
                Some(TerminalEvent::Resize { rows, columns }) => {
                    pair.resize_from_host(rows, columns)
                }
                Some(TerminalEvent::Signal(signal @ 1..=64)) => {
                    pair.queue_host_signals(vec![signal])
                }
                Some(_) => {}
                None => break,
            }
        }
        pair.flush_echo();
        if !self.collect_output()? {
            return Ok(());
        }
        let pair = self.terminal.as_ref().expect("embedding transport");
        if self.consumed == self.output.len() {
            self.output.clear();
            self.consumed = 0;
            match pair.master_read(4096) {
                Ok(bytes) => self.output = bytes,
                Err(Errno(5 | 11)) => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        if self.consumed != self.output.len() {
            if let Some(console) = self.console.as_ref().filter(|c| c.host_work()) {
                if console.poll(trames_vfs::ConsoleStream::Output, 4).0 != 0 {
                    let result = Arc::new(Pending(Default::default(), std::thread::current()));
                    let work = Write {
                        source: console.clone(),
                        pair: pair.clone(),
                        bytes: std::mem::take(&mut self.output),
                        offset: self.consumed,
                        result: result.clone(),
                    };
                    self.consumed = 0;
                    self.pending = Some(result);
                    self.executor.write(work);
                }
                return Ok(());
            }
            match self
                .inner
                .write(OutputFd::Stdout, &self.output[self.consumed..])
            {
                Ok(n) if n <= self.output.len() - self.consumed => self.consumed += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
                _ => return Err(io::Error::other("invalid terminal output count")),
            }
        }
        Ok(())
    }
    pub fn finish(mut self) -> Option<Terminal> {
        // The original runtime pool has completed its accepted native work.
        let _ = self.collect_output();
        debug_assert!(self.pending.is_none());
        let pair = self.terminal?;
        let mut tty = pair.terminal.borrow_mut();
        // CPUs have stopped. Unwritten accepted host bytes remain first on a
        // resumable Runtime; a guest flush can never discard a later write.
        for &byte in self.output[self.consumed..].iter().rev() {
            tty.output_queue.push_front(byte);
        }
        Some(tty.clone())
    }
}
fn io_error(error: Errno) -> io::Error {
    io::Error::other(error.to_string())
}
impl<T: GuestOutput> GuestOutput for Adapter<'_, T> {
    fn paused(&self) -> bool {
        self.inner.paused()
    }
    fn bind_host_files(
        &mut self,
        executor: Arc<dyn trames_linux::FileExecutor>,
        layouts: Arc<trames_linux::FileLayouts>,
    ) {
        self.inner.bind_host_files(executor, layouts);
    }
    fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
        self.console
            .clone()
            .unwrap_or_else(|| self.inner.source_console())
    }
    fn host_memory_source(&self) -> Option<Arc<dyn Fn() -> HostMemoryInfo + Send + Sync>> {
        self.inner.host_memory_source()
    }
    fn host_memory(&self) -> Option<HostMemoryInfo> {
        self.inner.host_memory()
    }
    fn live_host_processes(&self) -> bool {
        self.inner.live_host_processes()
    }
    fn waits_for_host(&self) -> bool {
        self.terminal.is_some() || self.inner.waits_for_host()
    }
    fn control_poll_interval(&self) -> Duration {
        self.inner
            .control_poll_interval()
            .min(if self.terminal.is_some() {
                Duration::from_millis(2)
            } else {
                Duration::MAX
            })
    }
    fn poll_control(&mut self, vfs: &Vfs) -> io::Result<bool> {
        let join = self.inner.poll_control(vfs)?;
        if !join {
            self.pump()?;
        }
        Ok(join)
    }
    fn control(&mut self, vfs: &mut Vfs) -> io::Result<bool> {
        let running = self.inner.control(vfs)?;
        if running {
            self.pump()?;
        }
        Ok(running)
    }
    fn host_spawn(&mut self) -> Option<HostSpawn> {
        self.inner.host_spawn()
    }
    fn host_signal(&mut self) -> Option<(u32, u32)> {
        self.inner.host_signal()
    }
    fn root_signal(&mut self) -> Option<u32> {
        self.inner.root_signal()
    }
    fn write(&mut self, fd: OutputFd, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(fd, bytes)
    }
    fn read_stdin(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read_stdin(bytes)
    }
    fn poll_stdin(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.poll_stdin(bytes)
    }
    fn stdin_ready(&mut self) -> io::Result<bool> {
        self.inner.stdin_ready()
    }
    fn terminal_event(&mut self) -> Option<TerminalEvent> {
        self.inner.terminal_event()
    }
    fn flush_output(&mut self) -> io::Result<bool> {
        self.pump()?;
        let empty = self.terminal.as_ref().is_none_or(|pair| {
            let tty = pair.terminal.borrow();
            self.pending.is_none()
                && self.consumed == self.output.len()
                && tty.output_queue.is_empty()
                && tty.echo.is_empty()
        });
        Ok(empty && self.inner.flush_output()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};
    struct Unused;
    impl Executor for Unused {
        fn write(&self, _: Write) {
            panic!("non-native callbacks must remain on their host caller");
        }
    }
    struct Host {
        source: Arc<dyn trames_vfs::ConsoleIo>,
        input: Arc<Mutex<VecDeque<u8>>>,
        output: Vec<u8>,
        quota: usize,
        eof: bool,
        replace: Option<Arc<Pty>>,
    }
    impl Default for Host {
        fn default() -> Self {
            Self {
                source: Arc::new(trames_vfs::CapturedConsole::default()),
                input: Default::default(),
                output: Vec::new(),
                quota: usize::MAX,
                eof: false,
                replace: None,
            }
        }
    }
    impl GuestOutput for Host {
        fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
            self.source.clone()
        }
        fn poll_control(&mut self, _: &Vfs) -> io::Result<bool> {
            Ok(false)
        }
        fn write(&mut self, _: OutputFd, bytes: &[u8]) -> io::Result<usize> {
            assert!(
                !self.source.host_work(),
                "blocking native bytes use the original I/O pool"
            );
            let n = bytes.len().min(self.quota);
            self.output.extend_from_slice(&bytes[..n]);
            if let Some(pair) = self.replace.take() {
                let mut tty = pair.terminal.borrow_mut();
                tty.output_queue.clear();
                tty.queue_output(b"Z").unwrap();
            }
            Ok(n)
        }
        fn poll_stdin(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let mut input = self.input.lock().unwrap();
            if input.is_empty() && !self.eof {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = bytes.len().min(input.len());
            for byte in &mut bytes[..n] {
                *byte = input.pop_front().unwrap();
            }
            Ok(n)
        }
    }
    fn terminal() -> (Vfs, Arc<Pty>) {
        let mut vfs = Vfs::default();
        vfs.enable_terminal().unwrap();
        let pair = vfs.embedding_terminal().unwrap();
        (vfs, pair)
    }
    #[test]
    fn partial_host_output_survives_a_guest_flush_and_runtime_handoff_without_losing_new_bytes() {
        let (mut vfs, pair) = terminal();
        pair.terminal.borrow_mut().queue_output(b"abcd").unwrap();
        let mut host = Host {
            quota: 1,
            replace: Some(pair.clone()),
            ..Host::default()
        };
        let mut adapter = Adapter::new(&mut host, Some(pair.clone()), Arc::new(Unused));
        adapter.control(&mut vfs).unwrap();
        let saved = adapter.finish().unwrap();
        assert_eq!(host.output, b"a");
        assert_eq!(
            saved.output_queue.iter().copied().collect::<Vec<_>>(),
            b"bcdZ"
        );
        *pair.terminal.borrow_mut() = saved;
        let mut adapter = Adapter::new(&mut host, Some(pair), Arc::new(Unused));
        for _ in 0..8 {
            if adapter.flush_output().unwrap() {
                break;
            }
        }
        assert!(adapter.flush_output().unwrap());
        adapter.finish();
        assert_eq!(host.output, b"abcdZ");
    }
    #[test]
    fn host_input_eof_is_a_half_close_and_keeps_guest_output_alive() {
        let (mut vfs, pair) = terminal();
        let mut host = Host {
            eof: true,
            ..Host::default()
        };
        let mut adapter = Adapter::new(&mut host, Some(pair.clone()), Arc::new(Unused));
        adapter.control(&mut vfs).unwrap();
        assert!(pair.terminal.borrow().eof);
        assert!(pair.master_alive.load(std::sync::atomic::Ordering::Relaxed));
        pair.terminal
            .borrow_mut()
            .queue_output(b"after-eof")
            .unwrap();
        assert!(adapter.flush_output().unwrap());
        adapter.finish();
        assert_eq!(host.output, b"after-eof");
    }
    #[test]
    fn xoff_and_xon_use_the_original_line_discipline_without_owner_pause() {
        let (mut vfs, pair) = terminal();
        let mut host = Host::default();
        let input = host.input.clone();
        input.lock().unwrap().push_back(19);
        pair.terminal.borrow_mut().queue_output(b"a").unwrap();
        let mut adapter = Adapter::new(&mut host, Some(pair.clone()), Arc::new(Unused));
        assert!(!adapter.poll_control(&vfs).unwrap());
        assert!(pair.terminal.borrow().flow_stopped);
        assert!(!adapter.flush_output().unwrap());
        input.lock().unwrap().push_back(17);
        assert!(!adapter.poll_control(&vfs).unwrap());
        assert!(!pair.terminal.borrow().flow_stopped);
        assert!(adapter.flush_output().unwrap());
        adapter.control(&mut vfs).unwrap();
        adapter.finish();
        assert_eq!(host.output, b"a");
    }
    #[cfg(trames_interpreter_conformance)]
    #[test]
    fn blocking_native_output_keeps_host_control_and_original_input_live_on_the_existing_pool() {
        let (mut vfs, pair) = terminal();
        let (started, entered) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        let output = Arc::new(Mutex::new(Vec::new()));
        let written = output.clone();
        let first = std::sync::atomic::AtomicBool::new(true);
        let source = trames_vfs::ConsoleCallbacks::new(
            |_| Err(Errno(11)),
            move |_, bytes| {
                if first.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    started.send(()).unwrap();
                    released
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                }
                written.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            },
            |_, events| (events & 4, [0; 2]),
        )
        .host();
        let mut host = Host {
            source: Arc::new(source),
            ..Host::default()
        };
        let input = host.input.clone();
        pair.terminal.borrow_mut().queue_output(b"native").unwrap();
        let pool = crate::workers::Pool::<trames_cpu::Cpu>::new(1);
        let mut adapter = Adapter::new(&mut host, Some(pair.clone()), pool.terminal_executor());
        adapter.control(&mut vfs).unwrap();
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        input.lock().unwrap().extend(b"x\n");
        assert!(!adapter.poll_control(&vfs).unwrap());
        assert_eq!(pair.terminal.borrow_mut().read(2).unwrap(), b"x\n");
        release.send(()).unwrap();
        drop(pool);
        let saved = adapter.finish().unwrap();
        assert!(saved.output_queue.is_empty());
        assert_eq!(*output.lock().unwrap(), b"nativex\r\n");
    }
}
