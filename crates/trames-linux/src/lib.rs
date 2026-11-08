// SPDX-License-Identifier: GPL-3.0-or-later
//! AArch64 Linux syscall ABI. No host syscall is forwarded blindly.
// Nested io_uring/resource subscriptions retain native readiness capabilities.
#![recursion_limit = "256"]
use std::io;
use trames_execution::Registers;
pub mod image;
pub mod vdso;
use trames_memory::{Access, Memory, ADDRESS_LIMIT};
mod bpf;
mod syscall_diagnostics;
pub use syscall_diagnostics::SyscallDiagnostics;
mod credentials;
pub use credentials::{credential_call, credential_entry, credential_mutation, CredentialResult};
mod descriptor_create;
mod entropy;
pub use entropy::getrandom;
mod direct;
pub use direct::{
    epoll_parameters, epoll_scatter, Aio, DirectSyscalls, FileBoundary, FileCheckpoint,
    FileExecutor, FileOutput, FilePending, FileResult, IoAttempt, PendingIo, RetainedAio,
    RetainedByte, RetainedSocket, UringActor, UringBackground, UringEnter, UringEpoch,
    UringSnapshot,
};
mod file_calls;
mod file_layouts;
pub use file_layouts::{FileLayoutDriver, FileLayoutRequest, FileLayouts};
mod heap;
mod path_queries;
mod render;
pub use heap::ProgramBreak;
mod event_wait;
mod network;
mod network_batch;
mod poll;
pub use event_wait::{event_wait, wait_mask, RetainedWait};
mod pty;
pub use poll::{RetainedPoll, RetainedSelect};
pub use pty::{
    pty_control, pty_control_request, terminal_control, terminal_query, terminal_query_request,
};
mod record_locks;
mod state;
mod syslog;
mod uts;
pub use uts::uts_call;
mod timer;
pub use syslog::syslog;
mod uring;
pub use state::{Linux, MmapPlan};
pub use timer::{timerfd_control, timerfd_control_with_boot};
pub use trames_shared::boottime::Boottime;

pub fn fill_entropy(bytes: &mut [u8]) -> Result<(), trames_vfs::Errno> {
    getrandom::fill(bytes).map_err(|_| trames_vfs::Errno(5))
}

pub const SYS_WRITE: u64 = 64;
pub const SYS_EXIT: u64 = 93;
pub const SYS_EXIT_GROUP: u64 = 94;
pub const MAX_WRITE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFd {
    Stdout,
    Stderr,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalEvent {
    Resize { rows: u16, columns: u16 },
    Signal(u32),
}

/// Optional host memory snapshot for a host-managed session. Values are bytes;
/// available may include reclaimable pages and is a hint, never a reservation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostMemoryInfo {
    pub total: usize,
    pub free: usize,
    pub available: usize,
}

/// A host-authorized process launch over independent descriptors into the
/// original shared byte resources. Image work can outlive its host transport.
/// Completion is a Linux wait status (or negative errno on launch failure).
pub struct HostSpawn {
    pub argv: Vec<Vec<u8>>,
    pub environment: Vec<Vec<u8>>,
    pub vfs: trames_vfs::Vfs,
    pub process: std::sync::Arc<HostProcess>,
}
pub const HOST_RUNNING: i32 = i32::MIN;
/// One original launch/transport lifetime. PID publication and cancellation
/// share a single atomic modification order; neither can miss the other.
pub struct HostProcess {
    state: std::sync::atomic::AtomicU32,
    status: std::sync::Arc<std::sync::atomic::AtomicI32>,
    cancellation: std::sync::OnceLock<std::sync::Arc<trames_shared::Readiness>>,
    control: std::sync::OnceLock<std::sync::Arc<dyn Fn(u32, u32) + Send + Sync>>,
}
impl Default for HostProcess {
    fn default() -> Self {
        Self {
            state: Default::default(),
            status: std::sync::Arc::new(std::sync::atomic::AtomicI32::new(HOST_RUNNING)),
            cancellation: Default::default(),
            control: Default::default(),
        }
    }
}
impl HostProcess {
    const CANCELLED: u32 = 1 << 31;
    pub fn pid(&self) -> u32 {
        self.state.load(std::sync::atomic::Ordering::Acquire) & !Self::CANCELLED
    }
    pub fn status(&self) -> i32 {
        self.status.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn status_cell(&self) -> std::sync::Arc<std::sync::atomic::AtomicI32> {
        self.status.clone()
    }
    pub fn cancelled(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Relaxed) & Self::CANCELLED != 0
    }
    pub fn publish(&self, pid: u32) -> bool {
        assert!(pid != 0 && pid < Self::CANCELLED);
        self.state
            .compare_exchange(
                0,
                pid,
                std::sync::atomic::Ordering::Release,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    }
    /// Returns the already published group, if any. A concurrent publication
    /// instead observes cancellation and retires its unissued launch.
    pub fn cancel(&self) -> Option<u32> {
        let old = self
            .state
            .fetch_or(Self::CANCELLED, std::sync::atomic::Ordering::Acquire);
        if let Some(ready) = self.cancellation.get() {
            ready.notify_locked();
        }
        let pid = old & !Self::CANCELLED;
        if pid != 0 && old & Self::CANCELLED == 0 {
            if let Some(route) = self.control.get() {
                route(pid, 1);
            }
        }
        (pid != 0 && old & Self::CANCELLED == 0).then_some(pid)
    }
    pub fn bind_control(&self, control: std::sync::Arc<dyn Fn(u32, u32) + Send + Sync>) {
        self.control.get_or_init(|| control);
    }
    pub fn signal(&self, signal: u32) {
        let pid = self.pid();
        if pid != 0 && (1..=64).contains(&signal) {
            if let Some(route) = self.control.get() {
                route(pid, signal);
            }
        }
    }
    pub fn fail(&self, errno: u32) {
        self.status
            .store(-(errno as i32), std::sync::atomic::Ordering::Relaxed);
    }
    pub fn subscribe(
        &self,
        signal: &std::sync::Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.cancellation
            .get_or_init(Default::default)
            .subscribe(signal)
    }
}

pub trait GuestOutput {
    /// Original byte resource, shared with execution workers. Lifecycle hooks
    /// remain on the host; console bytes never call those hooks through RPC.
    fn source_console(&mut self) -> std::sync::Arc<dyn trames_vfs::ConsoleIo>;
    /// Read-only host accounting can run on the querying executor. Adapters
    /// retain their actual provider, not a periodically copied memory hint.
    fn host_memory_source(
        &self,
    ) -> Option<std::sync::Arc<dyn Fn() -> HostMemoryInfo + Send + Sync>> {
        None
    }
    /// Host adapters opt in; bounded/iPad sessions retain guest-budget reports.
    /// Queried only for memory/proc metadata, never on CPU/native byte access.
    fn host_memory(&self) -> Option<HostMemoryInfo> {
        None
    }
    /// The adapter can prepare independent stdio/terminal resources while
    /// executors run. Accepted spawn/signal work uses original session resources.
    fn live_host_processes(&self) -> bool {
        false
    }
    /// A connected embedding can supply external events when guest actors park.
    fn waits_for_host(&self) -> bool {
        false
    }
    /// Maximum interval between actual embedding transport/control polls.
    fn control_poll_interval(&self) -> std::time::Duration {
        std::time::Duration::MAX
    }
    /// Complete accepted host output before normal session teardown.
    fn flush_output(&mut self) -> io::Result<bool> {
        Ok(true)
    }

    /// Poll host queues/original resources without touching guest bytes.
    /// True requests the stopped control hook.
    /// Legacy adapters conservatively retain their existing joined callback.
    fn poll_control(&mut self, _vfs: &trames_vfs::Vfs) -> io::Result<bool> {
        Ok(true)
    }
    /// Embedding control at each scheduler round. Returning false cancels the
    /// entire session. Host adapters may perform queued, authorized VFS work here.
    fn control(&mut self, _vfs: &mut trames_vfs::Vfs) -> io::Result<bool> {
        Ok(true)
    }
    /// An accepted host launch. Opted-in adapters submit while executors run;
    /// legacy embeddings consume it after the stopped control hook.
    fn host_spawn(&mut self) -> Option<HostSpawn> {
        None
    }
    /// An explicitly authorized signal to one host-launched process group.
    fn host_signal(&mut self) -> Option<(u32, u32)> {
        None
    }
    fn root_signal(&mut self) -> Option<u32> {
        None
    }
    fn write(&mut self, fd: OutputFd, bytes: &[u8]) -> io::Result<usize>;
    fn read_stdin(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
    /// Nonblocking input for the cooperative scheduler. Interactive adapters must
    /// return WouldBlock until bytes or EOF are available.
    fn poll_stdin(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_stdin(bytes)
    }
    fn stdin_ready(&mut self) -> io::Result<bool> {
        Ok(true)
    }
    /// Events from the embedding application's PTY master, scoped to guest jobs.
    fn terminal_event(&mut self) -> Option<TerminalEvent> {
        None
    }
}

#[derive(Default)]
pub struct CapturedOutput {
    pub stdout: trames_vfs::CapturedBytes,
    pub stderr: trames_vfs::CapturedBytes,
    pub stdin: trames_vfs::CapturedBytes,
}
impl GuestOutput for CapturedOutput {
    fn source_console(&mut self) -> std::sync::Arc<dyn trames_vfs::ConsoleIo> {
        std::sync::Arc::new(trames_vfs::CapturedConsole {
            input: self.stdin.clone(),
            output: self.stdout.clone(),
            error: self.stderr.clone(),
        })
    }
    fn poll_control(&mut self, _: &trames_vfs::Vfs) -> io::Result<bool> {
        Ok(false)
    }
    fn read_stdin(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let input = self.stdin.read(bytes.len());
        let count = input.len();
        bytes[..count].copy_from_slice(&input);
        Ok(count)
    }
    fn write(&mut self, fd: OutputFd, bytes: &[u8]) -> io::Result<usize> {
        match fd {
            OutputFd::Stdout => &mut self.stdout,
            OutputFd::Stderr => &mut self.stderr,
        }
        .append(bytes);
        Ok(bytes.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallOutcome {
    Continue,
    Exit(u8),
}

fn errno(value: u64) -> u64 {
    0u64.wrapping_sub(value)
}
fn io_errno(error: io::Error) -> u64 {
    match error.kind() {
        io::ErrorKind::Interrupted => 4,
        io::ErrorKind::WouldBlock => 11,
        io::ErrorKind::PermissionDenied => 13,
        io::ErrorKind::InvalidInput => 22,
        io::ErrorKind::BrokenPipe => 32,
        _ => 5,
    }
}

pub fn dispatch(
    cpu: &mut impl Registers,
    memory: &Memory,
    output: &mut impl GuestOutput,
) -> SyscallOutcome {
    let result = match cpu.x(8) {
        SYS_EXIT | SYS_EXIT_GROUP => return SyscallOutcome::Exit(cpu.x(0) as u8),
        SYS_WRITE => {
            let fd = match cpu.x(0) as u32 {
                1 => OutputFd::Stdout,
                2 => OutputFd::Stderr,
                _ => {
                    cpu.set_x(0, errno(9));
                    return SyscallOutcome::Continue;
                }
            };
            let len = cpu.x(2).min(MAX_WRITE as u64) as usize;
            // Linux access_ok rejects out-of-domain pointers even for a zero-byte write.
            if cpu.x(1) >= ADDRESS_LIMIT {
                errno(14)
            } else if len == 0 {
                0
            } else if memory.check(cpu.x(1), len, Access::Read).is_err() {
                errno(14)
            } else {
                let mut bytes = vec![0; len];
                // The address space is borrowed throughout validation and copying.
                memory
                    .read(cpu.x(1), &mut bytes)
                    .expect("validated guest buffer");
                match output.write(fd, &bytes) {
                    Ok(written) if written <= len => written as u64,
                    Ok(_) => errno(5),
                    Err(e) => errno(io_errno(e)),
                }
            }
        }
        _ => errno(38),
    };
    cpu.set_x(0, result);
    SyscallOutcome::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_execution::Aarch64State as Cpu;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn write_cpu(fd: u64, pointer: u64, count: u64) -> Cpu {
        let mut c = Cpu::default();
        c.set_x(8, SYS_WRITE);
        c.set_x(0, fd);
        c.set_x(1, pointer);
        c.set_x(2, count);
        c
    }
    #[test]
    fn validates_fd_and_buffer_before_output() {
        let m = Memory::default();
        let mut out = CapturedOutput::default();
        let mut c = write_cpu(1, u64::MAX, 3);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), errno(14));
        assert!(out.stdout.is_empty());
        c = write_cpu(7, 0, 0);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), errno(9));
        c = write_cpu(1, u64::MAX, 0);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), errno(14));
        c = write_cpu(1, 0, 0);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), 0);
        c.set_x(8, 99999);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), errno(38));
    }
    #[test]
    fn writes_binary_streams_and_returns_count() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, b"a\0b").unwrap();
        let mut c = write_cpu(2, 0x1000, 3);
        let mut out = CapturedOutput::default();
        dispatch(&mut c, &m, &mut out);
        assert_eq!(out.stderr, b"a\0b");
        assert_eq!(c.x(0), 3);
        c.set_x(8, SYS_EXIT_GROUP);
        c.set_x(0, 0x123);
        assert_eq!(dispatch(&mut c, &m, &mut out), SyscallOutcome::Exit(0x23));
    }
    #[test]
    fn partial_write_and_error_are_never_retried() {
        struct Partial {
            calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
            fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        impl GuestOutput for Partial {
            fn source_console(&mut self) -> std::sync::Arc<dyn trames_vfs::ConsoleIo> {
                let calls = self.calls.clone();
                let fail = self.fail.clone();
                std::sync::Arc::new(trames_vfs::ConsoleCallbacks::new(
                    |_| Ok(Vec::new()),
                    move |_, _| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if fail.load(std::sync::atomic::Ordering::Relaxed) {
                            Err(trames_vfs::Errno(4))
                        } else {
                            Ok(1)
                        }
                    },
                    |_, events| (events, [0; 2]),
                ))
            }
            fn write(&mut self, _: OutputFd, _: &[u8]) -> io::Result<usize> {
                self.calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(1)
                }
            }
        }
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut out = Partial {
            calls: Default::default(),
            fail: Default::default(),
        };
        let mut c = write_cpu(1, 0x1000, 3);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), 1);
        assert_eq!(out.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        out.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        c = write_cpu(1, 0x1000, 3);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), errno(4));
        assert_eq!(out.calls.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
}

#[cfg(test)]
mod host_process_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Barrier,
    };
    #[test]
    fn cancellation_and_publication_cannot_miss_each_other_or_deliver_twice() {
        for _ in 0..64 {
            let process = Arc::new(HostProcess::default());
            let delivered = Arc::new(AtomicU32::new(0));
            let result = delivered.clone();
            process.bind_control(Arc::new(move |group, signal| {
                assert_eq!((group, signal), (7, 1));
                result.fetch_add(1, Ordering::Relaxed);
            }));
            let barrier = Arc::new(Barrier::new(2));
            let peer = process.clone();
            let ready = barrier.clone();
            let sender = std::thread::spawn(move || {
                ready.wait();
                peer.publish(7)
            });
            barrier.wait();
            process.cancel();
            let published = sender.join().unwrap();
            assert_eq!(delivered.load(Ordering::Relaxed), u32::from(published));
            assert!(process.cancelled());
            assert_eq!(process.cancel(), None);
            assert_eq!(delivered.load(Ordering::Relaxed), u32::from(published));
        }
    }
}
