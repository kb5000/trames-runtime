// SPDX-License-Identifier: GPL-3.0-or-later
//! AArch64 Linux syscall ABI. No host syscall is forwarded blindly.
use std::io;
use trames_cpu::Cpu;
use trames_memory::{Access, Memory, ADDRESS_LIMIT};
mod state;
pub use state::Linux;

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

pub trait GuestOutput {
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
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdin: Vec<u8>,
    input_position: usize,
}
impl GuestOutput for CapturedOutput {
    fn read_stdin(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input_position = self.input_position.min(self.stdin.len());
        let count = bytes.len().min(self.stdin.len() - self.input_position);
        bytes[..count]
            .copy_from_slice(&self.stdin[self.input_position..self.input_position + count]);
        self.input_position += count;
        Ok(count)
    }
    fn write(&mut self, fd: OutputFd, bytes: &[u8]) -> io::Result<usize> {
        match fd {
            OutputFd::Stdout => &mut self.stdout,
            OutputFd::Stderr => &mut self.stderr,
        }
        .extend_from_slice(bytes);
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

pub fn dispatch(cpu: &mut Cpu, memory: &Memory, output: &mut impl GuestOutput) -> SyscallOutcome {
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
            calls: usize,
            fail: bool,
        }
        impl GuestOutput for Partial {
            fn write(&mut self, _: OutputFd, _: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.fail {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(1)
                }
            }
        }
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut out = Partial {
            calls: 0,
            fail: false,
        };
        let mut c = write_cpu(1, 0x1000, 3);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), 1);
        assert_eq!(out.calls, 1);
        out.fail = true;
        c = write_cpu(1, 0x1000, 3);
        dispatch(&mut c, &m, &mut out);
        assert_eq!(c.x(0), errno(4));
        assert_eq!(out.calls, 2);
    }
}
