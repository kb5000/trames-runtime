// SPDX-License-Identifier: GPL-3.0-or-later
//! AArch64 sendmmsg uses the existing sendmsg memory/socket path per message.
use super::Linux;
use trames_memory::Memory;
use trames_vfs::{Errno, FdKind};

type Result<T> = std::result::Result<T, Errno>;
fn word(memory: &Memory, address: u64, offset: u64) -> Result<u64> {
    memory
        .read_array::<8>(address.checked_add(offset).ok_or(Errno(14))?)
        .map(u64::from_le_bytes)
        .map_err(|_| Errno(14))
}
fn requested(memory: &Memory, header: u64) -> Result<u64> {
    let vectors = word(memory, header, 16)?;
    let count = word(memory, header, 24)?;
    if count > 1024 {
        return Err(Errno(90));
    }
    let mut total = 0u64;
    for index in 0..count {
        let length = word(memory, vectors, index * 16 + 8)?;
        total = total
            .checked_add(length)
            .filter(|&n| n <= trames_net::MAX_TRANSFER as u64)
            .ok_or(Errno(90))?;
    }
    Ok(total)
}
impl Linux {
    /// Batch sends can deliver SIGPIPE after earlier messages succeeded, even
    /// though the syscall returns a positive count instead of the final EPIPE.
    pub fn take_batch_pipe_signal(&mut self) -> bool {
        std::mem::take(&mut self.batch_pipe_signal)
    }
    pub(super) fn send_messages(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        // Linux rejects compat flags, validates fd even for vlen=0, caps vlen,
        // reports completed messages after later errors, and stops on a short
        // stream send. It writes msg_len after sending (an EFAULT cannot undo I/O).
        let flags = a[3] as u32;
        if flags & 0x8000_0000 != 0 {
            return Err(Errno(22));
        }
        if self.vfs.fd_kind(a[0] as u32)? != FdKind::Socket {
            return Err(Errno(88));
        }
        let count = (a[2] as u32).min(1024) as u64;
        let mut completed = 0;
        while completed < count {
            let send: Result<bool> = (|| {
                let header = a[1].checked_add(completed * 64).ok_or(Errno(14))?;
                let length = requested(memory, header)?;
                let sent =
                    self.network_syscall(211, [a[0], header, flags as u64, 0, 0, 0], memory)?;
                memory
                    .write(
                        header.checked_add(56).ok_or(Errno(14))?,
                        &(sent as u32).to_le_bytes(),
                    )
                    .map_err(|_| Errno(14))?;
                Ok(sent < length)
            })();
            match send {
                Ok(short) => {
                    completed += 1;
                    if short {
                        break;
                    }
                }
                Err(error) => {
                    if error.0 == 32 && flags & 0x4000 == 0 {
                        self.batch_pipe_signal = true;
                    }
                    return if completed == 0 {
                        Err(error)
                    } else {
                        Ok(completed)
                    };
                }
            }
        }
        Ok(completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn setup() -> (Linux, Memory, [u32; 2]) {
        let mut linux = Linux::new(0);
        let fds = linux
            .vfs
            .socketpair(1, 2 | trames_vfs::O_NONBLOCK, 0)
            .unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[0; 128]).unwrap();
        memory.write(0x1400, b"abcxyz").unwrap();
        for i in 0..2 {
            for (address, value) in [
                (0x1010 + i * 64, 0x1300 + i * 16),
                (0x1018 + i * 64, 1),
                (0x1300 + i * 16, 0x1400 + i * 3),
                (0x1308 + i * 16, 3),
            ] {
                memory.write(address, &value.to_le_bytes()).unwrap();
            }
        }
        (linux, memory, fds)
    }
    #[test]
    fn batches_preserve_datagrams_lengths_and_partial_progress() {
        let (mut linux, mut memory, fds) = setup();
        assert_eq!(
            linux.send_messages([fds[0] as u64, 0x1000, 2, 0x4000, 0, 0], &mut memory),
            Ok(2)
        );
        assert_eq!(memory.read_array::<4>(0x1038).unwrap(), 3u32.to_le_bytes());
        assert_eq!(memory.read_array::<4>(0x1078).unwrap(), 3u32.to_le_bytes());
        assert_eq!(linux.vfs.read(fds[1], 10).unwrap(), b"abc");
        assert_eq!(linux.vfs.read(fds[1], 10).unwrap(), b"xyz");
        memory.write(0x1310, &0x9000u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.send_messages([fds[0] as u64, 0x1000, 2, 0, 0, 0], &mut memory),
            Ok(1)
        );
        assert_eq!(linux.vfs.read(fds[1], 10).unwrap(), b"abc");
        assert_eq!(linux.vfs.read(fds[1], 10), Err(Errno(11)));
    }
    #[test]
    fn zero_length_fd_validation_and_post_send_length_fault_match_linux() {
        let (mut linux, mut memory, fds) = setup();
        assert_eq!(
            linux.send_messages([999, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(9))
        );
        assert_eq!(
            linux.send_messages([1, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(88))
        );
        assert_eq!(
            linux.send_messages([fds[0] as u64, 0, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(
            linux.send_messages([fds[0] as u64, 0x1000, 1, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(linux.vfs.read(fds[1], 10).unwrap(), b"abc");
    }
}
