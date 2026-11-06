// SPDX-License-Identifier: GPL-3.0-or-later
//! Original session log and calling task identity for source ENOSYS completion.
use crate::Linux;

pub struct SyscallDiagnostics {
    log: trames_vfs::KernelLogAccess,
    pid: u32,
    name: [u8; 15],
    length: usize,
}
impl Linux {
    pub fn syscall_diagnostics(&self, pid: u32) -> SyscallDiagnostics {
        let length = self.command_name.len().min(15);
        let mut name = [0; 15];
        name[..length].copy_from_slice(&self.command_name[..length]);
        SyscallDiagnostics {
            log: self.vfs.kernel_log_capability(),
            pid,
            name,
            length,
        }
    }
}
impl SyscallDiagnostics {
    pub fn unsupported(&self, number: u32, pc: u64, args: [u64; 6]) -> u64 {
        self.log.log_syscall(
            self.pid,
            number as u64,
            pc.saturating_sub(4),
            args,
            38,
            &self.name[..self.length],
        );
        (-38i64) as u64
    }
}
