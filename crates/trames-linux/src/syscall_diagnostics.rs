// SPDX-License-Identifier: GPL-3.0-or-later
//! Original session log and calling task identity for source ENOSYS completion.
use crate::Linux;

pub struct SyscallDiagnostics {
    log: trames_vfs::KernelLogAccess,
    pid: u32,
    name: trames_vfs::TaskName,
}
impl Linux {
    pub fn syscall_diagnostics(&self, pid: u32) -> SyscallDiagnostics {
        SyscallDiagnostics {
            log: self.vfs.kernel_log_capability(),
            pid,
            name: self.command_name.clone(),
        }
    }
}
impl SyscallDiagnostics {
    pub fn unsupported(&self, number: u32, pc: u64, args: [u64; 6]) -> u64 {
        let name = self.name.bytes();
        let length = name.iter().position(|b| *b == 0).unwrap_or(15);
        self.log.log_syscall(
            self.pid,
            number as u64,
            pc.saturating_sub(4),
            args,
            38,
            &name[..length],
        );
        (-38i64) as u64
    }
}
