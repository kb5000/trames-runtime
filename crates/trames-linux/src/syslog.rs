// SPDX-License-Identifier: GPL-3.0-or-later
//! One syslog ABI for owner memory and executing workers. Authority is frozen
//! for a worker epoch; log records/stream/clear state are the actual shared log.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, KernelLogAccess};

pub fn syslog(
    log: &KernelLogAccess,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let action = a[0] as u32;
    if matches!(action, 9 | 10) {
        return log.size(action);
    }
    let count = if matches!(action, 2..=4) {
        if (a[2] as u32 as i32) < 0 {
            return Err(Errno(22));
        }
        let count = (a[2] as u32 as usize).min(trames_vfs::kernel_log_capacity());
        // Preflight every output page before consuming the stream or clearing.
        Linux::check(memory, a[1], count, Access::Write)?;
        count
    } else {
        0
    };
    let bytes = log.syslog(action, count)?;
    if !bytes.is_empty() {
        memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
    }
    Ok(bytes.len() as u64)
}
