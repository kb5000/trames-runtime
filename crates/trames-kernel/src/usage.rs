// SPDX-License-Identifier: GPL-3.0-or-later
//! ARM64 Linux resource usage from the guest execution clock and resident mm.
use crate::{children::Children, signal::IoTask};
use std::time::Duration;
use trames_memory::CpuMemory;
use trames_vfs::Errno;

#[derive(Clone, Copy, Default)]
pub(crate) struct Usage {
    pub cpu: Duration,
    pub peak_bytes: usize,
}
impl Usage {
    pub fn include(&mut self, other: Self) {
        self.cpu = self.cpu.saturating_add(other.cpu);
        self.peak_bytes = self.peak_bytes.max(other.peak_bytes);
    }
    pub fn write(self, memory: &mut impl CpuMemory, address: u64) -> Result<(), Errno> {
        // timeval utime/stime, followed by fourteen signed long counters.
        // The virtual execution clock currently attributes CPU time to utime.
        let mut bytes = [0; 144];
        bytes[..8].copy_from_slice(&self.cpu.as_secs().to_le_bytes());
        bytes[8..16].copy_from_slice(&u64::from(self.cpu.subsec_micros()).to_le_bytes());
        bytes[32..40].copy_from_slice(&((self.peak_bytes / 1024) as u64).to_le_bytes());
        memory.write_array(address, bytes).map_err(|_| Errno(14))
    }
}
pub fn getrusage(
    task: &IoTask,
    children: &Children,
    who: i32,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let usage = match who {
        -1 => children.usage(),
        0 | 1 => {
            let group = task.lifecycle();
            let cpu = if who == 1 {
                task.proc_view.elapsed()
            } else {
                group.cpu_time()
            };
            Usage {
                cpu,
                peak_bytes: group.image_peak().max(
                    task.proc_view
                        .memory_report()
                        .map_or(0, |mm| mm.peak_resident_bytes()),
                ),
            }
        }
        _ => return Err(Errno(22)),
    };
    usage.write(memory, address)?;
    Ok(0)
}

/// ARM64 USER_HZ is 100. The return clock and the four tms fields share this
/// unit. A null output pointer requests only the elapsed tick count.
pub fn times(
    task: &IoTask,
    children: &Children,
    elapsed: Duration,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let ticks = |time: Duration| (time.as_millis() / 10) as u64;
    if address != 0 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&ticks(task.lifecycle().cpu_time()).to_le_bytes());
        bytes[16..24].copy_from_slice(&ticks(children.usage().cpu).to_le_bytes());
        memory.write_array(address, bytes).map_err(|_| Errno(14))?;
    }
    Ok(ticks(elapsed))
}
