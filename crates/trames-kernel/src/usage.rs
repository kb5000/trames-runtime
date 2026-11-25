// SPDX-License-Identifier: GPL-3.0-or-later
//! ARM64 Linux resource usage from the guest execution clock and resident mm.
use crate::{children::Children, signal::IoTask};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use trames_memory::CpuMemory;
use trames_vfs::Errno;

#[derive(Default, Copy, Clone)]
pub(crate) struct IoUsage {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    syscw: u64,
}
impl IoUsage {
    pub(crate) fn include(&mut self, other: Self) {
        self.rchar = self.rchar.wrapping_add(other.rchar);
        self.wchar = self.wchar.wrapping_add(other.wchar);
        self.syscr = self.syscr.wrapping_add(other.syscr);
        self.syscw = self.syscw.wrapping_add(other.syscw);
    }
    pub(crate) fn text(self) -> Vec<u8> {
        // Only logical VFS counters are tracked. Host writeback is not
        // attributable to the thread completing a guest write syscall.
        format!(
            "rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\n",
            self.rchar, self.wchar, self.syscr, self.syscw
        )
        .into_bytes()
    }
}
#[derive(Default)]
pub struct TaskIo {
    rchar: AtomicU64,
    wchar: AtomicU64,
    syscr: AtomicU64,
    syscw: AtomicU64,
}
impl TaskIo {
    /// Charge a completed guest operation on its original task. Checkpoint,
    /// retry and seccomp-denied entries never call this hook.
    #[inline]
    pub fn complete(&self, number: u32, position: u64, result: Result<u64, Errno>) {
        let (read, write) = match number {
            // Scalar operations reject invalid descriptors and positioned
            // arguments before entering vfs_read/vfs_write.
            63 | 64 | 67 | 68 => {
                if result.is_err_and(|e| matches!(e.0, 9 | 29))
                    || matches!(number, 67 | 68) && (position as i64) < 0
                {
                    return;
                }
                (number == 63 || number == 67, number == 64 || number == 68)
            }
            65 | 66 => (number == 65, number == 66),
            69 | 70 | 286 | 287 => {
                if (position as i64) < 0 && !(number >= 286 && position == u64::MAX) {
                    return;
                }
                (number == 69 || number == 286, number == 70 || number == 287)
            }
            71 | 285 if result.is_ok() => (true, true),
            _ => return,
        };
        let bytes = result.unwrap_or(0);
        if read {
            self.syscr.fetch_add(1, Relaxed);
            if bytes != 0 {
                self.rchar.fetch_add(bytes, Relaxed);
            }
        }
        if write {
            self.syscw.fetch_add(1, Relaxed);
            if bytes != 0 {
                self.wchar.fetch_add(bytes, Relaxed);
            }
        }
    }
    #[inline]
    pub fn complete_return(&self, number: u32, position: u64, raw: u64) {
        let result = if raw >= (-4095i64) as u64 {
            Err(Errno(raw.wrapping_neg() as u32))
        } else {
            Ok(raw)
        };
        self.complete(number, position, result);
    }
    pub(crate) fn snapshot(&self) -> IoUsage {
        IoUsage {
            rchar: self.rchar.load(Relaxed),
            wchar: self.wchar.load(Relaxed),
            syscr: self.syscr.load(Relaxed),
            syscw: self.syscw.load(Relaxed),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Usage {
    pub io: IoUsage,
    pub cpu: Duration,
    pub peak_bytes: usize,
}
impl Usage {
    pub fn include(&mut self, other: Self) {
        self.io.include(other.io);
        self.cpu = self.cpu.saturating_add(other.cpu);
        self.peak_bytes = self.peak_bytes.max(other.peak_bytes);
    }
    pub fn write(self, memory: &mut impl CpuMemory, address: u64) -> Result<(), Errno> {
        crate::user_copy::write_bytes(memory, address, &self.encode()).map_err(|_| Errno(14))
    }
    pub(crate) fn encode(self) -> [u8; 144] {
        // timeval utime/stime, followed by fourteen signed long counters.
        // The virtual execution clock currently attributes CPU time to utime.
        let mut bytes = [0; 144];
        bytes[..8].copy_from_slice(&self.cpu.as_secs().to_le_bytes());
        bytes[8..16].copy_from_slice(&u64::from(self.cpu.subsec_micros()).to_le_bytes());
        bytes[32..40].copy_from_slice(&((self.peak_bytes / 1024) as u64).to_le_bytes());
        bytes
    }
}
pub fn getrusage(
    task: &IoTask,
    children: &Children,
    who: i32,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    observe(task, children, who)?.write(memory, address)?;
    Ok(0)
}
pub(crate) fn observe(task: &IoTask, children: &Children, who: i32) -> Result<Usage, Errno> {
    Ok(match who {
        -1 => children.usage(),
        0 | 1 => {
            let group = task.lifecycle();
            let cpu = if who == 1 {
                task.proc_view.elapsed()
            } else {
                group.cpu_time()
            };
            Usage {
                io: Default::default(),
                cpu,
                peak_bytes: group.image_peak().max(
                    task.proc_view
                        .memory_report()
                        .map_or(0, |mm| mm.peak_resident_bytes()),
                ),
            }
        }
        _ => return Err(Errno(22)),
    })
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
    if address != 0 {
        crate::user_copy::write_bytes(memory, address, &times_bytes(task, children))
            .map_err(|_| Errno(14))?;
    }
    Ok(ticks(elapsed))
}
pub(crate) fn ticks(time: Duration) -> u64 {
    (time.as_millis() / 10) as u64
}
pub(crate) fn times_bytes(task: &IoTask, children: &Children) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&ticks(task.lifecycle().cpu_time()).to_le_bytes());
    bytes[16..24].copy_from_slice(&ticks(children.usage().cpu).to_le_bytes());
    bytes
}
pub fn times_since(
    task: &IoTask,
    children: &Children,
    started: std::time::Instant,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    times(task, children, Duration::ZERO, address, memory)?;
    Ok(ticks(started.elapsed()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn io_counts_operations_and_only_transferred_bytes() {
        let io = TaskIo::default();
        io.complete(63, 0, Ok(0));
        io.complete(63, 0, Err(Errno(9)));
        io.complete(65, 0, Err(Errno(9)));
        io.complete(68, 0, Ok(7));
        io.complete(71, 0, Ok(5));
        io.complete(69, u64::MAX, Err(Errno(22)));
        io.complete(286, u64::MAX, Ok(11));
        let got = io.snapshot();
        assert_eq!((got.syscr, got.rchar, got.syscw, got.wchar), (4, 16, 2, 12));
    }
}
