// SPDX-License-Identifier: GPL-3.0-or-later
//! Source/solo time observation ABI. Clocks are read on the calling executor.
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;

pub fn gettimeofday(memory: &mut impl CpuMemory, tv: u64, tz: u64) -> Result<u64, Errno> {
    // Preserve the original two-buffer preflight and store ordering, including
    // overlapping destinations. No resource service or mutable clock copy.
    if tv != 0 {
        crate::Linux::check(memory, tv, 16, Access::Write)?;
    }
    if tz != 0 {
        crate::Linux::check(memory, tz, 8, Access::Write)?;
    }
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Errno(5))?;
    if tv != 0 {
        memory
            .write(tv, &time.as_secs().to_le_bytes())
            .map_err(|_| Errno(14))?;
        memory
            .write(tv + 8, &(time.subsec_micros() as u64).to_le_bytes())
            .map_err(|_| Errno(14))?;
    }
    if tz != 0 {
        memory.write(tz, &[0; 8]).map_err(|_| Errno(14))?;
    }
    Ok(0)
}

pub fn clock_read(
    memory: &mut impl CpuMemory,
    number: u32,
    id: u64,
    address: u64,
    started: Instant,
    boot: Option<crate::Boottime>,
    task: Option<&trames_vfs::ProcessView>,
) -> Result<u64, Errno> {
    // clockid_t is a signed 32-bit Linux ABI argument, including raw SVCs.
    let id = id as u32;
    if !matches!(id, 0 | 1 | 3..=9) {
        return Err(Errno(22));
    }
    if number == 114 && address == 0 {
        return Ok(0);
    }
    memory
        .check(address, 16, Access::Write)
        .map_err(|_| Errno(14))?;
    let (seconds, nanos) = if number == 114 {
        (0, 1)
    } else {
        // Realtime/coarse realtime retain Unix time; all monotonic variants
        // retain the session epoch. Boottime includes actual host suspension.
        let elapsed = if id == 3 {
            // Original guest-task accounting follows execution-slot migration
            // and freezes while parked. Read it only for the requested clock;
            // host worker/process clocks would charge unrelated guest tasks.
            // This is charged assignment time, as in /proc, including host
            // preemption during an assignment. Process-wide CPU clocks still
            // need live plus retired thread accounting; do not fake wall time.
            task.ok_or(Errno(22))?.elapsed()
        } else if matches!(id, 0 | 5 | 8) {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Errno(5))?
        } else if matches!(id, 7 | 9) {
            boot.map_or_else(|| started.elapsed(), |b| b.elapsed())
        } else {
            started.elapsed()
        };
        (elapsed.as_secs(), elapsed.subsec_nanos() as u64)
    };
    let mut out = [0; 16];
    out[..8].copy_from_slice(&seconds.to_le_bytes());
    out[8..].copy_from_slice(&nanos.to_le_bytes());
    memory.write_array(address, out).map_err(|_| Errno(14))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};

    #[test]
    fn thread_clock_uses_original_task_accounting_across_slots_and_parking() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let started = Instant::now();
        let task = trames_vfs::ProcessView::default();
        let other = trames_vfs::ProcessView::default();
        task.account(std::time::Duration::new(2, 123), 0);
        other.account(std::time::Duration::from_secs(19), 1);
        let mut read = |task: &trames_vfs::ProcessView| {
            assert_eq!(
                clock_read(
                    &mut memory,
                    113,
                    0xffff_ffff_0000_0003,
                    0x1000,
                    started,
                    None,
                    Some(task)
                ),
                Ok(0)
            );
            (
                u64::from_le_bytes(memory.read_array::<8>(0x1000).unwrap()),
                u64::from_le_bytes(memory.read_array::<8>(0x1008).unwrap()),
            )
        };
        assert_eq!(read(&task), (2, 123));
        assert_eq!(read(&other), (19, 0));
        // Parking leaves this total frozen; subsequent execution on another
        // slot resumes the same task rather than that worker's lifetime.
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(read(&task), (2, 123));
        let began = Instant::now();
        task.begin_accounting(began, 2);
        assert!(read(&task) >= (2, 123));
        task.finish_accounting(began, std::time::Duration::from_millis(5), 2);
        assert_eq!(read(&task), (2, 5_000_123));
        assert_eq!(read(&other), (19, 0));
    }

    #[test]
    fn thread_clock_resolution_and_fault_abi() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let started = Instant::now();
        let task = trames_vfs::ProcessView::default();
        assert_eq!(
            clock_read(&mut memory, 114, 3, 0, started, None, None),
            Ok(0)
        );
        assert_eq!(
            clock_read(&mut memory, 114, 3, 0x1000, started, None, None),
            Ok(0)
        );
        assert_eq!(
            memory.read_array::<16>(0x1000).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
        memory.write(0x1000, &[0xa7; 16]).unwrap();
        for number in [113, 114] {
            assert_eq!(
                clock_read(&mut memory, number, 3, 0x1ff8, started, None, Some(&task)),
                Err(Errno(14))
            );
            assert_eq!(memory.read_array::<16>(0x1000).unwrap(), [0xa7; 16]);
        }
        assert_eq!(
            clock_read(&mut memory, 113, 3, 0, started, None, Some(&task)),
            Err(Errno(14))
        );
        assert_eq!(
            clock_read(&mut memory, 113, 3, 0x1000, started, None, None),
            Err(Errno(22))
        );
        assert_eq!(
            clock_read(&mut memory, 113, 2, 0x1000, started, None, Some(&task)),
            Err(Errno(22))
        );
        assert_eq!(
            clock_read(&mut memory, 114, u64::MAX, 0, started, None, Some(&task)),
            Err(Errno(22))
        );
    }

    #[test]
    fn realtime_preflights_both_buffers_and_preserves_overlap_and_null_abi() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[0xa7; 32]).unwrap();
        assert_eq!(gettimeofday(&mut memory, 0x1000, 0x1ffc), Err(Errno(14)));
        assert_eq!(memory.read_array::<32>(0x1000).unwrap(), [0xa7; 32]);
        assert_eq!(gettimeofday(&mut memory, 0x1ff8, 0x1000), Err(Errno(14)));
        assert_eq!(memory.read_array::<32>(0x1000).unwrap(), [0xa7; 32]);
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(gettimeofday(&mut memory, 0x1000, 0), Ok(0));
        let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let seconds = u64::from_le_bytes(memory.read_array::<8>(0x1000).unwrap());
        let micros = u64::from_le_bytes(memory.read_array::<8>(0x1008).unwrap());
        let observed = std::time::Duration::new(seconds, (micros * 1000) as u32);
        assert!(micros < 1_000_000);
        assert!(observed >= before.saturating_sub(std::time::Duration::from_micros(1)));
        assert!(observed <= after);
        assert_eq!(gettimeofday(&mut memory, 0x1000, 0x1008), Ok(0));
        assert_eq!(memory.read_array::<8>(0x1008).unwrap(), [0; 8]);
        assert_eq!(gettimeofday(&mut memory, 0, 0x1010), Ok(0));
        assert_eq!(memory.read_array::<8>(0x1010).unwrap(), [0; 8]);
        assert_eq!(gettimeofday(&mut memory, 0, 0), Ok(0));
    }
}
