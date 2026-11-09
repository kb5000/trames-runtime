// SPDX-License-Identifier: GPL-3.0-or-later
//! Common sysinfo ABI, over original session statistics rather than a VFS copy.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;
#[derive(Clone, Copy, Default)]
pub struct SystemInfo {
    pub uptime: std::time::Duration,
    pub load: [f64; 3],
    pub total: usize,
    pub free: usize,
    pub tasks: usize,
}
pub trait SystemStatistics: Send + Sync {
    fn observe(&self) -> Option<SystemInfo>;
}
/// Preflight precedes provider/host sampling, including capability-less callers.
pub fn sysinfo<M: CpuMemory>(
    memory: &mut M,
    address: u64,
    observe: impl FnOnce(&M) -> Option<SystemInfo>,
) -> Option<Result<u64, Errno>> {
    if let Err(e) = Linux::check(memory, address, 112, Access::Write) {
        return Some(Err(e));
    }
    let info = observe(memory)?;
    let mut out = [0; 112];
    for (offset, value) in [
        (0, info.uptime.as_secs()),
        (32, info.total as u64),
        (40, info.free as u64),
    ] {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (i, load) in info.load.iter().enumerate() {
        out[8 + i * 8..16 + i * 8].copy_from_slice(&((load * 65536.0) as u64).to_le_bytes());
    }
    out[80..82].copy_from_slice(&(info.tasks as u16).to_le_bytes());
    out[104..108].copy_from_slice(&1u32.to_le_bytes());
    Some(
        memory
            .write(address, &out)
            .map(|()| 0)
            .map_err(|_| Errno(14)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn sysinfo_checks_full_destination_before_sampling_and_preserves_legacy_deferral() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[0xa5; 112]).unwrap();
        assert_eq!(
            sysinfo(&mut memory, 0x1fff, |_| panic!("sample after fault")),
            Some(Err(Errno(14)))
        );
        assert_eq!(sysinfo(&mut memory, 0x1000, |_| None), None);
        assert_eq!(memory.read_array::<112>(0x1000).unwrap(), [0xa5; 112]);
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert_eq!(
            sysinfo(&mut memory, 0x1000, |_| panic!("read-only destination")),
            Some(Err(Errno(14)))
        );
    }
    #[test]
    fn sysinfo_encodes_original_aarch64_layout_and_zeroes_padding() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[0xff; 112]).unwrap();
        assert_eq!(
            sysinfo(&mut memory, 0x1000, |_| Some(SystemInfo {
                uptime: std::time::Duration::from_millis(12345),
                load: [1.25, 2.5, 0.5],
                total: 1 << 30,
                free: 1 << 29,
                tasks: 65539,
            })),
            Some(Ok(0))
        );
        let out = memory.read_array::<112>(0x1000).unwrap();
        let mut expected = [0u8; 112];
        for (offset, value) in [
            (0, 12u64),
            (8, 81920),
            (16, 163840),
            (24, 32768),
            (32, 1 << 30),
            (40, 1 << 29),
        ] {
            expected[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        expected[80..82].copy_from_slice(&3u16.to_le_bytes());
        expected[104..108].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(out, expected);
    }
}
