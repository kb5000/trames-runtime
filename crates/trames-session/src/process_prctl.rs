// SPDX-License-Identifier: GPL-3.0-or-later
//! Residual task controls use the same original resources on source and solo.
use super::*;
use trames_memory::CpuMemory;

pub(crate) fn entry(a: [u64; 6]) -> bool {
    !trames_linux::credential_entry(167, a) && !matches!(a[0], 21 | 22)
}
pub(crate) fn call<C: Cpu>(
    cpu: &mut C,
    name: &trames_vfs::TaskName,
    parent: Option<&trames_kernel::task_parent::Parentage>,
    family: Option<&trames_kernel::family::Family>,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Option<Result<u64, Errno>> {
    Some(match a[0] {
        1 if a[1] > 64 => Err(Errno(22)),
        1 => {
            parent?.set_death_signal(a[1] as u32);
            Ok(0)
        }
        2 => memory
            .write(a[1], &parent?.death_signal().to_le_bytes())
            .map(|()| 0)
            .map_err(|_| Errno(14)),
        15 | 16 => trames_linux::task_name_call(name, a, memory),
        36 => {
            family?.set_subreaper(a[1] != 0);
            Ok(0)
        }
        37 => memory
            .write(a[1], &u32::from(family?.subreaper()).to_le_bytes())
            .map(|()| 0)
            .map_err(|_| Errno(14)),
        63 | 64 => (|| {
            let mut config = cpu.sme_config().ok_or(Errno(22))?;
            if a[0] == 64 {
                return Ok(config.get());
            }
            let value = config.set(a[1], C::sme_lengths()).ok_or(Errno(22))?;
            cpu.set_sme_config(config);
            Ok(value)
        })(),
        _ => Err(Errno(22)),
    })
}
