// SPDX-License-Identifier: GPL-3.0-or-later
//! Capability ABI translation; the state and policy live in guest credentials.
use super::*;
impl<C: Cpu> Kernel<C> {
    pub(super) fn capcall(
        &self,
        pid: u32,
        p: &mut Process<C>,
        set: bool,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let version = read_u32(&p.memory, a[0])?;
        let words = match version {
            0x1998_0330 => 1,
            0x2007_1026 | 0x2008_0522 => 2,
            _ => {
                write_u32(&mut p.memory, a[0], 0x2008_0522)?;
                return if !set && a[1] == 0 {
                    Ok(0)
                } else {
                    Err(Errno(22))
                };
            }
        };
        let target = read_u32(&p.memory, a[0].checked_add(4).ok_or(Errno(14))?)? as i32;
        if !set && target < 0 {
            return Err(Errno(22));
        }
        let local = p.linux.vfs.visible_pid(pid);
        if set && target != 0 && target as u32 != local {
            return Err(Errno(1));
        }
        // Linux permits a NULL capget data pointer as an ABI version query.
        if !set && a[1] == 0 {
            return Ok(0);
        }
        if set {
            Linux::check(&p.memory, a[1], words * 12, Access::Read)?;
            let mut masks = [0u64; 3];
            for word in 0..words {
                for (field, mask) in masks.iter_mut().enumerate() {
                    *mask |= (read_u32(&p.memory, a[1] + (word * 12 + field * 4) as u64)? as u64)
                        << (word * 32);
                }
            }
            p.linux
                .vfs
                .credentials
                .caps
                .set(masks[0], masks[1], masks[2])?;
        } else {
            let c = if target == 0 || target as u32 == local {
                &p.linux.vfs.credentials.caps
            } else {
                let global = p.linux.vfs.global_pid(target as u32)?;
                &self
                    .processes
                    .get(&global)
                    .ok_or(Errno(3))?
                    .linux
                    .vfs
                    .credentials
                    .caps
            };
            let masks = [c.effective, c.permitted, c.inheritable];
            Linux::check(&p.memory, a[1], words * 12, Access::Write)?;
            for word in 0..words {
                for (field, mask) in masks.iter().enumerate() {
                    write_u32(
                        &mut p.memory,
                        a[1] + (word * 12 + field * 4) as u64,
                        (mask >> (word * 32)) as u32,
                    )?;
                }
            }
        }
        Ok(0)
    }
}
