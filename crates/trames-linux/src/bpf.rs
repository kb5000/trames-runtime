// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest cgroup device filters only. No program is handed to the host kernel.
use super::{Access, Linux, Memory};
use trames_vfs::Errno;

impl Linux {
    pub(super) fn bpf_syscall(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64, Errno> {
        self.vfs.bpf_authorized()?;
        let command = a[0] as u32;
        let size = a[2] as u32 as usize;
        if size > 4096 {
            return Err(Errno(7));
        }
        Self::check(memory, a[1], size, Access::Read)?;
        let mut attr = vec![0; size.max(152)];
        memory
            .read(a[1], &mut attr[..size])
            .map_err(|_| Errno(14))?;
        let u32_at = |i| u32::from_le_bytes(attr[i..i + 4].try_into().unwrap());
        let u64_at = |i| u64::from_le_bytes(attr[i..i + 8].try_into().unwrap());
        let tail = |i| {
            if attr[i..].iter().any(|b| *b != 0) {
                Err(Errno(7))
            } else {
                Ok(())
            }
        };
        match command {
            5 => {
                // BPF_PROG_LOAD
                tail(72)?;
                if u32_at(0) != 15 || !matches!(u32_at(68), 0 | 6) {
                    return Err(Errno(95));
                }
                if u32_at(40) != 0 || u32_at(44) != 0 || u32_at(64) != 0 || u32_at(24) & !7 != 0 {
                    return Err(Errno(22));
                }
                if attr[48..64]
                    .iter()
                    .take_while(|b| **b != 0)
                    .any(|b| !b.is_ascii_alphanumeric() && *b != b'_')
                {
                    return Err(Errno(22));
                }
                let count = u32_at(4) as usize;
                if count == 0 {
                    return Err(Errno(22));
                }
                if count > 4096 {
                    return Err(Errno(7));
                }
                memory
                    .read_c_string(u64_at(16), 128)
                    .map_err(|_| Errno(14))?;
                Self::check(memory, u64_at(8), count * 8, Access::Read)?;
                let mut code = vec![0; count * 8];
                memory.read(u64_at(8), &mut code).map_err(|_| Errno(14))?;
                // Preflight the bounded log before allocating an FD. The verifier
                // has no host pointers, helpers, loops, maps or stack memory.
                let log =
                    b"cgroup device verifier: unsupported or invalid instruction/control flow\n\0";
                let log_size = if u32_at(24) != 0 {
                    (u32_at(28) as usize).min(log.len())
                } else {
                    0
                };
                if log_size > 0 {
                    Self::check(memory, u64_at(32), log_size, Access::Write)?;
                }
                let result = self.vfs.bpf_load_device(&code);
                if log_size > 0 {
                    let mut bytes = if result.is_ok() {
                        vec![0]
                    } else {
                        log[..log_size].to_vec()
                    };
                    *bytes.last_mut().unwrap() = 0;
                    memory.write(u64_at(32), &bytes).map_err(|_| Errno(14))?;
                }
                result.map(u64::from)
            }
            8 | 9 => {
                // BPF_PROG_ATTACH / BPF_PROG_DETACH
                tail(20)?;
                if u32_at(8) != 6 {
                    return Err(Errno(95));
                }
                if command == 8 {
                    if u32_at(12) & 4 == 0 && u32_at(16) != 0 {
                        return Err(Errno(22));
                    }
                    self.vfs
                        .bpf_attach_device(u32_at(0), u32_at(4), u32_at(12), u32_at(16))?;
                } else {
                    if u32_at(12) != 0 || u32_at(16) != 0 {
                        return Err(Errno(22));
                    }
                    self.vfs.bpf_detach_device(u32_at(0), u32_at(4))?;
                }
                Ok(0)
            }
            13 => {
                // BPF_PROG_GET_FD_BY_ID
                tail(4)?;
                self.vfs.bpf_get_fd(u32_at(0)).map(u64::from)
            }
            16 => {
                // BPF_PROG_QUERY
                tail(28)?;
                if u32_at(4) != 6 {
                    return Err(Errno(95));
                }
                if u32_at(8) & !1 != 0 {
                    return Err(Errno(22));
                }
                let (flags, ids) = self.vfs.bpf_query_device(u32_at(0), u32_at(8) == 1)?;
                let capacity = u32_at(24) as usize;
                let copied = capacity.min(ids.len());
                Self::check(memory, a[1] + 12, 4, Access::Write)?;
                Self::check(memory, a[1] + 24, 4, Access::Write)?;
                Self::check(memory, u64_at(16), copied * 4, Access::Write)?;
                let bytes: Vec<_> = ids[..copied]
                    .iter()
                    .flat_map(|id| id.to_le_bytes())
                    .collect();
                memory.write(u64_at(16), &bytes).map_err(|_| Errno(14))?;
                memory
                    .write(a[1] + 12, &flags.to_le_bytes())
                    .map_err(|_| Errno(14))?;
                memory
                    .write(a[1] + 24, &(ids.len() as u32).to_le_bytes())
                    .map_err(|_| Errno(14))?;
                if capacity < ids.len() {
                    Err(Errno(28))
                } else {
                    Ok(0)
                }
            }
            _ => Err(Errno(95)),
        }
    }
}
