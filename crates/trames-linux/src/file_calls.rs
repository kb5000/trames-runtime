// SPDX-License-Identifier: GPL-3.0-or-later
use crate::state::Linux;
use crate::{GuestOutput, MAX_WRITE};
use trames_memory::{Access, Memory};
use trames_vfs::Errno;
type Result<T> = std::result::Result<T, Errno>;
impl Linux {
    fn regular_file(&self, fd: u32) -> Result<[u8; 128]> {
        let stat = self.vfs.stat_fd(fd)?;
        if u32::from_le_bytes(stat[16..20].try_into().expect("mode")) & 0o170000 != 0o100000 {
            return Err(Errno(22));
        }
        Ok(stat)
    }
    fn copy_offset(&self, fd: u32, pointer: u64, memory: &Memory) -> Result<u64> {
        if pointer == 0 {
            return Err(Errno(22));
        }
        Self::check(memory, pointer, 8, Access::Read)?;
        Self::check(memory, pointer, 8, Access::Write)?;
        self.vfs.fd_kind(fd)?;
        let offset = memory.read_u64(pointer).map_err(|_| Errno(14))?;
        if offset > i64::MAX as u64 {
            return Err(Errno(22));
        }
        Ok(offset)
    }
    pub(super) fn file_syscall(
        &mut self,
        number: u64,
        a: [u64; 6],
        memory: &mut Memory,
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
        match number {
            213 | 223 => {
                self.regular_file(a[0] as u32)?;
                if a[1] > i64::MAX as u64 || number == 223 && (a[2] > i64::MAX as u64 || a[3] > 5) {
                    return Err(Errno(22));
                }
                Ok(0) // Kernel prefetch/eviction advice is optional, not a data operation.
            }
            267 => {
                self.vfs.fd_kind(a[0] as u32)?;
                self.vfs.sync()?;
                Ok(0)
            }
            452 => {
                if a[3] & !0x1100 != 0 {
                    return Err(Errno(22));
                }
                let path = if a[1] == 0 && a[3] & 0x1000 != 0 {
                    Vec::new()
                } else {
                    Self::path(memory, a[1])?
                };
                if path.is_empty() && a[3] & 0x1000 != 0 {
                    if a[0] as i32 == -100 {
                        self.vfs.chmod_at(-100, b".", a[2] as u32)?;
                    } else {
                        self.vfs.chmod_fd_at(a[0] as u32, a[2] as u32)?;
                    }
                } else {
                    self.vfs
                        .chmod_at_flags(a[0] as i32, &path, a[2] as u32, a[3] & 0x100 != 0)?;
                }
                Ok(0)
            }
            437 => {
                if a[3] < 24 {
                    return Err(Errno(22));
                }
                if a[3] > 4096 {
                    return Err(Errno(7));
                }
                Self::check(memory, a[2], a[3] as usize, Access::Read)?;
                let flags = memory.read_u64(a[2]).map_err(|_| Errno(14))?;
                let mode = memory.read_u64(a[2] + 8).map_err(|_| Errno(14))?;
                let resolve = memory.read_u64(a[2] + 16).map_err(|_| Errno(14))?;
                let mut tail = vec![0; (a[3] - 24) as usize];
                memory.read(a[2] + 24, &mut tail).map_err(|_| Errno(14))?;
                if tail.iter().any(|b| *b != 0) {
                    return Err(Errno(7));
                }
                if flags > u32::MAX as u64
                    || mode & !0o7777 != 0
                    || mode != 0 && flags & 0x40 == 0
                    || resolve & !63 != 0
                {
                    return Err(Errno(22));
                }
                if resolve != 0 {
                    return Err(Errno(95));
                } // Never silently ignore a path-containment requirement.
                let path = Self::path(memory, a[1])?;
                Ok(self
                    .vfs
                    .open_at(a[0] as i32, &path, flags as u32, mode as u32)?
                    as u64)
            }
            286 | 287 => {
                if a[5] & !6 != 0 {
                    return Err(Errno(95));
                }
                let result = if a[3] == u64::MAX {
                    if number == 286 {
                        self.readv(a, memory, io)?
                    } else {
                        self.writev(a, memory, io)?
                    }
                } else {
                    self.positioned_vector(a, memory, number == 287)?
                };
                if number == 287 && a[5] & 6 != 0 {
                    self.vfs.sync_fd(a[0] as u32, a[5] & 4 == 0)?;
                }
                Ok(result)
            }
            71 | 285 => {
                let copy = number == 285;
                let (input, output, in_pointer, out_pointer, count) = if copy {
                    (a[0] as u32, a[2] as u32, a[1], a[3], a[4])
                } else {
                    (a[1] as u32, a[0] as u32, a[2], 0, a[3])
                };
                if copy && a[5] != 0 {
                    return Err(Errno(22));
                }
                let from = self.regular_file(input)?;
                self.vfs.fd_kind(output)?;
                let from_offset = if in_pointer == 0 {
                    self.vfs.seek(input, 0, 1)?
                } else {
                    self.copy_offset(input, in_pointer, memory)?
                };
                let to_offset = if copy {
                    let to = self.regular_file(output)?;
                    if self.vfs.flags(output)? & 0x400 != 0 {
                        return Err(Errno(9));
                    }
                    let offset = if out_pointer == 0 {
                        self.vfs.seek(output, 0, 1)?
                    } else {
                        self.copy_offset(output, out_pointer, memory)?
                    };
                    if from[..16] == to[..16]
                        && from_offset < offset.saturating_add(count)
                        && offset < from_offset.saturating_add(count)
                    {
                        return Err(Errno(22));
                    }
                    Some(offset)
                } else {
                    None
                };
                let bytes =
                    self.vfs
                        .pread(input, (count.min(MAX_WRITE as u64)) as usize, from_offset)?;
                let written = if let Some(to) = to_offset {
                    self.vfs.pwrite(output, &bytes, to)? as u64
                } else {
                    self.write_bytes(output, &bytes, io)?
                };
                if in_pointer == 0 {
                    self.vfs.seek(input, (from_offset + written) as i64, 0)?;
                } else {
                    memory
                        .write(in_pointer, &(from_offset + written).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if let Some(to) = to_offset {
                    if out_pointer == 0 {
                        self.vfs.seek(output, (to + written) as i64, 0)?;
                    } else {
                        memory
                            .write(out_pointer, &(to + written).to_le_bytes())
                            .map_err(|_| Errno(14))?;
                    }
                }
                Ok(written)
            }
            _ => Err(Errno(38)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapturedOutput;
    use trames_memory::Permissions;
    #[test]
    fn invalid_copy_offset_does_not_write_or_advance_descriptors() {
        let mut l = Linux::new(0x3000);
        let mut memory = Memory::default();
        memory.map(0x1000, 4096, Permissions::RW).unwrap();
        l.vfs.import_file(b"/src", b"abcdef".to_vec()).unwrap();
        let from = l.vfs.open_at(-100, b"/src", 0, 0).unwrap();
        let to = l.vfs.open_at(-100, b"/dst", 0x42, 0o600).unwrap();
        let mut io = CapturedOutput::default();
        let a = [from as u64, 0, to as u64, 0x9000, 3, 0];
        assert_eq!(l.file_syscall(285, a, &mut memory, &mut io), Err(Errno(14)));
        assert_eq!(l.vfs.seek(from, 0, 1).unwrap(), 0);
        assert_eq!(l.vfs.pread(to, 3, 0).unwrap(), b"");
        let a = [from as u64, 0, to as u64, 0, 3, 0];
        assert_eq!(l.file_syscall(285, a, &mut memory, &mut io), Ok(3));
        assert_eq!(l.vfs.seek(from, 0, 1).unwrap(), 3);
        assert_eq!(l.vfs.pread(to, 3, 0).unwrap(), b"abc");
    }
    #[test]
    fn openat2_never_ignores_containment_flags_or_unknown_tail_fields() {
        let mut l = Linux::new(0x3000);
        let mut memory = Memory::default();
        memory.map(0x1000, 4096, Permissions::RW).unwrap();
        memory.write(0x1000, b"/file\0").unwrap();
        memory.write(0x1100, &0x42u64.to_le_bytes()).unwrap();
        memory.write(0x1108, &0o600u64.to_le_bytes()).unwrap();
        memory.write(0x1110, &8u64.to_le_bytes()).unwrap();
        let mut io = CapturedOutput::default();
        assert_eq!(
            l.file_syscall(
                437,
                [(-100i64) as u64, 0x1000, 0x1100, 24, 0, 0],
                &mut memory,
                &mut io
            ),
            Err(Errno(95))
        );
        assert_eq!(l.vfs.stat_at(-100, b"/file"), Err(Errno(2)));
        memory.write(0x1110, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1118, &1u64.to_le_bytes()).unwrap();
        assert_eq!(
            l.file_syscall(
                437,
                [(-100i64) as u64, 0x1000, 0x1100, 32, 0, 0],
                &mut memory,
                &mut io
            ),
            Err(Errno(7))
        );
        assert_eq!(l.vfs.stat_at(-100, b"/file"), Err(Errno(2)));
    }
}
