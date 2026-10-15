// SPDX-License-Identifier: GPL-3.0-or-later
use super::{Access, Linux, Memory};
use trames_vfs::Errno;
impl Linux {
    pub(super) fn xattr_syscall(
        &mut self,
        number: u64,
        a: [u64; 6],
        memory: &mut Memory,
    ) -> Result<u64, Errno> {
        let variant = (number - 5) % 3;
        let path = if variant == 2 {
            None
        } else {
            Some(Self::path(memory, a[0])?)
        };
        let fd = if variant == 2 { a[0] as i32 } else { -100 };
        let follow = variant != 1;
        let list = (11..=13).contains(&number);
        let name = if list {
            Vec::new()
        } else {
            memory.read_c_string(a[1], 256).map_err(|e| match e {
                trames_memory::MemoryError::Limit => Errno(34),
                _ => Errno(14),
            })?
        };
        match number {
            5..=7 => {
                if a[3] > 65536 {
                    return Err(Errno(7));
                }
                Self::check(memory, a[2], a[3] as usize, Access::Read)?;
                let mut value = vec![0; a[3] as usize];
                memory.read(a[2], &mut value).map_err(|_| Errno(14))?;
                self.vfs.set_xattr(
                    fd,
                    path.as_deref(),
                    follow,
                    &name,
                    Some(&value),
                    a[4] as u32,
                )?;
                Ok(0)
            }
            8..=13 => {
                let value = if list {
                    self.vfs.list_xattrs(fd, path.as_deref(), follow)?
                } else {
                    self.vfs.get_xattr(fd, path.as_deref(), follow, &name)?
                };
                let (pointer, capacity) = if list { (a[1], a[2]) } else { (a[2], a[3]) };
                if capacity != 0 {
                    if capacity < value.len() as u64 {
                        return Err(Errno(34));
                    }
                    Self::check(memory, pointer, value.len(), Access::Write)?;
                    memory.write(pointer, &value).map_err(|_| Errno(14))?;
                }
                Ok(value.len() as u64)
            }
            14..=16 => {
                self.vfs
                    .set_xattr(fd, path.as_deref(), follow, &name, None, 0)?;
                Ok(0)
            }
            _ => unreachable!(),
        }
    }
}
