// SPDX-License-Identifier: GPL-3.0-or-later
use super::{errno, io_errno, GuestOutput, OutputFd, SyscallOutcome, MAX_WRITE};
use trames_cpu::Cpu;
use trames_memory::{Access, Memory, MemoryError, Permissions, ADDRESS_LIMIT, PAGE_SIZE};
use trames_vfs::{Errno, FdKind, Vfs, MAX_PATH};

type Result<T> = std::result::Result<T, Errno>;
#[derive(Clone)]
pub struct Linux {
    pub vfs: Vfs,
    pub trace: bool,
    brk_base: u64,
    brk: u64,
    mmap_next: u64,
    clear_child_tid: u64,
}

impl Linux {
    pub fn fork_tid(&mut self, address: u64) {
        self.clear_child_tid = address;
    }
    pub fn exit_tid(&mut self, memory: &mut Memory) {
        if self.clear_child_tid != 0 {
            let _ = memory.write(self.clear_child_tid, &[0; 4]);
        }
    }
    pub fn new(brk_base: u64) -> Self {
        Self {
            vfs: Vfs::default(),
            trace: false,
            brk_base,
            brk: brk_base,
            mmap_next: 0x1000_0000,
            clear_child_tid: 0,
        }
    }
    pub fn path(memory: &Memory, address: u64) -> Result<Vec<u8>> {
        memory.read_c_string(address, MAX_PATH).map_err(|e| {
            if e == MemoryError::Limit {
                Errno(36)
            } else {
                Errno(14)
            }
        })
    }
    pub fn check(memory: &Memory, address: u64, count: usize, access: Access) -> Result<()> {
        if address >= ADDRESS_LIMIT {
            return Err(Errno(14));
        }
        memory.check(address, count, access).map_err(|_| Errno(14))
    }
    fn write_bytes(&mut self, fd: u32, bytes: &[u8], io: &mut impl GuestOutput) -> Result<u64> {
        match self.vfs.fd_kind(fd)? {
            FdKind::Stdout | FdKind::Stderr => {
                let stream = if self.vfs.fd_kind(fd)? == FdKind::Stdout {
                    OutputFd::Stdout
                } else {
                    OutputFd::Stderr
                };
                if bytes.is_empty() {
                    return Ok(0);
                }
                let count = io
                    .write(stream, bytes)
                    .map_err(|e| Errno(io_errno(e) as u32))?;
                if count > bytes.len() {
                    return Err(Errno(5));
                }
                Ok(count as u64)
            }
            FdKind::Stdin => Err(Errno(9)),
            FdKind::Node(_) | FdKind::PipeRead | FdKind::PipeWrite | FdKind::Socket => {
                Ok(self.vfs.write(fd, bytes)? as u64)
            }
            FdKind::Terminal => Err(Errno(25)),
        }
    }
    fn read(&mut self, a: [u64; 6], memory: &mut Memory, io: &mut impl GuestOutput) -> Result<u64> {
        let fd = a[0] as u32;
        let kind = self.vfs.fd_kind(fd)?.clone();
        if matches!(kind, FdKind::Stdout | FdKind::Stderr) {
            return Err(Errno(9));
        }
        let count = a[2].min(MAX_WRITE as u64) as usize;
        Self::check(memory, a[1], count, Access::Write)?;
        let bytes = if kind == FdKind::Stdin {
            let mut bytes = vec![0; count];
            if count != 0 {
                let n = io
                    .poll_stdin(&mut bytes)
                    .map_err(|e| Errno(io_errno(e) as u32))?;
                if n > count {
                    return Err(Errno(5));
                }
                bytes.truncate(n);
            }
            bytes
        } else {
            self.vfs.read(fd, count)?
        };
        memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
        Ok(bytes.len() as u64)
    }
    fn write(&mut self, a: [u64; 6], memory: &Memory, io: &mut impl GuestOutput) -> Result<u64> {
        self.vfs.fd_kind(a[0] as u32)?;
        let count = a[2].min(MAX_WRITE as u64) as usize;
        Self::check(memory, a[1], count, Access::Read)?;
        let mut bytes = vec![0; count];
        memory.read(a[1], &mut bytes).map_err(|_| Errno(14))?;
        self.write_bytes(a[0] as u32, &bytes, io)
    }
    fn writev(&mut self, a: [u64; 6], memory: &Memory, io: &mut impl GuestOutput) -> Result<u64> {
        self.vfs.fd_kind(a[0] as u32)?;
        if a[2] > 1024 {
            return Err(Errno(22));
        }
        Self::check(memory, a[1], a[2] as usize * 16, Access::Read)?;
        let mut vectors = Vec::new();
        let mut total = 0usize;
        for index in 0..a[2] {
            let address = memory.read_u64(a[1] + index * 16).map_err(|_| Errno(14))?;
            let len = memory
                .read_u64(a[1] + index * 16 + 8)
                .map_err(|_| Errno(14))?;
            if len > i64::MAX as u64 {
                return Err(Errno(22));
            }
            let take = len.min((MAX_WRITE - total) as u64) as usize;
            Self::check(memory, address, take, Access::Read)?;
            vectors.push((address, take));
            total += take;
        }
        let mut bytes = vec![0; total];
        let mut position = 0;
        for (address, count) in vectors {
            memory
                .read(address, &mut bytes[position..position + count])
                .map_err(|_| Errno(14))?;
            position += count;
        }
        self.write_bytes(a[0] as u32, &bytes, io)
    }
    fn page_length(len: u64) -> Result<u64> {
        if len == 0 {
            return Err(Errno(22));
        }
        len.checked_add(PAGE_SIZE - 1)
            .map(|n| n & !(PAGE_SIZE - 1))
            .ok_or(Errno(22))
    }
    fn brk(&mut self, address: u64, memory: &mut Memory) -> u64 {
        if address == 0 || address < self.brk_base || address >= ADDRESS_LIMIT {
            return self.brk;
        }
        let Some(new_end) = address
            .checked_add(PAGE_SIZE - 1)
            .map(|n| n & !(PAGE_SIZE - 1))
        else {
            return self.brk;
        };
        let old_end = (self.brk + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if new_end > old_end
            && memory
                .map(old_end, new_end - old_end, Permissions::RW)
                .is_err()
        {
            return self.brk;
        }
        if new_end < old_end && memory.unmap(new_end, old_end - new_end).is_err() {
            return self.brk;
        }
        self.brk = address;
        address
    }
    fn mmap(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let len = Self::page_length(a[1])?;
        if len > trames_memory::DEFAULT_MEMORY_LIMIT as u64 {
            return Err(Errno(12));
        }
        let flags = a[3];
        const ALLOWED: u64 = 2 | 0x10 | 0x20 | 0x800 | 0x100000;
        if a[2] & !7 != 0
            || flags & !ALLOWED != 0
            || flags & 2 == 0
            || !a[5].is_multiple_of(PAGE_SIZE)
        {
            return Err(Errno(22));
        }
        let fixed = flags & (0x10 | 0x100000) != 0;
        if fixed && !a[0].is_multiple_of(PAGE_SIZE) {
            return Err(Errno(22));
        }
        let address = if fixed {
            a[0]
        } else if a[0] != 0 && memory.is_free(a[0] & !(PAGE_SIZE - 1), len) {
            a[0] & !(PAGE_SIZE - 1)
        } else {
            memory.find_free(self.mmap_next, len).ok_or(Errno(12))?
        };
        if flags & 0x100000 != 0 && !memory.is_free(address, len) {
            return Err(Errno(17));
        }
        let permissions = Permissions {
            read: a[2] & 1 != 0,
            write: a[2] & 2 != 0,
            execute: a[2] & 4 != 0,
        };
        // Read and validate the backing descriptor before MAP_FIXED changes memory.
        let file_bytes = if flags & 0x20 == 0 {
            let fd = a[4] as u32;
            let flags = self.vfs.flags(fd)?;
            if flags & 3 == 1 {
                return Err(Errno(13));
            }
            let stat = self.vfs.stat_fd(fd)?;
            if u32::from_le_bytes(stat[16..20].try_into().expect("stat")) & 0o170000 != 0o100000 {
                return Err(Errno(19));
            }
            let mut bytes = Vec::new();
            while bytes.len() < len as usize {
                let chunk = self.vfs.pread(
                    fd,
                    (len as usize - bytes.len()).min(MAX_WRITE),
                    a[5].checked_add(bytes.len() as u64).ok_or(Errno(22))?,
                )?;
                if chunk.is_empty() {
                    break;
                }
                bytes.extend(chunk);
            }
            Some(bytes)
        } else {
            None
        };
        let result = if flags & 0x10 != 0 {
            memory.map_fixed(address, len, Permissions::RW)
        } else {
            memory.map(address, len, Permissions::RW)
        };
        result.map_err(|_| Errno(12))?;
        if let Some(bytes) = file_bytes {
            memory.write(address, &bytes).map_err(|_| Errno(14))?;
        }
        memory
            .protect(address, len, permissions)
            .map_err(|_| Errno(12))?;
        if !fixed {
            self.mmap_next = address + len;
        }
        Ok(address)
    }
    pub fn dispatch(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        io: &mut impl GuestOutput,
    ) -> SyscallOutcome {
        let number = cpu.x(8) as u32 as u64;
        let a = std::array::from_fn(|index| cpu.x(index));
        if number == 93 || number == 94 {
            if self.clear_child_tid != 0 {
                let _ = memory.write(self.clear_child_tid, &[0; 4]);
            }
            if self.trace {
                eprintln!("trames syscall {number}: exit {}", a[0] as u8);
            }
            return SyscallOutcome::Exit(a[0] as u8);
        }
        let result = self.syscall(number, a, memory, io);
        let raw = match result {
            Ok(value) => value,
            Err(e) => errno(e.0 as u64),
        };
        if self.trace {
            eprintln!(
                "trames syscall {number}({:#x}, {:#x}, {:#x}) = {}",
                a[0], a[1], a[2], raw as i64
            );
        }
        cpu.set_x(0, raw);
        SyscallOutcome::Continue
    }
    fn syscall(
        &mut self,
        number: u64,
        a: [u64; 6],
        memory: &mut Memory,
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
        match number {
            32 => {
                self.vfs.flock(a[0] as u32, a[1] as u32)?;
                Ok(0)
            }
            278 => {
                if a[2] & !3 != 0 {
                    return Err(Errno(22));
                }
                let count = a[1].min(MAX_WRITE as u64) as usize;
                Self::check(memory, a[0], count, Access::Write)?;
                let mut bytes = vec![0; count];
                super::fill_entropy(&mut bytes)?;
                memory.write(a[0], &bytes).map_err(|_| Errno(14))?;
                Ok(count as u64)
            }
            198..=212 | 242 => self.network_syscall(number, a, memory),
            37 => {
                if a[4] & !0x400 != 0 {
                    return Err(Errno(22));
                }
                let old = Self::path(memory, a[1])?;
                let new = Self::path(memory, a[3])?;
                self.vfs.link_at(a[0] as i32, &old, a[2] as i32, &new)?;
                Ok(0)
            }
            38 | 276 => {
                let old = Self::path(memory, a[1])?;
                let new = Self::path(memory, a[3])?;
                self.vfs.rename_at(
                    a[0] as i32,
                    &old,
                    a[2] as i32,
                    &new,
                    if number == 276 { a[4] as u32 } else { 0 },
                )?;
                Ok(0)
            }
            43 | 44 => {
                if number == 43 {
                    let path = Self::path(memory, a[0])?;
                    self.vfs.stat_at(-100, &path)?;
                } else {
                    self.vfs.fd_kind(a[0] as u32)?;
                }
                Self::check(memory, a[1], 120, Access::Write)?;
                memory
                    .write(a[1], &self.vfs.storage_stat())
                    .map_err(|_| Errno(14))?;
                Ok(0)
            }
            45 => {
                let path = Self::path(memory, a[0])?;
                self.vfs.truncate_at(&path, a[1])?;
                Ok(0)
            }
            46 => {
                self.vfs.truncate_fd(a[0] as u32, a[1])?;
                Ok(0)
            }
            52 => {
                self.vfs.chmod_fd(a[0] as u32, a[1] as u32)?;
                Ok(0)
            }
            53 => {
                let path = Self::path(memory, a[1])?;
                self.vfs.chmod_at(a[0] as i32, &path, a[2] as u32)?;
                Ok(0)
            }
            67 | 68 => {
                self.vfs.fd_kind(a[0] as u32)?;
                let count = a[2].min(MAX_WRITE as u64) as usize;
                Self::check(
                    memory,
                    a[1],
                    count,
                    if number == 67 {
                        Access::Write
                    } else {
                        Access::Read
                    },
                )?;
                if number == 67 {
                    let bytes = self.vfs.pread(a[0] as u32, count, a[3])?;
                    memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
                    Ok(bytes.len() as u64)
                } else {
                    let mut bytes = vec![0; count];
                    memory.read(a[1], &mut bytes).map_err(|_| Errno(14))?;
                    Ok(self.vfs.pwrite(a[0] as u32, &bytes, a[3])? as u64)
                }
            }
            82 | 83 => {
                self.vfs.sync_fd(a[0] as u32, number == 83)?;
                Ok(0)
            }
            162 => {
                self.vfs.sync()?;
                Ok(0)
            }
            88 => {
                if a[3] & !0x100 != 0 {
                    return Err(Errno(22));
                }
                let path = if a[1] == 0 {
                    None
                } else {
                    Some(Self::path(memory, a[1])?)
                };
                let times = if a[2] == 0 {
                    None
                } else {
                    Self::check(memory, a[2], 32, Access::Read)?;
                    Some(std::array::from_fn(|i| {
                        std::array::from_fn(|j| {
                            memory
                                .read_u64(a[2] + (i * 16 + j * 8) as u64)
                                .expect("validated timespec") as i64
                        })
                    }))
                };
                self.vfs.set_times(a[0] as i32, path.as_deref(), times)?;
                Ok(0)
            }
            23 => Ok(self.vfs.dup(a[0] as u32, 0, false)? as u64),
            24 => Ok(self.vfs.dup3(a[0] as u32, a[1] as u32, a[2] as u32)? as u64),
            59 => {
                Self::check(memory, a[0], 8, Access::Write)?;
                let fds = self.vfs.pipe(a[1] as u32)?;
                let bytes: Vec<_> = fds.into_iter().flat_map(u32::to_le_bytes).collect();
                memory.write(a[0], &bytes).map_err(|_| Errno(14))?;
                Ok(0)
            }
            35 => {
                if a[2] & !0x200 != 0 {
                    return Err(Errno(22));
                }
                let path = Self::path(memory, a[1])?;
                self.vfs.unlink_at(a[0] as i32, &path, a[2] != 0)?;
                Ok(0)
            }
            63 => self.read(a, memory, io),
            64 => self.write(a, memory, io),
            66 => self.writev(a, memory, io),
            56 => {
                let path = Self::path(memory, a[1])?;
                Ok(self
                    .vfs
                    .open_at(a[0] as i32, &path, a[2] as u32, a[3] as u32)?
                    as u64)
            }
            57 => {
                self.vfs.close(a[0] as u32)?;
                Ok(0)
            }
            34 => {
                let path = Self::path(memory, a[1])?;
                self.vfs.mkdir_at(a[0] as i32, &path, a[2] as u32)?;
                Ok(0)
            }
            62 => self.vfs.seek(a[0] as u32, a[1] as i64, a[2] as u32),
            61 => {
                let count = a[2].min(MAX_WRITE as u64) as usize;
                self.vfs.fd_kind(a[0] as u32)?;
                Self::check(memory, a[1], count, Access::Write)?;
                let bytes = self.vfs.getdents(a[0] as u32, count)?;
                memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
                Ok(bytes.len() as u64)
            }
            79 => {
                if a[3] & !0x1100 != 0 {
                    return Err(Errno(22));
                }
                let path = Self::path(memory, a[1])?;
                Self::check(memory, a[2], 128, Access::Write)?;
                let stat = if path.is_empty() && a[3] & 0x1000 != 0 {
                    self.vfs.stat_fd(a[0] as u32)?
                } else {
                    self.vfs
                        .stat_at_flags(a[0] as i32, &path, a[3] & 0x100 != 0)?
                };
                memory.write(a[2], &stat).map_err(|_| Errno(14))?;
                Ok(0)
            }
            80 => {
                let stat = self.vfs.stat_fd(a[0] as u32)?;
                Self::check(memory, a[1], 128, Access::Write)?;
                memory.write(a[1], &stat).map_err(|_| Errno(14))?;
                Ok(0)
            }
            17 => {
                let mut bytes = self.vfs.cwd()?;
                let len = bytes.len() + 1;
                if a[1] < len as u64 {
                    return Err(Errno(34));
                }
                Self::check(memory, a[0], len, Access::Write)?;
                bytes.push(0);
                memory.write(a[0], &bytes).map_err(|_| Errno(14))?;
                Ok(len as u64)
            }
            50 => {
                self.vfs.chdir_fd(a[0] as u32)?;
                Ok(0)
            }
            49 => {
                let path = Self::path(memory, a[0])?;
                self.vfs.chdir(&path)?;
                Ok(0)
            }
            25 => {
                let flags = self.vfs.flags(a[0] as u32)?;
                match a[1] {
                    0 | 1030 => Ok(self.vfs.dup(a[0] as u32, a[2] as u32, a[1] == 1030)? as u64),
                    1 => Ok(if flags & 0x80000 != 0 { 1 } else { 0 }),
                    2 => {
                        self.vfs.set_cloexec(a[0] as u32, a[2] & 1 != 0)?;
                        Ok(0)
                    }
                    3 => Ok((flags & !(0x80000 | 0x40 | 0x80 | 0x100 | 0x200)) as u64),
                    4 => {
                        self.vfs.set_status_flags(a[0] as u32, a[2] as u32)?;
                        Ok(0)
                    }
                    _ => Err(Errno(22)),
                }
            }
            29 => {
                if self.vfs.fd_kind(a[0] as u32)? == FdKind::Socket {
                    self.network_ioctl(a, memory)
                } else {
                    Err(Errno(25))
                }
            }
            48 => {
                if a[2] & !7 != 0 {
                    return Err(Errno(22));
                }
                let path = Self::path(memory, a[1])?;
                let stat = self.vfs.stat_at(a[0] as i32, &path)?;
                let mode = u32::from_le_bytes(stat[16..20].try_into().expect("stat"));
                if mode & ((a[2] as u32) << 6) != (a[2] as u32) << 6 {
                    Err(Errno(13))
                } else {
                    Ok(0)
                }
            }
            36 => {
                let target = Self::path(memory, a[0])?;
                let path = Self::path(memory, a[2])?;
                self.vfs.symlink_at(&target, a[1] as i32, &path)?;
                Ok(0)
            }
            78 => {
                if a[3] == 0 {
                    return Err(Errno(22));
                }
                let path = Self::path(memory, a[1])?;
                let target = self.vfs.readlink_at(a[0] as i32, &path)?;
                let count = (a[3] as usize).min(target.len());
                Self::check(memory, a[2], count, Access::Write)?;
                memory
                    .write(a[2], &target[..count])
                    .map_err(|_| Errno(14))?;
                Ok(count as u64)
            }
            96 => {
                if a[0] != 0 {
                    Self::check(memory, a[0], 4, Access::Write)?;
                }
                self.clear_child_tid = a[0];
                Ok(1)
            }
            98 => {
                if !a[0].is_multiple_of(4) {
                    return Err(Errno(22));
                }
                Self::check(memory, a[0], 4, Access::Read)?;
                match a[1] & !128 {
                    1 => Ok(0),
                    0 => {
                        let mut bytes = [0; 4];
                        memory.read(a[0], &mut bytes).map_err(|_| Errno(14))?;
                        if u32::from_le_bytes(bytes) != a[2] as u32 {
                            Err(Errno(11))
                        } else {
                            Err(Errno(38))
                        }
                    }
                    _ => Err(Errno(38)),
                }
            }
            172 => Ok(1),
            173 => Ok(0),
            174..=177 => Ok(1000),
            166 => {
                let previous = self.vfs.umask;
                self.vfs.umask = a[0] as u32 & 0o777;
                Ok(previous as u64)
            }
            214 => Ok(self.brk(a[0], memory)),
            222 => self.mmap(a, memory),
            215 => {
                let len = Self::page_length(a[1])?;
                memory.unmap(a[0], len).map_err(|_| Errno(22))?;
                Ok(0)
            }
            226 => {
                if a[2] & !7 != 0 {
                    return Err(Errno(22));
                }
                if a[1] == 0 {
                    return if a[0].is_multiple_of(PAGE_SIZE) {
                        Ok(0)
                    } else {
                        Err(Errno(22))
                    };
                }
                let len = Self::page_length(a[1])?;
                memory
                    .protect(
                        a[0],
                        len,
                        Permissions {
                            read: a[2] & 1 != 0,
                            write: a[2] & 2 != 0,
                            execute: a[2] & 4 != 0,
                        },
                    )
                    .map_err(|e| {
                        if e == MemoryError::UnalignedMapping {
                            Errno(22)
                        } else {
                            Errno(12)
                        }
                    })?;
                Ok(0)
            }
            _ => Err(Errno(38)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapturedOutput;
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        m
    }

    #[test]
    fn invalid_read_buffer_does_not_consume_file_or_stdin() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let mut out = CapturedOutput {
            stdin: b"input".to_vec(),
            ..CapturedOutput::default()
        };
        linux.vfs.import_file(b"/file", b"abc".to_vec()).unwrap();
        let fd = linux.vfs.open_at(-100, b"/file", 0, 0).unwrap() as u64;
        assert_eq!(
            linux.syscall(63, [fd, u64::MAX, 3, 0, 0, 0], &mut m, &mut out),
            Err(Errno(14))
        );
        assert_eq!(
            linux.syscall(63, [fd, 0x1000, 3, 0, 0, 0], &mut m, &mut out),
            Ok(3)
        );
        let mut bytes = [0; 3];
        m.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");
        assert_eq!(
            linux.syscall(63, [0, u64::MAX, 5, 0, 0, 0], &mut m, &mut out),
            Err(Errno(14))
        );
        assert_eq!(
            linux.syscall(63, [0, 0x1000, 5, 0, 0, 0], &mut m, &mut out),
            Ok(5)
        );
        let mut bytes = [0; 5];
        m.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"input");
    }

    #[test]
    fn writev_validates_all_buffers_before_any_output() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let mut out = CapturedOutput::default();
        for (i, value) in [0x1100u64, 1, u64::MAX, 1].into_iter().enumerate() {
            m.write(0x1000 + i as u64 * 8, &value.to_le_bytes())
                .unwrap();
        }
        m.write(0x1100, b"a").unwrap();
        assert_eq!(
            linux.syscall(66, [1, 0x1000, 2, 0, 0, 0], &mut m, &mut out),
            Err(Errno(14))
        );
        assert!(out.stdout.is_empty());
        m.write(0x1010, &0x1100u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.syscall(66, [1, 0x1000, 2, 0, 0, 0], &mut m, &mut out),
            Ok(2)
        );
        assert_eq!(out.stdout, b"aa");
    }

    #[test]
    fn partial_vectored_output_is_returned_without_retry() {
        struct Short(usize);
        impl GuestOutput for Short {
            fn write(&mut self, _: OutputFd, _: &[u8]) -> std::io::Result<usize> {
                self.0 += 1;
                Ok(1)
            }
        }
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let mut out = Short(0);
        m.write(0x1000, &0x1100u64.to_le_bytes()).unwrap();
        m.write(0x1008, &3u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.syscall(66, [1, 0x1000, 1, 0, 0, 0], &mut m, &mut out),
            Ok(1)
        );
        assert_eq!(out.0, 1);
    }

    #[test]
    fn brk_rejection_keeps_the_previous_break_and_mapping() {
        let mut linux = Linux::new(0x1000);
        let mut m = Memory::new(4096);
        assert_eq!(linux.brk(0x1800, &mut m), 0x1800);
        m.write(0x1000, b"x").unwrap();
        assert_eq!(linux.brk(0x3000, &mut m), 0x1800);
        assert_eq!(m.mapped_bytes(), 4096);
        assert_eq!(linux.brk(0x800, &mut m), 0x1800);
        assert_eq!(linux.brk(0x1000, &mut m), 0x1000);
        assert_eq!(m.mapped_bytes(), 0);
    }

    #[test]
    fn mmap_fixed_noreplace_and_protection_are_checked() {
        let mut linux = Linux::new(0x1000);
        let mut m = Memory::new(8192);
        let mut out = CapturedOutput::default();
        let flags = 0x32;
        assert_eq!(
            linux.syscall(222, [0x1000, 4096, 3, flags, u64::MAX, 0], &mut m, &mut out),
            Ok(0x1000)
        );
        m.write(0x1000, b"x").unwrap();
        assert_eq!(
            linux.syscall(
                222,
                [0x1000, 4096, 3, 0x100022, u64::MAX, 0],
                &mut m,
                &mut out
            ),
            Err(Errno(17))
        );
        assert_eq!(
            linux.syscall(226, [0x1000, 8192, 1, 0, 0, 0], &mut m, &mut out),
            Err(Errno(12))
        );
        m.write(0x1000, b"y").unwrap();
        assert_eq!(
            linux.syscall(226, [0x1000, 4096, 1, 0, 0, 0], &mut m, &mut out),
            Ok(0)
        );
        assert!(m.write(0x1000, b"z").is_err());
        assert_eq!(
            linux.syscall(222, [0x1000, 4096, 3, flags, u64::MAX, 0], &mut m, &mut out),
            Ok(0x1000)
        );
        assert_eq!(m.read_u64(0x1000).unwrap(), 0);
    }

    #[test]
    fn futex_wait_does_not_pretend_to_complete_and_fds_are_stateful() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let mut out = CapturedOutput::default();
        assert_eq!(
            linux.syscall(98, [0x1000, 128, 1, 0, 0, 0], &mut m, &mut out),
            Err(Errno(11))
        );
        assert_eq!(
            linux.syscall(98, [0x1000, 128, 0, 0, 0, 0], &mut m, &mut out),
            Err(Errno(38))
        );
        assert_eq!(
            linux.syscall(25, [1, 2, 1, 0, 0, 0], &mut m, &mut out),
            Ok(0)
        );
        assert_eq!(
            linux.syscall(25, [1, 1, 0, 0, 0, 0], &mut m, &mut out),
            Ok(1)
        );
        assert_eq!(
            linux.syscall(57, [1, 0, 0, 0, 0, 0], &mut m, &mut out),
            Ok(0)
        );
        assert_eq!(
            linux.syscall(64, [1, 0x1000, 0, 0, 0, 0], &mut m, &mut out),
            Err(Errno(9))
        );
    }
}
