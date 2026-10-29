// SPDX-License-Identifier: GPL-3.0-or-later
use super::{errno, io_errno, GuestOutput, OutputFd, SyscallOutcome, MAX_WRITE};
use trames_execution::Registers;
use trames_memory::{
    Access, CpuMemory, Memory, MemoryError, Permissions, ADDRESS_LIMIT, PAGE_SIZE,
};
use trames_vfs::capabilities;
use trames_vfs::{Errno, FdKind, Vfs, MAX_PATH};

type Result<T> = std::result::Result<T, Errno>;
pub(crate) struct VectorImport {
    pub parts: Vec<(u64, usize)>,
    pub total: usize,
    pub requested: u64,
}

// Keep anonymous PROT_NONE cages/stacks away from the ordinary mmap cursor.
// Otherwise a large virtual-only reservation scatters subsequent small heap
// regions, making allocators such as Scudo scan vast empty spans on release.
// Memory's sparse reservation table finds/reuses holes without committing RAM.
const RESERVATION_BASE: u64 = 0x4000_0000_0000;

pub struct Linux {
    pub(crate) batch_pipe_signal: bool,
    pub(crate) uring_clock: std::time::Instant,
    pub(crate) uring_active: Vec<std::rc::Weak<trames_vfs::Uring>>,
    pub vfs: Vfs,
    pub trace: bool,
    /// Initial session capacity for guest processes and threads. Jobs and
    /// stacks remain demand allocated; this does not create host CPU workers.
    pub task_limit: usize,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<Vec<u8>>,
    pub executable_path: Vec<u8>,
    pub executable_file: Option<std::rc::Rc<trames_vfs::ExecutableFile>>,
    pub command_name: Vec<u8>,
    pub argument_pointers: Vec<u64>,
    pub auxiliary: Vec<u8>,
    heap: crate::heap::Heap,
    clear_child_tid: u64,
}
impl Clone for Linux {
    fn clone(&self) -> Self {
        self.clone_with_files(false)
    }
}
impl Linux {
    /// Clone task context while choosing Files, FS and VM allocation domains.
    /// CLONE_FILES never allocates a temporary private FD map or flag cells.
    pub fn clone_with_files(&self, shared: bool) -> Self {
        self.clone_with_resources(shared, false, false)
    }
    pub fn clone_with_resources(
        &self,
        shared_files: bool,
        shared_fs: bool,
        shared_vm: bool,
    ) -> Self {
        Self {
            batch_pipe_signal: false,
            uring_clock: self.uring_clock,
            uring_active: self.uring_active.clone(),
            vfs: self.vfs.clone_with_resources(shared_files, shared_fs),
            trace: self.trace,
            task_limit: self.task_limit,
            arguments: self.arguments.clone(),
            environment: self.environment.clone(),
            executable_path: self.executable_path.clone(),
            executable_file: self.executable_file.clone(),
            command_name: self.command_name.clone(),
            argument_pointers: self.argument_pointers.clone(),
            auxiliary: self.auxiliary.clone(),
            heap: if shared_vm {
                self.heap.shared()
            } else {
                self.heap.clone()
            },
            clear_child_tid: self.clear_child_tid,
        }
    }
}

impl Linux {
    /// Diagnostic snapshot only; normal syscalls do not compare or propagate it.
    pub fn heap_context(&self) -> (u64, u64, u64) {
        (self.heap.base(), self.heap.current(), self.heap.cursor())
    }
    pub fn program_break(&self) -> crate::ProgramBreak {
        self.heap.break_capability()
    }
    pub fn clear_tid_address(&self) -> u64 {
        self.clear_child_tid
    }
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
            batch_pipe_signal: false,
            uring_clock: std::time::Instant::now(),
            uring_active: Vec::new(),
            vfs: Vfs::default(),
            trace: false,
            task_limit: trames_vfs::MAX_TASKS,
            arguments: Vec::new(),
            environment: Vec::new(),
            executable_path: Vec::new(),
            executable_file: None,
            command_name: Vec::new(),
            argument_pointers: Vec::new(),
            auxiliary: Vec::new(),
            heap: crate::heap::Heap::new(brk_base),
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
    pub fn record_lock_holder(&self, memory: &Memory, a: [u64; 6]) -> Result<Option<u32>> {
        Self::check(memory, a[2], 32, Access::Read)?;
        let mut bytes = [0; 32];
        memory.read(a[2], &mut bytes).map_err(|_| Errno(14))?;
        let requested = self.vfs.normalize_lock(
            a[0] as u32,
            u16::from_le_bytes(bytes[..2].try_into().expect("lock type")),
            u16::from_le_bytes(bytes[2..4].try_into().expect("lock whence")),
            i64::from_le_bytes(bytes[8..16].try_into().expect("lock start")),
            i64::from_le_bytes(bytes[16..24].try_into().expect("lock length")),
        )?;
        Ok(self
            .vfs
            .record_lock_conflict(a[0] as u32, requested)?
            .map(|lock| lock.owner))
    }
    pub fn check(
        memory: &impl CpuMemory,
        address: u64,
        count: usize,
        access: Access,
    ) -> Result<()> {
        if address >= ADDRESS_LIMIT {
            return Err(Errno(14));
        }
        memory.check(address, count, access).map_err(|_| Errno(14))
    }
    pub(super) fn write_bytes(
        &mut self,
        fd: u32,
        bytes: &[u8],
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
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
            FdKind::Node(_)
            | FdKind::PipeRead
            | FdKind::PipeWrite
            | FdKind::Socket
            | FdKind::Anonymous => Ok(self.vfs.write(fd, bytes)? as u64),
            FdKind::Terminal => Err(Errno(25)),
        }
    }
    pub fn read(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
        let fd = a[0] as u32;
        self.vfs.fd_kind(fd)?;
        Self::read_transport(a, memory, |count| self.read_bytes(fd, count, io))
    }
    pub(crate) fn read_transport(
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        read: impl FnOnce(usize) -> Result<Vec<u8>>,
    ) -> Result<u64> {
        let count = a[2].min(MAX_WRITE as u64) as usize;
        Self::check(memory, a[1], count, Access::Write)?;
        let bytes = read(count)?;
        memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
        Ok(bytes.len() as u64)
    }
    fn read_bytes(&mut self, fd: u32, count: usize, io: &mut impl GuestOutput) -> Result<Vec<u8>> {
        let kind = self.vfs.fd_kind(fd)?.clone();
        if matches!(kind, FdKind::Stdout | FdKind::Stderr) {
            return Err(Errno(9));
        }
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
        Ok(bytes)
    }
    pub fn readv_parts(memory: &impl CpuMemory, a: [u64; 6]) -> Result<(Vec<(u64, usize)>, usize)> {
        if a[2] > 1024 {
            return Err(Errno(22));
        }
        Self::check(memory, a[1], a[2] as usize * 16, Access::Read)?;
        let mut parts = Vec::new();
        let mut total = 0usize;
        let mut requested = 0u64;
        for i in 0..a[2] {
            let pointer = memory.read_u64(a[1] + i * 16).map_err(|_| Errno(14))?;
            let length = memory.read_u64(a[1] + i * 16 + 8).map_err(|_| Errno(14))?;
            requested = requested
                .checked_add(length)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Errno(22))?;
            let take = length.min((MAX_WRITE - total) as u64) as usize;
            if take != 0 {
                Self::check(memory, pointer, take, Access::Write)?;
            }
            parts.push((pointer, take));
            total += take;
        }
        Ok((parts, total))
    }
    pub fn scatter(
        memory: &mut impl CpuMemory,
        parts: &[(u64, usize)],
        bytes: &[u8],
    ) -> Result<()> {
        let mut offset = 0;
        for &(pointer, length) in parts {
            let take = length.min(bytes.len() - offset);
            if take != 0 {
                memory
                    .write(pointer, &bytes[offset..offset + take])
                    .map_err(|_| Errno(14))?;
            }
            offset += take;
            if offset == bytes.len() {
                break;
            }
        }
        Ok(())
    }
    pub fn readv(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
        let records = self.vfs.readv_records(a[0] as u32)?;
        Self::readv_transport_mode(a, memory, records, |count| {
            self.read_bytes(a[0] as u32, count, io)
        })
    }
    pub(crate) fn readv_transport_mode(
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        records: bool,
        mut read: impl FnMut(usize) -> Result<Vec<u8>>,
    ) -> Result<u64> {
        let (parts, count) = Self::readv_parts(memory, a)?;
        if !records {
            let bytes = read(count)?;
            Self::scatter(memory, &parts, &bytes)?;
            return Ok(bytes.len() as u64);
        }
        let mut total = 0;
        for (pointer, count) in parts {
            if count == 0 {
                continue;
            }
            let bytes = match read(count) {
                Ok(bytes) => bytes,
                Err(error) if total == 0 => return Err(error),
                Err(_) => break,
            };
            memory.write(pointer, &bytes).map_err(|_| Errno(14))?;
            total += bytes.len() as u64;
            if bytes.len() < count {
                break;
            }
        }
        Ok(total)
    }
    pub fn write(
        &mut self,
        a: [u64; 6],
        memory: &impl CpuMemory,
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
        self.write_scratch(a, memory, io, &mut Vec::new())
    }
    pub fn write_scratch(
        &mut self,
        a: [u64; 6],
        memory: &impl CpuMemory,
        io: &mut impl GuestOutput,
        bytes: &mut Vec<u8>,
    ) -> Result<u64> {
        self.vfs.fd_kind(a[0] as u32)?;
        Self::write_transport(a, memory, bytes, |bytes| {
            self.write_bytes(a[0] as u32, bytes, io)
        })
    }
    pub(crate) fn write_transport(
        a: [u64; 6],
        memory: &impl CpuMemory,
        bytes: &mut Vec<u8>,
        write: impl FnOnce(&[u8]) -> Result<u64>,
    ) -> Result<u64> {
        let count = a[2].min(MAX_WRITE as u64) as usize;
        Self::check(memory, a[1], count, Access::Read)?;
        bytes.resize(count, 0);
        memory.read(a[1], bytes).map_err(|_| Errno(14))?;
        write(bytes)
    }
    /// ARM64 positioned scalar I/O, shared by joined and in-epoch dispatch.
    pub fn positioned(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        write: bool,
    ) -> Result<u64> {
        self.positioned_scratch(a, memory, write, &mut Vec::new())
    }
    pub fn positioned_scratch(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        write: bool,
        bytes: &mut Vec<u8>,
    ) -> Result<u64> {
        self.vfs.fd_kind(a[0] as u32)?;
        let count = a[2].min(MAX_WRITE as u64) as usize;
        Self::check(
            memory,
            a[1],
            count,
            if write { Access::Read } else { Access::Write },
        )?;
        if write {
            bytes.resize(count, 0);
            memory.read(a[1], bytes).map_err(|_| Errno(14))?;
            Ok(self.vfs.pwrite(a[0] as u32, bytes, a[3])? as u64)
        } else {
            let bytes = self.vfs.pread(a[0] as u32, count, a[3])?;
            memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
            Ok(bytes.len() as u64)
        }
    }
    /// Metadata/offset queries do not change mappings or file contents. The
    /// coordinator and in-epoch service use the same ABI and memory validation.
    pub fn fd_query(
        &mut self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        match number {
            25 => trames_vfs::query_fd_flags(self.vfs.flags(a[0] as u32)?, a[1]),
            62 => self.vfs.seek(a[0] as u32, a[1] as i64, a[2] as u32),
            80 => {
                let stat = self.vfs.stat_fd(a[0] as u32)?;
                Self::check(memory, a[1], 128, Access::Write)?;
                memory.write(a[1], &stat).map_err(|_| Errno(14))?;
                Ok(0)
            }
            _ => Err(Errno(38)),
        }
    }
    pub fn writev(
        &mut self,
        a: [u64; 6],
        memory: &impl CpuMemory,
        io: &mut impl GuestOutput,
    ) -> Result<u64> {
        self.writev_scratch(a, memory, io, &mut Vec::new())
    }
    pub fn writev_scratch(
        &mut self,
        a: [u64; 6],
        memory: &impl CpuMemory,
        io: &mut impl GuestOutput,
        bytes: &mut Vec<u8>,
    ) -> Result<u64> {
        let records = self.vfs.is_eventfd(a[0] as u32)?;
        Self::writev_transport_mode(a, memory, bytes, records, |bytes| {
            self.write_bytes(a[0] as u32, bytes, io)
        })
    }
    pub(crate) fn writev_transport_mode(
        a: [u64; 6],
        memory: &impl CpuMemory,
        bytes: &mut Vec<u8>,
        records: bool,
        mut write: impl FnMut(&[u8]) -> Result<u64>,
    ) -> Result<u64> {
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
        bytes.resize(total, 0);
        let mut position = 0;
        for &(address, count) in &vectors {
            memory
                .read(address, &mut bytes[position..position + count])
                .map_err(|_| Errno(14))?;
            position += count;
        }
        if !records {
            return write(bytes);
        }
        let mut position = 0;
        let mut total = 0;
        for (_, count) in vectors {
            if count == 0 {
                continue;
            }
            let written = match write(&bytes[position..position + count]) {
                Ok(written) => written,
                Err(error) if total == 0 => return Err(error),
                Err(_) => break,
            };
            total += written;
            if written < count as u64 {
                break;
            }
            position += count;
        }
        Ok(total)
    }
    pub fn positioned_vector(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        write: bool,
    ) -> Result<u64> {
        self.positioned_vector_scratch(a, memory, write, &mut Vec::new())
    }
    pub(crate) fn positioned_vector_parts(
        memory: &impl CpuMemory,
        a: [u64; 6],
        write: bool,
    ) -> Result<(Vec<(u64, usize)>, usize)> {
        Self::positioned_vector_import(memory, a, write).map(|v| (v.parts, v.total))
    }
    /// Import each iovec once. Keep the uncapped length for io_uring link
    /// short-transfer rules without re-reading a mutable guest vector table.
    pub(crate) fn positioned_vector_import(
        memory: &impl CpuMemory,
        a: [u64; 6],
        write: bool,
    ) -> Result<VectorImport> {
        if a[3] > i64::MAX as u64 {
            return Err(Errno(22));
        }
        if a[2] > 1024 {
            return Err(Errno(22));
        }
        Self::check(memory, a[1], a[2] as usize * 16, Access::Read)?;
        let mut parts = Vec::new();
        let mut total = 0usize;
        let mut requested = 0u64;
        for i in 0..a[2] {
            let vector = memory
                .read_array::<16>(a[1] + i * 16)
                .map_err(|_| Errno(14))?;
            let pointer = u64::from_le_bytes(vector[..8].try_into().unwrap());
            let length = u64::from_le_bytes(vector[8..].try_into().unwrap());
            requested = requested
                .checked_add(length)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Errno(22))?;
            let take = length.min((MAX_WRITE - total) as u64) as usize;
            if take != 0 {
                Self::check(
                    memory,
                    pointer,
                    take,
                    if write { Access::Read } else { Access::Write },
                )?;
            }
            parts.push((pointer, take));
            total += take;
        }
        Ok(VectorImport {
            parts,
            total,
            requested,
        })
    }
    pub(crate) fn gather_parts(
        memory: &impl CpuMemory,
        parts: &[(u64, usize)],
        total: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<()> {
        bytes.resize(total, 0);
        let mut cursor = 0;
        for &(pointer, take) in parts {
            if take != 0 {
                memory
                    .read(pointer, &mut bytes[cursor..cursor + take])
                    .map_err(|_| Errno(14))?;
            }
            cursor += take;
        }
        Ok(())
    }
    pub fn positioned_vector_scratch(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        write: bool,
        bytes: &mut Vec<u8>,
    ) -> Result<u64> {
        self.vfs.fd_kind(a[0] as u32)?;
        let offset = a[3];
        let (parts, total) = Self::positioned_vector_parts(memory, a, write)?;
        if write {
            Self::gather_parts(memory, &parts, total, bytes)?;
            Ok(self.vfs.pwrite(a[0] as u32, bytes, offset)? as u64)
        } else {
            let bytes = self.vfs.pread(a[0] as u32, total, offset)?;
            Self::scatter(memory, &parts, &bytes)?;
            Ok(bytes.len() as u64)
        }
    }
    fn statx(&self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let flags = a[2] as u32;
        if flags & !0x7900 != 0 || flags & 0x6000 == 0x6000 || a[3] as u32 & 0x80000000 != 0 {
            return Err(Errno(22));
        }
        Self::check(memory, a[4], 256, Access::Write)?;
        let path = if a[1] == 0 && flags & 0x1000 != 0 {
            Vec::new()
        } else {
            Self::path(memory, a[1])?
        };
        Self::statx_path(&self.vfs, a, &path, memory)
    }
    pub(crate) fn statx_path(
        vfs: &Vfs,
        a: [u64; 6],
        path: &[u8],
        memory: &mut Memory,
    ) -> Result<u64> {
        let flags = a[2] as u32;
        if flags & !0x7900 != 0 || flags & 0x6000 == 0x6000 || a[3] as u32 & 0x80000000 != 0 {
            return Err(Errno(22));
        }
        Self::check(memory, a[4], 256, Access::Write)?;
        let stat = if path.is_empty() && flags & 0x1000 != 0 {
            if a[0] as i32 == -100 {
                vfs.stat_at(-100, b".")?
            } else {
                vfs.stat_fd(a[0] as u32)?
            }
        } else {
            vfs.stat_at_flags(a[0] as i32, path, flags & 0x100 != 0)?
        };
        let mut out = [0u8; 256];
        out[..4].copy_from_slice(&0x17ffu32.to_le_bytes()); // BASIC_STATS and MNT_ID; no birth time.
        out[4..8].copy_from_slice(&stat[56..60]);
        out[16..20].copy_from_slice(&stat[20..24]);
        out[20..24].copy_from_slice(&stat[24..28]);
        out[24..28].copy_from_slice(&stat[28..32]);
        out[28..30].copy_from_slice(&stat[16..18]);
        out[32..40].copy_from_slice(&stat[8..16]);
        out[40..48].copy_from_slice(&stat[48..56]);
        out[48..56].copy_from_slice(&stat[64..72]);
        for (to, from) in [(64, 72), (96, 104), (112, 88)] {
            out[to..to + 8].copy_from_slice(&stat[from..from + 8]);
            out[to + 8..to + 12].copy_from_slice(&stat[from + 8..from + 12]);
        }
        let dev = u64::from_le_bytes(stat[..8].try_into().expect("stat dev"));
        let rdev = u64::from_le_bytes(stat[32..40].try_into().expect("stat rdev"));
        for (offset, value) in [(128, rdev), (136, dev)] {
            let major = ((value >> 8) & 0xfff) | ((value >> 32) & 0xfffff000);
            let minor = (value & 0xff) | ((value >> 12) & 0xffffff00);
            out[offset..offset + 4].copy_from_slice(&(major as u32).to_le_bytes());
            out[offset + 4..offset + 8].copy_from_slice(&(minor as u32).to_le_bytes());
        }
        let mount = if path.is_empty() && flags & 0x1000 != 0 {
            if a[0] as i32 == -100 {
                vfs.mount_id_at(-100, b".", false)?
            } else {
                vfs.mount_id_fd(a[0] as u32)?
            }
        } else {
            vfs.mount_id_at(a[0] as i32, path, flags & 0x100 != 0)?
        };
        out[144..152].copy_from_slice(&mount.to_le_bytes());
        memory.write(a[4], &out).map_err(|_| Errno(14))?;
        Ok(0)
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
        let current = self.heap.current();
        if address == 0 || address < self.heap.base() || address >= ADDRESS_LIMIT {
            return current;
        }
        let Some(new_end) = address
            .checked_add(PAGE_SIZE - 1)
            .map(|n| n & !(PAGE_SIZE - 1))
        else {
            return current;
        };
        let old_end = (current + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if new_end > old_end
            && memory
                .map(old_end, new_end - old_end, Permissions::RW)
                .is_err()
        {
            return current;
        }
        if new_end < old_end && memory.unmap(new_end, old_end - new_end).is_err() {
            return current;
        }
        self.heap.set_current(address);
        address
    }
    fn memory_errno(e: MemoryError) -> Errno {
        Errno(match e {
            MemoryError::UnalignedMapping
            | MemoryError::InvalidRange
            | MemoryError::AddressRange(_) => 22,
            MemoryError::Permission { .. } => 13,
            MemoryError::BackingIo(e) => e,
            _ => 12,
        })
    }
    pub fn mmap_is_additive(a: [u64; 6]) -> bool {
        a[2] == 3 && a[3] & 0x23 == 0x22 && a[3] & (0x10 | 0x100000) == 0
    }
    /// Pure new private-anonymous ownership; reuse the ordinary mmap ABI
    /// validation/address allocator, publishing only after the full preflight.
    pub fn mmap_additive(&mut self, a: [u64; 6], memory: &mut Memory) -> Option<Result<u64>> {
        Self::mmap_is_additive(a).then(|| self.mmap_impl(a, memory, true))
    }
    fn mmap(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        self.mmap_impl(a, memory, false)
    }
    fn mmap_impl(&mut self, a: [u64; 6], memory: &mut Memory, live: bool) -> Result<u64> {
        let len = Self::page_length(a[1])?;
        let reservation = a[2] == 0 && a[3] & 0x23 == 0x22;
        if a[3] & 0x23 != 0x22 && len > trames_memory::MAX_DESCRIBED_BYTES as u64 {
            return Err(Errno(12));
        }
        let flags = a[3];
        let shared = flags & 3 != 2;
        // Linux currently treats MAP_STACK as an advisory no-op. glibc uses
        // it for thread-stack reservations even when the initial prot is NONE.
        const ALLOWED: u64 =
            3 | 0x10 | 0x20 | 0x800 | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x20000 | 0x100000;
        if a[2] & !7 != 0
            || flags & !ALLOWED != 0
            || flags & 3 == 0
            || !a[5].is_multiple_of(PAGE_SIZE)
        {
            return Err(Errno(22));
        }
        if flags & 3 == 3 && flags & 0x20 != 0 {
            return Err(Errno(22));
        }
        let fixed = flags & (0x10 | 0x100000) != 0;
        if fixed && !a[0].is_multiple_of(PAGE_SIZE) {
            return Err(Errno(22));
        }
        let hinted = !fixed && a[0] != 0 && memory.is_free(a[0] & !(PAGE_SIZE - 1), len);
        let address = if fixed {
            a[0]
        } else if hinted {
            a[0] & !(PAGE_SIZE - 1)
        } else {
            let start = if reservation {
                RESERVATION_BASE
            } else {
                self.heap.cursor()
            };
            memory.find_free(start, len).ok_or(Errno(12))?
        };
        if flags & 0x100000 != 0 && !memory.is_free(address, len) {
            return Err(Errno(17));
        }
        let permissions = Permissions {
            read: a[2] & 1 != 0,
            write: a[2] & 2 != 0,
            execute: a[2] & 4 != 0,
        };
        if flags & 0x20 == 0 || shared {
            memory
                .check_backed_mapping(address, len, flags & 0x10 != 0)
                .map_err(Self::memory_errno)?;
        }
        if flags & 0x20 == 0 {
            a[5].checked_add(len)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(Errno(75))?;
            if permissions.execute && !self.vfs.mapping_executable(a[4] as u32)? {
                return Err(Errno(1));
            }
            let objects =
                self.vfs
                    .mapping_pages(a[4] as u32, a[5], len, shared, permissions.write)?;
            memory
                .map_backed(address, objects, shared, permissions, flags & 0x10 != 0)
                .map_err(Self::memory_errno)?;
        } else if reservation {
            memory
                .reserve(address, len, flags & 0x10 != 0)
                .map_err(Self::memory_errno)?;
        } else if shared {
            memory
                .map_shared_anonymous(address, len, permissions, flags & 0x10 != 0)
                .map_err(Self::memory_errno)?;
        } else if flags & 0x10 != 0 {
            memory
                .map_fixed(address, len, permissions)
                .map_err(Self::memory_errno)?;
        } else {
            if live {
                memory
                    .map_anonymous_live(address, len)
                    .map_err(Self::memory_errno)?;
            } else {
                memory
                    .map(address, len, permissions)
                    .map_err(Self::memory_errno)?;
            }
        }
        // A successful caller-chosen hint must not move the ordinary search
        // cursor. Scudo deliberately probes randomized high addresses; moving
        // every later allocation there creates enormous sparse region spans.
        if !fixed && !hinted && !reservation {
            self.heap.set_cursor(address + len);
        }
        Ok(address)
    }
    fn mremap(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let old_len = Self::page_length(a[1])?;
        let new_len = Self::page_length(a[2])?;
        if a[3] & !3 != 0 || a[3] & 2 != 0 && a[3] & 1 == 0 {
            return Err(Errno(22));
        }
        let reservation = memory.is_reserved(a[0], old_len);
        let fixed = a[3] & 2 != 0;
        let address = if fixed {
            a[4]
        } else if new_len <= old_len
            || memory.is_free(
                a[0].checked_add(old_len).ok_or(Errno(22))?,
                new_len - old_len,
            )
        {
            a[0]
        } else if a[3] & 1 != 0 {
            let start = if reservation {
                RESERVATION_BASE
            } else {
                self.heap.cursor()
            };
            memory.find_free(start, new_len).ok_or(Errno(12))?
        } else {
            return Err(Errno(12));
        };
        memory
            .remap(a[0], old_len, address, new_len, fixed)
            .map_err(Self::memory_errno)?;
        if address != a[0] && !fixed && !reservation {
            self.heap.set_cursor(address + new_len);
        }
        Ok(address)
    }
    pub fn dispatch(
        &mut self,
        cpu: &mut impl Registers,
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
        let old_ids = matches!(number, 143..=147 | 149 | 151 | 152).then(|| self.vfs.fs_identity());
        let result = self.syscall(number, a, memory, io);
        if let Some(old) = old_ids {
            self.vfs.reset_dumpable_after_ids(old);
        }
        let raw = match result {
            Ok(value) => value,
            Err(e) => errno(e.0 as u64),
        };
        if raw == errno(38) || raw == errno(95) {
            self.vfs.log_syscall(
                number,
                cpu.pc().saturating_sub(4),
                a,
                raw.wrapping_neg() as u32,
                &self.command_name,
            );
        }
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
            425 => self.uring_setup(a, memory),
            426 => self
                .uring_enter(a, memory, None, 0)
                .and_then(|(count, ready)| {
                    if ready {
                        Ok(count as u64)
                    } else {
                        Err(Errno(11))
                    }
                }),
            427 => self.uring_register(a, memory),
            280 => self.bpf_syscall(a, memory),
            5..=16 => self.xattr_syscall(number, a, memory),
            51 => {
                let path = Self::path(memory, a[0])?;
                self.vfs.chroot(&path)?;
                Ok(0)
            }
            number @ 160..=162 => {
                crate::uts_call(&self.vfs.uts_capability(), number as u32, a, memory)
            }
            71 | 76 | 213 | 223 | 267 | 285 | 286 | 287 | 437 | 452 => {
                self.file_syscall(number, a, memory, io)
            }
            279 => {
                let name = Self::path(memory, a[0])?;
                Ok(self.vfs.memfd_create(&name, a[1] as u32)? as u64)
            }
            69 | 70 => self.positioned_vector(a, memory, number == 70),
            291 => self.statx(a, memory),
            436 => {
                self.vfs
                    .close_range(a[0] as u32, a[1] as u32, a[2] as u32)?;
                Ok(0)
            }
            116 => crate::syslog(&self.vfs.kernel_log_capability(), a, memory),
            19 => Ok(self.vfs.eventfd(a[0] as u32, a[1] as u32)? as u64),
            20 => Ok(self.vfs.epoll_create(a[0] as u32)? as u64),
            21 => {
                let (events, data) = if a[1] == 2 {
                    (0, 0)
                } else {
                    Self::check(memory, a[3], 16, Access::Read)?;
                    let mut bytes = [0; 4];
                    memory.read(a[3], &mut bytes).map_err(|_| Errno(14))?;
                    (
                        u32::from_le_bytes(bytes),
                        memory.read_u64(a[3] + 8).map_err(|_| Errno(14))?,
                    )
                };
                self.vfs
                    .epoll_ctl(a[0] as u32, a[1] as u32, a[2] as u32, events, data)?;
                Ok(0)
            }
            26 => Ok(self.vfs.inotify_init(a[0] as u32)? as u64),
            27 => {
                let path = Self::path(memory, a[1])?;
                Ok(self.vfs.inotify_add(a[0] as u32, &path, a[2] as u32)? as u64)
            }
            28 => {
                self.vfs.inotify_remove(a[0] as u32, a[1] as i32)?;
                Ok(0)
            }
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
            269 => self.send_messages(a, memory),
            65 => self.readv(a, memory, io),
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
                let stat = if number == 43 {
                    let path = Self::path(memory, a[0])?;
                    self.vfs.statfs_at(&path)?
                } else {
                    self.vfs.statfs_fd(a[0] as u32)?
                };
                Self::check(memory, a[1], 120, Access::Write)?;
                memory.write(a[1], &stat).map_err(|_| Errno(14))?;
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
            47 => {
                self.vfs.allocate_fd(a[0] as u32, a[1], a[2], a[3])?;
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
            54 => {
                if a[4] & !0x1100 != 0 {
                    return Err(Errno(22));
                }
                let path = Self::path(memory, a[1])?;
                if path.is_empty() && a[4] & 0x1000 != 0 {
                    self.vfs
                        .chown_fd_at(a[0] as u32, a[2] as u32, a[3] as u32)?;
                } else {
                    self.vfs.chown_at(
                        a[0] as i32,
                        &path,
                        a[2] as u32,
                        a[3] as u32,
                        a[4] & 0x100 != 0,
                    )?;
                }
                Ok(0)
            }
            55 => {
                self.vfs.chown_fd(a[0] as u32, a[1] as u32, a[2] as u32)?;
                Ok(0)
            }
            67 | 68 => self.positioned(a, memory, number == 68),
            82 | 83 => {
                self.vfs.sync_fd(a[0] as u32, number == 83)?;
                Ok(0)
            }
            81 => {
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
                self.vfs
                    .set_times_flags(a[0] as i32, path.as_deref(), times, a[3] as u32)?;
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
            33 => {
                let path = Self::path(memory, a[1])?;
                self.vfs.mknod_at(a[0] as i32, &path, a[2] as u32, a[3])?;
                Ok(0)
            }
            34 => {
                let path = Self::path(memory, a[1])?;
                self.vfs.mkdir_at(a[0] as i32, &path, a[2] as u32)?;
                Ok(0)
            }
            62 => self.fd_query(62, a, memory),
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
            80 => self.fd_query(80, a, memory),
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
            25 if matches!(a[1], 1 | 3) => self.fd_query(25, a, memory),
            25 => {
                let flags = self.vfs.flags(a[0] as u32)?;
                if flags & trames_vfs::O_PATH != 0 && !matches!(a[1], 0..=3 | 1030) {
                    return Err(Errno(9));
                }
                match a[1] {
                    1033 => Ok(self.vfs.seals(a[0] as u32, Some(a[2] as u32))? as u64),
                    1034 => Ok(self.vfs.seals(a[0] as u32, None)? as u64),
                    0 | 1030 => Ok(self.vfs.dup(a[0] as u32, a[2] as u32, a[1] == 1030)? as u64),
                    2 => {
                        self.vfs.set_cloexec(a[0] as u32, a[2] & 1 != 0)?;
                        Ok(0)
                    }
                    4 => {
                        self.vfs.set_status_flags(a[0] as u32, a[2] as u32)?;
                        Ok(0)
                    }
                    5..=7 => crate::record_locks::call(
                        memory,
                        a[1],
                        a[2],
                        |kind, whence, start, length| {
                            Some(
                                self.vfs
                                    .normalize_lock(a[0] as u32, kind, whence, start, length),
                            )
                        },
                        |requested| self.vfs.record_lock_conflict(a[0] as u32, requested),
                        |requested| self.vfs.record_lock_set(a[0] as u32, requested),
                        |owner| self.vfs.visible_pid(owner),
                    )
                    .expect("owner lock normalization cannot defer"),
                    _ => Err(Errno(22)),
                }
            }
            29 => {
                if self.vfs.flags(a[0] as u32)? & trames_vfs::O_PATH != 0 {
                    return Err(Errno(9));
                }
                if a[1] as u32 == 0x541b {
                    if let Some(bytes) = self.vfs.readable_bytes(a[0] as u32)? {
                        memory
                            .write(a[2], &(bytes as u32).to_le_bytes())
                            .map_err(|_| Errno(14))?;
                        return Ok(0);
                    }
                }
                if a[1] as u32 == 0x5421 {
                    let mut value = [0; 4];
                    memory.read(a[2], &mut value).map_err(|_| Errno(14))?;
                    self.vfs
                        .set_nonblocking(a[0] as u32, u32::from_le_bytes(value) != 0)?;
                    Ok(0)
                } else if let Some(kind) = self.vfs.namespace_type(a[0] as u32)? {
                    match a[1] as u32 {
                        0xb703 => Ok(kind),
                        _ => Err(Errno(25)),
                    }
                } else if self.vfs.fd_kind(a[0] as u32)? == FdKind::Socket {
                    self.network_ioctl(a, memory)
                } else {
                    Err(Errno(25))
                }
            }
            48 | 439 => {
                if a[2] & !7 != 0 {
                    return Err(Errno(22));
                }
                let path = Self::path(memory, a[1])?;
                let flags = if number == 439 { a[3] } else { 0 };
                if flags & !0x300 != 0 {
                    return Err(Errno(22));
                }
                self.vfs.access_at(
                    a[0] as i32,
                    &path,
                    a[2] as u32,
                    flags & 0x200 != 0,
                    flags & 0x100 != 0,
                )?;
                Ok(0)
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
            125 | 126 => Ok(match a[0] as u32 {
                1 | 2 => {
                    if number == 125 {
                        99
                    } else {
                        1
                    }
                }
                0 | 3 | 5 | 6 => 0,
                _ => return Err(Errno(22)),
            }),
            168 => {
                for pointer in &a[..2] {
                    if *pointer != 0 {
                        Self::check(memory, *pointer, 4, Access::Write)?;
                    }
                }
                for pointer in &a[..2] {
                    if *pointer != 0 {
                        memory.write(*pointer, &[0; 4]).map_err(|_| Errno(14))?;
                    }
                }
                Ok(0)
            }
            172 => Ok(1),
            173 => Ok(0),
            174..=177 => {
                let c = &self.vfs.credentials;
                Ok(match number {
                    174 => c.uid,
                    175 => c.euid,
                    176 => c.gid,
                    _ => c.egid,
                } as u64)
            }
            167 if matches!(a[0], 15 | 16) => {
                if a[0] == 15 {
                    let mut name = Vec::new();
                    for i in 0..15 {
                        let mut byte = [0];
                        memory.read(a[1] + i, &mut byte).map_err(|_| Errno(14))?;
                        if byte[0] == 0 {
                            break;
                        }
                        name.push(byte[0]);
                    }
                    self.command_name = name;
                } else {
                    Self::check(memory, a[1], 16, Access::Write)?;
                    let mut name = [0; 16];
                    let len = self.command_name.len().min(15);
                    name[..len].copy_from_slice(&self.command_name[..len]);
                    memory.write(a[1], &name).map_err(|_| Errno(14))?;
                }
                Ok(0)
            }
            169 => {
                if a[0] != 0 {
                    Self::check(memory, a[0], 16, Access::Write)?;
                }
                if a[1] != 0 {
                    Self::check(memory, a[1], 8, Access::Write)?;
                }
                let time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Errno(5))?;
                if a[0] != 0 {
                    memory
                        .write(a[0], &time.as_secs().to_le_bytes())
                        .map_err(|_| Errno(14))?;
                    memory
                        .write(a[0] + 8, &(time.subsec_micros() as u64).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if a[1] != 0 {
                    memory.write(a[1], &[0; 8]).map_err(|_| Errno(14))?;
                }
                Ok(0)
            }
            144 | 146 => {
                self.vfs.credentials.set_id(number == 144, a[0] as u32)?;
                Ok(0)
            }
            143 | 145 | 147 | 149 => {
                let group = matches!(number, 143 | 149);
                let values = if matches!(number, 143 | 145) {
                    let c = &self.vfs.credentials;
                    let old_real = if group { c.gid } else { c.uid };
                    [
                        a[0] as u32,
                        a[1] as u32,
                        if a[0] as u32 != u32::MAX
                            || (a[1] as u32 != u32::MAX && a[1] as u32 != old_real)
                        {
                            if a[1] as u32 == u32::MAX {
                                if group {
                                    c.egid
                                } else {
                                    c.euid
                                }
                            } else {
                                a[1] as u32
                            }
                        } else {
                            u32::MAX
                        },
                    ]
                } else {
                    [a[0] as u32, a[1] as u32, a[2] as u32]
                };
                self.vfs.credentials.set_res_ids(group, values)?;
                Ok(0)
            }
            148 | 150 => {
                for pointer in a[..3].iter() {
                    Self::check(memory, *pointer, 4, Access::Write)?;
                }
                let c = &self.vfs.credentials;
                let values = if number == 148 {
                    [c.uid, c.euid, c.suid]
                } else {
                    [c.gid, c.egid, c.sgid]
                };
                for i in 0..3 {
                    memory
                        .write(a[i], &values[i].to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                Ok(0)
            }
            151 | 152 => {
                let c = &mut self.vfs.credentials;
                let group = number == 152;
                let old = if group { c.fsgid } else { c.fsuid };
                let ids = if group {
                    [c.gid, c.egid, c.sgid, old]
                } else {
                    [c.uid, c.euid, c.suid, old]
                };
                if c.has_cap(if group {
                    capabilities::SETGID
                } else {
                    capabilities::SETUID
                }) || ids.contains(&(a[0] as u32))
                {
                    if group {
                        c.fsgid = a[0] as u32;
                    } else {
                        c.caps.fsuid_changed(c.fsuid, a[0] as u32);
                        c.fsuid = a[0] as u32;
                    }
                }
                Ok(old as u64)
            }
            158 | 159 => {
                let count = a[0] as usize;
                if count > 65536 {
                    return Err(Errno(22));
                }
                if number == 158 {
                    let groups = &self.vfs.credentials.groups;
                    if count == 0 {
                        return Ok(groups.len() as u64);
                    }
                    if count < groups.len() {
                        return Err(Errno(22));
                    }
                    Self::check(memory, a[1], groups.len() * 4, Access::Write)?;
                    for (i, value) in groups.iter().enumerate() {
                        memory
                            .write(a[1] + (i * 4) as u64, &value.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                    }
                    Ok(groups.len() as u64)
                } else {
                    if !self.vfs.credentials.has_cap(capabilities::SETGID) {
                        return Err(Errno(1));
                    }
                    Self::check(memory, a[1], count * 4, Access::Read)?;
                    let mut groups = Vec::with_capacity(count);
                    for i in 0..count {
                        let mut value = [0; 4];
                        memory
                            .read(a[1] + (i * 4) as u64, &mut value)
                            .map_err(|_| Errno(14))?;
                        groups.push(u32::from_le_bytes(value));
                    }
                    self.vfs.credentials.groups = groups;
                    Ok(0)
                }
            }
            166 => {
                let previous = self.vfs.set_umask(a[0] as u32);
                Ok(previous as u64)
            }
            216 => self.mremap(a, memory),
            227 => {
                if !a[0].is_multiple_of(PAGE_SIZE) || a[2] & !7 != 0 || a[2] & 5 == 5 {
                    return Err(Errno(22));
                }
                if a[1] == 0 {
                    return Ok(0);
                }
                let len = Self::page_length(a[1])?;
                memory.sync_range(a[0], len).map_err(Self::memory_errno)?;
                Ok(0)
            }
            232 => {
                if a[1] == 0 {
                    return if a[0].is_multiple_of(PAGE_SIZE) {
                        Ok(0)
                    } else {
                        Err(Errno(22))
                    };
                }
                let len = Self::page_length(a[1])?;
                if len > trames_memory::MAX_DESCRIBED_BYTES as u64 {
                    return Err(Errno(12));
                }
                let resident = memory.resident(a[0], len).map_err(Self::memory_errno)?;
                Self::check(memory, a[2], resident.len(), Access::Write)?;
                memory.write(a[2], &resident).map_err(|_| Errno(14))?;
                Ok(0)
            }
            233 => {
                if !a[0].is_multiple_of(PAGE_SIZE) {
                    return Err(Errno(22));
                }
                if !matches!(a[2] as u32,0..=4|14..=17) {
                    return Err(Errno(22));
                }
                if a[1] == 0 {
                    return Ok(0);
                }
                let len = Self::page_length(a[1])?;
                if a[2] as u32 == 4 {
                    memory.discard(a[0], len).map_err(Self::memory_errno)?;
                } else {
                    memory
                        .validate_mapped(a[0], len)
                        .map_err(Self::memory_errno)?;
                }
                Ok(0)
            }
            214 => Ok(self.brk(a[0], memory)),
            222 => self.mmap(a, memory),
            215 => {
                let len = Self::page_length(a[1])?;
                memory.unmap(a[0], len).map_err(Self::memory_errno)?;
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
                    .map_err(Self::memory_errno)?;
                Ok(0)
            }
            _ => Err(Errno(38)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_vfs::O_NONBLOCK;
    #[test]
    fn first_touch_output_quota_failure_does_not_consume_file_input() {
        let mut l = Linux::new(0);
        let mut m = Memory::new(4 * PAGE_SIZE as usize);
        m.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        m.set_total_limit(PAGE_SIZE as usize).unwrap();
        m.write_array(0x1000, [17u8]).unwrap();
        l.vfs
            .import_file(b"/quota-input", b"retained".to_vec())
            .unwrap();
        let fd = l
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/quota-input", 0, 0)
            .unwrap();
        assert_eq!(
            l.syscall(
                63,
                [fd as u64, 0x2000, 8, 0, 0, 0],
                &mut m,
                &mut CapturedOutput::default()
            ),
            Err(Errno(14))
        );
        assert_eq!(m.read_array::<8>(0x2000), Ok([0; 8]));
        assert_eq!(l.vfs.read(fd, 8).unwrap(), b"retained");
    }
    #[test]
    fn reused_write_scratch_shrinks_and_never_emits_stale_or_faulting_bytes() {
        let mut linux = Linux::new(0);
        let mut memory = memory();
        let fd = linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/scratch", 0x42, 0o600)
            .unwrap();
        let mut buffer = Vec::new();
        let mut io = crate::CapturedOutput::default();
        memory.write(0x1000, b"abcdef").unwrap();
        assert_eq!(
            linux.write_scratch(
                [fd as u64, 0x1000, 6, 0, 0, 0],
                &memory,
                &mut io,
                &mut buffer
            ),
            Ok(6)
        );
        let capacity = buffer.capacity();
        linux.vfs.seek(fd, 0, 0).unwrap();
        memory.write(0x1000, b"x").unwrap();
        assert_eq!(
            linux.write_scratch(
                [fd as u64, 0x1000, 1, 0, 0, 0],
                &memory,
                &mut io,
                &mut buffer
            ),
            Ok(1)
        );
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.capacity(), capacity);
        assert_eq!(
            linux.write_scratch(
                [fd as u64, 0x9000, 2, 0, 0, 0],
                &memory,
                &mut io,
                &mut buffer
            ),
            Err(Errno(14))
        );
        assert_eq!(linux.vfs.seek(fd, 0, 1).unwrap(), 1);
        assert_eq!(linux.vfs.pread(fd, 6, 0).unwrap(), b"xbcdef");
    }
    #[test]
    fn mmap_virtual_capacity_is_independent_of_the_resident_budget() {
        let mut linux = Linux::new(0);
        let mut memory = Memory::new(PAGE_SIZE as usize);
        // Length admission must not confuse virtual bytes with resident RAM.
        let args = [0, 513 * 1024 * 1024, 3, 0, 0, 0];
        assert_eq!(linux.mmap(args, &mut memory), Err(Errno(22)));
        assert_eq!(
            linux.mmap([0, ADDRESS_LIMIT, 3, 0x22, u64::MAX, 0], &mut memory),
            Err(Errno(12))
        );
        let base = linux
            .mmap([0, 32 * PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut memory)
            .unwrap();
        assert_eq!(memory.mapped_bytes(), 32 * PAGE_SIZE as usize);
        assert_eq!(memory.resident_bytes(), 0);
        memory.write(base, b"x").unwrap();
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(
            memory.write(base + PAGE_SIZE, b"y"),
            Err(MemoryError::Limit)
        );
    }
    #[test]
    fn huge_private_mmap_and_mremap_only_charge_reached_pages() {
        let mut linux = Linux::new(0x3000);
        let mut memory = Memory::new(2 * PAGE_SIZE as usize);
        let len = 32 << 30;
        let base = linux
            .mmap([0, len, 3, 0x22, u64::MAX, 0], &mut memory)
            .unwrap();
        assert_eq!(memory.resident_bytes(), 0);
        memory.write_array(base + len - 8, [42; 8]).unwrap();
        let target = 1 << 40;
        assert_eq!(
            linux.mremap([base, len, 2 * len, 3, target, 0], &mut memory),
            Ok(target)
        );
        assert_eq!(memory.read_array::<8>(target + len - 8).unwrap(), [42; 8]);
        assert_eq!(memory.read_array::<8>(target + len).unwrap(), [0; 8]);
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(
            linux.mmap([0, len, 3, 0x21, u64::MAX, 0], &mut memory),
            Err(Errno(12))
        );
    }

    #[test]
    fn munmap_metadata_exhaustion_returns_enomem_and_retains_the_range() {
        let mut linux = Linux::new(0);
        let mut m = Memory::new(0);
        let mut out = CapturedOutput::default();
        for i in 0..trames_memory::MAX_RESERVATIONS as u64 {
            m.reserve(0x10000 + i * 4 * PAGE_SIZE, 3 * PAGE_SIZE, false)
                .unwrap();
        }
        assert_eq!(
            linux.syscall(215, [0x11000, PAGE_SIZE, 0, 0, 0, 0], &mut m, &mut out),
            Err(Errno(12))
        );
        assert!(m.is_reserved(0x10000, 3 * PAGE_SIZE));
        assert_eq!(m.mapped_bytes(), 0);
        assert_eq!(
            linux.syscall(215, [0x11001, PAGE_SIZE, 0, 0, 0, 0], &mut m, &mut out),
            Err(Errno(22))
        );
        assert_eq!(
            linux.syscall(215, [0x10000, 3 * PAGE_SIZE, 0, 0, 0, 0], &mut m, &mut out),
            Ok(0)
        );
        assert!(m.is_free(0x10000, 3 * PAGE_SIZE));
    }
    use crate::CapturedOutput;
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        m
    }

    #[test]
    fn positioned_vectors_preserve_offset_and_preflight_all_buffers() {
        let mut l = Linux::new(0x3000);
        let mut m = memory();
        let mut io = CapturedOutput::default();
        l.vfs.import_file(b"/file", b"abcdef".to_vec()).unwrap();
        let fd = l.vfs.open_at(-100, b"/file", 2, 0).unwrap() as u64;
        l.vfs.seek(fd as u32, 3, 0).unwrap();
        for (i, value) in [0x1100u64, 2, 0x1200, 2].into_iter().enumerate() {
            m.write(0x1000 + i as u64 * 8, &value.to_le_bytes())
                .unwrap();
        }
        assert_eq!(
            l.syscall(69, [fd, 0x1000, 2, 1, 0, 0], &mut m, &mut io),
            Ok(4)
        );
        assert_eq!(m.read_array::<2>(0x1100).unwrap(), *b"bc");
        assert_eq!(m.read_array::<2>(0x1200).unwrap(), *b"de");
        assert_eq!(l.vfs.seek(fd as u32, 0, 1).unwrap(), 3);
        m.write(0x1010, &ADDRESS_LIMIT.to_le_bytes()).unwrap();
        assert_eq!(
            l.syscall(70, [fd, 0x1000, 2, 0, 0, 0], &mut m, &mut io),
            Err(Errno(14))
        );
        assert_eq!(l.vfs.pread(fd as u32, 6, 0).unwrap(), b"abcdef");
        assert_eq!(
            l.syscall(69, [fd, 0x1000, 0, u64::MAX, 0, 0], &mut m, &mut io),
            Err(Errno(22))
        );
        assert_eq!(
            l.syscall(69, [fd, 0x1000, 1025, 0, 0, 0], &mut m, &mut io),
            Err(Errno(22))
        );
    }
    #[test]
    fn statx_has_real_identity_and_does_not_claim_birth_time() {
        let mut l = Linux::new(0x3000);
        let mut m = memory();
        let mut io = CapturedOutput::default();
        l.vfs.import_file(b"/file", b"abc".to_vec()).unwrap();
        let fd = l.vfs.open_at(-100, b"/file", 0, 0).unwrap() as u64;
        m.write(0x1000, b"/file\0").unwrap();
        assert_eq!(
            l.syscall(
                291,
                [(-100i64) as u64, 0x1000, 0, 0x7ff, 0x1200, 0],
                &mut m,
                &mut io
            ),
            Ok(0)
        );
        assert_eq!(m.read_array::<4>(0x1200).unwrap(), 0x17ffu32.to_le_bytes());
        assert_eq!(m.read_u64(0x1228).unwrap(), 3);
        let inode = m.read_u64(0x1220).unwrap();
        assert_eq!(m.read_u64(0x1290).unwrap(), 1);
        assert_eq!(
            l.syscall(291, [fd, 0, 0x1000, 0, 0x1300, 0], &mut m, &mut io),
            Ok(0)
        );
        assert_eq!(m.read_u64(0x1320).unwrap(), inode);
        assert_eq!(
            l.syscall(291, [fd, 0, 0x7000, 0, 0x1300, 0], &mut m, &mut io),
            Err(Errno(22))
        );
        assert_eq!(
            l.syscall(291, [fd, 0, 0x1000, 0x80000000, 0x1300, 0], &mut m, &mut io),
            Err(Errno(22))
        );
    }
    #[test]
    fn invalid_syslog_buffer_cannot_consume_or_clear_diagnostics() {
        let mut l = Linux::new(0x3000);
        let mut m = memory();
        let mut io = CapturedOutput::default();
        l.vfs.log(4, "retained diagnostic");
        for action in [2, 4] {
            assert_eq!(
                l.syscall(116, [action, ADDRESS_LIMIT, 100, 0, 0, 0], &mut m, &mut io),
                Err(Errno(14))
            );
        }
        assert!(String::from_utf8(l.vfs.syslog(3, 4096).unwrap())
            .unwrap()
            .contains("retained diagnostic"));
        assert!(l.vfs.syslog_size(9).unwrap() > 0);
    }
    #[test]
    fn canonical_sync_persists_open_file_length_and_contents() {
        let directory = std::env::temp_dir().join(format!(
            "trames-linux-sync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut linux = Linux::new(0x3000);
        linux.vfs = Vfs::open_disk(&directory, trames_vfs::DiskOptions::default()).unwrap();
        let fd = linux.vfs.open_at(-100, b"/sync-data", 0x42, 0o600).unwrap();
        linux.vfs.write(fd, b"durable length and data").unwrap();
        let mut memory = memory();
        let mut io = CapturedOutput::default();
        assert_eq!(linux.syscall(162, [0; 6], &mut memory, &mut io), Ok(0));
        assert_eq!(linux.syscall(81, [0; 6], &mut memory, &mut io), Ok(0));
        drop(linux);
        let mut reopened = Vfs::open_disk(&directory, trames_vfs::DiskOptions::default()).unwrap();
        let fd = reopened.open_at(-100, b"/sync-data", 0, 0).unwrap();
        assert_eq!(reopened.read(fd, 64).unwrap(), b"durable length and data");
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn virtual_reservations_do_not_scatter_ordinary_heap_regions() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let first = linux
            .mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m)
            .unwrap();
        let large = linux
            .mmap([0, 16 << 30, 0, 0x4022, u64::MAX, 0], &mut m)
            .unwrap();
        assert_eq!(m.resident_bytes(), 0);
        let next = linux
            .mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m)
            .unwrap();
        assert_eq!(next, first + PAGE_SIZE);
        // The reservation remains exclusive and can be committed in place.
        assert!(!m.is_free(large, 16 << 30));
        let at = large + (8 << 30);
        assert_eq!(
            linux.mmap([at, PAGE_SIZE, 3, 0x32, u64::MAX, 0], &mut m),
            Ok(at)
        );
        m.write(at, b"reserved").unwrap();
        assert_eq!(m.read_array::<8>(at).unwrap(), *b"reserved");
        assert_eq!(
            linux.mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m),
            Ok(next + PAGE_SIZE)
        );
        assert!(m.is_reserved(at + PAGE_SIZE, PAGE_SIZE));
    }
    #[test]
    fn accepted_mmap_hints_do_not_relocate_ordinary_allocations() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let high = 0x4000_0000_0000;
        let args = [high, PAGE_SIZE, 0, 0x22, u64::MAX, 0];
        assert_eq!(linux.mmap(args, &mut m), Ok(high));
        assert_eq!(
            linux.mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m),
            Ok(0x1000_0000)
        );
        // A conflicting reservation hint searches the virtual-only arena.
        assert_eq!(linux.mmap(args, &mut m), Ok(high + PAGE_SIZE));
        assert_eq!(
            linux.mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m),
            Ok(0x1000_1000)
        );
        assert_eq!(
            linux.mmap([high + PAGE_SIZE, PAGE_SIZE, 0, 0x32, u64::MAX, 0], &mut m),
            Ok(high + PAGE_SIZE)
        );
        assert_eq!(
            linux.mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m),
            Ok(0x1000_2000)
        );
    }
    #[test]
    fn reservation_remaps_and_fixed_moves_preserve_ordinary_cursor() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let args = [0, PAGE_SIZE, 0, 0x22, u64::MAX, 0];
        let first = linux.mmap(args, &mut m).unwrap();
        let second = linux.mmap(args, &mut m).unwrap();
        let moved = linux
            .mremap([first, PAGE_SIZE, PAGE_SIZE * 2, 1, 0, 0], &mut m)
            .unwrap();
        assert_eq!(moved, second + PAGE_SIZE);
        assert!(m.is_reserved(moved, PAGE_SIZE * 2));
        assert!(m.is_free(first, PAGE_SIZE));
        assert_eq!(linux.mmap(args, &mut m), Ok(first));
        let heap = linux
            .mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m)
            .unwrap();
        m.write(heap, b"remapped").unwrap();
        let fixed = RESERVATION_BASE + (32 << 30);
        assert_eq!(
            linux.mremap([heap, PAGE_SIZE, PAGE_SIZE, 3, fixed, 0], &mut m),
            Ok(fixed)
        );
        assert_eq!(m.read_array::<8>(fixed).unwrap(), *b"remapped");
        assert_eq!(
            linux.mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut m),
            Ok(heap + PAGE_SIZE)
        );
    }
    #[test]
    fn fionread_bad_pointer_preserves_socket_and_pipe_data() {
        for pipe in [false, true] {
            let mut linux = Linux::new(0x3000);
            let [read, write] = if pipe {
                linux.vfs.pipe(O_NONBLOCK).unwrap()
            } else {
                linux.vfs.socketpair(1, 1 | O_NONBLOCK, 0).unwrap()
            };
            linux.vfs.write(write, b"queued").unwrap();
            let alias = linux.vfs.dup(read, 3, true).unwrap();
            let mut m = memory();
            let mut out = CapturedOutput::default();
            assert_eq!(
                linux.syscall(
                    29,
                    [alias as u64, 0x541b, u64::MAX, 0, 0, 0],
                    &mut m,
                    &mut out
                ),
                Err(Errno(14))
            );
            assert_eq!(
                linux.syscall(
                    29,
                    [alias as u64, 0x541b, 0x1000, 0, 0, 0],
                    &mut m,
                    &mut out
                ),
                Ok(0)
            );
            assert_eq!(u32::from_le_bytes(m.read_array(0x1000).unwrap()), 6);
            assert_eq!(linux.vfs.read(read, 6).unwrap(), b"queued");
            linux.vfs.close(write).unwrap();
            assert_eq!(
                linux.syscall(
                    29,
                    [alias as u64, 0x541b, 0x1000, 0, 0, 0],
                    &mut m,
                    &mut out
                ),
                Ok(0)
            );
            assert_eq!(m.read_array::<4>(0x1000).unwrap(), [0; 4]);
        }
    }
    #[test]
    fn stdio_nonblocking_ioctl_preserves_alias_flags_and_fault_atomicity() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let mut out = CapturedOutput::default();
        let alias = linux.vfs.dup(1, 3, true).unwrap();
        m.write(0x1000, &1u32.to_le_bytes()).unwrap();
        assert_eq!(
            linux.syscall(29, [1, 0x5421, 0x1000, 0, 0, 0], &mut m, &mut out),
            Ok(0)
        );
        assert_ne!(linux.vfs.flags(alias).unwrap() & O_NONBLOCK, 0);
        assert_ne!(linux.vfs.flags(alias).unwrap() & trames_vfs::O_CLOEXEC, 0);
        assert_eq!(
            linux.syscall(
                29,
                [alias as u64, 0x5421, u64::MAX, 0, 0, 0],
                &mut m,
                &mut out
            ),
            Err(Errno(14))
        );
        assert_ne!(linux.vfs.flags(1).unwrap() & O_NONBLOCK, 0);
        m.write(0x1000, &0u32.to_le_bytes()).unwrap();
        assert_eq!(
            linux.syscall(
                29,
                [alias as u64, 0x5421, 0x1000, 0, 0, 0],
                &mut m,
                &mut out
            ),
            Ok(0)
        );
        assert_eq!(linux.vfs.flags(1).unwrap() & O_NONBLOCK, 0);
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
    fn readv_preflights_every_destination_before_consuming_input() {
        let mut linux = Linux::new(0x3000);
        let mut m = memory();
        let mut io = CapturedOutput {
            stdin: b"abcd".to_vec(),
            ..CapturedOutput::default()
        };
        for (i, value) in [0x1100u64, 1, ADDRESS_LIMIT, 3].into_iter().enumerate() {
            m.write(0x1000 + i as u64 * 8, &value.to_le_bytes())
                .unwrap();
        }
        assert_eq!(
            linux.syscall(65, [0, 0x1000, 2, 0, 0, 0], &mut m, &mut io),
            Err(Errno(14))
        );
        assert_eq!(io.stdin, b"abcd");
        m.write(0x1010, &0x1200u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.syscall(65, [0, 0x1000, 2, 0, 0, 0], &mut m, &mut io),
            Ok(4)
        );
        let mut first = [0];
        let mut rest = [0; 3];
        m.read(0x1100, &mut first).unwrap();
        m.read(0x1200, &mut rest).unwrap();
        assert_eq!(first, b"a"[..]);
        assert_eq!(rest, b"bcd"[..]);
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
    fn allocation_context_shares_only_with_vm_and_commits_after_mapping_success() {
        let mut parent = Linux::new(0x1000);
        let mut memory = Memory::new(8 * PAGE_SIZE as usize);
        let mut shared = parent.clone_with_resources(false, false, true);
        let independent = parent.clone_with_resources(true, true, false);
        let shared_query = shared.program_break();
        let private_query = independent.program_break();
        assert_eq!(parent.brk(0x2000, &mut memory), 0x2000);
        assert_eq!(shared_query.get(), 0x2000);
        assert_eq!(private_query.get(), 0x1000);
        assert_eq!(shared.brk(ADDRESS_LIMIT, &mut memory), 0x2000);
        assert_eq!(shared_query.get(), 0x2000);

        let first = parent
            .mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut memory)
            .unwrap();
        assert_eq!(parent.heap_context(), shared.heap_context());
        let second = shared
            .mmap([0, PAGE_SIZE, 3, 0x22, u64::MAX, 0], &mut memory)
            .unwrap();
        assert_eq!(second, first + PAGE_SIZE);
        let before = parent.heap_context();
        assert_eq!(
            shared.mmap([0, ADDRESS_LIMIT, 3, 0x22, u64::MAX, 0], &mut memory),
            Err(Errno(12))
        );
        assert_eq!(parent.heap_context(), before);
        assert_eq!(shared.heap_context(), before);
        let moved = shared
            .mremap([first, PAGE_SIZE, 2 * PAGE_SIZE, 1, 0, 0], &mut memory)
            .unwrap();
        assert_eq!(moved, second + PAGE_SIZE);
        assert_eq!(parent.heap_context(), shared.heap_context());
        assert_eq!(parent.heap_context().2, moved + 2 * PAGE_SIZE);
        assert_eq!(independent.heap_context(), (0x1000, 0x1000, 0x1000_0000));
    }

    #[test]
    fn brk_rejection_keeps_the_previous_break_and_mapping() {
        let mut linux = Linux::new(0x1000);
        let mut m = Memory::new(4096);
        assert_eq!(linux.brk(0x1800, &mut m), 0x1800);
        m.write(0x1000, b"x").unwrap();
        assert_eq!(linux.brk(ADDRESS_LIMIT, &mut m), 0x1800);
        assert_eq!(m.mapped_bytes(), 4096);
        assert_eq!(m.read_array::<1>(0x1000), Ok(*b"x"));
        assert_eq!(linux.brk(0x3000, &mut m), 0x3000);
        assert_eq!(m.resident_bytes(), 4096);
        assert_eq!(m.write(0x2000, b"y"), Err(MemoryError::Limit));
        assert_eq!(linux.brk(0x800, &mut m), 0x3000);
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
