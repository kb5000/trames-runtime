// SPDX-License-Identifier: GPL-3.0-or-later
//! One short descriptor-control ABI over original OFDs on source and solo paths.
use crate::Linux;
use trames_memory::CpuMemory;
use trames_vfs::{Errno, FdKind, Vfs};

pub(crate) fn call(vfs: &mut Vfs, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
    // Linux's cmd is unsigned int. musl may sign-extend its int ioctl request
    // into the syscall register; upper register bits are not part of the ABI.
    let mut a = a;
    a[1] = u64::from(a[1] as u32);
    if vfs.flags(a[0] as u32)? & trames_vfs::O_PATH != 0 {
        return Err(Errno(9));
    }
    if let Some(file) = vfs.binder_file(a[0] as u32)? {
        return match trames_vfs::binder::Ioctl::start(
            file,
            vfs.descriptor_factory(),
            vfs.task_pid(),
            a[1] as u32,
            a[2],
            memory,
        )? {
            trames_vfs::binder::Started::Complete(value) => Ok(value),
            trames_vfs::binder::Started::Read(mut read) => read.finish(memory)?.ok_or(Errno(11)),
        };
    }
    if a[1] as u32 == 0x541b {
        if let Some(bytes) = vfs.readable_bytes(a[0] as u32)? {
            memory
                .write(a[2], &(bytes as u32).to_le_bytes())
                .map_err(|_| Errno(14))?;
            return Ok(0);
        }
    }
    if a[1] as u32 == 0x5421 {
        let mut value = [0; 4];
        memory.read(a[2], &mut value).map_err(|_| Errno(14))?;
        vfs.set_nonblocking(a[0] as u32, u32::from_le_bytes(value) != 0)?;
        Ok(0)
    } else if let Some(kind) = vfs.namespace_type(a[0] as u32)? {
        match a[1] as u32 {
            0xb703 => Ok(kind),
            _ => Err(Errno(25)),
        }
    } else if vfs.is_render_device(a[0] as u32)? {
        Linux::render_ioctl(a[1], a[2], memory)
    } else if vfs.fd_kind(a[0] as u32)? == FdKind::Socket {
        Linux::network_ioctl(vfs, a, memory)
    } else {
        Err(Errno(25))
    }
}
