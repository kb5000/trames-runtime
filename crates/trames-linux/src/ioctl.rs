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
    if a[1] as u32 != 0x5421 {
        if let Some(file) = vfs.tun_file(a[0] as u32)? {
            return tun_ioctl(vfs, &file, a[1] as u32, a[2], memory);
        }
    }
    if let Some(file) = vfs.sync_file(a[0] as u32)? {
        return file.ioctl(&vfs.descriptor_factory(), a[1] as u32, a[2], memory);
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

fn tun_ioctl(
    vfs: &Vfs,
    file: &trames_net::tun::Connection,
    request: u32,
    argument: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let net = |e: trames_net::NetError| Errno(e.0);
    match request {
        0x800454cf => {
            memory
                .write(argument, &trames_net::tun::FEATURES.to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        0x400454ca => {
            // Linux ifreq is 40 bytes on AArch64; preflight its output before publishing a link.
            let mut ifreq = memory.read_array::<40>(argument).map_err(|_| Errno(14))?;
            memory
                .check(argument, 40, trames_memory::Access::Write)
                .map_err(|_| Errno(14))?;
            let name = &ifreq[..ifreq[..16].iter().position(|b| *b == 0).ok_or(Errno(22))?];
            let flags = u16::from_le_bytes([ifreq[16], ifreq[17]]);
            let name = file
                .attach(
                    name,
                    flags,
                    vfs.descriptor_factory()
                        .local_credentials()
                        .has_cap(trames_vfs::capabilities::NET_ADMIN),
                )
                .map_err(net)?;
            ifreq[..16].fill(0);
            ifreq[..name.len()].copy_from_slice(&name);
            memory.write(argument, &ifreq).map_err(|_| Errno(14))?;
        }
        0x800454d2 => {
            let (name, flags) = file.interface().map_err(net)?;
            let mut ifreq = [0; 40];
            ifreq[..name.len()].copy_from_slice(&name);
            ifreq[16..18].copy_from_slice(&flags.to_le_bytes());
            memory.write(argument, &ifreq).map_err(|_| Errno(14))?;
        }
        0x400454d0 if argument == 0 => (), // No checksum/GSO offloads advertised.
        _ => return Err(Errno(95)),
    }
    Ok(0)
}

#[cfg(test)]
mod tun_tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn tun_creation_preflights_output_and_reports_real_interface_flags() {
        let mut linux = Linux::new(0x10000);
        linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Full)
            .unwrap();
        linux
            .vfs
            .set_runtime_info(1, trames_vfs::RuntimeInfo::default());
        let fd = linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/dev/net/tun", 2, 0)
            .unwrap();
        let before = linux.vfs.network_devices().len();

        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1200, &1u32.to_le_bytes()).unwrap();
        assert_eq!(
            call(
                &mut linux.vfs,
                [fd as u64, 0x5421, 0x1200, 0, 0, 0],
                &mut memory
            ),
            Ok(0)
        );
        assert_ne!(linux.vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
        let mut ifreq = [0u8; 40];
        ifreq[..5].copy_from_slice(b"tun%d");
        ifreq[16..18].copy_from_slice(&0x1001u16.to_le_bytes());
        memory.write(0x1000, &ifreq).unwrap();
        assert_eq!(
            call(
                &mut linux.vfs,
                [fd as u64, 0x400454ca, 0x9000, 0, 0, 0],
                &mut memory
            ),
            Err(Errno(14))
        );
        assert_eq!(linux.vfs.network_devices().len(), before);
        assert_eq!(
            call(
                &mut linux.vfs,
                [fd as u64, 0x400454ca, 0x1000, 0, 0, 0],
                &mut memory
            ),
            Ok(0)
        );
        assert_eq!(memory.read_array::<5>(0x1000).unwrap(), *b"tun0\0");
        let socket = linux.vfs.socket(2, 2, 0).unwrap();
        ifreq[..16].fill(0);
        ifreq[..4].copy_from_slice(b"tun0");
        ifreq[16..18].copy_from_slice(&0x91u16.to_le_bytes());
        memory.write(0x1100, &ifreq).unwrap();
        assert_eq!(
            call(
                &mut linux.vfs,
                [socket as u64, 0x8914, 0x1100, 0, 0, 0],
                &mut memory
            ),
            Ok(0)
        );
        assert_eq!(
            call(
                &mut linux.vfs,
                [socket as u64, 0x8913, 0x1100, 0, 0, 0],
                &mut memory
            ),
            Ok(0)
        );
        assert_eq!(
            u16::from_le_bytes(memory.read_array::<2>(0x1110).unwrap()) & 0x91,
            0x91
        );
        linux.vfs.close(fd).unwrap();
        assert_eq!(linux.vfs.network_devices().len(), before);
    }
}
