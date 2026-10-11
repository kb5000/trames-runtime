// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux AArch64 socket ABI. Preflight every destination before host side
//! effects. Never pass guest structs, flags, descriptors or pointers to the OS.
use super::Linux;
use std::net::SocketAddr;
use trames_memory::{Access, Memory};
use trames_net::{encode_address, NetError, MSG_TRUNC};
use trames_vfs::Errno;
type Result<T> = std::result::Result<T, Errno>;
fn net(error: NetError) -> Errno {
    Errno(error.0)
}

fn u32_at(memory: &Memory, address: u64) -> Result<u32> {
    let mut bytes = [0; 4];
    memory.read(address, &mut bytes).map_err(|_| Errno(14))?;
    Ok(u32::from_le_bytes(bytes))
}
fn u64_at(memory: &Memory, address: u64) -> Result<u64> {
    memory.read_u64(address).map_err(|_| Errno(14))
}
fn address(memory: &Memory, pointer: u64, length: u64) -> Result<Vec<u8>> {
    if !(2..=128).contains(&length) {
        return Err(Errno(22));
    }
    Linux::check(memory, pointer, length as usize, Access::Read)?;
    let mut bytes = vec![0; length as usize];
    memory.read(pointer, &mut bytes).map_err(|_| Errno(14))?;
    Ok(bytes)
}
struct AddressOutput {
    pointer: u64,
    length_pointer: u64,
    capacity: usize,
}
impl AddressOutput {
    fn prepare(
        memory: &Memory,
        pointer: u64,
        length_pointer: u64,
        size: usize,
    ) -> Result<Option<Self>> {
        if pointer == 0 {
            return Ok(None);
        }
        Linux::check(memory, length_pointer, 4, Access::Write)?;
        let capacity = u32_at(memory, length_pointer)?;
        if capacity > i32::MAX as u32 {
            return Err(Errno(22));
        }
        Linux::check(
            memory,
            pointer,
            (capacity as usize).min(size),
            Access::Write,
        )?;
        Ok(Some(Self {
            pointer,
            length_pointer,
            capacity: capacity as usize,
        }))
    }
    fn write(self, memory: &mut Memory, address: Option<SocketAddr>) -> Result<()> {
        let bytes = address.map_or_else(Vec::new, encode_address);
        self.write_bytes(memory, &bytes)
    }
    fn write_bytes(self, memory: &mut Memory, bytes: &[u8]) -> Result<()> {
        memory
            .write(self.pointer, &bytes[..bytes.len().min(self.capacity)])
            .map_err(|_| Errno(14))?;
        memory
            .write(self.length_pointer, &(bytes.len() as u32).to_le_bytes())
            .map_err(|_| Errno(14))
    }
}
struct Vectors {
    parts: Vec<(u64, usize)>,
    size: usize,
}
impl Vectors {
    fn prepare(memory: &Memory, pointer: u64, count: u64, access: Access) -> Result<Self> {
        if count > 1024 {
            return Err(Errno(90));
        }
        Linux::check(memory, pointer, count as usize * 16, Access::Read)?;
        let mut parts = Vec::new();
        let mut size = 0usize;
        for i in 0..count {
            let base = u64_at(memory, pointer + i * 16)?;
            let length = u64_at(memory, pointer + i * 16 + 8)?;
            // Datagram sends must never silently change a packet by shortening
            // the iovecs. Stream callers can retry a short send themselves.
            if length > (trames_net::MAX_TRANSFER - size) as u64 {
                return Err(Errno(90));
            }
            Linux::check(memory, base, length as usize, access)?;
            size += length as usize;
            parts.push((base, length as usize));
        }
        Ok(Self { parts, size })
    }
    fn read(&self, memory: &Memory) -> Result<Vec<u8>> {
        let mut bytes = vec![0; self.size];
        let mut offset = 0;
        for &(pointer, size) in &self.parts {
            memory
                .read(pointer, &mut bytes[offset..offset + size])
                .map_err(|_| Errno(14))?;
            offset += size;
        }
        Ok(bytes)
    }
    fn write(&self, memory: &mut Memory, bytes: &[u8]) -> Result<()> {
        let mut offset = 0;
        for &(pointer, size) in &self.parts {
            let take = size.min(bytes.len() - offset);
            memory
                .write(pointer, &bytes[offset..offset + take])
                .map_err(|_| Errno(14))?;
            offset += take;
            if offset == bytes.len() {
                break;
            }
        }
        Ok(())
    }
}
impl Linux {
    pub(super) fn network_ioctl(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        self.vfs.socket_fd(a[0] as u32)?;
        let request = a[1] as u32;
        if request != 0x5421 {
            let info = self.vfs.network_info().ok_or(Errno(25))?;
            if request == 0x8912 {
                // SIOCGIFCONF: AArch64 ifconf and two IPv4 ifreq entries.
                let capacity = u32_at(memory, a[2])?;
                if capacity > i32::MAX as u32 {
                    return Err(Errno(22));
                }
                let pointer = u64_at(memory, a[2] + 8)?;
                Self::check(memory, a[2], 16, Access::Write)?;
                let size = if pointer == 0 {
                    80
                } else {
                    (capacity as usize / 40).min(2) * 40
                };
                if pointer != 0 {
                    Self::check(memory, pointer, size, Access::Write)?;
                    let mut entries = vec![0; size];
                    for (i, (name, ip)) in [
                        (b"lo".as_slice(), std::net::Ipv4Addr::LOCALHOST),
                        (b"trames0".as_slice(), info.ipv4),
                    ]
                    .into_iter()
                    .take(size / 40)
                    .enumerate()
                    {
                        let e = &mut entries[i * 40..(i + 1) * 40];
                        e[..name.len()].copy_from_slice(name);
                        e[16..32].copy_from_slice(&encode_address(SocketAddr::new(ip.into(), 0)));
                    }
                    memory.write(pointer, &entries).map_err(|_| Errno(14))?;
                }
                memory
                    .write(a[2], &(size as u32).to_le_bytes())
                    .map_err(|_| Errno(14))?;
                return Ok(0);
            }
            if !matches!(
                request,
                0x8910 | 0x8913 | 0x8915 | 0x891b | 0x8921 | 0x8933 | 0x8942 | 0x8927
            ) {
                return Err(Errno(25));
            }
            Self::check(memory, a[2], 40, Access::Write)?;
            let mut entry = [0; 40];
            memory.read(a[2], &mut entry).map_err(|_| Errno(14))?;
            let loopback = if request == 0x8910 {
                match u32::from_le_bytes(entry[16..20].try_into().unwrap()) {
                    1 => true,
                    2 => false,
                    _ => return Err(Errno(19)),
                }
            } else {
                let end = entry[..16].iter().position(|b| *b == 0).unwrap_or(16);
                match &entry[..end] {
                    b"lo" => true,
                    b"trames0" => false,
                    _ => return Err(Errno(19)),
                }
            };
            match request {
                0x8942 => entry[16..20].copy_from_slice(&0u32.to_le_bytes()),
                0x8927 => {
                    entry[16..32].fill(0);
                    entry[16..18]
                        .copy_from_slice(&(if loopback { 772u16 } else { 65534 }).to_le_bytes());
                }
                0x8910 => {
                    entry[..16].fill(0);
                    let name = if loopback {
                        b"lo".as_slice()
                    } else {
                        b"trames0".as_slice()
                    };
                    entry[..name.len()].copy_from_slice(name);
                }
                0x8913 => entry[16..18]
                    .copy_from_slice(&(if loopback { 0x49u16 } else { 0xc1u16 }).to_le_bytes()),
                0x8915 | 0x891b => {
                    let ip = if request == 0x891b {
                        std::net::Ipv4Addr::new(
                            255,
                            if loopback { 0 } else { 255 },
                            if loopback { 0 } else { 255 },
                            0,
                        )
                    } else if loopback {
                        std::net::Ipv4Addr::LOCALHOST
                    } else {
                        info.ipv4
                    };
                    entry[16..32].copy_from_slice(&encode_address(SocketAddr::new(ip.into(), 0)));
                }
                0x8921 => entry[16..20].copy_from_slice(&info.mtu.to_le_bytes()),
                0x8933 => entry[16..20]
                    .copy_from_slice(&(if loopback { 1u32 } else { 2u32 }).to_le_bytes()),
                _ => unreachable!(),
            }
            memory.write(a[2], &entry).map_err(|_| Errno(14))?;
            return Ok(0);
        }
        let enabled = u32_at(memory, a[2])? != 0;
        let mut flags = self.vfs.flags(a[0] as u32)? & !trames_vfs::O_CLOEXEC;
        if enabled {
            flags |= trames_vfs::O_NONBLOCK;
        } else {
            flags &= !trames_vfs::O_NONBLOCK;
        }
        self.vfs.set_status_flags(a[0] as u32, flags)?;
        Ok(0)
    }
    pub fn resume_connect(&self, fd: u32) -> Result<bool> {
        self.vfs.socket_fd(fd)?.resume_connect().map_err(net)
    }
    pub(super) fn network_syscall(
        &mut self,
        number: u64,
        a: [u64; 6],
        memory: &mut Memory,
    ) -> Result<u64> {
        if number == 198 {
            return Ok(self.vfs.socket(a[0] as u32, a[1] as u32, a[2] as u32)? as u64);
        }
        if number == 199 {
            return Err(Errno(97));
        } // AF_UNIX/socketpair is a separate virtual IPC backend
        let socket = self.vfs.socket_fd(a[0] as u32)?;
        match number {
            200 | 203 => {
                let peer = address(memory, a[1], a[2])?;
                if number == 200 {
                    socket.bind_bytes(&peer).map_err(net)?;
                } else {
                    socket.connect_bytes(&peer).map_err(net)?;
                }
                Ok(0)
            }
            201 => {
                socket.listen(a[1] as u32).map_err(net)?;
                Ok(0)
            }
            202 | 242 => {
                let output = AddressOutput::prepare(memory, a[1], a[2], socket.address_size())?;
                let (fd, peer) = self
                    .vfs
                    .accept(a[0] as u32, if number == 242 { a[3] as u32 } else { 0 })?;
                if let Some(output) = output {
                    output.write(memory, Some(peer))?;
                }
                Ok(fd as u64)
            }
            204 | 205 => {
                let output = AddressOutput::prepare(memory, a[1], a[2], socket.address_size())?
                    .ok_or(Errno(14))?;
                let address = if number == 204 {
                    socket.local_bytes()
                } else {
                    socket.peer_bytes()
                }
                .map_err(net)?;
                output.write_bytes(memory, &address)?;
                Ok(0)
            }
            206 => {
                if a[2] > trames_net::MAX_TRANSFER as u64 {
                    return Err(Errno(90));
                }
                Linux::check(memory, a[1], a[2] as usize, Access::Read)?;
                let peer = if a[4] == 0 {
                    None
                } else {
                    Some(address(memory, a[4], a[5])?)
                };
                let mut bytes = vec![0; a[2] as usize];
                memory.read(a[1], &mut bytes).map_err(|_| Errno(14))?;
                Ok(socket
                    .send_bytes(&bytes, a[3] as u32, peer.as_deref())
                    .map_err(net)? as u64)
            }
            207 => {
                let count = a[2].min(trames_net::MAX_TRANSFER as u64) as usize;
                Linux::check(memory, a[1], count, Access::Write)?;
                let output = AddressOutput::prepare(memory, a[4], a[5], socket.address_size())?;
                let received = socket.recv(count, a[3] as u32).map_err(net)?;
                memory.write(a[1], &received.data).map_err(|_| Errno(14))?;
                if let Some(output) = output {
                    output.write_bytes(memory, &socket.received_address(&received))?;
                }
                Ok(if a[3] as u32 & MSG_TRUNC != 0 {
                    received.length
                } else {
                    received.data.len()
                } as u64)
            }
            208 => {
                if (a[4] as u32) < 4 || (a[4] as u32) > i32::MAX as u32 {
                    return Err(Errno(22));
                }
                // SOL_SOCKET receive/send timeouts require a timespec ABI and
                // scheduler deadlines; never pretend a timeout was installed.
                if a[1] == 1 && matches!(a[2], 20 | 21) {
                    return Err(Errno(95));
                }
                if a[4] > 65536 {
                    return Err(Errno(22));
                }
                Self::check(memory, a[3], a[4] as usize, Access::Read)?;
                let mut value = vec![0; a[4] as usize];
                memory.read(a[3], &mut value).map_err(|_| Errno(14))?;
                socket
                    .set_option_bytes(a[1] as u32, a[2] as u32, &value)
                    .map_err(net)?;
                Ok(0)
            }
            209 => {
                Linux::check(memory, a[4], 4, Access::Write)?;
                let capacity = u32_at(memory, a[4])?;
                if capacity > i32::MAX as u32 {
                    return Err(Errno(22));
                }
                let count = capacity.min(4) as usize;
                Linux::check(memory, a[3], count, Access::Write)?;
                let value = socket
                    .get_option(a[1] as u32, a[2] as u32)
                    .map_err(net)?
                    .to_le_bytes();
                memory.write(a[3], &value[..count]).map_err(|_| Errno(14))?;
                memory
                    .write(a[4], &(count as u32).to_le_bytes())
                    .map_err(|_| Errno(14))?;
                Ok(0)
            }
            210 => {
                socket.shutdown(a[1] as u32).map_err(net)?;
                Ok(0)
            }
            211 | 212 => {
                let receive = number == 212;
                Linux::check(
                    memory,
                    a[1],
                    56,
                    if receive { Access::Write } else { Access::Read },
                )?;
                // Also validate reads of the msghdr when the destination is writable-only.
                Linux::check(memory, a[1], 56, Access::Read)?;
                let name = u64_at(memory, a[1])?;
                let name_size = u32_at(memory, a[1] + 8)?;
                let control = u64_at(memory, a[1] + 32)?;
                let control_size = u64_at(memory, a[1] + 40)?;
                if control_size != 0 {
                    if !receive {
                        return Err(Errno(95));
                    }
                    if control_size > trames_net::MAX_TRANSFER as u64 {
                        return Err(Errno(22));
                    }
                    Linux::check(memory, control, control_size as usize, Access::Write)?;
                }
                let vectors = Vectors::prepare(
                    memory,
                    u64_at(memory, a[1] + 16)?,
                    u64_at(memory, a[1] + 24)?,
                    if receive { Access::Write } else { Access::Read },
                )?;
                if receive {
                    let output =
                        AddressOutput::prepare(memory, name, a[1] + 8, socket.address_size())?;
                    let received = socket.recv(vectors.size, a[2] as u32).map_err(net)?;
                    vectors.write(memory, &received.data)?;
                    if let Some(output) = output {
                        output.write_bytes(memory, &socket.received_address(&received))?;
                    } else {
                        memory
                            .write(a[1] + 8, &0u32.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                    }
                    let mut ancillary = Vec::new();
                    if let Some((level, kind, hop)) = socket.ancillary_hop() {
                        ancillary.resize(24, 0);
                        ancillary[..8].copy_from_slice(&20u64.to_le_bytes());
                        ancillary[8..12].copy_from_slice(&level.to_le_bytes());
                        ancillary[12..16].copy_from_slice(&kind.to_le_bytes());
                        ancillary[16..20].copy_from_slice(&(hop as u32).to_le_bytes());
                    }
                    let control_count = ancillary.len().min(control_size as usize);
                    if control_count != 0 {
                        memory
                            .write(control, &ancillary[..control_count])
                            .map_err(|_| Errno(14))?;
                    }
                    memory
                        .write(a[1] + 40, &(control_count as u64).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                    memory
                        .write(
                            a[1] + 48,
                            &((if received.truncated { MSG_TRUNC } else { 0 })
                                | if control_count < ancillary.len() {
                                    8
                                } else {
                                    0
                                })
                            .to_le_bytes(),
                        )
                        .map_err(|_| Errno(14))?;
                    Ok(if a[2] as u32 & MSG_TRUNC != 0 {
                        received.length
                    } else {
                        received.data.len()
                    } as u64)
                } else {
                    let peer = if name == 0 {
                        None
                    } else {
                        Some(address(memory, name, name_size as u64)?)
                    };
                    Ok(socket
                        .send_bytes(&vectors.read(memory)?, a[2] as u32, peer.as_deref())
                        .map_err(net)? as u64)
                }
            }
            _ => Err(Errno(38)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpStream};
    use trames_memory::{Permissions, PAGE_SIZE};
    use trames_vfs::NetworkMode;
    #[test]
    fn invalid_accept_destination_does_not_drop_queued_connection() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.configure_network(NetworkMode::Loopback).unwrap();
        let fd = linux.vfs.socket(2, 1, 0).unwrap();
        let socket = linux.vfs.socket_fd(fd).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.listen(1).unwrap();
        let mut client = TcpStream::connect(socket.local_addr().unwrap()).unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &16u32.to_le_bytes()).unwrap();
        assert_eq!(
            linux.network_syscall(202, [fd as u64, 0x9000, 0x1000, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(linux.vfs.live_sockets(), 1);
        let accepted = linux
            .network_syscall(202, [fd as u64, 0x1100, 0x1000, 0, 0, 0], &mut memory)
            .unwrap() as u32;
        client.write_all(b"x").unwrap();
        assert_eq!(linux.vfs.read(accepted, 1).unwrap(), b"x");
    }
    #[test]
    fn socket_output_preflight_and_descriptor_type_errors() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.configure_network(NetworkMode::Loopback).unwrap();
        let fd = linux.vfs.socket(2, 1, 0).unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &4u32.to_le_bytes()).unwrap();
        assert_eq!(
            linux.network_syscall(209, [fd as u64, 1, 4, 0x9000, 0x1000, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(
            linux.network_syscall(209, [fd as u64, 1, 3, 0x1100, 0x1000, 0], &mut memory),
            Ok(0)
        );
        assert_eq!(u32_at(&memory, 0x1100), Ok(1));
        let reserved = linux.vfs.socket(2, 1, 0).unwrap();
        let reserved = linux.vfs.socket_fd(reserved).unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let socket = linux.vfs.socket_fd(fd).unwrap();
        let error = socket
            .connect(reserved.local_addr().unwrap())
            .unwrap_err()
            .0;
        assert!(matches!(error, 115 | 111));
        if error == 115 {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while socket.connect_complete() == Ok(false) {
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
            assert_eq!(
                linux.network_syscall(209, [fd as u64, 1, 4, 0x9000, 0x1000, 0], &mut memory),
                Err(Errno(14))
            );
            assert_eq!(
                linux.network_syscall(209, [fd as u64, 1, 4, 0x1100, 0x1000, 0], &mut memory),
                Ok(0)
            );
            assert_eq!(u32_at(&memory, 0x1100), Ok(111));
            assert_eq!(
                linux.network_syscall(209, [fd as u64, 1, 4, 0x1100, 0x1000, 0], &mut memory),
                Ok(0)
            );
            assert_eq!(u32_at(&memory, 0x1100), Ok(0));
        }
        assert_eq!(
            linux.network_syscall(206, [1, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(88))
        );
        assert_eq!(
            linux.network_syscall(206, [999, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(9))
        );
    }
}
