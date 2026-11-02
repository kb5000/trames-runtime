// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux AArch64 socket ABI. Preflight every destination before host side
//! effects. Never pass guest structs, flags, descriptors or pointers to the OS.
use super::Linux;
use std::net::SocketAddr;
#[cfg(test)]
use trames_memory::Memory;
use trames_memory::{Access, CpuMemory};
use trames_net::{encode_address, NetError, MSG_TRUNC};
use trames_vfs::Errno;
type Result<T> = std::result::Result<T, Errno>;
pub(crate) mod local;
pub(crate) mod unix;
pub(super) fn control_number(number: u32) -> bool {
    matches!(number, 200..=205 | 208..=210 | 242)
}
pub(super) fn control_publishes(number: u32, a: [u64; 6]) -> bool {
    matches!(number, 200 | 201 | 203 | 208) || number == 209 && (a[1] as u32, a[2] as u32) == (1, 4)
}
/// Identical socket control ABI for owner and executing-worker dispatch.
pub(super) fn control(
    factory: &trames_vfs::DescriptorFactory,
    socket: &trames_net::Socket,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Option<Result<u64>> {
    if !control_number(number) {
        return None;
    }
    Some((|| match number {
        200 | 203 => {
            let peer = address(memory, a[1], a[2])?;
            if number == 200 {
                socket
                    .bind_authorized(&peer, factory.can_bind_service())
                    .map_err(net)?;
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
            let (fd, _) = factory.accept_socket_output(
                socket,
                if number == 242 { a[3] as u32 } else { 0 },
                |peer| match output {
                    Some(output) => output.write(memory, Some(peer)),
                    None => Ok(()),
                },
            )?;
            Ok(fd as u64)
        }
        204 | 205 => query_address(memory, a, socket.address_size(), || {
            if number == 204 {
                socket.local_bytes()
            } else {
                socket.peer_bytes()
            }
            .map_err(net)
        }),
        208 => {
            if a[1] == 1 && matches!(a[2], 20 | 21 | 66 | 67) {
                if (a[4] as u32) < 4 || (a[4] as u32) > i32::MAX as u32 || a[4] < 16 {
                    return Err(Errno(22));
                }
                Linux::check(memory, a[3], 16, Access::Read)?;
                let seconds = u64_at(memory, a[3])? as i64;
                let micros = u64_at(memory, a[3] + 8)? as i64;
                if !(0..1_000_000).contains(&micros) {
                    return Err(Errno(33));
                }
                let timeout = if seconds < 0 {
                    Some(std::time::Duration::ZERO)
                } else if seconds == 0 && micros == 0 {
                    None
                } else {
                    Some(std::time::Duration::new(
                        seconds as u64,
                        micros as u32 * 1000,
                    ))
                };
                socket.set_io_timeout(matches!(a[2], 20 | 66), timeout);
                return Ok(0);
            }
            write_option(memory, a, |value| {
                socket
                    .set_option_bytes(a[1] as u32, a[2] as u32, value)
                    .map_err(net)
            })
        }
        209 => {
            if a[1] == 1 && matches!(a[2], 20 | 21 | 66 | 67) {
                return read_option(memory, a, || {
                    let timeout = socket
                        .io_timeout(matches!(a[2], 20 | 66))
                        .unwrap_or_default();
                    let mut value = [0; 16];
                    value[..8].copy_from_slice(&timeout.as_secs().to_le_bytes());
                    value[8..].copy_from_slice(&(timeout.subsec_micros() as u64).to_le_bytes());
                    Ok(value)
                });
            }
            read_option(memory, a, || {
                socket
                    .get_option(a[1] as u32, a[2] as u32)
                    .map(i32::to_le_bytes)
                    .map_err(net)
            })
        }
        210 => {
            socket.shutdown(a[1] as u32).map_err(net)?;
            Ok(0)
        }
        _ => unreachable!("socket control number"),
    })())
}

fn net(error: NetError) -> Errno {
    Errno(error.0)
}

fn packet_control(
    memory: &impl CpuMemory,
    address: u64,
    size: u64,
) -> Result<Option<trames_net::PacketInfo>> {
    let mut offset = 0;
    let mut info = None;
    while size - offset >= 16 {
        let length = u64_at(memory, address + offset)?;
        if length < 16 || length > size - offset {
            return Err(Errno(22));
        }
        if info.is_some() {
            return Err(Errno(22));
        }
        let level = u32_at(memory, address + offset + 8)?;
        let kind = u32_at(memory, address + offset + 12)?;
        let data = address + offset + 16;
        info = Some(match (level, kind, length) {
            (0, 8, 28) => {
                let mut ip = [0; 4];
                memory.read(data + 4, &mut ip).map_err(|_| Errno(14))?;
                trames_net::PacketInfo {
                    address: std::net::Ipv4Addr::from(ip).into(),
                    interface: u32_at(memory, data)?,
                }
            }
            (41, 50, 36) => {
                let mut ip = [0; 16];
                memory.read(data, &mut ip).map_err(|_| Errno(14))?;
                trames_net::PacketInfo {
                    address: std::net::Ipv6Addr::from(ip).into(),
                    interface: u32_at(memory, data + 16)?,
                }
            }
            (0, 8, _) | (41, 50, _) => return Err(Errno(22)),
            _ => return Err(Errno(95)),
        });
        let padded = (length + 7) & !7;
        if padded > size - offset {
            offset = size;
        } else {
            offset += padded;
        }
    }
    if size != 0 && info.is_none() {
        return Err(Errno(22));
    }
    Ok(info)
}
fn push_control(out: &mut Vec<u8>, level: u32, kind: u32, payload: &[u8]) {
    let size = 16 + payload.len();
    let at = out.len();
    out.resize(at + ((size + 7) & !7), 0);
    out[at..at + 8].copy_from_slice(&(size as u64).to_le_bytes());
    out[at + 8..at + 12].copy_from_slice(&level.to_le_bytes());
    out[at + 12..at + 16].copy_from_slice(&kind.to_le_bytes());
    out[at + 16..at + size].copy_from_slice(payload);
}
fn u32_at(memory: &impl CpuMemory, address: u64) -> Result<u32> {
    let mut bytes = [0; 4];
    memory.read(address, &mut bytes).map_err(|_| Errno(14))?;
    Ok(u32::from_le_bytes(bytes))
}
fn u64_at(memory: &impl CpuMemory, address: u64) -> Result<u64> {
    memory.read_u64(address).map_err(|_| Errno(14))
}
fn address(memory: &impl CpuMemory, pointer: u64, length: u64) -> Result<Vec<u8>> {
    if !(2..=128).contains(&length) {
        return Err(Errno(22));
    }
    Linux::check(memory, pointer, length as usize, Access::Read)?;
    let mut bytes = vec![0; length as usize];
    memory.read(pointer, &mut bytes).map_err(|_| Errno(14))?;
    Ok(bytes)
}
#[derive(Clone, Copy)]
struct AddressOutput {
    pointer: u64,
    length_pointer: u64,
    capacity: usize,
}
impl AddressOutput {
    fn prepare(
        memory: &impl CpuMemory,
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
    fn write(self, memory: &mut impl CpuMemory, address: Option<SocketAddr>) -> Result<()> {
        let bytes = address.map_or_else(Vec::new, encode_address);
        self.write_bytes(memory, &bytes)
    }
    fn write_bytes(self, memory: &mut impl CpuMemory, bytes: &[u8]) -> Result<()> {
        memory
            .write(self.pointer, &bytes[..bytes.len().min(self.capacity)])
            .map_err(|_| Errno(14))?;
        memory
            .write(self.length_pointer, &(bytes.len() as u32).to_le_bytes())
            .map_err(|_| Errno(14))
    }
}
fn query_address(
    memory: &mut impl CpuMemory,
    a: [u64; 6],
    size: usize,
    read: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<u64> {
    let output = AddressOutput::prepare(memory, a[1], a[2], size)?.ok_or(Errno(14))?;
    let address = read()?;
    output.write_bytes(memory, &address)?;
    Ok(0)
}
fn read_option<const N: usize>(
    memory: &mut impl CpuMemory,
    a: [u64; 6],
    read: impl FnOnce() -> Result<[u8; N]>,
) -> Result<u64> {
    Linux::check(memory, a[4], 4, Access::Write)?;
    let capacity = u32_at(memory, a[4])?;
    if capacity > i32::MAX as u32 {
        return Err(Errno(22));
    }
    let count = (capacity as usize).min(N);
    Linux::check(memory, a[3], count, Access::Write)?;
    let value = read()?;
    memory.write(a[3], &value[..count]).map_err(|_| Errno(14))?;
    memory
        .write(a[4], &(count as u32).to_le_bytes())
        .map_err(|_| Errno(14))?;
    Ok(0)
}
fn write_option(
    memory: &impl CpuMemory,
    a: [u64; 6],
    write: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<u64> {
    if a[4] < 4 || a[4] > 65536 {
        return Err(Errno(22));
    }
    Linux::check(memory, a[3], a[4] as usize, Access::Read)?;
    // Ordinary scalar options do not need a temporary heap allocation.
    let mut small = [0; 64];
    let mut large;
    let bytes = if a[4] <= 64 {
        &mut small[..a[4] as usize]
    } else {
        large = vec![0; a[4] as usize];
        &mut large
    };
    memory.read(a[3], bytes).map_err(|_| Errno(14))?;
    write(bytes)?;
    Ok(0)
}
/// Restricted before any guest or host effects. Stateful native controls use
/// the original shared transport; namespace-dependent operations retain owner authority.
pub(crate) fn direct_control(
    control: &trames_net::DirectControl,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64> {
    match number {
        204 | 205 => query_address(memory, a, control.address_size(), || {
            control
                .address(number == 205)
                .map(encode_address)
                .map_err(net)
        }),
        208 => write_option(memory, a, |value| {
            control
                .set_option_bytes(a[1] as u32, a[2] as u32, value)
                .map_err(net)
        }),
        209 => read_option(memory, a, || {
            control
                .get_option(a[1] as u32, a[2] as u32)
                .map(i32::to_le_bytes)
                .map_err(net)
        }),
        210 => control.shutdown(a[1] as u32).map(|()| 0).map_err(net),
        _ => unreachable!("restricted control admission"),
    }
}
#[derive(Clone)]
struct Vectors {
    parts: Vec<(u64, usize)>,
    size: usize,
}
impl Vectors {
    fn prepare(memory: &impl CpuMemory, pointer: u64, count: u64, access: Access) -> Result<Self> {
        Self::prepare_prefix(
            memory,
            pointer,
            count,
            access,
            matches!(access, Access::Write),
        )
    }
    fn prepare_stream(
        memory: &impl CpuMemory,
        pointer: u64,
        count: u64,
        access: Access,
    ) -> Result<Self> {
        Self::prepare_prefix(memory, pointer, count, access, true)
    }
    fn prepare_prefix(
        memory: &impl CpuMemory,
        pointer: u64,
        count: u64,
        access: Access,
        short: bool,
    ) -> Result<Self> {
        if count > 1024 {
            return Err(Errno(90));
        }
        Linux::check(memory, pointer, count as usize * 16, Access::Read)?;
        let mut parts = Vec::new();
        let mut size = 0usize;
        let mut requested = 0u64;
        for i in 0..count {
            let vector = memory
                .read_array::<16>(pointer + i * 16)
                .map_err(|_| Errno(14))?;
            let base = u64::from_le_bytes(vector[..8].try_into().unwrap());
            let length = u64::from_le_bytes(vector[8..].try_into().unwrap());
            // Keep the Linux signed-iovec total valid even when only a short
            // transport prefix will be copied from a large receive capacity.
            requested = requested
                .checked_add(length)
                .filter(|&n| n <= i64::MAX as u64)
                .ok_or(Errno(22))?;
            // Stream sends and receives can complete one transport prefix.
            // Datagram sends must preserve the entire message or fail.
            let room = (trames_net::MAX_TRANSFER - size) as u64;
            let length = if short {
                length.min(room)
            } else if length > room {
                return Err(Errno(90));
            } else {
                length
            };
            Linux::check(memory, base, length as usize, access)?;
            size += length as usize;
            parts.push((base, length as usize));
        }
        Ok(Self { parts, size })
    }
    fn read(&self, memory: &impl CpuMemory) -> Result<Vec<u8>> {
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
    fn write(&self, memory: &mut impl CpuMemory, bytes: &[u8]) -> Result<()> {
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
    pub(super) fn network_ioctl(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        if self.vfs.local_socket(a[0] as u32)?.is_none() {
            self.vfs.socket_fd(a[0] as u32)?;
        }
        let request = a[1] as u32;
        if request != 0x5421 {
            let devices = self.vfs.network_devices();
            if request == 0x8912 {
                // SIOCGIFCONF: AArch64 ifconf and two IPv4 ifreq entries.
                let capacity = u32_at(memory, a[2])?;
                if capacity > i32::MAX as u32 {
                    return Err(Errno(22));
                }
                let pointer = u64_at(memory, a[2] + 8)?;
                Self::check(memory, a[2], 16, Access::Write)?;
                let interfaces: Vec<_> = devices
                    .iter()
                    .flat_map(|d| {
                        d.addresses.iter().filter_map(move |a| {
                            if let std::net::IpAddr::V4(ip) = a.ip {
                                (d.kind != trames_net::DeviceKind::Loopback || d.up)
                                    .then_some((d.name.as_slice(), ip))
                            } else {
                                None
                            }
                        })
                    })
                    .collect();
                let size = if pointer == 0 {
                    interfaces.len() * 40
                } else {
                    (capacity as usize / 40).min(interfaces.len()) * 40
                };
                if pointer != 0 {
                    Self::check(memory, pointer, size, Access::Write)?;
                    let mut entries = vec![0; size];
                    for (i, (name, ip)) in interfaces.into_iter().take(size / 40).enumerate() {
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
                0x8910 | 0x8913 | 0x8914 | 0x8915 | 0x891b | 0x8921 | 0x8933 | 0x8942 | 0x8927
            ) {
                return Err(Errno(25));
            }
            Self::check(memory, a[2], 40, Access::Write)?;
            let mut entry = [0; 40];
            memory.read(a[2], &mut entry).map_err(|_| Errno(14))?;
            let device = if request == 0x8910 {
                let index = u32::from_le_bytes(entry[16..20].try_into().unwrap());
                devices.iter().find(|d| d.index == index)
            } else {
                let end = entry[..16].iter().position(|b| *b == 0).unwrap_or(16);
                devices.iter().find(|d| d.name == entry[..end])
            }
            .ok_or(Errno(19))?;
            let loopback = device.kind == trames_net::DeviceKind::Loopback;
            match request {
                0x8914 => {
                    let flags = u16::from_le_bytes(entry[16..18].try_into().unwrap());
                    if flags & !(1 | 2 | 8 | 0x40 | 0x1000) != 0 {
                        return Err(Errno(95));
                    }
                    self.vfs
                        .set_network_device_up(device.index, flags & 1 != 0)?;
                    return Ok(0);
                }
                0x8942 => entry[16..20].copy_from_slice(&device.master.unwrap_or(0).to_le_bytes()),
                0x8927 => {
                    entry[16..32].fill(0);
                    entry[16..18].copy_from_slice(
                        &(if loopback {
                            772u16
                        } else if device.kind == trames_net::DeviceKind::Direct {
                            65534
                        } else {
                            1
                        })
                        .to_le_bytes(),
                    );
                    entry[18..24].copy_from_slice(&device.mac);
                }
                0x8910 => {
                    entry[..16].fill(0);
                    entry[..device.name.len()].copy_from_slice(&device.name);
                }
                0x8913 => {
                    let flags: u16 = if loopback {
                        8 | if device.up { 0x41 } else { 0 }
                    } else if device.kind == trames_net::DeviceKind::Direct {
                        0xc1
                    } else {
                        0x1002
                            | u16::from(device.up)
                            | if self.vfs.network_carrier(device) {
                                0x40
                            } else {
                                0
                            }
                    };
                    entry[16..18].copy_from_slice(&flags.to_le_bytes());
                }
                0x8915 | 0x891b => {
                    let address = device
                        .addresses
                        .iter()
                        .find(|a| a.ip.is_ipv4())
                        .filter(|_| !loopback || device.up)
                        .ok_or(Errno(99))?;
                    let ip = if request == 0x891b {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                            u32::MAX
                                .checked_shl(32 - u32::from(address.prefix))
                                .unwrap_or(0),
                        ))
                    } else {
                        address.ip
                    };
                    entry[16..32].copy_from_slice(&encode_address(SocketAddr::new(ip, 0)));
                }
                0x8921 => entry[16..20].copy_from_slice(&device.mtu.to_le_bytes()),
                0x8933 => entry[16..20].copy_from_slice(&device.index.to_le_bytes()),
                _ => unreachable!(),
            }
            memory.write(a[2], &entry).map_err(|_| Errno(14))?;
            return Ok(0);
        }
        let enabled = u32_at(memory, a[2])? != 0;
        self.vfs.set_nonblocking(a[0] as u32, enabled)?;
        Ok(0)
    }
    pub fn resume_connect(&self, fd: u32) -> Result<bool> {
        self.vfs.socket_fd(fd)?.resume_connect().map_err(net)
    }
    pub(super) fn network_syscall(
        &mut self,
        number: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        Self::network_vfs(&mut self.vfs, number, a, memory)
    }
    /// Short control operations on the existing owner, without stopping peer
    /// CPUs. Reject before effects when waits or other owner domains are needed.
    pub fn network_service(
        &mut self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64>> {
        if number == 57 {
            return self
                .vfs
                .close_quiescent_tcp(a[0] as u32)
                .map(|r| r.map(|()| 0));
        }
        if number == 198 {
            if !matches!(a[0] as u32, 2 | 10) {
                return None;
            }
            return Some(Self::network_vfs(&mut self.vfs, number as u64, a, memory));
        }
        if !matches!(number, 200..=205 | 208..=210 | 242) {
            return None;
        }
        let socket = self.vfs.socket_operation(a[0] as u32).ok()?;
        if !matches!(socket.address_size(), 16 | 28) {
            return None;
        }
        if matches!(number, 202 | 203 | 242) && socket.flags() & trames_vfs::O_NONBLOCK == 0 {
            return None;
        }
        Some(if control_publishes(number, a) {
            socket.with_tcp_publication(|| {
                Self::network_socket(&mut self.vfs, &socket, number as u64, a, memory)
            })
        } else {
            Self::network_socket(&mut self.vfs, &socket, number as u64, a, memory)
        })
    }
    pub(crate) fn network_vfs(
        vfs: &mut trames_vfs::Vfs,
        number: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        if number == 198 {
            return Ok(vfs.socket(a[0] as u32, a[1] as u32, a[2] as u32)? as u64);
        }
        if number == 199 {
            Self::check(memory, a[3], 8, Access::Write)?;
            let fds = vfs.socketpair(a[0] as u32, a[1] as u32, a[2] as u32)?;
            let bytes: Vec<_> = fds.into_iter().flat_map(u32::to_le_bytes).collect();
            memory.write(a[3], &bytes).map_err(|_| Errno(14))?;
            return Ok(0);
        }
        if let Some(socket) = vfs.local_socket(a[0] as u32)? {
            return Self::local_network_vfs(vfs, &socket, number, a, memory);
        }
        let socket = vfs.socket_operation(a[0] as u32)?;
        // Non-netlink sends can finish an in-progress TCP connection. Their
        // implementation never resolves namespace descriptors through Files.
        if control_publishes(number as u32, a)
            || matches!(number, 206 | 211) && socket.address_size() != 12
        {
            socket.with_tcp_publication(|| Self::network_socket(vfs, &socket, number, a, memory))
        } else {
            Self::network_socket(vfs, &socket, number, a, memory)
        }
    }
    fn network_socket(
        vfs: &mut trames_vfs::Vfs,
        socket: &trames_net::Socket,
        number: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        if control_number(number as u32) {
            return control(&vfs.descriptor_factory(), socket, number as u32, a, memory)
                .expect("socket control ABI");
        }
        match number {
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
                Ok(vfs.socket_send_bytes(socket, &bytes, a[3] as u32, peer.as_deref())? as u64)
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
                    if control_size > trames_net::MAX_TRANSFER as u64 {
                        return Err(Errno(22));
                    }
                    Linux::check(
                        memory,
                        control,
                        control_size as usize,
                        if receive { Access::Write } else { Access::Read },
                    )?;
                }
                let packet_info = if receive {
                    None
                } else {
                    packet_control(memory, control, control_size)?
                };
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
                        push_control(&mut ancillary, level, kind, &(hop as u32).to_le_bytes());
                    }
                    if let Some(info) = received.packet_info {
                        let mut payload = vec![];
                        match info.address {
                            std::net::IpAddr::V4(ip) => {
                                payload.extend_from_slice(&info.interface.to_le_bytes());
                                payload.extend_from_slice(&ip.octets());
                                payload.extend_from_slice(&ip.octets());
                                push_control(&mut ancillary, 0, 8, &payload);
                            }
                            std::net::IpAddr::V6(ip) => {
                                payload.extend_from_slice(&ip.octets());
                                payload.extend_from_slice(&info.interface.to_le_bytes());
                                push_control(&mut ancillary, 41, 50, &payload);
                            }
                        }
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
                    let bytes = vectors.read(memory)?;
                    if let Some(info) = packet_info {
                        let peer = peer
                            .as_deref()
                            .map(trames_net::decode_address)
                            .transpose()
                            .map_err(net)?;
                        Ok(socket
                            .send_packet(&bytes, a[2] as u32, peer, info)
                            .map_err(net)? as u64)
                    } else {
                        Ok(
                            vfs.socket_send_bytes(socket, &bytes, a[2] as u32, peer.as_deref())?
                                as u64,
                        )
                    }
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
    fn worker_so_error_fault_does_not_consume_the_original_pending_failure() {
        use std::{
            net::{Ipv4Addr, TcpListener},
            time::{Duration, Instant},
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut v = trames_vfs::Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1 | trames_vfs::O_NONBLOCK, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert_eq!(socket.connect(address), Err(NetError(115)));
        let deadline = Instant::now() + Duration::from_secs(2);
        while matches!(socket.connect_complete(), Ok(false)) {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let direct = crate::DirectSyscalls::default().with_network(v.direct_network());
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &4u32.to_le_bytes()).unwrap();
        assert_eq!(
            direct.invoke_socket_control(209, [fd as u64, 1, 4, u64::MAX, 0x1000, 0], &mut memory),
            Some(Err(Errno(14)))
        );
        assert_eq!(
            direct.invoke_socket_control(209, [fd as u64, 1, 4, 0x1008, 0x1000, 0], &mut memory),
            Some(Ok(0))
        );
        assert_eq!(
            memory.read_array::<4>(0x1008).unwrap(),
            111i32.to_le_bytes()
        );
        assert_eq!(socket.get_option(1, 4), Ok(0));
        assert_eq!(socket.connect_complete(), Err(NetError(111)));
        assert!(v.direct_tcp_fd(fd).is_none());
    }
    #[test]
    fn direct_and_owner_controls_share_copyout_and_option_error_order() {
        let cases: [(u32, [u64; 6]); 17] = [
            (208, [3, 6, 1, 0x1100, 4, 0]),
            (208, [3, 6, 1, 0x9000, 4, 0]),
            (208, [3, 6, 1, 0x1100, 3, 0]),
            (208, [3, 6, 1, 0x1100, 65537, 0]),
            (209, [3, 6, 1, 0x1110, 0x1000, 0]),
            (209, [3, 6, 1, 0x9000, 0x1000, 0]),
            (209, [3, 1, 3, 0x1110, 0x9000, 0]),
            (204, [3, 0x1300, 0x1200, 0, 0, 0]),
            (204, [3, 0, 0x1200, 0, 0, 0]),
            (205, [3, 0x1300, 0x1200, 0, 0, 0]),
            (208, [3, 1, 9, 0x1100, 4, 0]),
            (209, [3, 1, 9, 0x1110, 0x1000, 0]),
            (209, [3, 1, 4, 0x1110, 0x1000, 0]),
            (209, [3, 1, 4, 0x9000, 0x1000, 0]),
            (209, [3, 1, 30, 0x1110, 0x1000, 0]),
            (210, [3, 3, 0, 0, 0, 0]),
            (210, [3, 1, 0, 0, 0, 0]),
        ];
        for (number, args) in cases {
            let mut results = Vec::new();
            for worker in [false, true] {
                let mut linux = Linux::new(0x10000);
                linux.vfs.configure_network(NetworkMode::Loopback).unwrap();
                assert_eq!(linux.vfs.socket(2, 1, 0).unwrap(), 3);
                let mut memory = Memory::default();
                memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
                memory.write_array(0x1000, 4u32.to_le_bytes()).unwrap();
                memory.write_array(0x1100, 1i32.to_le_bytes()).unwrap();
                memory.write_array(0x1200, 16u32.to_le_bytes()).unwrap();
                let value = if worker {
                    let direct =
                        crate::DirectSyscalls::default().with_network(linux.vfs.direct_network());
                    let mut view = memory.parallel_view(&mut Default::default()).unwrap();
                    let value = direct
                        .invoke_socket_control(number, args, &mut view)
                        .unwrap();
                    drop(view);
                    memory.commit_parallel().unwrap();
                    assert_eq!(direct.socket_completed(), 1);
                    value
                } else {
                    Linux::network_vfs(&mut linux.vfs, number as u64, args, &mut memory)
                };
                results.push((
                    value,
                    memory.read_array::<4096>(0x1000).unwrap(),
                    linux.vfs.socket_fd(3).unwrap().get_option(6, 1),
                ));
            }
            assert_eq!(results[0], results[1], "control {number} {args:?}");
        }
    }
    #[test]
    fn explicit_dns_send_retires_native_control_publication() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.configure_network(NetworkMode::Full).unwrap();
        let fd = linux.vfs.socket(2, 1, 0).unwrap();
        let direct = crate::DirectSyscalls::default().with_network(linux.vfs.direct_network());
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .write(0x1000, &encode_address("127.0.0.53:53".parse().unwrap()))
            .unwrap();
        assert!(direct
            .invoke_socket_control(204, [fd as u64, 0, 0, 0, 0, 0], &mut memory)
            .is_some());
        assert_eq!(
            Linux::network_vfs(
                &mut linux.vfs,
                206,
                [fd as u64, 0, 0, 0, 0x1000, 16],
                &mut memory
            ),
            Ok(0)
        );
        assert_eq!(
            direct.invoke_socket_control(204, [fd as u64, 0, 0, 0, 0, 0], &mut memory),
            None
        );
    }
    #[test]
    fn unsupported_socket_options_defer_before_memory_or_native_effects() {
        let mut v = trames_vfs::Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let direct = crate::DirectSyscalls::default().with_network(v.direct_network());
        let mut memory = Memory::default();
        for (number, level, option) in [(208, 1, 20), (209, 1, 20), (208, 0, 8), (209, 0, 8)] {
            assert_eq!(
                direct.invoke_socket_control(
                    number,
                    [fd as u64, level, option, u64::MAX, u64::MAX, 0],
                    &mut memory
                ),
                None
            );
        }
        assert_eq!(direct.socket_completed(), 0);
    }

    #[test]
    fn idle_tcp_close_services_preserve_aliases_and_defer_active_resources() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.configure_network(NetworkMode::Loopback).unwrap();
        let mut memory = Memory::default();
        let capture = linux.vfs.direct_network();
        let fd = linux.vfs.socket(2, 1, 0).unwrap();
        let alias = linux.vfs.dup(fd, 0, false).unwrap();
        assert_eq!(
            linux.network_service(57, [fd as u64, 0, 0, 0, 0, 0], &mut memory),
            Some(Ok(0))
        );
        assert_eq!(linux.vfs.live_sockets(), 1);
        assert!(linux.vfs.socket_fd(alias).unwrap().idle_tcp());
        let factory = linux.vfs.descriptor_factory();
        let event = std::thread::spawn(move || factory.eventfd(0, 0).unwrap())
            .join()
            .unwrap();
        assert_eq!(event, fd);
        assert_eq!(
            linux.network_service(57, [event as u64, 0, 0, 0, 0, 0], &mut memory),
            None
        );
        assert_eq!(
            linux.network_service(57, [alias as u64, 0, 0, 0, 0, 0], &mut memory),
            Some(Ok(0))
        );
        assert_eq!(linux.vfs.live_sockets(), 0);
        assert!(capture.get(fd).is_none());
        let fd = linux.vfs.socket(2, 1, 0).unwrap();
        let socket = linux.vfs.socket_fd(fd).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(socket.idle_tcp());
        socket.listen(1).unwrap();
        assert!(!socket.idle_tcp());
        assert_eq!(
            linux.network_service(57, [fd as u64, 0, 0, 0, 0, 0], &mut memory),
            None
        );
        let _client = std::net::TcpStream::connect(socket.local_addr().unwrap()).unwrap();
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let connected = linux.vfs.socket(2, 1, 0).unwrap();
        let tcp = linux.vfs.socket_fd(connected).unwrap();
        assert!(matches!(
            tcp.connect(peer.local_addr().unwrap()),
            Ok(()) | Err(NetError(115))
        ));
        assert!(!tcp.idle_tcp());
        assert_eq!(
            linux.network_service(57, [connected as u64, 0, 0, 0, 0, 0], &mut memory),
            None
        );
        let (_peer, _) = peer.accept().unwrap();
        assert_eq!(tcp.connect_complete(), Ok(true));
        let accepted = linux.vfs.direct_network().get(connected).unwrap();
        assert_eq!(
            linux.network_service(57, [connected as u64, 0, 0, 0, 0, 0], &mut memory),
            None
        );
        drop(accepted);
        assert_eq!(
            linux.network_service(57, [connected as u64, 0, 0, 0, 0, 0], &mut memory),
            Some(Ok(0))
        );
        let udp = linux.vfs.socket(2, 2, 0).unwrap();
        assert_eq!(
            linux.network_service(57, [udp as u64, 0, 0, 0, 0, 0], &mut memory),
            None
        );
        assert_eq!(
            linux.network_service(57, [9999, 0, 0, 0, 0, 0], &mut memory),
            Some(Err(Errno(9)))
        );
    }

    #[test]
    fn network_services_use_live_views_and_defer_blocking_before_effects() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.configure_network(NetworkMode::Loopback).unwrap();
        let capture = linux.vfs.direct_network();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        memory
            .write(0x1000, &encode_address(peer.local_addr().unwrap()))
            .unwrap();
        memory.write(0x1100, &4u32.to_le_bytes()).unwrap();
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let fd = linux
            .network_service(198, [2, 1, 0, 0, 0, 0], &mut view)
            .unwrap()
            .unwrap();
        assert_eq!(
            linux.network_service(203, [fd, 0x1000, 16, 0, 0, 0], &mut view),
            None
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        linux.vfs.set_nonblocking(fd as u32, true).unwrap();
        let result = linux
            .network_service(203, [fd, 0x1000, 16, 0, 0, 0], &mut view)
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(Errno(115))));
        peer.set_nonblocking(false).unwrap();
        let (_peer, _) = peer.accept().unwrap();
        assert_eq!(
            linux.vfs.socket_fd(fd as u32).unwrap().connect_complete(),
            Ok(true)
        );
        assert_eq!(
            linux.network_service(209, [fd, 1, 4, 0x1110, 0x1100, 0], &mut view),
            Some(Ok(0))
        );
        assert!(capture.get(fd as u32).is_some());
        let local = linux
            .network_service(
                198,
                [2, 1 | trames_vfs::O_NONBLOCK as u64, 0, 0, 0, 0],
                &mut view,
            )
            .unwrap()
            .unwrap();
        linux
            .vfs
            .socket_fd(local as u32)
            .unwrap()
            .bind("127.0.0.1:0".parse().unwrap())
            .unwrap();
        assert_eq!(
            linux.network_service(201, [local, 1, 0, 0, 0, 0], &mut view),
            Some(Ok(0))
        );
        assert_eq!(
            linux.network_service(242, [local, 0, 0, 0, 0, 0], &mut view),
            Some(Err(Errno(11)))
        );
        assert_eq!(
            linux.network_service(198, [1, 1, 0, 0, 0, 0], &mut view),
            None
        );
        drop(view);
        memory.commit_parallel().unwrap();
        assert_eq!(u32_at(&memory, 0x1110), Ok(0));
    }

    #[test]
    fn udp_pktinfo_cmsg_roundtrip_and_invalid_receive_are_transactional() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.configure_network(NetworkMode::Full).unwrap();
        let fd = linux.vfs.socket(2, 2 | trames_vfs::O_NONBLOCK, 0).unwrap();
        let socket = linux.vfs.socket_fd(fd).unwrap();
        socket.bind("0.0.0.0:0".parse().unwrap()).unwrap();
        socket.set_option(0, 8, 1).unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.send_to(b"abc", ("127.0.0.1", socket.local_addr().unwrap().port()))
            .unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1000, &[0; 56]).unwrap();
        memory.write(0x1000, &0x1700u64.to_le_bytes()).unwrap();
        memory.write(0x1008, &16u32.to_le_bytes()).unwrap();
        for (offset, value) in [(16, 0x1200u64), (24, 1), (32, 0x9000), (40, 32)] {
            memory.write(0x1000 + offset, &value.to_le_bytes()).unwrap();
        }
        memory.write(0x1200, &0x1300u64.to_le_bytes()).unwrap();
        memory.write(0x1208, &10u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.network_syscall(212, [fd as u64, 0x1000, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        memory.write(0x1020, &0x1400u64.to_le_bytes()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while socket.poll(1).unwrap() & 1 == 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            linux.network_syscall(212, [fd as u64, 0x1000, 0, 0, 0, 0], &mut memory),
            Ok(3)
        );
        assert_eq!(memory.read_u64(0x1400).unwrap(), 28);
        assert_eq!(u32_at(&memory, 0x140c), Ok(8));
        assert_eq!(u32_at(&memory, 0x1410), Ok(1));
        assert_eq!(
            u32_at(&memory, 0x1414),
            Ok(u32::from_le_bytes([127, 0, 0, 1]))
        );
        memory.write(0x1208, &3u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.network_syscall(211, [fd as u64, 0x1000, 0, 0, 0, 0], &mut memory),
            Ok(3)
        );
        let mut bytes = [0; 10];
        let n = loop {
            match peer.recv(&mut bytes) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::yield_now();
                }
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(n, 3);
        assert_eq!(&bytes[..3], b"abc");
        memory.write(0x1400, &15u64.to_le_bytes()).unwrap();
        assert_eq!(
            linux.network_syscall(211, [fd as u64, 0x1000, 0, 0, 0, 0], &mut memory),
            Err(Errno(22))
        );
        assert_eq!(
            peer.recv(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn invalid_accept_destination_does_not_drop_queued_connection() {
        fn ready<T>(
            socket: &std::sync::Arc<trames_net::Socket>,
            mut operation: impl FnMut() -> Result<T>,
        ) -> T {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match operation() {
                    Ok(value) => return value,
                    Err(Errno(11)) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "socket readiness timed out"
                        );
                        trames_net::wait(
                            &[(socket.clone(), 1)],
                            std::time::Duration::from_millis(10),
                        )
                        .unwrap();
                    }
                    Err(error) => panic!("unexpected socket error: {error:?}"),
                }
            }
        }
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
        // Successful connect/send does not synchronously publish readiness to
        // the nonblocking guest endpoint on every host (notably Darwin).
        let accepted = ready(&socket, || {
            linux.network_syscall(202, [fd as u64, 0x1100, 0x1000, 0, 0, 0], &mut memory)
        }) as u32;
        client.write_all(b"x").unwrap();
        let socket = linux.vfs.socket_fd(accepted).unwrap();
        assert_eq!(ready(&socket, || linux.vfs.read(accepted, 1)), b"x");
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
        let reserved_fd = linux.vfs.socket(2, 1, 0).unwrap();
        let reserved = linux.vfs.socket_fd(reserved_fd).unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = reserved.local_addr().unwrap();
        // Test a closed port. Darwin may silently retain SYNs for a bound,
        // non-listening socket, which is not a portable refusal fixture.
        linux.vfs.close(reserved_fd).unwrap();
        drop(reserved);
        let socket = linux.vfs.socket_fd(fd).unwrap();
        let error = socket.connect(address).unwrap_err().0;
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
