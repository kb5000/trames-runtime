// SPDX-License-Identifier: GPL-3.0-or-later
//! The original IP message ABI, prepared once for an accepted operation.
use super::*;

enum Buffer {
    Scalar(u64, usize),
    Vectored(Vectors),
    RawVectors(Vec<(u64, usize)>, usize),
}
impl Buffer {
    fn size(&self) -> usize {
        match self {
            Self::Scalar(_, size) => *size,
            Self::Vectored(vectors) => vectors.size,
            Self::RawVectors(_, size) => *size,
        }
    }
    fn write(&self, memory: &mut impl CpuMemory, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Scalar(pointer, _) => memory.write(*pointer, bytes).map_err(|_| Errno(14)),
            Self::Vectored(vectors) => vectors.write(memory, bytes),
            Self::RawVectors(parts, _) => Linux::scatter(memory, parts, bytes),
        }
    }
}
struct MessageOutput {
    header: u64,
    control: u64,
    capacity: usize,
}
enum Transfer {
    Send {
        bytes: Vec<u8>,
        peer: Option<Vec<u8>>,
        info: Option<trames_net::PacketInfo>,
    },
    Receive {
        buffer: Buffer,
        address: Option<AddressOutput>,
        message: Option<MessageOutput>,
    },
}
pub(crate) struct Prepared {
    flags: u32,
    address_size: usize,
    transfer: Transfer,
}
impl Prepared {
    /// Only a parked receive needs to revalidate its captured destinations.
    /// No guest header or send input is imported again after acceptance.
    pub fn recheck(&self, memory: &impl CpuMemory) -> Result<()> {
        let Transfer::Receive {
            buffer,
            address,
            message,
        } = &self.transfer
        else {
            return Ok(());
        };
        match buffer {
            Buffer::Scalar(pointer, size) => Linux::check(memory, *pointer, *size, Access::Write)?,
            Buffer::Vectored(vectors) => {
                for &(pointer, size) in &vectors.parts {
                    Linux::check(memory, pointer, size, Access::Write)?;
                }
            }
            Buffer::RawVectors(parts, _) => {
                for &(pointer, size) in parts {
                    if size != 0 {
                        Linux::check(memory, pointer, size, Access::Write)?;
                    }
                }
            }
        }
        if let Some(output) = message {
            Linux::check(memory, output.header, 56, Access::Write)?;
            Linux::check(memory, output.control, output.capacity, Access::Write)?;
        }
        if let Some(output) = address {
            Linux::check(memory, output.length_pointer, 4, Access::Write)?;
            Linux::check(
                memory,
                output.pointer,
                output.capacity.min(self.address_size),
                Access::Write,
            )?;
        }
        Ok(())
    }
    /// Raw byte calls retain their original scalar/vector ABI, including its
    /// caps, empty records, error order and one-packet gather/scatter behavior.
    pub fn raw(number: u32, a: [u64; 6], memory: &impl CpuMemory, flags: u32) -> Result<Self> {
        let read = matches!(number, 63 | 65);
        let transfer = if read {
            let buffer = if number == 63 {
                Buffer::Scalar(a[1], Linux::read_parameters(a, memory)?)
            } else {
                let (parts, size) = Linux::readv_parts(memory, a)?;
                Buffer::RawVectors(parts, size)
            };
            Transfer::Receive {
                buffer,
                address: None,
                message: None,
            }
        } else {
            let mut bytes = Vec::new();
            if number == 64 {
                Linux::write_transport(a, memory, &mut bytes, |_| Ok(0))?;
            } else {
                Linux::writev_transport_mode(a, memory, &mut bytes, false, |_| Ok(0))?;
            }
            Transfer::Send {
                bytes,
                peer: None,
                info: None,
            }
        };
        // The original VFS checks access after the raw ABI imports its buffers.
        // O_PATH read behavior and the original write access order are retained.
        if if read {
            flags & trames_vfs::O_PATH != 0 || flags & 3 == 1
        } else {
            flags & 3 == 0
        } {
            return Err(Errno(9));
        }
        Ok(Self {
            flags: 0,
            address_size: 0,
            transfer,
        })
    }
    pub fn new(
        number: u32,
        a: [u64; 6],
        memory: &impl CpuMemory,
        address_size: usize,
    ) -> Result<Self> {
        let transfer = match number {
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
                Transfer::Send {
                    bytes,
                    peer,
                    info: None,
                }
            }
            207 => {
                let count = a[2].min(trames_net::MAX_TRANSFER as u64) as usize;
                Linux::check(memory, a[1], count, Access::Write)?;
                Transfer::Receive {
                    buffer: Buffer::Scalar(a[1], count),
                    address: AddressOutput::prepare(memory, a[4], a[5], address_size)?,
                    message: None,
                }
            }
            211 | 212 => {
                let receive = number == 212;
                let access = if receive { Access::Write } else { Access::Read };
                Linux::check(memory, a[1], 56, access)?;
                Linux::check(memory, a[1], 56, Access::Read)?;
                let name = u64_at(memory, a[1])?;
                let name_size = u32_at(memory, a[1] + 8)?;
                let control = u64_at(memory, a[1] + 32)?;
                let control_size = u64_at(memory, a[1] + 40)?;
                if control_size != 0 {
                    if control_size > trames_net::MAX_TRANSFER as u64 {
                        return Err(Errno(22));
                    }
                    Linux::check(memory, control, control_size as usize, access)?;
                }
                let info = if receive {
                    None
                } else {
                    packet_control(memory, control, control_size)?
                };
                let vectors = Vectors::prepare(
                    memory,
                    u64_at(memory, a[1] + 16)?,
                    u64_at(memory, a[1] + 24)?,
                    access,
                )?;
                if receive {
                    Transfer::Receive {
                        buffer: Buffer::Vectored(vectors),
                        address: AddressOutput::prepare(memory, name, a[1] + 8, address_size)?,
                        message: Some(MessageOutput {
                            header: a[1],
                            control,
                            capacity: control_size as usize,
                        }),
                    }
                } else {
                    let peer = if name == 0 {
                        None
                    } else {
                        Some(address(memory, name, name_size as u64)?)
                    };
                    Transfer::Send {
                        bytes: vectors.read(memory)?,
                        peer,
                        info,
                    }
                }
            }
            _ => return Err(Errno(38)),
        };
        Ok(Self {
            address_size,
            flags: a[if matches!(number, 206 | 207) { 3 } else { 2 }] as u32,
            transfer,
        })
    }
    pub fn progress(
        &self,
        socket: &trames_net::Socket,
        memory: &mut impl CpuMemory,
        send: impl FnOnce(&[u8], u32, Option<&[u8]>) -> Result<usize>,
    ) -> Result<u64> {
        match &self.transfer {
            Transfer::Send { bytes, peer, info } => {
                let sent = if let Some(info) = info {
                    let peer = peer
                        .as_deref()
                        .map(trames_net::decode_address)
                        .transpose()
                        .map_err(net)?;
                    socket
                        .send_packet(bytes, self.flags, peer, *info)
                        .map_err(net)?
                } else {
                    send(bytes, self.flags, peer.as_deref())?
                };
                Ok(sent as u64)
            }
            Transfer::Receive {
                buffer,
                address,
                message,
            } => {
                let received = socket.recv(buffer.size(), self.flags).map_err(net)?;
                buffer.write(memory, &received.data)?;
                if let Some(output) = address {
                    output.write_bytes(memory, &socket.received_address(&received))?;
                }
                if let Some(output) = message {
                    if address.is_none() {
                        memory
                            .write(output.header + 8, &0u32.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                    }
                    let mut ancillary = Vec::new();
                    if let Some((level, kind, hop)) = socket.ancillary_hop() {
                        push_control(&mut ancillary, level, kind, &(hop as u32).to_le_bytes());
                    }
                    if let Some(info) = received.packet_info {
                        let mut payload = Vec::new();
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
                    let count = ancillary.len().min(output.capacity);
                    if count != 0 {
                        memory
                            .write(output.control, &ancillary[..count])
                            .map_err(|_| Errno(14))?;
                    }
                    memory
                        .write(output.header + 40, &(count as u64).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                    let flags = (if received.truncated { MSG_TRUNC } else { 0 })
                        | if count < ancillary.len() { 8 } else { 0 };
                    memory
                        .write(output.header + 48, &flags.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                Ok(if self.flags & MSG_TRUNC != 0 {
                    received.length
                } else {
                    received.data.len()
                } as u64)
            }
        }
    }
}
