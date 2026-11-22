// SPDX-License-Identifier: GPL-3.0-or-later
//! The original IP message ABI, prepared once for an accepted operation.
use super::*;

enum Buffer {
    Scalar(u64, usize),
    Vectored(Vectors),
    RawVectors(Vec<(u64, usize)>, usize),
}
const MSG_PEEK: u32 = 2;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;

impl Buffer {
    fn size(&self) -> usize {
        match self {
            Self::Scalar(_, size) => *size,
            Self::Vectored(vectors) => vectors.size,
            Self::RawVectors(_, size) => *size,
        }
    }
    fn write_at(&self, memory: &mut impl CpuMemory, offset: usize, mut bytes: &[u8]) -> Result<()> {
        if offset == 0 {
            return self.write(memory, bytes);
        }
        let parts = match self {
            Self::Scalar(pointer, _) => {
                return memory
                    .write(*pointer + offset as u64, bytes)
                    .map_err(|_| Errno(14))
            }
            Self::Vectored(vectors) => &vectors.parts,
            Self::RawVectors(parts, _) => parts,
        };
        let mut skip = offset;
        for &(pointer, length) in parts {
            if bytes.is_empty() {
                break;
            }
            if skip >= length {
                skip -= length;
                continue;
            }
            let n = (length - skip).min(bytes.len());
            memory
                .write(pointer + skip as u64, &bytes[..n])
                .map_err(|_| Errno(14))?;
            bytes = &bytes[n..];
            skip = 0;
        }
        Ok(())
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
/// Linux counts available alignment padding, but only missing header or payload
/// bytes set MSG_CTRUNC. A partial payload reports its actual cmsg_len.
struct ControlOutput {
    bytes: Vec<u8>,
    capacity: usize,
    truncated: bool,
}
impl ControlOutput {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: Vec::new(),
            capacity,
            truncated: false,
        }
    }
    fn push(&mut self, level: u32, kind: u32, payload: &[u8]) {
        let left = self.capacity - self.bytes.len();
        if left < 16 {
            self.truncated = true;
            return;
        }
        let n = payload.len().min(left - 16);
        self.truncated |= n < payload.len();
        push_control(&mut self.bytes, level, kind, &payload[..n]);
        self.bytes.truncate(self.capacity);
    }
}

enum Transfer {
    Send {
        bytes: Vec<u8>,
        peer: Option<Vec<u8>>,
        info: Option<trames_net::DatagramControl>,
    },
    Receive {
        buffer: Buffer,
        address: Option<AddressOutput>,
        message: Option<MessageOutput>,
    },
}
pub(crate) struct Prepared {
    transferred: usize,
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
            !trames_vfs::fd_can_read(flags)
        } else {
            !trames_vfs::fd_can_write(flags)
        } {
            return Err(Errno(9));
        }
        Ok(Self {
            transferred: 0,
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
        datagram_limit: Option<usize>,
    ) -> Result<Self> {
        let transfer = match number {
            206 => {
                if datagram_limit.is_some_and(|limit| a[2] > limit as u64) {
                    return Err(Errno(90));
                }
                let count = a[2].min(trames_net::MAX_TRANSFER as u64) as usize;
                Linux::check(memory, a[1], count, Access::Read)?;
                let peer = if a[4] == 0 {
                    None
                } else {
                    Some(address(memory, a[4], a[5])?)
                };
                let mut bytes = vec![0; count];
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
                let vectors = Vectors::prepare_prefix(
                    memory,
                    u64_at(memory, a[1] + 16)?,
                    u64_at(memory, a[1] + 24)?,
                    access,
                    receive || datagram_limit.is_none(),
                    if receive {
                        trames_net::MAX_TRANSFER
                    } else {
                        datagram_limit.unwrap_or(trames_net::MAX_TRANSFER)
                    },
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
            transferred: 0,
            address_size,
            flags: a[if matches!(number, 206 | 207) { 3 } else { 2 }] as u32,
            transfer,
        })
    }
    pub fn partial(&self) -> Option<u64> {
        (self.transferred != 0).then_some(self.transferred as u64)
    }
    pub fn progress(
        &mut self,
        socket: &trames_vfs::SocketOperation,
        memory: &mut impl CpuMemory,
        retained: bool,
        project_credentials: impl Fn([u32; 3]) -> [u32; 3],
        mut send: impl FnMut(&[u8], u32, Option<&[u8]>) -> Result<usize>,
    ) -> Result<u64> {
        match &self.transfer {
            Transfer::Send { bytes, peer, info } => loop {
                let remaining = &bytes[self.transferred..];
                let result = if let Some(info) = info {
                    let peer = peer
                        .as_deref()
                        .map(trames_net::decode_address)
                        .transpose()
                        .map_err(net)?;
                    socket
                        .send_datagram(remaining, self.flags, peer, *info)
                        .map_err(net)
                } else {
                    send(remaining, self.flags, peer.as_deref())
                };
                let sent = match result {
                    Ok(sent) => sent,
                    Err(Errno(11)) => return Err(Errno(11)),
                    Err(_) if self.transferred != 0 => return Ok(self.transferred as u64),
                    Err(error) => return Err(error),
                };
                self.transferred += sent;
                if self.transferred >= bytes.len()
                    || sent == 0
                    || !retained
                    || self.flags & MSG_DONTWAIT != 0
                    || socket.flags() & trames_vfs::O_NONBLOCK != 0
                    || !socket.is_guest_tcp()
                {
                    return Ok(self.transferred as u64);
                }
            },
            Transfer::Receive {
                buffer,
                address,
                message,
            } => {
                let flags = self.flags
                    | if socket.flags() & trames_vfs::O_NONBLOCK != 0 {
                        0x40
                    } else {
                        0
                    };
                let offset = if flags & MSG_PEEK != 0 {
                    0
                } else {
                    self.transferred
                };
                let received = match socket.recv(buffer.size() - offset, flags) {
                    Ok(packet) => packet,
                    Err(e) if e.0 != 11 && self.transferred != 0 => {
                        return Ok(self.transferred as u64)
                    }
                    Err(e) => return Err(net(e)),
                };
                buffer.write_at(memory, offset, &received.data)?;
                if let Some(output) = address {
                    output.write_bytes(memory, &socket.received_address(&received))?;
                }
                if let Some(output) = message {
                    if address.is_none() {
                        memory
                            .write(output.header + 8, &0u32.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                    }
                    let mut ancillary = ControlOutput::new(output.capacity);
                    if let Some(credentials) = received.credentials {
                        let payload: Vec<_> = project_credentials(credentials)
                            .into_iter()
                            .flat_map(u32::to_le_bytes)
                            .collect();
                        ancillary.push(1, 2, &payload);
                    }
                    if let Some((level, kind, hop)) = socket.ancillary_hop() {
                        ancillary.push(level, kind, &(hop as u32).to_le_bytes());
                    }
                    let ip = &received.ip;
                    if let Some(error) = &ip.error {
                        let mut payload = Vec::with_capacity(44);
                        payload.extend_from_slice(&error.errno.to_le_bytes());
                        payload.extend_from_slice(&[error.origin, error.kind, error.code, 0]);
                        payload.extend_from_slice(&error.info.to_le_bytes());
                        payload.extend_from_slice(&0u32.to_le_bytes());
                        if let Some(reporter) = error.reporter {
                            payload.extend_from_slice(&encode_address(std::net::SocketAddr::new(
                                reporter, 0,
                            )));
                        } else {
                            payload.resize(if ip.ipv6 { 44 } else { 32 }, 0);
                        }
                        let (level, kind) = if ip.ipv6 { (41, 25) } else { (0, 11) };
                        ancillary.push(level, kind, &payload);
                    }
                    if let Some((kind, ns)) = ip.timestamp {
                        ancillary.push(
                            1,
                            kind,
                            &super::socket_timestamp(ns, matches!(kind, 35 | 64)),
                        );
                    }
                    if let Some(remaining) = ip.tcp_inq {
                        ancillary.push(6, 36, &remaining.to_le_bytes());
                    }
                    if let Some(hops) = ip.fields.hop_limit {
                        let (level, kind) = if ip.ipv6 { (41, 52) } else { (0, 2) };
                        ancillary.push(level, kind, &i32::from(hops).to_le_bytes());
                    }
                    if let Some(class) = ip.fields.traffic_class {
                        if ip.ipv6 {
                            ancillary.push(41, 67, &i32::from(class).to_le_bytes());
                        } else {
                            ancillary.push(0, 1, &[class]);
                        }
                    }
                    if let Some(info) = received.packet_info {
                        let mut payload = Vec::new();
                        match info.address {
                            std::net::IpAddr::V4(ip) => {
                                payload.extend_from_slice(&info.interface.to_le_bytes());
                                payload.extend_from_slice(
                                    &received.ip.spec_destination.unwrap_or(ip).octets(),
                                );
                                payload.extend_from_slice(&ip.octets());
                                ancillary.push(0, 8, &payload);
                                if received.ip.mapped_info {
                                    payload.clear();
                                    payload.extend_from_slice(&ip.to_ipv6_mapped().octets());
                                    payload.extend_from_slice(&info.interface.to_le_bytes());
                                    ancillary.push(41, 50, &payload);
                                }
                            }
                            std::net::IpAddr::V6(ip) => {
                                payload.extend_from_slice(&ip.octets());
                                payload.extend_from_slice(&info.interface.to_le_bytes());
                                ancillary.push(41, 50, &payload);
                            }
                        }
                    }
                    if let Some(dst) = ip.original_destination {
                        let (level, kind) = if dst.is_ipv4() { (0, 20) } else { (41, 74) };
                        ancillary.push(level, kind, &encode_address(dst));
                    }
                    let count = ancillary.bytes.len();
                    if count != 0 {
                        memory
                            .write(output.control, &ancillary.bytes)
                            .map_err(|_| Errno(14))?;
                    }
                    memory
                        .write(output.header + 40, &(count as u64).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                    let flags = (if received.truncated { MSG_TRUNC } else { 0 })
                        | if ip.error.is_some() {
                            trames_net::MSG_ERRQUEUE
                        } else {
                            0
                        }
                        | if ancillary.truncated { 8 } else { 0 };
                    memory
                        .write(output.header + 48, &flags.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                let copied = if flags & MSG_TRUNC != 0 && received.ip.error.is_none() {
                    received.length
                } else {
                    received.data.len()
                };
                self.transferred = offset + copied;
                let target = if flags & MSG_WAITALL != 0 {
                    buffer.size()
                } else {
                    buffer.size().min(received.stream_minimum)
                };
                if retained
                    && flags & MSG_DONTWAIT == 0
                    && received.stream_minimum != 0
                    && copied != 0
                    && self.transferred < target
                {
                    Err(Errno(11))
                } else {
                    Ok(self.transferred as u64)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_capacity_distinguishes_short_payload_from_missing_padding() {
        for (capacity, written, truncated) in [
            (0, 0, true),
            (15, 0, true),
            (16, 16, true),
            (17, 17, false),
            (20, 20, false),
            (24, 24, false),
            (25, 24, false),
        ] {
            let mut output = ControlOutput::new(capacity);
            output.push(0, 1, &[0xab]);
            assert_eq!((output.bytes.len(), output.truncated), (written, truncated));
            if written >= 16 {
                assert_eq!(
                    u64::from_le_bytes(output.bytes[..8].try_into().unwrap()),
                    written.min(17) as u64
                );
            }
        }
        let mut output = ControlOutput::new(39);
        output.push(0, 1, &[7]);
        output.push(0, 2, &64i32.to_le_bytes());
        assert_eq!((output.bytes.len(), output.truncated), (24, true));
    }
}
