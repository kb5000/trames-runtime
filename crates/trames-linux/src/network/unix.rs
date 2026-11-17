// SPDX-License-Identifier: GPL-3.0-or-later
//! Owner-side Unix socket control and per-message metadata.
use super::*;
mod packet;
pub(crate) use packet::{prepare_transfer, DatagramState, PreparedTransfer};
impl Linux {
    pub(super) fn local_network_vfs(
        vfs: &mut trames_vfs::Vfs,
        socket: &std::rc::Rc<trames_vfs::LocalSocket>,
        number: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64> {
        let nonblocking = if vfs.flags(a[0] as u32)? & trames_vfs::O_NONBLOCK != 0 {
            0x40
        } else {
            0
        };
        match number {
            200 | 203 => {
                let bytes = address(memory, a[1], a[2])?;
                if number == 200 {
                    vfs.local_bind(socket, &bytes)?;
                } else {
                    vfs.local_connect(socket, &bytes)?;
                }
                Ok(0)
            }
            201 => control(&vfs.descriptor_factory(), socket, number as u32, a, memory)
                .expect("Unix listen ABI"),
            202 | 242 => accept(&vfs.descriptor_factory(), socket, number as u32, a, memory),
            204 | 205 => control(&vfs.descriptor_factory(), socket, number as u32, a, memory)
                .expect("Unix address ABI"),
            207 if socket.kind() == 1 => local::recv(a, memory, |count| {
                socket
                    .recv(count, a[3] as u32 | nonblocking)
                    .map(|r| r.data)
            }),
            206 | 207 => packet_transfer(
                number as u32,
                a,
                memory,
                &mut OwnerMessage {
                    vfs,
                    socket,
                    nonblocking,
                    datagram: None,
                },
            )
            .expect("owner Unix packet ABI"),
            208..=210 => control(&vfs.descriptor_factory(), socket, number as u32, a, memory)
                .expect("Unix control ABI"),
            211 | 212 => message(
                number as u32,
                a,
                memory,
                &mut OwnerMessage {
                    vfs,
                    socket,
                    nonblocking,
                    datagram: None,
                },
            )
            .expect("owner Unix message"),
            _ => Err(Errno(95)),
        }
    }
}

pub(crate) fn accept(
    factory: &trames_vfs::DescriptorFactory,
    socket: &trames_vfs::LocalResource,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64> {
    factory
        .accept_local_output(
            socket,
            if number == 242 { a[3] as u32 } else { 0 },
            memory,
            |memory, size| AddressOutput::prepare(memory, a[1], a[2], size),
            |memory, output, peer| match output {
                Some(output) => output.write_bytes(memory, peer),
                None => Ok(()),
            },
        )
        .map(|(fd, _)| fd as u64)
}

/// Shared original Unix control decoder for owner and worker execution.
pub(crate) fn control(
    factory: &trames_vfs::DescriptorFactory,
    socket: &trames_vfs::LocalResource,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Option<Result<u64>> {
    if !matches!(number, 201 | 204 | 205 | 208..=210) {
        return None;
    }
    Some((|| match number {
        201 => {
            factory.local_listen(socket, a[1] as u32)?;
            Ok(0)
        }
        204 | 205 => {
            let name = socket.name(number == 205)?;
            let output =
                AddressOutput::prepare(memory, a[1], a[2], name.len())?.ok_or(Errno(14))?;
            output.write_bytes(memory, &name)?;
            Ok(0)
        }
        208 => {
            if a[1] != 1 {
                return Err(Errno(92));
            }
            if matches!(a[2], 20 | 21 | 66 | 67) {
                socket.set_io_timeout(matches!(a[2], 20 | 66), timeout_option(memory, a)?);
                return Ok(0);
            }
            if (a[4] as u32) < 4 || a[4] as u32 > i32::MAX as u32 {
                return Err(Errno(22));
            }
            if matches!(a[2], 32 | 33)
                && !factory
                    .local_credentials()
                    .has_cap(trames_vfs::capabilities::NET_ADMIN)
            {
                return Err(Errno(1));
            }
            socket.set_reuse(a[2] as u32, u32_at(memory, a[3])?)?;
            Ok(0)
        }
        209 => {
            if a[1] != 1 {
                return Err(Errno(92));
            }
            if matches!(a[2], 20 | 21 | 66 | 67) {
                return read_option(memory, a, || {
                    Ok(timeout_bytes(socket.io_timeout(matches!(a[2], 20 | 66))))
                });
            }
            if a[2] == 17 {
                let mut credentials = socket.peer_credentials();
                credentials[0] = factory.local_pid(credentials[0]);
                let value: Vec<_> = credentials.into_iter().flat_map(u32::to_le_bytes).collect();
                let size = u32_at(memory, a[4])? as usize;
                if size > i32::MAX as usize {
                    return Err(Errno(22));
                }
                Linux::check(memory, a[4], 4, Access::Write)?;
                Linux::check(memory, a[3], size.min(12), Access::Write)?;
                memory
                    .write(a[3], &value[..size.min(12)])
                    .map_err(|_| Errno(14))?;
                memory
                    .write(a[4], &(size.min(12) as u32).to_le_bytes())
                    .map_err(|_| Errno(14))?;
                return Ok(0);
            }
            let value: u32 = match a[2] {
                2 | 15 | 16 | 29 | 35 | 63 | 64 => socket.reuse(a[2] as u32),
                3 => socket.kind(),
                4 => 0,
                7 | 8 => socket.buffer_size(a[2] == 8) as u32,
                30 => u32::from(socket.listening()),
                38 => 0,
                39 => 1,
                _ => return Err(Errno(92)),
            };
            let size = u32_at(memory, a[4])? as usize;
            Linux::check(memory, a[4], 4, Access::Write)?;
            Linux::check(memory, a[3], size.min(4), Access::Write)?;
            memory
                .write(a[3], &value.to_le_bytes()[..size.min(4)])
                .map_err(|_| Errno(14))?;
            memory
                .write(a[4], &(size.min(4) as u32).to_le_bytes())
                .map_err(|_| Errno(14))?;
            Ok(0)
        }
        210 => {
            socket.shutdown(a[1] as u32)?;
            Ok(0)
        }
        _ => unreachable!("Unix control number"),
    })())
}

pub(crate) trait MessageIo {
    type Rights: Clone;
    fn kind(&self) -> u32;
    fn nonblocking(&self) -> u32;
    fn recv(
        &mut self,
        count: usize,
        flags: u32,
    ) -> Option<Result<trames_vfs::LocalReceived<Self::Rights>>>;
    fn send(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: Self::Rights,
        identity: [u32; 3],
    ) -> Option<Result<usize>>;
    fn send_explicit(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: Self::Rights,
        identity: [u32; 3],
    ) -> Option<Result<usize>>;
    fn sender_credentials(&self) -> [u32; 3];
    fn credentials(&self) -> &trames_vfs::Credentials;
    fn local_pid(&self, global: u32) -> u32;
    fn global_pid(&self, local: u32) -> Result<u32>;
    fn send_rights(&self, fds: &[u32]) -> Option<Result<Self::Rights>>;
    fn receive_rights(
        &mut self,
        rights: Self::Rights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool);
}
struct OwnerMessage<'a> {
    vfs: &'a mut trames_vfs::Vfs,
    socket: &'a std::rc::Rc<trames_vfs::LocalSocket>,
    nonblocking: u32,
    datagram: Option<&'a DatagramState>,
}
impl MessageIo for OwnerMessage<'_> {
    type Rights = trames_vfs::LocalRights;
    fn kind(&self) -> u32 {
        self.socket.kind()
    }
    fn nonblocking(&self) -> u32 {
        self.nonblocking
    }
    fn recv(&mut self, count: usize, flags: u32) -> Option<Result<trames_vfs::LocalReceived>> {
        Some(self.socket.recv_message(count, flags))
    }
    fn send(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: trames_vfs::LocalRights,
        identity: [u32; 3],
    ) -> Option<Result<usize>> {
        if let Some(datagram) = self.datagram {
            return Some(self.vfs.send_datagram_owned(
                &datagram.source,
                &datagram.target,
                bytes,
                flags,
                destination,
                rights,
                identity,
                false,
            ));
        }
        Some(self.vfs.local_send_credentials(
            self.socket,
            bytes,
            flags,
            destination,
            rights,
            identity,
        ))
    }
    fn send_explicit(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: Self::Rights,
        identity: [u32; 3],
    ) -> Option<Result<usize>> {
        if let Some(datagram) = self.datagram {
            return Some(self.vfs.send_datagram_owned(
                &datagram.source,
                &datagram.target,
                bytes,
                flags,
                destination,
                rights,
                identity,
                true,
            ));
        }
        Some(self.vfs.local_send_credentials_mode(
            self.socket,
            bytes,
            flags,
            destination,
            rights,
            identity,
            true,
        ))
    }
    fn sender_credentials(&self) -> [u32; 3] {
        self.vfs.local_sender_credentials()
    }
    fn credentials(&self) -> &trames_vfs::Credentials {
        &self.vfs.credentials
    }
    fn local_pid(&self, global: u32) -> u32 {
        self.vfs.pid_namespace().local(global)
    }
    fn global_pid(&self, local: u32) -> Result<u32> {
        self.vfs.credential_pid(local)
    }
    fn send_rights(&self, fds: &[u32]) -> Option<Result<trames_vfs::LocalRights>> {
        Some(self.vfs.send_rights(fds))
    }
    fn receive_rights(
        &mut self,
        rights: trames_vfs::LocalRights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool) {
        self.vfs.receive_rights(rights, capacity, cloexec)
    }
}
/// One original ancillary ABI for owner and worker transports. Deferral occurs
/// before any transport effect; actual shared rights require no owner ledger.
pub(crate) fn message(
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    io: &mut impl MessageIo,
) -> Option<Result<u64>> {
    match prepare_message(number, a, memory, io)? {
        Ok(prepared) => prepared.progress(memory, io),
        Err(error) => Some(Err(error)),
    }
}
#[derive(Clone)]
pub(crate) struct PreparedMessage<R> {
    frame: Message,
    args: [u64; 6],
    receive: bool,
    send: Option<(Vec<u8>, R, [u32; 3], bool)>,
}
/// Import buffers, credentials and descriptor references once, before waiting.
/// The typed worker Rights graph owns only actual shared OFDs.
pub(crate) fn prepare_message<I: MessageIo>(
    number: u32,
    a: [u64; 6],
    memory: &impl CpuMemory,
    io: &I,
) -> Option<Result<PreparedMessage<I::Rights>>> {
    let deferred = std::cell::Cell::new(false);
    let result = (|| {
        let receive = number == 212;
        let frame = Message::prepare(memory, a[1], receive, io.kind() == 1)?;
        if receive {
            return Ok(PreparedMessage {
                frame,
                args: a,
                receive,
                send: None,
            });
        }
        let control = frame.control;
        let control_size = frame.control_size;
        let vectors = &frame.vectors;
        let mut fds = Vec::new();
        let mut identity = io.sender_credentials();
        let mut explicit = false;
        let mut offset = 0;
        while control_size - offset >= 16 {
            let length = u64_at(memory, control + offset)?;
            if length < 16 || length > control_size - offset {
                return Err(Errno(22));
            }
            let level = u32_at(memory, control + offset + 8)?;
            let kind = u32_at(memory, control + offset + 12)?;
            if level != 1 || !matches!(kind, 1 | 2) {
                return Err(Errno(95));
            }
            if kind == 2 {
                if length != 28 {
                    return Err(Errno(22));
                }
                let pid = u32_at(memory, control + offset + 16)?;
                let uid = u32_at(memory, control + offset + 20)?;
                let gid = u32_at(memory, control + offset + 24)?;
                let c = io.credentials();
                if uid == u32::MAX || gid == u32::MAX {
                    return Err(Errno(22));
                }
                // Permission precedes PID lookup, as for Linux SCM_CREDENTIALS.
                // Ordinary self credentials need no process-directory lookup.
                if (pid != io.local_pid(identity[0])
                    && !c.has_cap(trames_vfs::capabilities::SYS_ADMIN))
                    || (![c.uid, c.euid, c.suid].contains(&uid)
                        && !c.has_cap(trames_vfs::capabilities::SETUID))
                    || (![c.gid, c.egid, c.sgid].contains(&gid)
                        && !c.has_cap(trames_vfs::capabilities::SETGID))
                {
                    return Err(Errno(1));
                }
                let global = if pid == io.local_pid(identity[0]) {
                    identity[0]
                } else {
                    io.global_pid(pid)?
                };
                identity = [global, uid, gid];
                explicit = true;
            } else {
                for i in 0..(length - 16) / 4 {
                    fds.push(u32_at(memory, control + offset + 16 + i * 4)?);
                }
            }
            if fds.len() > 253 {
                return Err(Errno(22));
            }
            let next = (length + 7) & !7;
            if next > control_size - offset {
                break;
            }
            offset += next;
        }
        if control_size != 0 && control_size < 16 {
            return Err(Errno(22));
        }
        let rights = io.send_rights(&fds).unwrap_or_else(|| {
            deferred.set(true);
            Err(Errno(11))
        })?;

        let bytes = vectors.read(memory)?;
        Ok(PreparedMessage {
            frame,
            args: a,
            receive,
            send: Some((bytes, rights, identity, explicit)),
        })
    })();
    if deferred.get() {
        None
    } else {
        Some(result)
    }
}
impl<R: Clone> PreparedMessage<R> {
    pub(crate) fn recheck(&self, memory: &impl CpuMemory) -> Result<()> {
        if !self.receive {
            return Ok(());
        }
        Linux::check(memory, self.args[1], 56, Access::Write)?;
        Linux::check(
            memory,
            self.frame.control,
            self.frame.control_size as usize,
            Access::Write,
        )?;
        for &(pointer, size) in &self.frame.vectors.parts {
            Linux::check(memory, pointer, size, Access::Write)?;
        }
        if let Some(output) = &self.frame.output {
            Linux::check(memory, output.length_pointer, 4, Access::Write)?;
            Linux::check(
                memory,
                output.pointer,
                output.capacity.min(110),
                Access::Write,
            )?;
        }
        Ok(())
    }
    pub(crate) fn progress(
        &self,
        memory: &mut impl CpuMemory,
        io: &mut impl MessageIo<Rights = R>,
    ) -> Option<Result<u64>> {
        let a = self.args;
        let control = self.frame.control;
        let control_size = self.frame.control_size;
        let vectors = &self.frame.vectors;
        let output = self.frame.output;
        let deferred = std::cell::Cell::new(false);
        let nonblocking = io.nonblocking();
        let result = (|| {
            if self.receive {
                let received = io
                    .recv(vectors.size, a[2] as u32 | nonblocking)
                    .unwrap_or_else(|| {
                        deferred.set(true);
                        Err(Errno(11))
                    })?;
                vectors.write(memory, &received.data)?;
                let mut ancillary = Vec::new();
                let mut control_truncated = false;
                if let Some(mut credentials) = received.credentials {
                    credentials[0] = io.local_pid(credentials[0]);
                    let value: Vec<_> =
                        credentials.into_iter().flat_map(u32::to_le_bytes).collect();
                    push_control(&mut ancillary, 1, 2, &value);
                    if control_size < 28 {
                        control_truncated = true;
                    }
                    ancillary.truncate(control_size as usize);
                    if ancillary.len() >= 16 {
                        let length = ancillary.len().min(28) as u64;
                        ancillary[..8].copy_from_slice(&length.to_le_bytes());
                    } else {
                        ancillary.clear();
                    }
                }
                if let Some((kind, stamp)) = received.timestamp {
                    let remaining = control_size as usize - ancillary.len();
                    let value: Vec<_> = stamp.into_iter().flat_map(u64::to_le_bytes).collect();
                    let mut bytes = Vec::new();
                    push_control(&mut bytes, 1, kind, &value);
                    if remaining < bytes.len() {
                        control_truncated = true;
                    }
                    bytes.truncate(remaining);
                    if bytes.len() >= 16 {
                        let length = bytes.len() as u64;
                        bytes[..8].copy_from_slice(&length.to_le_bytes());
                        ancillary.extend_from_slice(&bytes);
                    }
                }
                let remaining = control_size as usize - ancillary.len();
                let capacity = remaining.saturating_sub(16) / 4;
                let (fds, truncated) =
                    io.receive_rights(received.rights, capacity, a[2] & 0x40000000 != 0);
                if !fds.is_empty() {
                    let size = 16 + fds.len() * 4;
                    let space = ((size + 7) & !7).min(remaining);
                    let mut bytes = vec![0; space];
                    bytes[..8].copy_from_slice(&(size as u64).to_le_bytes());
                    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
                    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
                    for (i, fd) in fds.iter().enumerate() {
                        bytes[16 + i * 4..20 + i * 4].copy_from_slice(&fd.to_le_bytes());
                    }
                    ancillary.extend_from_slice(&bytes);
                }
                memory.write(control, &ancillary).map_err(|_| Errno(14))?;
                let control_count = ancillary.len();
                if let Some(output) = output {
                    output.write_bytes(
                        memory,
                        if io.kind() == 1 {
                            &[]
                        } else {
                            &received.source
                        },
                    )?;
                } else {
                    memory
                        .write(a[1] + 8, &0u32.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                memory
                    .write(a[1] + 40, &(control_count as u64).to_le_bytes())
                    .map_err(|_| Errno(14))?;
                memory
                    .write(
                        a[1] + 48,
                        &((if received.truncated { MSG_TRUNC } else { 0 })
                            | if truncated || control_truncated { 8 } else { 0 })
                        .to_le_bytes(),
                    )
                    .map_err(|_| Errno(14))?;
                Ok(if a[2] & MSG_TRUNC as u64 != 0 {
                    received.length
                } else {
                    received.data.len()
                } as u64)
            } else {
                let (bytes, rights, identity, explicit) =
                    self.send.as_ref().expect("prepared send");
                let sent = if *explicit {
                    io.send_explicit(
                        bytes,
                        a[2] as u32,
                        self.frame.destination.as_deref(),
                        rights.clone(),
                        *identity,
                    )
                } else {
                    io.send(
                        bytes,
                        a[2] as u32,
                        self.frame.destination.as_deref(),
                        rights.clone(),
                        *identity,
                    )
                };
                sent.unwrap_or_else(|| {
                    deferred.set(true);
                    Err(Errno(11))
                })
                .map(|n| n as u64)
            }
        })();
        if deferred.get() {
            None
        } else {
            Some(result)
        }
    }
}

fn packet_transfer(
    number: u32,
    args: [u64; 6],
    memory: &mut impl CpuMemory,
    io: &mut impl MessageIo,
) -> Option<Result<u64>> {
    match prepare_transfer(number, args, memory, io)? {
        Ok(prepared) => prepared.progress(memory, io),
        Err(error) => Some(Err(error)),
    }
}

#[derive(Clone)]
struct Message {
    control: u64,
    control_size: u64,
    output: Option<AddressOutput>,
    vectors: Vectors,
    destination: Option<Vec<u8>>,
}
impl Message {
    fn prepare(memory: &impl CpuMemory, pointer: u64, receive: bool, stream: bool) -> Result<Self> {
        if receive {
            Linux::check(memory, pointer, 56, Access::Write)?;
        }
        let header = memory.read_array::<56>(pointer).map_err(|_| Errno(14))?;
        let word = |at| u64::from_le_bytes(header[at..at + 8].try_into().unwrap());
        let name = word(0);
        let control = word(32);
        // A NULL receive control pointer disables ancillary copyout regardless
        // of the advertised size; transport still consumes/truncates rights.
        let control_size = if receive && control == 0 { 0 } else { word(40) };
        if control_size > crate::MAX_WRITE as u64 {
            return Err(Errno(22));
        }
        Linux::check(
            memory,
            control,
            control_size as usize,
            if receive { Access::Write } else { Access::Read },
        )?;
        let output = if receive {
            AddressOutput::prepare(memory, name, pointer + 8, 110)?
        } else {
            None
        };
        let destination = if !receive && name != 0 {
            Some(address(
                memory,
                name,
                u32::from_le_bytes(header[8..12].try_into().unwrap()) as u64,
            )?)
        } else {
            None
        };
        let prepare = if stream {
            Vectors::prepare_stream
        } else {
            Vectors::prepare
        };
        let vectors = prepare(
            memory,
            word(16),
            word(24),
            if receive { Access::Write } else { Access::Read },
        )?;
        Ok(Self {
            control,
            control_size,
            output,
            vectors,
            destination,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};

    #[test]
    fn null_control_and_zero_length_messages_preserve_original_rights_and_payload_boundaries() {
        for worker in [false, true] {
            for kind in [1, 2, 5] {
                for null_control in [false, true] {
                    let mut v = trames_vfs::Vfs::default();
                    let [tx, rx] = v.socketpair(1, kind, 0).unwrap();
                    let event = v.eventfd(42, 0).unwrap();
                    let mut m = Memory::default();
                    m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
                    let mut header = [0; 56];
                    for (offset, value) in [(16, 0x1100u64), (24, 1), (32, 0x1300), (40, 24)] {
                        header[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                    }
                    m.write(0x1000, &header).unwrap();
                    m.write_array(0x1100, 0x1200u64.to_le_bytes()).unwrap();
                    m.write_array(0x1108, 1u64.to_le_bytes()).unwrap();
                    m.write(0x1200, b"x").unwrap();
                    let mut control = Vec::new();
                    push_control(&mut control, 1, 1, &event.to_le_bytes());
                    m.write(0x1300, &control).unwrap();
                    let call = |v: &mut trames_vfs::Vfs, number: u32, args, m: &mut Memory| {
                        if worker {
                            crate::DirectSyscalls::new(v.direct_descriptors())
                                .with_resources(v.descriptor_factory())
                                .invoke(number, args, m)
                                .expect("accepted Unix message")
                        } else {
                            Linux::network_vfs(v, number as u64, args, m)
                        }
                    };
                    assert_eq!(
                        call(&mut v, 211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
                        Ok(1)
                    );
                    v.close(event).unwrap();
                    assert_eq!(v.eventfd(99, 0).unwrap(), event);
                    if null_control {
                        m.write_array(0x1020, 0u64.to_le_bytes()).unwrap();
                    } else {
                        // read(0) leaves ancillary state untouched; recvmsg(0)
                        // receives it while retaining the stream's payload byte.
                        if kind == 1 {
                            assert_eq!(v.read(rx, 0).unwrap(), b"");
                        }
                        m.write_array(0x1018, 0u64.to_le_bytes()).unwrap();
                    }
                    assert_eq!(
                        call(
                            &mut v,
                            212,
                            [rx as u64, 0x1000, 0x40000000, 0, 0, 0],
                            &mut m
                        ),
                        Ok(u64::from(null_control))
                    );
                    let flags = u32::from_le_bytes(m.read_array(0x1030).unwrap());
                    if null_control {
                        assert_eq!(m.read_u64(0x1028).unwrap(), 0);
                        assert_eq!(flags, 8);
                    } else {
                        assert_eq!(flags, if kind == 1 { 0 } else { 0x20 });
                        let passed = u32::from_le_bytes(m.read_array(0x1310).unwrap());
                        assert_ne!(v.flags(passed).unwrap() & trames_vfs::O_CLOEXEC, 0);
                        assert_eq!(v.read(passed, 8).unwrap(), 42u64.to_le_bytes());
                        if kind == 1 {
                            m.write(0x1000, &header).unwrap();
                            assert_eq!(
                                call(&mut v, 212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
                                Ok(1)
                            );
                            assert_eq!(m.read_array::<1>(0x1200).unwrap(), [b'x']);
                            assert_eq!(m.read_u64(0x1028).unwrap(), 0);
                        }
                    }
                    assert_eq!(v.read(event, 8).unwrap(), 99u64.to_le_bytes());
                    assert_eq!(
                        call(&mut v, 212, [rx as u64, 0x1000, 0x40, 0, 0, 0], &mut m),
                        Err(Errno(11))
                    );
                }
            }
        }
    }
    #[test]
    fn explicit_credentials_reject_nonexistent_pid_after_permission_checks() {
        for worker in [false, true] {
            let mut v = trames_vfs::Vfs::default();
            v.set_lock_owner(1);
            let privileged = v.credentials.clone();
            let [tx, rx] = v.socketpair(1, 2, 0).unwrap();
            let mut m = Memory::default();
            m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            for (offset, value) in [(16, 0x1100u64), (24, 1), (32, 0x1300), (40, 32)] {
                m.write_array(0x1000 + offset, value.to_le_bytes()).unwrap();
            }
            m.write_array(0x1100, 0x1200u64.to_le_bytes()).unwrap();
            m.write_array(0x1108, 1u64.to_le_bytes()).unwrap();
            m.write(0x1200, b"x").unwrap();
            for identity in [
                [u32::MAX, 1000, 1000],
                [77, 1000, 1000],
                [1, u32::MAX, 1000],
            ] {
                let mut control = Vec::new();
                let credentials: Vec<_> = identity.into_iter().flat_map(u32::to_le_bytes).collect();
                push_control(&mut control, 1, 2, &credentials);
                m.write(0x1300, &control).unwrap();
                for root in [false, true] {
                    v.credentials = if root {
                        privileged.clone()
                    } else {
                        trames_vfs::Credentials::user(1000, 1000)
                    };
                    let args = [tx as u64, 0x1000, 0, 0, 0, 0];
                    let result = if worker {
                        crate::DirectSyscalls::new(v.direct_descriptors())
                            .with_resources(v.descriptor_factory())
                            .invoke(211, args, &mut m)
                            .unwrap()
                    } else {
                        Linux::network_vfs(&mut v, 211, args, &mut m)
                    };
                    assert_eq!(
                        result,
                        Err(Errno(if identity[1] == u32::MAX {
                            22
                        } else if root {
                            3
                        } else {
                            1
                        }))
                    );
                    assert_eq!(
                        v.local_socket(rx).unwrap().unwrap().recv(1, 0).err(),
                        Some(Errno(11))
                    );
                }
            }
        }
    }
    #[test]
    fn large_stream_messages_short_write_on_owner_and_worker_and_keep_rights_once() {
        use crate::DirectSyscalls;
        for worker in [false, true] {
            let mut vfs = trames_vfs::Vfs::default();
            let [sender, receiver] = vfs.socketpair(1, 1, 0).unwrap();
            let event = vfs.eventfd(42, 0).unwrap();
            let direct = DirectSyscalls::new(vfs.direct_descriptors());
            let mut memory = Memory::default();
            let total = crate::MAX_WRITE * 2 + 73;
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory
                .map(
                    0x10000,
                    (total as u64).div_ceil(PAGE_SIZE) * PAGE_SIZE,
                    Permissions::RW,
                )
                .unwrap();
            let bytes: Vec<u8> = (0..total).map(|n| (n % 251) as u8).collect();
            memory.write(0x10000, &bytes).unwrap();
            let mut header = [0u8; 56];
            for (at, value) in [(16, 0x1100u64), (24, 2), (32, 0x1300), (40, 24)] {
                header[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            memory.write(0x1000, &header).unwrap();
            let first = crate::MAX_WRITE / 2 + 17;
            let iov: Vec<_> = [
                0x10000u64,
                first as u64,
                0x10000 + first as u64,
                (total - first) as u64,
            ]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
            memory.write(0x1100, &iov).unwrap();
            let mut control = Vec::new();
            push_control(&mut control, 1, 1, &event.to_le_bytes());
            memory.write(0x1300, &control).unwrap();
            let args = [sender as u64, 0x1000, 0x40, 0, 0, 0];
            let mut sent = Linux::network_vfs(&mut vfs, 211, args, &mut memory).unwrap() as usize;
            assert!(sent > 0 && sent <= crate::MAX_WRITE);
            let socket = vfs.local_socket(receiver).unwrap().unwrap();
            let received = socket.recv(total, 0).unwrap();
            assert_eq!(received.data, bytes[..sent]);
            let (rights, truncated) = vfs.receive_rights(received.rights, 3, true);
            assert!(!truncated);
            assert_eq!(rights.len(), 1);
            assert_eq!(vfs.read(rights[0], 8).unwrap(), 42u64.to_le_bytes());
            memory.write_array(0x1018, 1u64.to_le_bytes()).unwrap();
            memory.write_array(0x1028, 0u64.to_le_bytes()).unwrap();
            while sent < total {
                memory
                    .write_array(0x1100, (0x10000 + sent as u64).to_le_bytes())
                    .unwrap();
                memory
                    .write_array(0x1108, ((total - sent) as u64).to_le_bytes())
                    .unwrap();
                let count = if worker {
                    direct
                        .invoke(211, args, &mut memory)
                        .expect("stream worker owns plain bytes")
                } else {
                    Linux::network_vfs(&mut vfs, 211, args, &mut memory)
                }
                .unwrap() as usize;
                assert!(count > 0 && count <= crate::MAX_WRITE);
                let received = socket.recv(total, 0).unwrap();
                assert_eq!(received.data, bytes[sent..sent + count]);
                assert_eq!(vfs.receive_rights(received.rights, 3, true).0.len(), 0);
                sent += count;
            }
            // Message transports must still reject an oversized atomic packet.
            for kind in [2, 5] {
                let [sender, receiver] = vfs.socketpair(1, kind, 0).unwrap();
                memory
                    .write_array(0x1100, 0x10000u64.to_le_bytes())
                    .unwrap();
                memory
                    .write_array(0x1108, (total as u64).to_le_bytes())
                    .unwrap();
                assert_eq!(
                    Linux::network_vfs(
                        &mut vfs,
                        211,
                        [sender as u64, 0x1000, 0x40, 0, 0, 0],
                        &mut memory
                    ),
                    Err(Errno(90))
                );
                assert!(vfs
                    .local_socket(receiver)
                    .unwrap()
                    .unwrap()
                    .recv(1, 0)
                    .is_err());
            }
        }
    }

    #[test]
    fn explicit_credentials_enforce_authority_and_receive_faults_leave_packets_queued() {
        for worker in [false, true] {
            let call =
                |vfs: &mut trames_vfs::Vfs, number: u64, args: [u64; 6], memory: &mut Memory| {
                    if worker {
                        crate::DirectSyscalls::new(vfs.direct_descriptors())
                            .with_resources(vfs.descriptor_factory())
                            .invoke(number as u32, args, memory)
                            .expect("paired datagram message worker")
                    } else {
                        Linux::network_vfs(vfs, number, args, memory)
                    }
                };
            let mut vfs = trames_vfs::Vfs::default();
            vfs.set_lock_owner(1);
            vfs.credentials = trames_vfs::Credentials::user(1000, 1001);
            let [sender, receiver] = vfs.socketpair(1, 2, 0).unwrap();
            let endpoint = vfs.local_socket(receiver).unwrap().unwrap();
            endpoint.set_reuse(16, 1).unwrap();
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            let mut header = [0u8; 56];
            for (offset, value) in [(16, 0x1100u64), (24, 1), (32, 0x1300), (40, 32)] {
                header[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            memory.write(0x1000, &header).unwrap();
            memory.write(0x1100, &0x1200u64.to_le_bytes()).unwrap();
            memory.write(0x1108, &1u64.to_le_bytes()).unwrap();
            memory.write(0x1200, b"x").unwrap();
            let mut control = Vec::new();
            let identity: Vec<_> = [1u32, 1002, 1001]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            push_control(&mut control, 1, 2, &identity);
            memory.write(0x1300, &control).unwrap();
            let send = [sender as u64, 0x1000, 0, 0, 0, 0];
            assert_eq!(call(&mut vfs, 211, send, &mut memory), Err(Errno(1)));
            assert_eq!(endpoint.recv(1, 0).err(), Some(Errno(11)));
            memory.write(0x1314, &1000u32.to_le_bytes()).unwrap();
            assert_eq!(call(&mut vfs, 211, send, &mut memory), Ok(1));
            memory.write(0x1020, &0x9000u64.to_le_bytes()).unwrap();
            let recv = [receiver as u64, 0x1000, 0, 0, 0, 0];
            assert_eq!(call(&mut vfs, 212, recv, &mut memory), Err(Errno(14)));
            let received = endpoint.recv(1, 0).unwrap();
            assert_eq!(received.data, b"x");
            assert_eq!(received.credentials, Some([1, 1000, 1001]));
        }
    }
}
