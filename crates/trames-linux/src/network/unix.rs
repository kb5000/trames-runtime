// SPDX-License-Identifier: GPL-3.0-or-later
//! Owner-side Unix socket control and per-message metadata.
use super::*;
impl Linux {
    pub(super) fn local_network_vfs(
        vfs: &mut trames_vfs::Vfs,
        socket: &std::rc::Rc<trames_vfs::LocalSocket>,
        number: u64,
        a: [u64; 6],
        memory: &mut Memory,
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
            201 => {
                vfs.local_listen(socket, a[1] as u32)?;
                Ok(0)
            }
            202 | 242 => {
                let output =
                    AddressOutput::prepare(memory, a[1], a[2], socket.accept_address_size()?)?;
                let (fd, peer) =
                    vfs.local_accept(socket, if number == 242 { a[3] as u32 } else { 0 })?;
                if let Some(output) = output {
                    output.write_bytes(memory, &peer)?;
                }
                Ok(fd as u64)
            }
            204 | 205 => {
                let name = socket.name(number == 205)?;
                let output =
                    AddressOutput::prepare(memory, a[1], a[2], name.len())?.ok_or(Errno(14))?;
                output.write_bytes(memory, &name)?;
                Ok(0)
            }
            206 => {
                let destination = if a[4] == 0 {
                    None
                } else {
                    Some(address(memory, a[4], a[5])?)
                };
                Linux::write_transport(a, memory, &mut Vec::new(), |bytes| {
                    vfs.local_send_to(
                        socket,
                        bytes,
                        a[3] as u32,
                        destination.as_deref(),
                        trames_vfs::LocalRights::default(),
                    )
                    .map(|n| n as u64)
                })
            }
            207 => {
                if socket.kind() == 1 {
                    return local::recv(a, memory, |count| {
                        socket
                            .recv(count, a[3] as u32 | nonblocking)
                            .map(|r| r.data)
                    });
                }

                let count = a[2].min(crate::MAX_WRITE as u64) as usize;
                Self::check(memory, a[1], count, Access::Write)?;
                let output = AddressOutput::prepare(memory, a[4], a[5], 110)?;
                let received = socket.recv(count, a[3] as u32 | nonblocking)?;
                memory.write(a[1], &received.data).map_err(|_| Errno(14))?;
                if let Some(output) = output {
                    output.write_bytes(memory, &received.source)?;
                }
                Ok(if a[3] & MSG_TRUNC as u64 != 0 {
                    received.length
                } else {
                    received.data.len()
                } as u64)
            }
            208 => {
                if a[1] != 1 {
                    return Err(Errno(92));
                }
                if (a[4] as u32) < 4 || a[4] as u32 > i32::MAX as u32 {
                    return Err(Errno(22));
                }
                socket.set_reuse(a[2] as u32, u32_at(memory, a[3])?)?;
                Ok(0)
            }
            209 => {
                if a[1] != 1 {
                    return Err(Errno(92));
                }
                if a[2] == 17 {
                    let mut credentials = socket.peer_credentials();
                    credentials[0] = vfs.pid_namespace().local(credentials[0]);
                    let value: Vec<_> =
                        credentials.into_iter().flat_map(u32::to_le_bytes).collect();
                    let size = u32_at(memory, a[4])? as usize;
                    if size > i32::MAX as usize {
                        return Err(Errno(22));
                    }
                    Self::check(memory, a[4], 4, Access::Write)?;
                    Self::check(memory, a[3], size.min(12), Access::Write)?;
                    memory
                        .write(a[3], &value[..size.min(12)])
                        .map_err(|_| Errno(14))?;
                    memory
                        .write(a[4], &(size.min(12) as u32).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                    return Ok(0);
                }
                let value: u32 = match a[2] {
                    2 | 15 | 16 => socket.reuse(a[2] as u32),
                    3 => socket.kind(),
                    4 => 0,
                    7 | 8 => trames_vfs::PIPE_CAPACITY as u32,
                    30 => u32::from(socket.listening()),
                    38 => 0,
                    39 => 1,
                    _ => return Err(Errno(92)),
                };
                let size = u32_at(memory, a[4])? as usize;
                Self::check(memory, a[4], 4, Access::Write)?;
                Self::check(memory, a[3], size.min(4), Access::Write)?;
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
            211 | 212 => {
                let receive = number == 212;
                let Message {
                    control,
                    control_size,
                    output,
                    vectors,
                    destination,
                } = Message::prepare(memory, a[1], receive)?;
                if receive {
                    let received = socket.recv(vectors.size, a[2] as u32 | nonblocking)?;
                    vectors.write(memory, &received.data)?;
                    let mut ancillary = Vec::new();
                    let mut control_truncated = false;
                    if let Some(mut credentials) = received.credentials {
                        credentials[0] = vfs.pid_namespace().local(credentials[0]);
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
                    let remaining = control_size as usize - ancillary.len();
                    let capacity = remaining.saturating_sub(16) / 4;
                    let (fds, truncated) =
                        vfs.receive_rights(received.rights, capacity, a[2] & 0x40000000 != 0);
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
                            if socket.kind() == 1 {
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
                    let mut fds = Vec::new();
                    let mut identity = vfs.local_sender_credentials();
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
                            let c = &vfs.credentials;
                            let global = vfs.global_pid(pid)?;
                            if (global != identity[0]
                                && !c.has_cap(trames_vfs::capabilities::SYS_ADMIN))
                                || (![c.uid, c.euid, c.suid].contains(&uid)
                                    && !c.has_cap(trames_vfs::capabilities::SETUID))
                                || (![c.gid, c.egid, c.sgid].contains(&gid)
                                    && !c.has_cap(trames_vfs::capabilities::SETGID))
                            {
                                return Err(Errno(1));
                            }
                            identity = [global, uid, gid];
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
                    let rights = vfs.send_rights(&fds)?;
                    Ok(vfs.local_send_credentials(
                        socket,
                        &vectors.read(memory)?,
                        a[2] as u32,
                        destination.as_deref(),
                        rights,
                        identity,
                    )? as u64)
                }
            }
            _ => Err(Errno(95)),
        }
    }
}

struct Message {
    control: u64,
    control_size: u64,
    output: Option<AddressOutput>,
    vectors: Vectors,
    destination: Option<Vec<u8>>,
}
impl Message {
    fn prepare(memory: &Memory, pointer: u64, receive: bool) -> Result<Self> {
        if receive {
            Linux::check(memory, pointer, 56, Access::Write)?;
        }
        let header = memory.read_array::<56>(pointer).map_err(|_| Errno(14))?;
        let word = |at| u64::from_le_bytes(header[at..at + 8].try_into().unwrap());
        let name = word(0);
        let control = word(32);
        let control_size = word(40);
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
        let vectors = Vectors::prepare(
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
    fn explicit_credentials_enforce_authority_and_receive_faults_leave_packets_queued() {
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
        assert_eq!(
            Linux::network_vfs(&mut vfs, 211, send, &mut memory),
            Err(Errno(1))
        );
        assert_eq!(endpoint.recv(1, 0).err(), Some(Errno(11)));
        memory.write(0x1314, &1000u32.to_le_bytes()).unwrap();
        assert_eq!(Linux::network_vfs(&mut vfs, 211, send, &mut memory), Ok(1));
        memory.write(0x1020, &0x9000u64.to_le_bytes()).unwrap();
        let recv = [receiver as u64, 0x1000, 0, 0, 0, 0];
        assert_eq!(
            Linux::network_vfs(&mut vfs, 212, recv, &mut memory),
            Err(Errno(14))
        );
        let received = endpoint.recv(1, 0).unwrap();
        assert_eq!(received.data, b"x");
        assert_eq!(received.credentials, Some([1, 1000, 1001]));
    }
}
