// SPDX-License-Identifier: GPL-3.0-or-later
//! Resource operations outside the canonical ring lock. Only real owner-only
//! descriptions use the joined VFS; shared resources execute on their caller.
use super::*;
pub(crate) fn resource_rw(
    vfs: &mut trames_vfs::Vfs,
    request: &UringRequest,
    memory: &mut impl trames_memory::CpuMemory,
) -> Result<(i32, bool)> {
    let s = &request.sqe;
    let write = matches!(s.opcode(), 2 | 5 | 23);
    if s.op_flags() & !8 != 0 {
        return Err(Errno(95));
    } // RWF_NOWAIT only
    let parts = if let Some(parts) = &request.parts {
        parts.clone()
    } else {
        vec![(s.address(), (s.length() as usize).min(MAX_WRITE))]
    };
    let count: usize = parts.iter().map(|p| p.1).sum();
    for &(address, len) in &parts {
        if len != 0 && request.buffer.is_none() {
            Linux::check(
                memory,
                address,
                len,
                if write { Access::Read } else { Access::Write },
            )?;
        }
    }
    let file = request.file.as_ref().ok_or(Errno(9))?;
    let stream = file.stream();
    if stream && !matches!(s.offset(), 0 | u64::MAX) {
        return Err(Errno(29));
    }
    let mut bytes = Vec::new();
    let result = if write {
        if let Some(buffer) = &request.buffer {
            bytes = buffer
                .read(
                    buffer.range(s.address(), count).map_err(|_| Errno(14))?,
                    count,
                )
                .map_err(|_| Errno(14))?;
        } else {
            Linux::gather_parts(memory, &parts, count, &mut bytes)?;
        }
        vfs.with_uring_fd(file, |v, fd| {
            if stream || s.offset() == u64::MAX {
                v.write(fd, &bytes)
            } else {
                v.pwrite(fd, &bytes, s.offset())
            }
        })?
    } else {
        bytes = vfs.with_uring_fd(file, |v, fd| {
            if stream || s.offset() == u64::MAX {
                v.read(fd, count)
            } else {
                v.pread(fd, count, s.offset())
            }
        })?;
        if let Some(buffer) = &request.buffer {
            buffer
                .write(
                    buffer
                        .range(s.address(), bytes.len())
                        .map_err(|_| Errno(14))?,
                    &bytes,
                )
                .map_err(|_| Errno(14))?;
        } else {
            Linux::scatter(memory, &parts, &bytes)?;
        }
        bytes.len()
    };
    Ok((result as i32, result as u64 == request.requested))
}
pub(crate) fn resource_network(
    vfs: &mut trames_vfs::Vfs,
    request: &UringRequest,
    memory: &mut impl trames_memory::CpuMemory,
) -> Result<(i32, bool)> {
    let s = &request.sqe;
    let file = request.file.as_ref().ok_or(Errno(9))?;
    if matches!(s.opcode(), 16 | 56) {
        if s.op_flags() != 0 || s.length() != 0 {
            return Err(Errno(22));
        }
        return vfs.with_uring_fd(file, |v, fd| {
            v.with_socket_control(fd, |v| {
                if let Some(socket) = v.local_socket(fd)? {
                    if s.opcode() == 16 {
                        v.local_connect(&socket, request.path.as_deref().unwrap())?;
                    } else {
                        v.local_bind(&socket, request.path.as_deref().unwrap())?;
                    }
                } else {
                    let socket = v.socket_fd(fd)?;
                    let result = if s.opcode() == 56 {
                        socket.bind_authorized(
                            request.path.as_deref().unwrap(),
                            v.credentials
                                .has_cap(trames_vfs::capabilities::NET_BIND_SERVICE),
                        )
                    } else if request.started {
                        socket.resume_connect().and_then(|ready| {
                            if ready {
                                Ok(())
                            } else {
                                Err(trames_net::NetError(11))
                            }
                        })
                    } else {
                        socket.connect_bytes(request.path.as_deref().unwrap())
                    };
                    result.map_err(|e| Errno(if e.0 == 115 { 11 } else { e.0 }))?;
                }
                Ok((0, true))
            })
        });
    }
    if s.opcode() == 13 {
        if s.length() != 0 {
            return Err(Errno(22));
        }
        return vfs
            .with_uring_install(file, |v, fd| {
                Linux::network_vfs(
                    v,
                    242,
                    [
                        fd as u64,
                        s.address(),
                        s.offset(),
                        s.op_flags() as u64,
                        0,
                        0,
                    ],
                    memory,
                )
                .map(|fd| fd as u32)
            })
            .map(|fd| (fd as i32, true));
    }
    let (number, args) = match s.opcode() {
        26 | 27 if s.offset() == 0 => (
            if s.opcode() == 26 { 206 } else { 207 },
            [0, s.address(), s.length() as u64, s.op_flags() as u64, 0, 0],
        ),
        34 if s.op_flags() == 0 => (210, [0, s.length() as u64, 0, 0, 0, 0]),
        57 if s.op_flags() == 0 => (201, [0, s.length() as u64, 0, 0, 0, 0]),
        _ => return Err(Errno(22)),
    };
    vfs.with_uring_fd(file, |v, fd| {
        let mut args = args;
        args[0] = fd as u64;
        Linux::network_vfs(v, number, args, memory).map(|n| {
            (
                n as i32,
                !matches!(s.opcode(), 26 | 27) || n == request.requested,
            )
        })
    })
}

pub(crate) fn owner(
    vfs: &mut trames_vfs::Vfs,
    request: &mut UringRequest,
    memory: &mut impl trames_memory::CpuMemory,
    selected: Option<trames_vfs::UringProvidedBuffer>,
) -> Result<(i32, bool)> {
    let mut view;
    let request = if let Some(buffer) = selected {
        let file = request.file.as_ref().ok_or(Errno(9))?;
        if vfs.with_uring_fd(file, |v, fd| v.poll(fd, 1)) == 0 {
            return Err(Errno(11));
        }
        view = request.clone();
        let length = if request.sqe.opcode() == 27 && request.sqe.length() == 0 {
            buffer.length
        } else {
            buffer.length.min(request.sqe.length())
        };
        view.sqe.0[16..24].copy_from_slice(&buffer.address.to_le_bytes());
        view.sqe.0[24..28].copy_from_slice(&length.to_le_bytes());
        view.requested = length as u64;
        &mut view
    } else {
        request
    };
    let s = &request.sqe;
    let scalar = |n: u64| (n as i32, true);
    match s.opcode() {
        1 | 2 | 4 | 5 | 22 | 23 => resource_rw(vfs, request, memory),
        3 => {
            if s.op_flags() & !1 != 0 {
                return Err(Errno(22));
            }
            vfs.with_uring_fd(request.file.as_ref().unwrap(), |v, fd| {
                v.sync_fd(fd, s.op_flags() & 1 != 0)
            })
            .map(|()| (0, true))
        }
        6 => {
            if s.length() & !9 != 0
                || s.length() & 8 != 0 && !s.multishot()
                || s.op_flags() & !0x201f != 0
            {
                return Err(Errno(22));
            }
            let file = request.file.as_ref().unwrap();
            let (events, epoch) = file.with_retained(vfs, |f| f.readiness(s.op_flags() as u16));
            let fresh = !s.multishot()
                || s.length() & 8 != 0
                || events & !request.poll_ready != 0
                || events & 3 != 0 && epoch[0] != request.poll_epoch[0]
                || events & 4 != 0 && epoch[1] != request.poll_epoch[1];
            if events == 0 || !fresh {
                if events == 0 {
                    request.poll_ready = 0;
                    request.poll_epoch = epoch;
                }
                Err(Errno(11))
            } else {
                request.poll_ready = events;
                request.poll_epoch = epoch;
                Ok((events as i32, true))
            }
        }
        13 | 16 | 26 | 27 | 34 | 56 | 57 => resource_network(vfs, request, memory),
        17 => vfs
            .with_uring_fd(request.file.as_ref().unwrap(), |v, fd| {
                v.allocate_fd(fd, s.length() as u64, s.offset(), s.address())
            })
            .map(|()| (0, true)),
        18 | 28 => {
            let path = request.path.as_deref().unwrap();
            let (flags, mode, resolve) = request.how.unwrap_or((s.op_flags(), s.length(), 0));
            if s.opcode() == 28 && s.op_flags() != 0 {
                return Err(Errno(22));
            }
            if let Some(file) = &request.file {
                vfs.with_uring_install(file, |v, fd| {
                    v.open_at_resolve(fd as i32, path, flags, mode, resolve)
                })
            } else {
                vfs.open_at_resolve(s.fd(), path, flags, mode, resolve)
            }
            .map(|fd| (fd as i32, true))
        }
        19 => {
            if s.op_flags() != 0 || s.length() != 0 {
                Err(Errno(22))
            } else if vfs.uring(s.fd() as u32).is_ok() {
                Err(Errno(9))
            } else {
                vfs.close(s.fd() as u32).map(|()| (0, true))
            }
        }
        21 => {
            let a = [
                s.fd() as u64,
                0,
                s.op_flags() as u64,
                s.length() as u64,
                s.offset(),
                0,
            ];
            let path = request.path.as_deref().unwrap();
            if let Some(file) = &request.file {
                vfs.with_uring_path_fd(file, |v, fd| {
                    let mut a = a;
                    a[0] = fd as u64;
                    Linux::statx_path(v, a, path, memory)
                })
            } else {
                Linux::statx_path(vfs, a, path, memory)
            }
            .map(scalar)
        }
        45 => {
            if s.op_flags() & !(trames_vfs::O_CLOEXEC | trames_vfs::O_NONBLOCK) != 0
                || s.address() != 0
                || s.offset() > u32::MAX as u64
            {
                Err(Errno(22))
            } else {
                vfs.socket(s.fd() as u32, s.offset() as u32 | s.op_flags(), s.length())
                    .map(|fd| (fd as i32, true))
            }
        }
        55 => vfs
            .with_uring_fd(request.file.as_ref().unwrap(), |v, fd| {
                v.truncate_fd(fd, s.offset())
            })
            .map(|()| (0, true)),
        _ => Err(Errno(22)),
    }
}
