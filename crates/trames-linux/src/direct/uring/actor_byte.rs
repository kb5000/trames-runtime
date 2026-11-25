// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted byte operations retain imported input and dequeued output. This is
//! the same original OFD path, including owner-only providers and signal records.
use super::*;
use crate::direct::{byte_read::Read, ByteOperation, RetainedByte};
use trames_vfs::FileCommand;

#[allow(clippy::large_enum_variant)] // Inline cursor in an already-owned cold request; no second allocation.
pub(super) enum ByteIo {
    Read(Read),
    Write(Vec<u8>),
    Network(RetainedByte),
}
pub(super) fn signal(
    request: &Request,
    memory: &mut impl CpuMemory,
) -> Option<Result<(i32, bool)>> {
    let s = &request.sqe;
    if s.op_flags() & !8 != 0 {
        return Some(Err(Errno(95)));
    }
    if !matches!(s.offset(), 0 | u64::MAX) {
        return Some(Err(Errno(29)));
    }
    if matches!(s.opcode(), 2 | 5 | 23) {
        return Some(Err(Errno(22)));
    }
    let Object::Byte(fd) = &request.resource.as_ref()?.object else {
        return None;
    };
    // A registered buffer is already pinned; ordinary synchronous copies have
    // no lazy page. Use the original accepted task's reader directly, without
    // building a VFS projection or adopting a CQ observer's reader.
    let scalar = [(s.address(), (s.length() as usize).min(crate::MAX_WRITE))];
    let parts = request.parts.as_deref().unwrap_or(&scalar);
    Some(
        crate::direct::signal_read::SignalRead::uring(
            fd,
            parts,
            memory,
            s.opcode() == 1,
            request.buffer.as_deref(),
        )
        .map(|n| (n as i32, n == request.requested)),
    )
}
pub(super) fn execute(
    execution: &Execution,
    call: &mut Accepted,
    request: &Request,
    memory: &mut impl CpuMemory,
) -> Option<Result<(i32, bool)>> {
    let s = &request.sqe;
    if !matches!(s.offset(), 0 | u64::MAX) {
        return Some(Err(Errno(29)));
    }
    let file = request.file.as_ref()?;
    let direct = DirectSyscalls::new(execution.descriptors.clone())
        .with_resources(execution.factory.clone());
    if call.byte.is_none() {
        let bytes = call.input.get_or_insert_with(Default::default);
        let reader = file_input::Reader::new(memory, bytes);
        let result = file::parameters(request, &reader);
        if let Some(fault) = reader.fault() {
            call.page = Some(fault.wait);
            return Some(Err(Errno(11)));
        }
        let (command, parts) = match result {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        call.byte = Some(match command {
            FileCommand::Write { bytes, .. } => ByteIo::Write(bytes),
            FileCommand::Read { .. } => {
                let fd = match &request.resource.as_ref()?.object {
                    Object::Byte(fd) => RetainedByte {
                        fd: fd.clone(),
                        operation: ByteOperation::Plain,
                    },
                    Object::Tcp(_) => {
                        let (fd, tcp) = execution.descriptors.tcp_file(file.shared_file()?)?;
                        RetainedByte {
                            fd,
                            operation: ByteOperation::Tcp(Arc::new(tcp)),
                        }
                    }
                    Object::File(_) => return None,
                };
                match Read::with_parts(fd, parts, s.opcode() == 1) {
                    Ok(read) => ByteIo::Read(read),
                    Err(error) => return Some(Err(error)),
                }
            }
            _ => unreachable!("byte read/write admission"),
        });
        call.input = None;
    }
    let result = match call.byte.as_mut().unwrap() {
        ByteIo::Read(read) => {
            // io_uring treats its imported vectors as one byte destination.
            // Signal records retain their normal whole-record error boundary.
            let number = if s.opcode() == 1 && read.original.fd.is_signalfd() {
                65
            } else {
                63
            };
            let result =
                read.attempt_with(number, [0; 6], memory, |original, count| {
                    direct.read_byte_owned(original, count).or_else(|| {
                        execution.paths.lock().unwrap().uring_query(|vfs| {
                            vfs.with_uring_fd(file, |vfs, fd| vfs.read(fd, count))
                        })
                    })
                })?;
            if let Some(fault) = read.fault.take() {
                call.page = Some(fault.wait);
                return Some(Err(Errno(11)));
            }
            result.map(|n| n as usize)
        }
        ByteIo::Write(bytes) => execution
            .paths
            .lock()
            .unwrap()
            .uring_query(|vfs| vfs.with_uring_fd(file, |vfs, fd| vfs.write(fd, bytes)))?,
        ByteIo::Network(_) => unreachable!("separate message ABI"),
    };
    Some(result.map(|n| (n as i32, n as u64 == request.requested)))
}

pub(super) fn network(
    execution: &Execution,
    call: &mut Accepted,
    request: &Request,
    memory: &mut impl CpuMemory,
) -> Option<Result<(i32, bool)>> {
    let s = &request.sqe;
    let number = if s.opcode() == 26 { 206 } else { 207 };
    let args = [0, s.address(), s.length() as u64, s.op_flags() as u64, 0, 0];
    let direct = DirectSyscalls::new(execution.descriptors.clone())
        .with_resources(execution.factory.clone());
    if call.byte.is_none() {
        let Object::Byte(fd) = &request.resource.as_ref()?.object else {
            return None;
        };
        let original = RetainedByte {
            fd: fd.clone(),
            operation: ByteOperation::Plain,
        };
        let accepted = match direct.prepare_packet_byte(&original, number, args, memory)? {
            Ok(accepted) => accepted,
            Err(error) => return Some(Err(error)),
        };
        call.byte = Some(ByteIo::Network(accepted));
    }
    let ByteIo::Network(accepted) = call.byte.as_ref().unwrap() else {
        unreachable!("message byte lifetime")
    };
    let result = direct.transfer_retained(accepted, number, args, memory, None)?;
    if let Some(fault) = accepted.take_input_fault() {
        call.page = Some(fault.wait);
        return Some(Err(Errno(11)));
    }
    Some(result.map(|n| (n as i32, n == request.requested)))
}
