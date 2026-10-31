// SPDX-License-Identifier: GPL-3.0-or-later
//! Original AF_UNIX byte ABI, shared by owner and concurrent worker transports.
use super::*;

pub(super) struct Message {
    pub control_size: u64,
    pub output: Option<AddressOutput>,
    pub vectors: Vectors,
}
impl Message {
    pub fn prepare(memory: &impl CpuMemory, address: u64, receive: bool) -> Result<Self> {
        Linux::check(memory, address, 56, Access::Read)?;
        if receive {
            Linux::check(memory, address, 56, Access::Write)?;
        }
        let name = u64_at(memory, address)?;
        let control = u64_at(memory, address + 32)?;
        let control_size = u64_at(memory, address + 40)?;
        if !receive && name != 0 {
            return Err(Errno(106));
        }
        if control_size != 0 {
            if control_size > crate::MAX_WRITE as u64 {
                return Err(Errno(22));
            }
            Linux::check(
                memory,
                control,
                control_size as usize,
                if receive { Access::Write } else { Access::Read },
            )?;
        }
        let output = if receive {
            AddressOutput::prepare(memory, name, address + 8, 2)?
        } else {
            None
        };
        let vectors = Vectors::prepare(
            memory,
            u64_at(memory, address + 16)?,
            u64_at(memory, address + 24)?,
            if receive { Access::Write } else { Access::Read },
        )?;
        Ok(Self {
            control_size,
            output,
            vectors,
        })
    }
}
pub(crate) fn send(
    a: [u64; 6],
    memory: &impl CpuMemory,
    scratch: &mut Vec<u8>,
    send: impl FnOnce(&[u8]) -> Result<u64>,
) -> Result<u64> {
    if a[4] != 0 {
        return Err(Errno(106));
    }
    Linux::write_transport(a, memory, scratch, send)
}
pub(crate) fn recv(
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    recv: impl FnOnce(usize) -> Result<Vec<u8>>,
) -> Result<u64> {
    let count = a[2].min(crate::MAX_WRITE as u64) as usize;
    Linux::check(memory, a[1], count, Access::Write)?;
    let output = AddressOutput::prepare(memory, a[4], a[5], 2)?;
    let bytes = recv(count)?;
    memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
    if let Some(output) = output {
        output.write_bytes(memory, &[])?;
    }
    Ok(bytes.len() as u64)
}
/// None is a descriptor-control send, before resource effects. Receive control
/// buffers can complete here when the resource has no queued descriptor rights.
pub(crate) fn message(
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    scratch: &mut Vec<u8>,
    recv: impl FnOnce(usize) -> Result<Vec<u8>>,
    send: impl FnOnce(&[u8]) -> Result<u64>,
) -> Option<Result<u64>> {
    let receive = number == 212;
    let message = match Message::prepare(memory, a[1], receive) {
        Ok(message) => message,
        Err(error) => return Some(Err(error)),
    };
    if !receive && message.control_size != 0 {
        return None;
    }
    Some((|| {
        if receive {
            let bytes = recv(message.vectors.size)?;
            message.vectors.write(memory, &bytes)?;
            if let Some(output) = message.output {
                output.write_bytes(memory, &[])?;
            } else {
                memory
                    .write_array(a[1] + 8, 0u32.to_le_bytes())
                    .map_err(|_| Errno(14))?;
            }
            memory
                .write_array(a[1] + 40, 0u64.to_le_bytes())
                .map_err(|_| Errno(14))?;
            memory
                .write_array(a[1] + 48, 0u32.to_le_bytes())
                .map_err(|_| Errno(14))?;
            Ok(bytes.len() as u64)
        } else {
            Linux::gather_parts(
                memory,
                &message.vectors.parts,
                message.vectors.size,
                scratch,
            )?;
            send(scratch)
        }
    })())
}
