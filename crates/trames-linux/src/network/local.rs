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
        // Import the ABI record once. Each checked guest read can acquire a
        // hardware byte borrow; separate scalar reads repeat that boundary.
        let header = memory.read_array::<56>(address).map_err(|_| Errno(14))?;
        let word = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
        let name = word(0);
        let control = word(32);
        let control_size = word(40);
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
        let vectors = Vectors::prepare_stream(
            memory,
            word(16),
            word(24),
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
            // msg_controllen and msg_flags are adjacent ABI output fields.
            memory
                .write_array(a[1] + 40, [0; 12])
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use trames_memory::{Permissions, PAGE_SIZE};

    #[test]
    fn message_records_cross_pages_and_fault_before_transport_effects() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
        let address = 0x1fe0;
        let mut header = [0; 56];
        header[16..24].copy_from_slice(&0x2ff8u64.to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        let mut vector = [0; 16];
        vector[..8].copy_from_slice(&0x4000u64.to_le_bytes());
        vector[8..].copy_from_slice(&3u64.to_le_bytes());
        memory.write(address, &header).unwrap();
        memory.write(0x2ff8, &vector).unwrap();
        memory.write(0x4000, b"abc").unwrap();
        let args = [0, address, 0, 0, 0, 0];
        let mut scratch = Vec::new();
        let result = message(
            211,
            args,
            &mut memory,
            &mut scratch,
            |_| panic!("send must not receive"),
            |bytes| {
                assert_eq!(bytes, b"abc");
                Ok(bytes.len() as u64)
            },
        );
        assert_eq!(result, Some(Ok(3)));
        let result = message(
            212,
            args,
            &mut memory,
            &mut scratch,
            |capacity| {
                assert_eq!(capacity, 3);
                Ok(b"xyz".to_vec())
            },
            |_| panic!("receive must not send"),
        );
        assert_eq!(result, Some(Ok(3)));
        assert_eq!(memory.read_array::<3>(0x4000).unwrap(), *b"xyz");
        assert_eq!(memory.read_array::<12>(address + 40).unwrap(), [0; 12]);

        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        let touched = Cell::new(false);
        let result = message(
            212,
            args,
            &mut memory,
            &mut scratch,
            |_| {
                touched.set(true);
                Ok(Vec::new())
            },
            |_| panic!("receive must not send"),
        );
        assert_eq!(result, Some(Err(Errno(14))));
        assert!(!touched.get());

        memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.unmap(0x3000, PAGE_SIZE).unwrap();
        let result = message(
            211,
            args,
            &mut memory,
            &mut scratch,
            |_| panic!("send must not receive"),
            |_| {
                touched.set(true);
                Ok(0)
            },
        );
        assert_eq!(result, Some(Err(Errno(14))));
        assert!(!touched.get());
    }
}
