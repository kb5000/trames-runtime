// SPDX-License-Identifier: GPL-3.0-or-later
use trames_memory::{CopiedOutput, CpuMemory, MemoryError};
use trames_vfs::{Credentials, Errno, KeyOperation, KeyRegistry, KeyResult, SessionKeys};

pub fn keyctl(
    keys: &SessionKeys,
    registry: &KeyRegistry,
    c: &Credentials,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let mut output = CopiedOutput::default();
    let (value, _key) = prepare(keys, registry, c, a, memory, &mut output)?;
    output.progress(memory).map_err(|_| Errno(14))?;
    Ok(value)
}
pub(crate) fn prepare(
    keys: &SessionKeys,
    registry: &KeyRegistry,
    c: &Credentials,
    a: [u64; 6],
    memory: &impl CpuMemory,
    output: &mut CopiedOutput,
) -> Result<(u64, Option<trames_vfs::KeyLease>), Errno> {
    let op = match a[0] as u32 {
        0 => KeyOperation::Lookup(a[2] as i32 != 0),
        1 => {
            let name =
                if a[1] == 0 {
                    None
                } else {
                    Some(memory.read_c_string(a[1], 4096).map_err(|error| {
                        Errno(if error == MemoryError::Limit { 22 } else { 14 })
                    })?)
                };
            return keys.join(registry, c, name).map(|value| (value, None));
        }
        5 => KeyOperation::SetPermissions(a[2] as u32),
        6 => KeyOperation::Describe,
        7 => {
            return keys
                .clear(registry, c, a[1] as i32)
                .map(|value| (value, None))
        }
        8 | 9 => {
            return keys
                .link(registry, c, a[1] as i32, a[2] as i32, a[0] as u32 == 9)
                .map(|value| (value, None))
        }
        11 => KeyOperation::Read,
        _ => return Err(Errno(95)),
    };
    let (value, retained) = keys.access_retained(registry, c, a[1] as i32, op)?;
    match value {
        KeyResult::Number(n) => Ok((n, retained)),
        KeyResult::Description(bytes) | KeyResult::Bytes(bytes) => {
            if a[0] as u32 == 11 && a[2] != 0 && a[3] <= trames_memory::PAGE_SIZE && a[3] & 3 != 0 {
                return Err(Errno(22));
            }
            let length = bytes.len() as u64;
            let capacity = if a[0] as u32 == 11 {
                a[3] as usize
            } else {
                a[3] as u32 as usize
            };
            if a[2] != 0 && capacity >= bytes.len() && !bytes.is_empty() {
                output.push(a[2], bytes);
            }
            Ok((length, retained))
        }
    }
}
