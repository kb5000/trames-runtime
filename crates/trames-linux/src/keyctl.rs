// SPDX-License-Identifier: GPL-3.0-or-later
use crate::Linux;
use trames_memory::CpuMemory;
use trames_vfs::{Credentials, Errno, KeyOperation, KeyRegistry, KeyResult, SessionKeys};

pub fn keyctl(
    keys: &SessionKeys,
    registry: &KeyRegistry,
    c: &Credentials,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let op = match a[0] as u32 {
        0 => KeyOperation::Lookup(a[2] as i32 != 0),
        1 => {
            let name = if a[1] == 0 {
                None
            } else {
                Some(Linux::path(memory, a[1])?)
            };
            return keys.join(registry, c, name);
        }
        5 => KeyOperation::SetPermissions(a[2] as u32),
        6 => KeyOperation::Describe,
        _ => return Err(Errno(95)),
    };
    match keys.access(registry, c, a[1] as i32, op)? {
        KeyResult::Number(n) => Ok(n),
        KeyResult::Description(bytes) => {
            let length = bytes.len() as u64;
            if a[2] != 0 && (a[3] as u32 as u64) >= length {
                memory.write(a[2], &bytes).map_err(|_| Errno(14))?;
            }
            Ok(length)
        }
    }
}
