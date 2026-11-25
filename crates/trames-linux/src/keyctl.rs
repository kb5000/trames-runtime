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
        7 => return keys.clear(registry, c, a[1] as i32),
        8 | 9 => return keys.link(registry, c, a[1] as i32, a[2] as i32, a[0] as u32 == 9),
        11 => KeyOperation::Read,
        _ => return Err(Errno(95)),
    };
    match keys.access(registry, c, a[1] as i32, op)? {
        KeyResult::Number(n) => Ok(n),
        KeyResult::Description(bytes) | KeyResult::Bytes(bytes) => {
            // Linux queries with a null/zero buffer without invoking the read
            // method at the requested size. Its small keyring read buffers must
            // contain whole serials; larger buffers are resized to the payload.
            if a[0] as u32 == 11 && a[2] != 0 && a[3] <= trames_memory::PAGE_SIZE && a[3] & 3 != 0 {
                return Err(Errno(22));
            }
            let length = bytes.len() as u64;
            if a[2] != 0 {
                let capacity = if a[0] as u32 == 11 {
                    a[3] as usize
                } else {
                    a[3] as u32 as usize
                };
                if capacity >= bytes.len() && !bytes.is_empty() {
                    // Both keyctl operations return the required length and
                    // leave an undersized user buffer unchanged.
                    memory.write(a[2], &bytes).map_err(|_| Errno(14))?;
                }
            }
            Ok(length)
        }
    }
}
