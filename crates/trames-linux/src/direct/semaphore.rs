// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_vfs::{
    sysv_semaphore::{Operation, Request, MAX_OPS},
    DescriptorFactory,
};

pub(super) fn control(
    f: &DescriptorFactory,
    n: u32,
    a: [u64; 6],
    mem: &mut impl CpuMemory,
    pid: u32,
) -> Result<u64, Errno> {
    if n == 190 {
        return f
            .semaphore_get(a[0] as i32, a[1] as u32, a[2] as u32)
            .map(u64::from);
    }
    let cmd = a[2] as u32 & !0x100;
    let id = a[0] as u32;
    if (id as i32) < 0 {
        return Err(Errno(22));
    }
    if cmd == 0 {
        return f.semaphore_remove(id).map(|()| 0);
    }
    let (result, bytes) = if matches!(cmd, 3 | 19) {
        f.semaphore_info(cmd == 19)
    } else {
        let set = f.semaphore_set(id, matches!(cmd, 18 | 20))?;
        let mut input = vec![
            0;
            match cmd {
                1 => 88,
                17 => set.size() * 2,
                _ => 0,
            }
        ];
        if !input.is_empty() {
            mem.read(a[3], &mut input).map_err(|_| Errno(14))?;
        }
        set.control(f, a[1] as u32, cmd, a[3], &input, pid)?
    };
    if !bytes.is_empty() {
        mem.write(a[3], &bytes).map_err(|_| Errno(14))?;
    }
    Ok(result)
}
pub(super) fn import(
    f: &DescriptorFactory,
    n: u32,
    a: [u64; 6],
    mem: &impl CpuMemory,
    pid: u32,
) -> Result<(Request, Option<Instant>), Errno> {
    let count = a[2] as u32 as usize;
    if (a[0] as i32) < 0 || count == 0 {
        return Err(Errno(22));
    }
    if count > MAX_OPS {
        return Err(Errno(7));
    }
    let deadline = if n == 192 && a[3] != 0 {
        let ts = mem.read_array::<16>(a[3]).map_err(|_| Errno(14))?;
        let sec = i64::from_le_bytes(ts[..8].try_into().unwrap());
        let ns = i64::from_le_bytes(ts[8..].try_into().unwrap());
        if sec < 0 || !(0..1_000_000_000).contains(&ns) {
            return Err(Errno(22));
        }
        Instant::now().checked_add(Duration::new(sec as u64, ns as u32))
    } else {
        None
    };
    let mut buf = vec![0; count * 6];
    mem.read(a[1], &mut buf).map_err(|_| Errno(14))?;
    let ops = buf
        .chunks_exact(6)
        .map(|b| Operation {
            index: u16::from_le_bytes([b[0], b[1]]),
            change: i16::from_le_bytes([b[2], b[3]]),
            flags: u16::from_le_bytes([b[4], b[5]]),
        })
        .collect();
    Ok((f.semaphore_request(a[0] as u32, ops, pid)?, deadline))
}
