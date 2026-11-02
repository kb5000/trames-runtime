// SPDX-License-Identifier: GPL-3.0-or-later
//! Short PTY controls use the accepted original endpoint on either execution path.
use trames_memory::CpuMemory;
use trames_vfs::{Errno, PtyEnd};

pub fn pty_control_request(request: u32) -> bool {
    matches!(
        request,
        0x80045430 | 0x40045431 | 0x80045439 | 0x5420 | 0x80045438
    )
}

pub fn pty_control(
    end: &PtyEnd,
    request: u32,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    use std::sync::atomic::Ordering::Relaxed;
    // Preserve ENOTTY before touching guest memory, including invalid pointers.
    if !end.master {
        return Err(Errno(25));
    }
    let read = |memory: &mut _| {
        let mut bytes = [0; 4];
        CpuMemory::read(memory, address, &mut bytes).map_err(|_| Errno(14))?;
        Ok::<_, Errno>(u32::from_le_bytes(bytes))
    };
    let value = match request {
        0x80045430 => end.pair.number,
        0x80045439 => u32::from(end.pair.locked.load(Relaxed)),
        0x80045438 => u32::from(end.pair.packet.load(Relaxed)),
        0x40045431 => {
            end.pair.locked.store(read(memory)? != 0, Relaxed);
            return Ok(0);
        }
        0x5420 => {
            end.pair.packet.store(read(memory)? != 0, Relaxed);
            end.pair.packet_status.store(0, Relaxed);
            return Ok(0);
        }
        _ => return Err(Errno(25)),
    };
    memory
        .write_array(address, value.to_le_bytes())
        .map_err(|_| Errno(14))?;
    Ok(0)
}
