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
pub(crate) fn terminal_job_request(request: u32) -> bool {
    matches!(request, 0x5402..=0x5404 | 0x5409 | 0x540b | 0x5410 | 0x402c542b..=0x402c542d)
}
pub fn terminal_query_request(request: u32) -> bool {
    matches!(
        request,
        0x5401 | 0x802c542a | 0x540f | 0x5413 | 0x541b | 0x5429
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

/// Read-only controls use the original endpoint and guest memory directly. They
/// need neither an async call envelope nor task authority for termios/winsize.
pub fn terminal_query(
    end: &PtyEnd,
    request: u32,
    address: u64,
    task: &dyn trames_vfs::TerminalTask,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let tty = end.pair.terminal.borrow();
    if !end.master && matches!(request, 0x540f | 0x5429) {
        let access = task.access();
        if access.session != tty.session || access.controlling != Some(end.pair.id) {
            return Err(Errno(25));
        }
    }
    match request {
        0x5401 => memory
            .write(address, &tty.attributes)
            .map_err(|_| Errno(14))?,
        0x802c542a => memory
            .write(address, &tty.termios2())
            .map_err(|_| Errno(14))?,
        0x540f => memory
            .write_array(address, task.visible(tty.foreground).to_le_bytes())
            .map_err(|_| Errno(14))?,
        0x5413 => memory.write(address, &tty.window).map_err(|_| Errno(14))?,
        0x541b => memory
            .write_array(
                address,
                (if end.master {
                    tty.output_queue.len()
                } else {
                    tty.available()
                } as u32)
                    .to_le_bytes(),
            )
            .map_err(|_| Errno(14))?,
        0x5429 => {
            if tty.session == 0 {
                return Err(Errno(25));
            }
            memory
                .write_array(address, task.visible(tty.session).to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        _ => return Err(Errno(25)),
    }
    Ok(0)
}

/// Shared ABI body for worker and solo execution. Job stops retain the accepted
/// SVC/OFD and return the executor slot; they never become guest errno values.
pub fn terminal_control(
    end: &PtyEnd,
    request: u32,
    address: u64,
    flags: u32,
    task: &dyn trames_vfs::TerminalTask,
    memory: &mut impl CpuMemory,
) -> trames_vfs::TerminalIo<u64> {
    use trames_vfs::TerminalIo;
    if terminal_query_request(request) {
        return TerminalIo::Complete(terminal_query(end, request, address, task, memory));
    }
    let pair = &end.pair;
    if request == 0x540e {
        return TerminalIo::Complete(
            task.acquire(pair, address == 1, trames_vfs::fd_can_read(flags), false)
                .map(|()| 0),
        );
    }
    if request == 0x5422 {
        return TerminalIo::Complete(if end.master {
            Err(Errno(25))
        } else {
            task.detach(pair, false).map(|()| 0)
        });
    }
    if terminal_job_request(request) {
        match pair.check_job(task, 22) {
            TerminalIo::Complete(Ok(())) => {}
            TerminalIo::Complete(Err(e)) => {
                return TerminalIo::Complete(Err(if request == 0x5410 && e == Errno(5) {
                    Errno(25)
                } else {
                    e
                }))
            }
            TerminalIo::Stopped => return TerminalIo::Stopped,
        }
    }
    TerminalIo::Complete((|| {
        let mut tty = pair.terminal.borrow_mut();
        if request == 0x5410 {
            let access = task.access();
            if access.session != tty.session || access.controlling != Some(pair.id) {
                return Err(Errno(25));
            }
        }
        match request {
            0x5402..=0x5404 => {
                let attr = memory.read_array::<36>(address).map_err(|_| Errno(14))?;
                tty.set_attributes(attr, None, request == 0x5404)?;
            }
            0x402c542b..=0x402c542d => {
                let raw = memory.read_array::<44>(address).map_err(|_| Errno(14))?;
                let speeds = [
                    u32::from_le_bytes(raw[36..40].try_into().unwrap()),
                    u32::from_le_bytes(raw[40..].try_into().unwrap()),
                ];
                tty.set_attributes(
                    raw[..36].try_into().unwrap(),
                    Some(speeds),
                    request == 0x402c542d,
                )?;
            }
            0x5409 => {} // A pseudoterminal has no physical break or transmitter to drain.
            0x5410 => {
                let local = u32::from_le_bytes(memory.read_array(address).map_err(|_| Errno(14))?);
                tty.foreground = task.foreground(tty.session, local)?;
                pair.retain_job_ids(task.namespace(), tty.session, tty.foreground);
            }
            0x5414 => {
                let window = memory.read_array::<8>(address).map_err(|_| Errno(14))?;
                let changed = tty.window != window;
                tty.window = window;
                let (session, group) = (tty.session, tty.foreground);
                drop(tty);
                if changed {
                    task.signal(session, group, 28);
                }
                return Ok(0);
            }
            0x540b => {
                if address > 2 {
                    return Err(Errno(22));
                }
                if address == u64::from(end.master) || address == 2 {
                    tty.flush_input();
                }
                if address == u64::from(!end.master) || address == 2 {
                    tty.echo.clear();
                    tty.output_queue.clear();
                    tty.output_space_epoch = tty.output_space_epoch.wrapping_add(1);
                }
                if !end.master && pair.packet.load(std::sync::atomic::Ordering::Relaxed) {
                    pair.packet_status.fetch_or(
                        [1, 2, 3][address as usize],
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    tty.output_epoch = tty.output_epoch.wrapping_add(1);
                }
            }
            _ => return Err(Errno(25)),
        }
        Ok(0)
    })())
}
