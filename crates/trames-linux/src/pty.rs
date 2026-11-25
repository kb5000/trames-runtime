// SPDX-License-Identifier: GPL-3.0-or-later
//! Short PTY controls use the accepted original endpoint on either execution path.
use trames_memory::{CopiedOutput, CpuMemory};
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

/// Snapshot the original endpoint while locked, then copy outside its lock.
/// Resident-memory termios/winsize queries need no task authority.
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
    let mut output = CopiedOutput::default();
    match request {
        0x5401 => output.push_slice(address, &tty.attributes),
        0x802c542a => output.push_slice(address, &tty.termios2()),
        0x540f => output.push_scalar(address, &task.visible(tty.foreground).to_le_bytes()),
        0x5413 => output.push_slice(address, &tty.window),
        0x541b => output.push_scalar(
            address,
            &((if end.master {
                tty.output_queue.len()
            } else {
                tty.available()
            }) as u32)
                .to_le_bytes(),
        ),
        0x5429 => {
            if tty.session == 0 {
                return Err(Errno(25));
            }
            output.push_scalar(address, &task.visible(tty.session).to_le_bytes());
        }
        _ => return Err(Errno(25)),
    }
    drop(tty);
    output.progress(memory).map_err(|_| Errno(14))?;
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
    terminal_control_impl(end, request, address, flags, task, memory, true)
}
pub(crate) fn terminal_control_prechecked(
    end: &PtyEnd,
    request: u32,
    address: u64,
    flags: u32,
    task: &dyn trames_vfs::TerminalTask,
    memory: &mut impl CpuMemory,
) -> trames_vfs::TerminalIo<u64> {
    terminal_control_impl(end, request, address, flags, task, memory, false)
}
pub(crate) fn terminal_check_job(
    end: &PtyEnd,
    request: u32,
    task: &dyn trames_vfs::TerminalTask,
) -> trames_vfs::TerminalIo<()> {
    use trames_vfs::TerminalIo;
    if !terminal_job_request(request) {
        return TerminalIo::Complete(Ok(()));
    }
    match end.pair.check_job(task, 22) {
        TerminalIo::Complete(Err(error)) => {
            TerminalIo::Complete(Err(if request == 0x5410 && error == Errno(5) {
                Errno(25)
            } else {
                error
            }))
        }
        result => result,
    }
}
fn terminal_control_impl(
    end: &PtyEnd,
    request: u32,
    address: u64,
    flags: u32,
    task: &dyn trames_vfs::TerminalTask,
    memory: &mut impl CpuMemory,
    check_job: bool,
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
    if check_job {
        match terminal_check_job(end, request, task) {
            TerminalIo::Complete(Ok(())) => {}
            TerminalIo::Complete(Err(error)) => return TerminalIo::Complete(Err(error)),
            TerminalIo::Stopped => return TerminalIo::Stopped,
        }
    }
    TerminalIo::Complete((|| {
        // Faultable input is imported before taking the terminal state lock.
        // The original job-control check has already completed for this call.
        let mut input = [0; 44];
        let count = match request {
            0x5402..=0x5404 => 36,
            0x402c542b..=0x402c542d => 44,
            0x5410 => 4,
            0x5414 => 8,
            _ => 0,
        };
        if count != 0 {
            memory
                .read(address, &mut input[..count])
                .map_err(|_| Errno(14))?;
        }
        if request == 0x5410 && i32::from_le_bytes(input[..4].try_into().unwrap()) < 0 {
            return Err(Errno(22));
        }
        let mut tty = pair.terminal.borrow_mut();
        if request == 0x5410 {
            let access = task.access();
            if access.session != tty.session || access.controlling != Some(pair.id) {
                return Err(Errno(25));
            }
        }
        match request {
            0x5402..=0x5404 => {
                let attr = input[..36].try_into().unwrap();
                tty.set_attributes(attr, None, request == 0x5404)?;
            }
            0x402c542b..=0x402c542d => {
                let raw = input;
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
                let local = u32::from_le_bytes(input[..4].try_into().unwrap());
                tty.foreground = task.foreground(tty.session, local)?;
                pair.retain_job_ids(task.namespace(), tty.session, tty.foreground);
            }
            0x5414 => {
                let window = input[..8].try_into().unwrap();
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
