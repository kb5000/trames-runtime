// SPDX-License-Identifier: GPL-3.0-or-later
//! Cooperative futex waits, signal waits and POSIX timers; all addresses are guest addresses.
use super::*;

pub(super) struct Timer {
    pub tgid: u32,
    target: u32,
    thread: bool,
    clock: u64,
    signal: u32,
    value: u64,
    pub deadline: Option<Instant>,
    interval: Duration,
    overrun: i32,
}
pub(super) use trames_kernel::signal::write_siginfo;

fn timespec(m: &Memory, address: u64) -> Result<Duration, Errno> {
    let sec = read_u64(m, address)?;
    let ns = read_u64(m, address.checked_add(8).ok_or(Errno(14))?)?;
    if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
        return Err(Errno(22));
    }
    Ok(Duration::new(sec, ns as u32))
}
fn put_timespec(m: &mut Memory, address: u64, d: Duration) -> Result<(), Errno> {
    write_u64(m, address, d.as_secs())?;
    write_u64(m, address + 8, d.subsec_nanos() as u64)
}
impl<C: Cpu> Kernel<C> {
    pub(super) fn timerfd(
        &self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        if number == 85 {
            return p
                .linux
                .vfs
                .timerfd(a[0] as u32, a[1] as u32)
                .map(|fd| Some(fd as u64));
        }
        let timer = p.linux.vfs.timerfd_resource(a[0] as u32)?;
        trames_linux::timerfd_control(&timer, number, a, &mut p.memory, self.started).map(Some)
    }
    pub(super) fn epoll(
        &self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        io: &mut impl GuestOutput,
    ) -> Result<Option<u64>, Errno> {
        let timeout = trames_linux::epoll_parameters(&p.memory, number, a)?;
        let mask = if a[4] == 0 {
            None
        } else {
            if a[5] != 8 {
                return Err(Errno(22));
            }
            Some(read_u64(&p.memory, a[4])? & !UNBLOCKABLE)
        };
        let ready = p.linux.vfs.epoll_wait_signals(
            a[0] as u32,
            a[2] as usize,
            p.pending_bits(),
            |kind, events| {
                Ok(match kind {
                    FdKind::Stdin => Some((
                        if io.stdin_ready().map_err(|_| Errno(5))? {
                            events & 1
                        } else {
                            0
                        },
                        [0; 2],
                    )),
                    FdKind::Terminal => {
                        let t = self.terminal.as_ref().ok_or(Errno(25))?;
                        Some((
                            (events & 4) | if t.readable() { events & 1 } else { 0 },
                            [t.input_epoch, t.output_space_epoch],
                        ))
                    }
                    _ => None,
                })
            },
        )?;
        if let Some(timeout) = timeout {
            if p.poll_deadline.is_none() {
                p.poll_deadline = Some(Instant::now().checked_add(timeout).ok_or(Errno(22))?);
            }
        }
        if !ready.is_empty() || p.poll_deadline.is_some_and(|d| Instant::now() >= d) {
            trames_linux::epoll_scatter(&mut p.memory, a[1], &ready)?;
            if let Some(mask) = p.poll_mask.take() {
                p.signals.mask = mask;
            }
            p.poll_deadline = None;
            Ok(Some(ready.len() as u64))
        } else {
            if let Some(mask) = mask {
                if p.poll_mask.is_none() {
                    p.poll_mask = Some(p.signals.mask);
                }
                p.signals.mask = mask;
            }
            Ok(None)
        }
    }
    pub(super) fn wake_futex(
        &mut self,
        p: &Process<C>,
        address: u64,
        count: u32,
        bits: u32,
    ) -> u64 {
        if address == 0 {
            return 0;
        }
        Self::futex_key(p, address, false).map_or(0, |key| self.wake_futex_key(key, count, bits))
    }
    fn futex_key(p: &Process<C>, address: u64, private: bool) -> Result<(u64, u64, u64), Errno> {
        crate::worker_syscalls::futex_key(&p.memory, p.vm_id, address, private)
    }

    fn wake_futex_key(&mut self, key: (u64, u64, u64), count: u32, bits: u32) -> u64 {
        let woke = self.futexes.wake(key, count, bits);
        if woke != 0 {
            self.resume_futex_ready();
        }
        woke
    }
    pub(super) fn resume_futex_ready(&mut self) -> bool {
        let mut ready = std::mem::take(&mut self.futex_ready);
        self.futexes.take_ready(&mut ready);
        let mut progress = false;
        for ticket in ready.drain(..) {
            let Some(p) = self.processes.get_mut(&ticket.pid) else {
                continue;
            };
            // PID reuse or a preceding signal/exit cannot apply an old wake to
            // a different wait. Stopped tasks retain the ticket until SIGCONT.
            if matches!(&p.state, State::Futex { wait, .. } if std::sync::Arc::ptr_eq(&wait.ticket, &ticket))
            {
                p.state = State::Ready;
                p.cpu.set_x(0, 0);
                progress = true;
            }
        }
        self.futex_ready = ready;
        progress
    }
    pub(super) fn resume_event(&mut self, p: &mut Process<C>) -> bool {
        match p.state {
            State::Futex { ref wait, .. } if wait.woken() => {
                p.state = State::Ready;
                p.cpu.set_x(0, 0);
                true
            }
            State::Futex {
                ref wait,
                deadline: Some(d),
            } if Instant::now() >= d && wait.timeout() => {
                p.state = State::Ready;
                p.cpu.set_x(0, error(Errno(110)));
                true
            }
            State::Sigwait {
                mask,
                info,
                deadline,
            } => {
                if let Some((sig, shared)) = p.next_signal(mask) {
                    let value = p.take_signal(sig, shared);
                    if info != 0 {
                        let mut bytes = [0; 128];
                        write_siginfo(&mut bytes, sig, value);
                        if p.memory.write(info, &bytes).is_err() {
                            p.cpu.set_x(0, error(Errno(14)));
                            p.state = State::Ready;
                            return true;
                        }
                    }
                    p.cpu.set_x(0, sig as u64);
                    p.state = State::Ready;
                    true
                } else if deadline.is_some_and(|d| Instant::now() >= d) {
                    p.cpu.set_x(0, error(Errno(11)));
                    p.state = State::Ready;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
    pub(super) fn tick_timers(&mut self) {
        let now = Instant::now();
        for (&id, timer) in &mut self.timers {
            let Some(deadline) = timer.deadline.filter(|d| *d <= now) else {
                continue;
            };
            let extra = if timer.interval.is_zero() {
                0
            } else {
                now.saturating_duration_since(deadline).as_nanos() / timer.interval.as_nanos()
            };
            timer.deadline = if timer.interval.is_zero() {
                None
            } else {
                let remaining = timer.interval.as_nanos()
                    - now.saturating_duration_since(deadline).as_nanos()
                        % timer.interval.as_nanos();
                now.checked_add(Duration::new(
                    (remaining / 1_000_000_000) as u64,
                    (remaining % 1_000_000_000) as u32,
                ))
            };
            timer.overrun = extra.min(i32::MAX as u128) as i32;
            if timer.signal == 0 {
                continue;
            }
            if let Some(p) = self
                .processes
                .iter_mut()
                .find(|(id, p)| {
                    (if timer.thread {
                        **id == timer.target
                    } else {
                        p.tgid == timer.tgid
                    }) && !matches!(p.state, State::Zombie(_))
                })
                .map(|(_, p)| p)
            {
                let value = Info {
                    sender: 0,
                    uid: 0,
                    status: 0,
                    code: if id < 0 { 128 } else { -2 },
                    fault: None,
                    timer: if id < 0 {
                        None
                    } else {
                        Some((id, timer.overrun, timer.value))
                    },
                };
                let mut shared = p.signals.shared_pending.borrow_mut();
                let pending = if timer.thread {
                    &mut p.signals.pending
                } else {
                    &mut shared
                };
                if let Some(previous) = pending.timer_mut(timer.signal, id) {
                    if let Some((_, overrun, _)) = &mut previous.timer {
                        *overrun = overrun.saturating_add(timer.overrun).saturating_add(1);
                        timer.overrun = *overrun;
                    }
                } else {
                    let _ = pending.enqueue(timer.signal, value);
                }
            }
        }
    }
    pub(super) fn event_call(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        match number {
            98 => {
                if matches!(a[1] & 127, 0 | 9) {
                    let key = crate::worker_syscalls::futex_parameters(&p.memory, p.vm_id, a)?;
                    let (bits, deadline) =
                        crate::worker_syscalls::futex_wait_parameters(&p.memory, a, self.started)?;
                    let wait = self.futexes.wait(key, pid, bits, || {
                        if read_u32(&p.memory, a[0])? != a[2] as u32 {
                            return Err(Errno(11));
                        }
                        Ok(())
                    })?;
                    p.state = State::Futex { wait, deadline };
                    Ok(None)
                } else {
                    let effect =
                        crate::worker_syscalls::futex_queue(&self.futexes, &p.memory, p.vm_id, a)?;
                    if effect.woken != 0 {
                        self.resume_futex_ready();
                    }
                    Ok(Some(effect.total()))
                }
            }
            137 => {
                if a[3] != 8 {
                    return Err(Errno(22));
                }
                let mask = read_u64(&p.memory, a[0])? & !UNBLOCKABLE;
                if a[1] != 0 {
                    Linux::check(&p.memory, a[1], 128, Access::Write)?;
                }
                let deadline = if a[2] == 0 {
                    None
                } else {
                    Some(
                        Instant::now()
                            .checked_add(timespec(&p.memory, a[2])?)
                            .ok_or(Errno(22))?,
                    )
                };
                p.state = State::Sigwait {
                    mask,
                    info: a[1],
                    deadline,
                };
                self.resume_event(p);
                if matches!(p.state, State::Ready) {
                    Ok(Some(p.cpu.x(0)))
                } else {
                    Ok(None)
                }
            }
            102 | 103 => {
                if a[0] != 0 {
                    return Err(Errno(if a[0] <= 2 { 95 } else { 22 }));
                }
                let id = -(p.tgid as i32);
                let output = if number == 102 { a[1] } else { a[2] };
                if number == 102 || output != 0 {
                    Linux::check(&p.memory, output, 32, Access::Write)?;
                }
                let new = if number == 103 {
                    let get = |address| -> Result<Duration, Errno> {
                        let sec = read_u64(&p.memory, address)?;
                        let us = read_u64(&p.memory, address + 8)?;
                        if sec > i64::MAX as u64 || us >= 1_000_000 {
                            return Err(Errno(22));
                        }
                        Ok(Duration::new(sec, us as u32 * 1000))
                    };
                    let interval = get(a[1])?;
                    let value = get(a[1].checked_add(16).ok_or(Errno(14))?)?;
                    let deadline = if value.is_zero() {
                        None
                    } else {
                        Some(Instant::now().checked_add(value).ok_or(Errno(22))?)
                    };
                    Some((interval, deadline))
                } else {
                    None
                };
                if number == 102 || output != 0 {
                    let interval = self.timers.get(&id).map_or(Duration::ZERO, |t| t.interval);
                    let left = self
                        .timers
                        .get(&id)
                        .and_then(|t| t.deadline)
                        .map_or(Duration::ZERO, |d| {
                            d.saturating_duration_since(Instant::now())
                        });
                    for (offset, d) in [(0, interval), (16, left)] {
                        write_u64(&mut p.memory, output + offset, d.as_secs())?;
                        write_u64(&mut p.memory, output + offset + 8, d.subsec_micros() as u64)?;
                    }
                }
                if let Some((interval, deadline)) = new {
                    if deadline.is_none() {
                        self.timers.remove(&id);
                    } else {
                        self.timers.insert(
                            id,
                            Timer {
                                tgid: p.tgid,
                                target: p.tgid,
                                thread: false,
                                clock: 1,
                                signal: 14,
                                value: 0,
                                deadline,
                                interval,
                                overrun: 0,
                            },
                        );
                    }
                }
                Ok(Some(0))
            }
            107 => {
                if !matches!(a[0], 0 | 1) {
                    return Err(Errno(22));
                }
                Linux::check(&p.memory, a[2], 4, Access::Write)?;
                let id = self.next_timer;
                let (signal, value, target, thread) = if a[1] == 0 {
                    (14, id as u64, p.tgid, false)
                } else {
                    let value = read_u64(&p.memory, a[1])?;
                    let signal = read_u32(&p.memory, a[1] + 8)?;
                    let notify = read_u32(&p.memory, a[1] + 12)?;
                    match notify {
                        0 => {
                            if signal == 0 || signal > 64 {
                                return Err(Errno(22));
                            }
                            (signal, value, p.tgid, false)
                        }
                        1 => (0, value, p.tgid, false),
                        4 => {
                            if signal == 0 || signal > 64 {
                                return Err(Errno(22));
                            }
                            let target = p
                                .linux
                                .vfs
                                .global_pid(read_u32(&p.memory, a[1] + 16)?)
                                .map_err(|_| Errno(22))?;
                            if target != pid
                                && !self.processes.get(&target).is_some_and(|t| {
                                    t.tgid == p.tgid && !matches!(t.state, State::Zombie(_))
                                })
                            {
                                return Err(Errno(22));
                            }
                            (signal, value, target, true)
                        }
                        _ => return Err(Errno(22)),
                    }
                };
                if self.timers.len() >= 32 {
                    return Err(Errno(11));
                }
                self.next_timer = id.checked_add(1).ok_or(Errno(11))?;
                p.memory
                    .write(a[2], &id.to_le_bytes())
                    .map_err(|_| Errno(14))?;
                self.timers.insert(
                    id,
                    Timer {
                        tgid: p.tgid,
                        target,
                        thread,
                        clock: a[0],
                        signal,
                        value,
                        deadline: None,
                        interval: Duration::ZERO,
                        overrun: 0,
                    },
                );
                Ok(Some(0))
            }
            108..=111 => {
                let id = a[0] as i32;
                if id < 1 {
                    return Err(Errno(22));
                }
                let timer = self
                    .timers
                    .get_mut(&id)
                    .filter(|t| t.tgid == p.tgid)
                    .ok_or(Errno(22))?;
                match number {
                    109 => Ok(Some(timer.overrun as u64)),
                    111 => {
                        self.timers.remove(&id);
                        Ok(Some(0))
                    }
                    108 | 110 => {
                        let output = if number == 108 { a[1] } else { a[3] };
                        if number == 108 || output != 0 {
                            Linux::check(&p.memory, output, 32, Access::Write)?;
                        }
                        let new = if number == 110 {
                            if a[1] & !1 != 0 {
                                return Err(Errno(22));
                            }
                            let interval = timespec(&p.memory, a[2])?;
                            let value =
                                timespec(&p.memory, a[2].checked_add(16).ok_or(Errno(14))?)?;
                            let deadline = if value.is_zero() {
                                None
                            } else {
                                let duration = if a[1] & 1 == 0 {
                                    value
                                } else {
                                    let now = if timer.clock == 0 {
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map_err(|_| Errno(5))?
                                    } else {
                                        self.started.elapsed()
                                    };
                                    value.saturating_sub(now)
                                };
                                Some(Instant::now().checked_add(duration).ok_or(Errno(22))?)
                            };
                            Some((interval, deadline))
                        } else {
                            None
                        };
                        if number == 108 || output != 0 {
                            put_timespec(&mut p.memory, output, timer.interval)?;
                            put_timespec(
                                &mut p.memory,
                                output + 16,
                                timer.deadline.map_or(Duration::ZERO, |d| {
                                    d.saturating_duration_since(Instant::now())
                                }),
                            )?;
                        }
                        if let Some((interval, deadline)) = new {
                            timer.interval = interval;
                            timer.deadline = deadline;
                            timer.overrun = 0;
                        }
                        Ok(Some(0))
                    }
                    _ => unreachable!(),
                }
            }
            _ => Err(Errno(38)),
        }
    }
}
