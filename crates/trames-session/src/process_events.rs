// SPDX-License-Identifier: GPL-3.0-or-later
//! Cooperative futex waits, signal waits and POSIX timers; all addresses are guest addresses.
use super::*;

pub(super) use trames_kernel::signal::write_siginfo;

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
        trames_linux::timerfd_control_with_boot(
            &timer,
            number,
            a,
            &mut p.memory,
            self.started,
            Some(p.linux.boot_clock()),
        )
        .map(Some)
    }
    pub(super) fn epoll(
        &mut self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        io: &mut impl GuestOutput,
    ) -> Result<Option<u64>, Errno> {
        if p.retained_poll.is_some()
            || p.linux
                .vfs
                .direct_descriptors()
                .get(a[0] as u32)
                .is_some_and(|fd| fd.is_epoll())
        {
            return self.poll(p, number, a, io);
        }
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
            if let Some(mask) = p.signals.wait_mask.take() {
                p.signals.mask = mask;
            }
            p.poll_deadline = None;
            Ok(Some(ready.len() as u64))
        } else {
            if let Some(mask) = mask {
                if p.signals.wait_mask.is_none() {
                    p.signals.wait_mask = Some(p.signals.mask);
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
                let wait = trames_kernel::signal::SignalWait::Timed {
                    mask,
                    info,
                    deadline,
                };
                if let Some(value) =
                    wait.check(&p.signals.io, &mut p.memory, p.linux.vfs.pid_namespace())
                {
                    p.cpu.set_x(0, value.unwrap_or_else(error));
                    p.state = State::Ready;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }
    pub(super) fn tick_timers(&self) {
        self.timers.tick();
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
                let trames_kernel::signal::SignalWait::Timed {
                    mask,
                    info,
                    deadline,
                } = trames_kernel::signal::SignalWait::prepare(number, a, &p.memory)?
                else {
                    unreachable!()
                };
                p.state = State::Sigwait {
                    mask,
                    info,
                    deadline,
                };
                self.resume_event(p);
                if matches!(p.state, State::Ready) {
                    Ok(Some(p.cpu.x(0)))
                } else {
                    Ok(None)
                }
            }
            102 | 103 | 107..=111 => {
                if number == 107 || number == 103 {
                    self.publish_io_tasks(Some((pid, p)));
                }
                self.timers
                    .call(
                        number,
                        a,
                        &mut p.memory,
                        self.started,
                        p.tgid,
                        &p.signals.io_directory,
                        p.linux.vfs.pid_namespace(),
                    )
                    .map(Some)
            }
            _ => Err(Errno(38)),
        }
    }
}
