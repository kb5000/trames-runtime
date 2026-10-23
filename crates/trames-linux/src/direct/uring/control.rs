// SPDX-License-Identifier: GPL-3.0-or-later
//! The original timeout/cancel rules over the worker-owned request index.
use super::*;

pub(super) struct Running {
    owner: u64,
    key: Option<usize>,
    data: u64,
    opcode: u8,
}
impl Request {
    pub(super) fn import_timer(&mut self, memory: &impl CpuMemory, clock: Instant) {
        if self.error.is_some() {
            return;
        }
        let s = &self.sqe;
        let address = match s.opcode() {
            11 => {
                if s.length() != 1 || s.multishot() && s.op_flags() & 1 != 0 {
                    self.error = Some(Errno(22));
                    return;
                }
                s.address()
            }
            15 => {
                self.timeout_target = self.dependency.map(|d| d.0);
                if self.dependency.is_none() || s.length() != 1 || s.offset() != 0 {
                    self.error = Some(Errno(22));
                    return;
                }
                s.address()
            }
            12 if s.op_flags() & 18 != 0 => {
                if s.op_flags() & 18 == 18 || s.op_flags() & !31 != 0 {
                    self.error = Some(Errno(22));
                    return;
                }
                s.offset()
            }
            _ => return,
        };
        let flags = if s.opcode() == 11 {
            s.op_flags() & !64
        } else if s.opcode() == 12 {
            s.op_flags() & !18
        } else {
            s.op_flags()
        };
        match crate::uring::time::deadline(memory, address, flags, clock) {
            Ok((deadline, duration)) => {
                self.timeout_duration = Some(duration);
                if s.opcode() != 11 || flags & 1 != 0 {
                    self.deadline = Some(deadline);
                }
            }
            Err(e) => self.error = Some(e),
        }
    }
    pub(super) fn running(&self) -> Running {
        Running {
            owner: self.owner,
            key: self.resource.as_ref().map(|f| f.identity),
            data: self.sqe.user_data(),
            opcode: self.sqe.opcode(),
        }
    }
    pub(super) fn selected(&self) -> bool {
        self.sqe.flags() & 32 != 0
    }
}
impl State {
    /// Metadata-only operations run under this ring's lock. No guest byte I/O,
    /// file/socket operation or another VM's memory is executed here.
    pub(super) fn control(&mut self, r: &mut Request) -> Option<Result<(i32, bool)>> {
        if let Some(e) = r.error {
            return Some(Err(e));
        }
        let s = &r.sqe;
        let result = match s.opcode() {
            0 => {
                if s.op_flags() == 0 {
                    Ok((0, true))
                } else {
                    Err(Errno(22))
                }
            }
            31 | 32 => crate::uring::buffers::provide(s, r.owner, &mut self.provided),
            11 => {
                if !r.started {
                    if s.op_flags() & 1 == 0 {
                        r.deadline = r
                            .timeout_duration
                            .and_then(|d| Instant::now().checked_add(d));
                    }
                    if !s.multishot() && s.offset() != 0 {
                        r.timeout_count = Some(self.completion_count.saturating_add(s.offset()));
                    }
                    r.started = true;
                }
                if r.timeout_count.is_some_and(|n| self.completion_count >= n) {
                    Ok((0, true))
                } else if r.deadline.is_some_and(|d| Instant::now() >= d) {
                    if s.op_flags() & 32 != 0 {
                        Ok((0, true))
                    } else {
                        Err(Errno(62))
                    }
                } else {
                    Err(Errno(11))
                }
            }
            15 => {
                if let Some(success) = r
                    .timeout_target
                    .and_then(|t| self.completed.get(&t))
                    .copied()
                {
                    Ok((-125, success))
                } else {
                    if !r.started
                        && r.timeout_target.is_some_and(|t| {
                            self.running.contains_key(&t)
                                || self.pending.iter().any(|p| p.sequence == t && p.started)
                        })
                    {
                        if s.op_flags() & 1 == 0 {
                            r.deadline = r
                                .timeout_duration
                                .and_then(|d| Instant::now().checked_add(d));
                        }
                        r.started = true;
                    }
                    if r.started && r.deadline.is_some_and(|d| Instant::now() >= d) {
                        if let Some(i) = self
                            .pending
                            .iter()
                            .position(|p| Some(p.sequence) == r.timeout_target)
                        {
                            let target = self.pending.remove(i).unwrap();
                            self.terminal(&target, Err(Errno(125)));
                        }
                        if s.op_flags() & 32 != 0 {
                            Ok((0, true))
                        } else {
                            Err(Errno(62))
                        }
                    } else {
                        Err(Errno(11))
                    }
                }
            }
            7 | 12 | 14 => self.cancel_or_update(r),
            _ => return None,
        };
        Some(result)
    }
    fn cancel_or_update(&mut self, r: &Request) -> Result<(i32, bool)> {
        let s = &r.sqe;
        let flags = s.op_flags();
        if s.opcode() == 7 && s.length() != 0 {
            if s.length() & !6 != 0
                || s.length() & 2 == 0 && flags != 0
                || s.length() & 2 != 0 && flags & !0x201f != 0
            {
                return Err(Errno(22));
            }
            let target = self
                .pending
                .iter_mut()
                .find(|p| {
                    p.owner == r.owner && p.sqe.opcode() == 6 && p.sqe.user_data() == s.address()
                })
                .ok_or(Errno(2))?;
            if s.length() & 2 != 0 {
                target.sqe.0[28..32].copy_from_slice(&flags.to_le_bytes());
            }
            if s.length() & 4 != 0 {
                target.sqe.0[32..40].copy_from_slice(&s.offset().to_le_bytes());
            }
            target.poll_ready = 0;
            target.poll_epoch = [0; 2];
            return Ok((0, true));
        }
        if s.opcode() == 12 && flags & 18 != 0 {
            let link = flags & 16 != 0;
            let target = self
                .pending
                .iter_mut()
                .find(|p| {
                    p.owner == r.owner
                        && p.sqe.user_data() == s.address()
                        && p.sqe.opcode() == if link { 15 } else { 11 }
                })
                .ok_or(Errno(2))?;
            target.deadline = r.deadline;
            target.timeout_count = None;
            let timeout_flags = (target.sqe.op_flags() & (64 | 32)) | (flags & (1 | 4 | 8));
            target.sqe.0[28..32].copy_from_slice(&timeout_flags.to_le_bytes());
            if target.sqe.opcode() == 11 && !target.sqe.multishot() {
                target.sqe.0[8..16].copy_from_slice(&0u64.to_le_bytes());
            }
            if target.sqe.multishot() {
                target.timeout_duration = r.timeout_duration;
            }
            if link {
                target.started = true;
            }
            return Ok((0, true));
        }
        if s.opcode() != 14 && flags != 0
            || s.opcode() == 14
                && (flags & !15 != 0 || flags & 8 != 0 && flags & 2 == 0 || flags & 6 == 6)
        {
            return Err(Errno(22));
        }
        let all = s.opcode() == 14 && flags & 5 != 0;
        let matches = |target: &Running| {
            target.owner == r.owner
                && (if flags & 4 != 0 {
                    true
                } else if flags & 2 != 0 {
                    target
                        .key
                        .zip(r.resource.as_ref().map(|f| f.identity))
                        .is_some_and(|(a, b)| a == b)
                } else {
                    target.data == s.address()
                })
                && (s.opcode() == 14
                    || s.opcode() == 7 && target.opcode == 6
                    || s.opcode() == 12 && target.opcode == 11)
        };
        let mut cancelled = 0;
        let mut i = 0;
        while i < self.pending.len() {
            if matches(&self.pending[i].running()) && (all || cancelled == 0) {
                let target = self.pending.remove(i).unwrap();
                self.terminal(&target, Err(Errno(125)));
                cancelled += 1;
            } else {
                i += 1;
            }
        }
        if cancelled != 0 {
            Ok((if all { cancelled } else { 0 }, true))
        } else if self.running.values().any(matches) {
            Err(Errno(114))
        } else {
            Err(Errno(2))
        }
    }
}
