// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted memory controller write; no hierarchy/position guard is parked.
use super::*;
use trames_memory::{MemoryCgroup, PageWait};
use trames_shared::ResourceWait;

enum Mode {
    Max(usize),
    High(usize),
    Reclaim { bytes: usize, anonymous_only: bool },
}
pub(crate) struct MemoryWrite {
    file: Arc<CgroupFile>,
    group: Arc<MemoryCgroup>,
    mode: Mode,
    baseline: usize,
    phase: u8,
    nonblocking: bool,
    attempted_victims: BTreeSet<usize>,
}
impl CgroupFile {
    pub(crate) fn memory_write_sync(
        self: &Arc<Self>,
        caller: &CgroupAccess,
        bytes: &[u8],
        flags: u32,
    ) -> Result<usize> {
        let Some(mut request) = MemoryWrite::begin(self.clone(), caller, bytes, flags)? else {
            return Ok(0);
        };
        let mut wait = host_sync::Wait::default();
        let mut receipt = None;
        loop {
            let _resumed = receipt.take();
            let Some(pending) = request.step()? else {
                return Ok(bytes.len());
            };
            wait.page(&pending)?;
            receipt = Some(pending);
        }
    }
    pub(crate) fn memory_write(&self) -> bool {
        matches!(
            self.name.as_slice(),
            b"memory.max" | b"memory.high" | b"memory.reclaim"
        )
    }
}
impl MemoryWrite {
    pub(crate) fn begin(
        file: Arc<CgroupFile>,
        caller: &CgroupAccess,
        bytes: &[u8],
        flags: u32,
    ) -> Result<Option<Self>> {
        let cg = file.groups.borrow();
        file.check_write(&cg, caller, bytes)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Errno(22))?.trim();
        let mode = match file.name.as_slice() {
            b"memory.max" => Mode::Max(controllers::memory_limit(text)?),
            b"memory.high" => Mode::High(controllers::memory_limit(text)?),
            b"memory.reclaim" => {
                let mut fields = text.split_whitespace();
                let amount = fields
                    .next()
                    .filter(|value| *value != "max")
                    .ok_or(Errno(22))?;
                let bytes = controllers::memory_limit(amount)?;
                let mut anonymous_only = false;
                if let Some(option) = fields.next() {
                    let value = option.strip_prefix("swappiness=").ok_or(Errno(22))?;
                    if value == "max" {
                        anonymous_only = true;
                    } else if value.parse::<u16>().ok().is_none_or(|value| value > 200) {
                        return Err(Errno(22));
                    }
                }
                if fields.next().is_some() {
                    return Err(Errno(22));
                }
                Mode::Reclaim {
                    bytes,
                    anonymous_only,
                }
            }
            _ => return Err(Errno(22)),
        };
        let group = cg.groups[&file.id]
            .memory
            .as_ref()
            .ok_or(Errno(19))?
            .clone();
        drop(cg);
        let baseline = group.reclaimed_bytes();
        match mode {
            Mode::Max(limit) => group.set_limit(limit),
            Mode::High(limit) => group.set_high(limit),
            _ => {}
        }
        Ok(Some(Self {
            file,
            group,
            mode,
            baseline,
            phase: 0,
            nonblocking: flags & O_NONBLOCK != 0,
            attempted_victims: BTreeSet::new(),
        }))
    }
    fn remaining(&self) -> usize {
        match self.mode {
            Mode::Max(limit) | Mode::High(limit) => self.group.current().saturating_sub(limit),
            Mode::Reclaim { bytes, .. } => {
                bytes.saturating_sub(self.group.reclaimed_bytes().wrapping_sub(self.baseline))
            }
        }
    }
    pub(crate) fn step(&mut self) -> Result<Option<Arc<PageWait>>> {
        // A different writer's accepted configuration supersedes this writer's
        // synchronous work. Never reinstall the old limit after a resource wait.
        if matches!(self.mode, Mode::Max(limit) if self.group.limit() != limit)
            || matches!(self.mode, Mode::High(limit) if self.group.high() != limit)
            || self.file.check_live(&self.file.groups.borrow()).is_err()
            || self.nonblocking && !matches!(self.mode, Mode::Reclaim { .. })
        {
            return Ok(None);
        }
        if matches!(self.mode, Mode::Reclaim { anonymous_only: true, bytes } if bytes != 0) {
            return Err(Errno(11));
        }
        loop {
            self.group.reclaim(self.remaining());
            let remaining = self.remaining();
            if remaining == 0 {
                return Ok(None);
            }
            match self.phase {
                0 => {
                    self.phase = 1;
                    if let Some(wait) = self.group.writeback(remaining).filter(|wait| !wait.ready())
                    {
                        return Ok(Some(self.configuration_wait(wait)));
                    }
                }
                1 => {
                    self.phase = 2;
                    if let Some(wait) = self
                        .group
                        .release_mappings(remaining)
                        .filter(|wait| !wait.ready())
                    {
                        return Ok(Some(self.configuration_wait(wait)));
                    }
                }
                _ => {
                    return match self.mode {
                        Mode::Reclaim { .. } => Err(Errno(11)),
                        Mode::High(_) => Ok(None),
                        Mode::Max(limit) => {
                            if let Some(wait) = self.oom(limit) {
                                self.phase = 0;
                                Ok(Some(wait))
                            } else {
                                Ok(None)
                            }
                        }
                    }
                }
            }
        }
    }
    fn configuration_wait(&self, wait: Arc<PageWait>) -> Arc<PageWait> {
        let limit = match self.mode {
            Mode::Max(limit) => Some((false, limit)),
            Mode::High(limit) => Some((true, limit)),
            _ => None,
        };
        let Some(limit) = limit else { return wait };
        PageWait::resource(Arc::new(Configured {
            wait,
            group: self.group.clone(),
            limit,
        }))
    }
    fn oom(&mut self, limit: usize) -> Option<Arc<PageWait>> {
        self.group.record_oom();
        let cg = self.file.groups.borrow();
        let member = cg
            .tasks
            .values()
            .find(|member| {
                !member.oom_protected()
                    && !self
                        .attempted_victims
                        .contains(&(Arc::as_ptr(member) as usize))
                    && cg
                        .memory_at(member.group())
                        .is_some_and(|owner| owner.is_within(&self.group))
                    && member
                        .wake
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .is_some()
            })?
            .clone();
        let origin = cg.memory_at(member.group())?;
        let kill_group = origin.oom_group_within(&self.group);
        let victims: Vec<_> = cg
            .tasks
            .values()
            .filter(|other| {
                !other.oom_protected()
                    && (other.tgid() == member.tgid()
                        || cg
                            .memory_at(other.group())
                            .zip(kill_group.as_ref())
                            .is_some_and(|(owner, group)| owner.is_within(group)))
            })
            .cloned()
            .collect();
        for victim in &victims {
            self.attempted_victims.insert(Arc::as_ptr(victim) as usize);
        }
        let mut seen = BTreeSet::new();
        let signals: Vec<_> = victims
            .iter()
            .filter_map(|victim| {
                if !seen.insert(victim.tgid()) {
                    return None;
                }
                Some((
                    cg.memory_at(victim.group())?,
                    victim.wake.lock().unwrap().as_ref()?.upgrade()?,
                ))
            })
            .collect();
        drop(cg);
        if let Some(group) = kill_group {
            group.record_group_kill();
        }
        for (group, signal) in signals {
            group.record_oom_kill();
            signal.terminate_process();
        }
        Some(PageWait::resource(Arc::new(Victims {
            members: victims,
            group: self.group.clone(),
            limit,
        })))
    }
}
struct Victims {
    members: Vec<Arc<Member>>,
    group: Arc<MemoryCgroup>,
    limit: usize,
}
impl ResourceWait for Victims {
    fn ready(&self) -> bool {
        self.group.limit() != self.limit
            || self
                .members
                .iter()
                .all(|member| member.exited.get().is_some())
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let mut subscriptions: Vec<_> = self
            .members
            .iter()
            .map(|member| {
                member
                    .exit_readiness
                    .get_or_init(Default::default)
                    .subscribe(signal)
            })
            .collect();
        subscriptions.push(self.group.subscribe_configuration(signal));
        subscriptions
    }
}

struct Configured {
    wait: Arc<PageWait>,
    group: Arc<MemoryCgroup>,
    limit: (bool, usize),
}
impl ResourceWait for Configured {
    fn ready(&self) -> bool {
        self.wait.ready()
            || (if self.limit.0 {
                self.group.high()
            } else {
                self.group.limit()
            }) != self.limit.1
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let mut subscriptions = self.wait.subscribe(signal);
        subscriptions.push(self.group.subscribe_configuration(signal));
        subscriptions
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        self.wait.deadline()
    }
}
