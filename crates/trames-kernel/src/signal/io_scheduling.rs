// SPDX-License-Identifier: GPL-3.0-or-later
//! Source/owner scheduling ABI over original task identities and attributes.
use super::*;
use crate::scheduling::RESET_ON_FORK;

impl IoRoutes {
    fn schedule_target(&self, source: &Arc<IoTask>, pid: u32) -> Result<Arc<IoTask>, Errno> {
        if (pid as i32) < 0 {
            return Err(Errno(22));
        }
        if pid == 0 {
            return Ok(source.clone());
        }
        let id = self.namespace.global(pid).ok_or(Errno(3))?;
        self.directory
            .tasks(0, id)
            .into_iter()
            .next()
            .ok_or(Errno(3))
    }
    fn priority_targets(
        &self,
        source: &Arc<IoTask>,
        which: u32,
        who: u32,
    ) -> Result<Vec<Arc<IoTask>>, Errno> {
        let mut tasks = match which {
            0 if who == 0 => vec![source.clone()],
            0 => self
                .directory
                .tasks(0, self.namespace.global(who).ok_or(Errno(3))?),
            1 => {
                let id = if who == 0 {
                    source.group()
                } else {
                    self.namespace.global(who).ok_or(Errno(3))?
                };
                self.directory.tasks(2, id)
            }
            2 => {
                let uid = {
                    let cred = source.credentials().read();
                    if who == 0 {
                        cred.uid
                    } else {
                        cred.mapped_id(false, who).map_err(|_| Errno(3))?
                    }
                };
                let ids: Vec<_> = self
                    .directory
                    .groups
                    .lock()
                    .unwrap()
                    .keys()
                    .filter(|key| key.0 == 0)
                    .map(|key| key.1)
                    .collect();
                ids.into_iter()
                    .flat_map(|id| self.directory.tasks(0, id))
                    .filter(|task| task.scheduling.authority().uid == uid)
                    .collect()
            }
            _ => return Err(Errno(22)),
        };
        // get/setpriority address unreaped zombies too. CPU eligibility is a
        // different lifetime from original PID/credential/priority ownership.
        tasks.retain(|t| t.identifies(0, t.tid()) && self.namespace.local(t.tid()) != 0);
        tasks.sort_by_key(|t| t.pid.load(Ordering::Relaxed));
        // Preserve the existing partial-application order, with the caller last.
        if let Some(i) = tasks.iter().position(|t| Arc::ptr_eq(t, source)) {
            let caller = tasks.remove(i);
            tasks.push(caller);
        }
        if tasks.is_empty() {
            Err(Errno(3))
        } else {
            Ok(tasks)
        }
    }
    fn io_priority(&self, source: &Arc<IoTask>, number: u32, a: [u64; 6]) -> Result<u64, Errno> {
        let which = a[0] as u32;
        let priority = u32::from(a[2] as u16);
        if number == 30 {
            let caller = source.credentials().read();
            match priority >> 13 {
                0 if priority & 7 != 0 => return Err(Errno(22)),
                1 if !caller.has_cap(trames_vfs::capabilities::SYS_ADMIN)
                    && !caller.has_cap(trames_vfs::capabilities::SYS_NICE) =>
                {
                    return Err(Errno(1))
                }
                0..=3 => {}
                _ => return Err(Errno(22)),
            }
        }
        let targets = self.priority_targets(source, which.wrapping_sub(1), a[1] as u32)?;
        if number == 31 {
            return Ok(u64::from(
                targets
                    .iter()
                    .map(|t| t.scheduling.io_priority(which != 1))
                    .min()
                    .ok_or(Errno(3))?,
            ));
        }
        let caller = source.scheduling.authority();
        for target in targets {
            let uid = target.scheduling.authority().uid;
            if !caller.privileged && uid != caller.uid && uid != caller.euid {
                return Err(Errno(1));
            }
            target.scheduling.set_io_priority(priority);
        }
        Ok(0)
    }
    pub fn scheduling(
        &self,
        source: &Arc<IoTask>,
        cpus: usize,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        self.scheduling_request(source, cpus, number, a, memory)
            .map(|(value, _)| value)
    }
    pub fn scheduling_request(
        &self,
        source: &Arc<IoTask>,
        cpus: usize,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<(u64, Option<Arc<crate::completion::Completion>>), Errno> {
        let mut migration = None;
        let value = self.scheduling_value(source, cpus, number, a, memory, &mut migration)?;
        Ok((value, migration))
    }
    fn scheduling_value(
        &self,
        source: &Arc<IoTask>,
        cpus: usize,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        migration: &mut Option<Arc<crate::completion::Completion>>,
    ) -> Result<u64, Errno> {
        if matches!(number, 30 | 31) {
            return self.io_priority(source, number, a);
        }
        if matches!(number, 274 | 275) {
            if (a[0] as i32) < 0 || a[1] == 0 {
                return Err(Errno(22));
            }
            if number == 274 {
                if a[2] as u32 != 0 {
                    return Err(Errno(22));
                }
                let attr = FairAttr::read(memory, a[1])?;
                let target = self.schedule_target(source, a[0] as u32)?;
                return attr.apply(source, &target);
            }
            let size = a[2] as u32;
            if !(FairAttr::SIZE..=4096).contains(&size) || a[3] as u32 != 0 {
                return Err(Errno(22));
            }
            let target = self.schedule_target(source, a[0] as u32)?;
            return FairAttr::write(&target, memory, a[1]);
        }
        if matches!(number, 125 | 126) {
            return match a[0] as u32 {
                1 | 2 => Ok(if number == 125 { 99 } else { 1 }),
                0 | 3 | 5 | 6 => Ok(0),
                _ => Err(Errno(22)),
            };
        }
        // Retain the existing unsupported interfaces as terminal ABI results,
        // without joining the cohort just to produce ENOSYS.
        if number == 127 {
            return Err(Errno(38));
        }
        if matches!(number, 140 | 141) {
            let targets = self.priority_targets(source, a[0] as u32, a[1] as u32)?;
            if number == 141 {
                return Ok(
                    (20 - targets.iter().map(|t| t.scheduling.nice()).min().unwrap()) as u64,
                );
            }
            let nice = (a[2] as u32 as i32).clamp(-20, 19);
            let caller = source.scheduling.authority();
            let mut error = None;
            for target in targets {
                let auth = target.scheduling.authority();
                if !caller.privileged && caller.euid != auth.uid && caller.euid != auth.euid {
                    error = Some(Errno(1));
                } else if !caller.privileged
                    && nice < target.scheduling.nice()
                    && (20 - nice) as u64
                        > target
                            .proc_limits
                            .get()
                            .map_or(0, |limits| limits.get(13).0)
                {
                    error = Some(Errno(13));
                } else {
                    target.scheduling.set_nice(nice);
                }
            }
            return error.map_or(Ok(0), Err);
        }
        let target = self.schedule_target(source, a[0] as u32)?;
        if matches!(number, 118..=119 | 121) && (if number == 119 { a[2] } else { a[1] }) == 0 {
            return Err(Errno(22));
        }
        if number == 122 {
            check_scheduler_owner(source, &target)?;
        }
        match number {
            118 | 119 => {
                let pointer = if number == 118 { a[1] } else { a[2] };
                let priority =
                    i32::from_le_bytes(memory.read_array::<4>(pointer).map_err(|_| Errno(14))?);
                let requested = (number == 119).then_some(a[1] as u32);
                let attr = FairAttr {
                    policy: requested.map(|p| p & !RESET_ON_FORK),
                    reset: requested.map(|p| p & RESET_ON_FORK != 0),
                    nice: None,
                    priority: priority as u32,
                };
                attr.apply(source, &target)
            }
            120 => Ok(target.scheduling.cpu().0 as u64),
            121 => memory
                .write_array(a[1], 0u32.to_le_bytes())
                .map(|()| 0)
                .map_err(|_| Errno(14)),
            122 => {
                if a[1] == 0 {
                    return Err(Errno(22));
                }
                let mut bytes = [0; 8];
                memory
                    .read(a[2], &mut bytes[..a[1].min(8) as usize])
                    .map_err(|_| Errno(14))?;
                let valid = if cpus >= 64 {
                    u64::MAX
                } else {
                    (1u64 << cpus) - 1
                };
                let mask = u64::from_le_bytes(bytes) & valid;
                if mask & target.cpuset() == 0 {
                    return Err(Errno(22));
                }
                if mask == 0 {
                    return Err(Errno(22));
                }
                *migration = target.lifecycle().affinity(&target, mask);
                Ok(0)
            }
            123 => {
                if a[1] < 8 || a[1] & 7 != 0 {
                    return Err(Errno(22));
                }
                memory
                    .write_array(a[2], target.effective_affinity().to_le_bytes())
                    .map(|()| 8)
                    .map_err(|_| Errno(14))
            }
            _ => Err(Errno(38)),
        }
    }
}

fn check_scheduler_owner(source: &IoTask, target: &IoTask) -> Result<bool, Errno> {
    let caller = source.scheduling.authority();
    let auth = target.scheduling.authority();
    if !caller.privileged
        && ((caller.euid != auth.uid && caller.euid != auth.euid)
            || auth.permitted & !caller.permitted != 0)
    {
        return Err(Errno(1));
    }
    Ok(caller.privileged)
}

// Linux sched_attr version 0. Newer zero-filled tails are accepted so callers
// built with utilization-clamp fields can still use the supported fair policies.
struct FairAttr {
    policy: Option<u32>,
    reset: Option<bool>,
    nice: Option<i32>,
    priority: u32,
}
impl FairAttr {
    const SIZE: u32 = 48;

    fn read(memory: &mut impl CpuMemory, addr: u64) -> Result<Self, Errno> {
        let mut size = u32::from_le_bytes(memory.read_array(addr).map_err(|_| Errno(14))?);
        if size == 0 {
            size = Self::SIZE;
        }
        let mut incompatible = !(Self::SIZE..=4096).contains(&size);
        if !incompatible && size > Self::SIZE {
            let mut offset = Self::SIZE;
            let mut tail = [0u8; 64];
            while offset < size {
                let n = ((size - offset) as usize).min(tail.len());
                memory
                    .read(
                        addr.checked_add(u64::from(offset)).ok_or(Errno(14))?,
                        &mut tail[..n],
                    )
                    .map_err(|_| Errno(14))?;
                if tail[..n].iter().any(|&byte| byte != 0) {
                    incompatible = true;
                    break;
                }
                offset += n as u32;
            }
        }
        if incompatible {
            memory
                .write_array(addr, Self::SIZE.to_le_bytes())
                .map_err(|_| Errno(14))?;
            return Err(Errno(7));
        }
        let bytes: [u8; 48] = memory.read_array(addr).map_err(|_| Errno(14))?;
        let word = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let flags = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        const RESET: u64 = 1;
        const KEEP_POLICY: u64 = 8;
        const KEEP_PARAMS: u64 = 16;
        if flags & !(RESET | KEEP_POLICY | KEEP_PARAMS) != 0 {
            return Err(Errno(22));
        }
        let policy = (flags & KEEP_POLICY == 0).then(|| word(4));
        if policy == Some(6) {
            let value = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
            let (runtime, deadline, period) = (value(24), value(32), value(40));
            return Err(Errno(
                if runtime < 1024
                    || runtime > deadline
                    || (period != 0 && deadline > period)
                    || deadline as i64 <= 0
                    || (period as i64) < 0
                {
                    22
                } else {
                    95
                },
            ));
        }
        Ok(Self {
            policy,
            reset: Some(flags & RESET != 0),
            nice: (flags & KEEP_PARAMS == 0).then(|| (word(16) as i32).clamp(-20, 19)),
            priority: word(20),
        })
    }

    fn apply(&self, source: &IoTask, target: &IoTask) -> Result<u64, Errno> {
        match self.policy {
            Some(1 | 2) if (1..=99).contains(&self.priority) => return Err(Errno(95)),
            Some(0 | 3 | 5) | None if self.priority == 0 => {}
            _ => return Err(Errno(22)),
        }
        let privileged = check_scheduler_owner(source, target)?;
        let limit = target
            .proc_limits
            .get()
            .map_or(0, |limits| limits.get(13).0);
        let ok = target.scheduling.update_cpu(|old, old_nice| {
            let old_policy = old & !RESET_ON_FORK;
            let policy = self.policy.unwrap_or(old_policy);
            let nice = self.nice.unwrap_or(old_nice);
            let reset = self.reset.unwrap_or(old & RESET_ON_FORK != 0);
            if !privileged
                && ((!reset && old & RESET_ON_FORK != 0)
                    || (nice < old_nice && (20 - nice) as u64 > limit)
                    || (old_policy == 5 && policy != 5 && (20 - old_nice) as u64 > limit))
            {
                return None;
            }
            Some((policy | if reset { RESET_ON_FORK } else { 0 }, nice))
        });
        if ok {
            Ok(0)
        } else {
            Err(Errno(1))
        }
    }

    fn write(target: &IoTask, memory: &mut impl CpuMemory, addr: u64) -> Result<u64, Errno> {
        let (policy, nice) = target.scheduling.cpu();
        let mut bytes = [0; Self::SIZE as usize];
        bytes[..4].copy_from_slice(&Self::SIZE.to_le_bytes());
        bytes[4..8].copy_from_slice(&(policy & !RESET_ON_FORK).to_le_bytes());
        bytes[8..16].copy_from_slice(&u64::from(policy & RESET_ON_FORK != 0).to_le_bytes());
        bytes[16..20].copy_from_slice(&nice.to_le_bytes());
        memory
            .write(addr, &bytes)
            .map(|()| 0)
            .map_err(|_| Errno(14))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::Credentials;
    fn task(directory: &Arc<IoDirectory>, pid: u32, group: u32, uid: u32) -> Signals {
        let signals = Signals {
            io_directory: directory.clone(),
            ..Default::default()
        };
        signals.publish_policy(&PidNamespace::default(), uid == 0);
        signals
            .io
            .scheduling
            .publish_credentials(&Credentials::user(uid, uid));
        signals.io.scheduling.set_affinity(15);
        directory.publish(&signals.io, pid, pid, group, uid, uid);
        signals
    }
    fn memory() -> Memory {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
    }
    #[test]
    fn reset_on_fork_and_io_priority_follow_the_original_task() {
        let routes = IoRoutes::default();
        let parent = task(&routes.directory, 7, 7, 0);
        let peer = task(&routes.directory, 8, 7, 0);
        let mut memory = memory();
        let call = |n, a, m: &mut Memory| routes.scheduling(&parent.io, 4, n, a, m);
        memory.write_array(0x1000, 56u32.to_le_bytes()).unwrap();
        memory.write_array(0x1004, 3u32.to_le_bytes()).unwrap();
        memory.write_array(0x1008, 1u64.to_le_bytes()).unwrap();
        memory.write_array(0x1010, (-5i32).to_le_bytes()).unwrap();
        assert_eq!(call(274, [0, 0x1000, 0, 0, 0, 0], &mut memory), Ok(0));
        assert_eq!(
            call(120, [0; 6], &mut memory),
            Ok(u64::from(RESET_ON_FORK | 3))
        );
        assert_eq!(call(30, [2, 0, 0x4006, 0, 0, 0], &mut memory), Ok(0));
        assert_eq!(call(30, [1, 8, 0x4003, 0, 0, 0], &mut memory), Ok(0));
        assert_eq!(call(31, [3, 0, 0, 0, 0, 0], &mut memory), Ok(0x4003));
        assert_eq!(peer.io.scheduling.io_priority(false), 0x4003);
        let child = parent.fork(false);
        assert_eq!(parent.io.scheduling.cpu(), (RESET_ON_FORK | 3, -5));
        assert_eq!(child.io.scheduling.cpu(), (3, 0));
        assert_eq!(child.io.scheduling.io_priority(false), 0x4006);
        child.io.scheduling.set_io_priority(0x6000);
        assert_eq!(parent.io.scheduling.io_priority(false), 0x4006);
        assert_eq!(call(275, [0, 0x1fd0, 56, 0, 0, 0], &mut memory), Ok(0));
        assert_eq!(
            call(275, [0, 0x1fd1, 48, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
    }
    #[test]
    fn scheduler_attributes_preserve_nice_limit_and_size_negotiation() {
        let routes = IoRoutes::default();
        let caller = task(&routes.directory, 4, 4, 1000);
        let mut memory = memory();
        let set =
            |m: &mut Memory| routes.scheduling(&caller.io, 4, 274, [0, 0x1000, 0, 0, 0, 0], m);
        memory.write_array(0x1000, 64u32.to_le_bytes()).unwrap();
        memory.write_array(0x103c, 1u32.to_le_bytes()).unwrap();
        assert_eq!(set(&mut memory), Err(Errno(7)));
        assert_eq!(u32::from_le_bytes(memory.read_array(0x1000).unwrap()), 48);
        memory.write_array(0x1004, 3u32.to_le_bytes()).unwrap();
        memory.write_array(0x1010, (-1i32).to_le_bytes()).unwrap();
        assert_eq!(set(&mut memory), Err(Errno(1)));
        assert_eq!(caller.io.scheduling.cpu(), (0, 0));
    }
    #[test]
    fn priority_keeps_original_zombie_authority_until_reaped_without_a_cpu() {
        let routes = IoRoutes::default();
        let source = task(&routes.directory, 1, 1, 0);
        let target = task(&routes.directory, 2, 1, 1000);
        target.io.exit();
        assert!(!target.io.live());
        assert!(target.presence.present());
        let mut memory = memory();
        assert_eq!(
            routes.scheduling(&source.io, 4, 140, [0, 2, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        let mut caller = Credentials::user(0, 0);
        caller.caps.effective &= !(1 << trames_vfs::capabilities::SYS_NICE);
        source.io.scheduling.publish_credentials(&caller);
        assert_eq!(
            routes.scheduling(&source.io, 4, 140, [0, 2, 0, 0, 0, 0], &mut memory),
            Err(Errno(1))
        );
        assert_eq!(
            routes.scheduling(&source.io, 4, 141, [0, 2, 0, 0, 0, 0], &mut memory),
            Ok(20)
        );
        target.presence.visibility().reap();
        assert_eq!(
            routes.scheduling(&source.io, 4, 141, [0, 2, 0, 0, 0, 0], &mut memory),
            Err(Errno(3))
        );
    }
    #[test]
    fn original_target_authority_fault_order_and_unsupported_results() {
        let routes = IoRoutes::default();
        let source = task(&routes.directory, 1, 1, 1000);
        let target = task(&routes.directory, 2, 2, 2000);
        let mut memory = memory();
        let call = |n, a, m: &mut Memory| routes.scheduling(&source.io, 4, n, a, m);
        assert_eq!(call(120, [0; 6], &mut memory), Ok(0));
        assert_eq!(call(122, [2, 8, 0, 0, 0, 0], &mut memory), Err(Errno(1)));
        assert_eq!(call(122, [999, 8, 0, 0, 0, 0], &mut memory), Err(Errno(3)));
        assert_eq!(
            call(120, [u32::MAX as u64, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(22))
        );
        assert_eq!(call(122, [0, 8, 0, 0, 0, 0], &mut memory), Err(Errno(14)));
        memory.write(0x1000, &0x80u64.to_le_bytes()).unwrap();
        assert_eq!(
            call(122, [0, 8, 0x1000, 0, 0, 0], &mut memory),
            Err(Errno(22))
        );
        assert_eq!(source.io.scheduling.affinity(), 15);
        memory.write(0x1000, &0x82u64.to_le_bytes()).unwrap();
        assert_eq!(call(122, [0, 8, 0x1000, 0, 0, 0], &mut memory), Ok(0));
        assert_eq!(call(123, [0, 7, 0, 0, 0, 0], &mut memory), Err(Errno(22)));
        assert_eq!(call(123, [0, 8, 0x1000, 0, 0, 0], &mut memory), Ok(8));
        assert_eq!(u64::from_le_bytes(memory.read_array(0x1000).unwrap()), 2);
        assert_eq!(target.io.scheduling.affinity(), 15);
        assert_eq!(call(127, [0; 6], &mut memory), Err(Errno(38)));
        for number in [274, 275] {
            assert_eq!(call(number, [0; 6], &mut memory), Err(Errno(22)));
        }
        for (policy, max, min) in [
            (0, 0, 0),
            (1, 99, 1),
            (2, 99, 1),
            (3, 0, 0),
            (5, 0, 0),
            (6, 0, 0),
        ] {
            assert_eq!(call(125, [policy, 0, 0, 0, 0, 0], &mut memory), Ok(max));
            assert_eq!(call(126, [policy, 0, 0, 0, 0, 0], &mut memory), Ok(min));
        }
    }
    #[test]
    fn priority_sets_keep_original_partial_effects_and_fork_attributes_are_independent() {
        let routes = IoRoutes::default();
        let source = task(&routes.directory, 10, 10, 1000);
        let peer = task(&routes.directory, 20, 10, 1000);
        let foreign = task(&routes.directory, 30, 10, 2000);
        let mut memory = memory();
        assert_eq!(
            routes.scheduling(&source.io, 4, 140, [1, 0, 7, 0, 0, 0], &mut memory),
            Err(Errno(1))
        );
        assert_eq!(source.io.scheduling.nice(), 7);
        assert_eq!(peer.io.scheduling.nice(), 7);
        assert_eq!(foreign.io.scheduling.nice(), 0);
        assert_eq!(
            routes.scheduling(&source.io, 4, 141, [1, 0, 0, 0, 0, 0], &mut memory),
            Ok(20)
        );
        assert_eq!(
            routes.scheduling(&source.io, 4, 140, [2, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(13))
        );
        assert!(source.io.scheduling.update_cpu(|_, nice| Some((3, nice))));
        source.io.scheduling.set_affinity(2);
        let child = source.fork(false);
        assert_eq!(
            (
                child.io.scheduling.nice(),
                child.io.scheduling.policy(),
                child.io.scheduling.affinity()
            ),
            (7, 3, 2)
        );
        child.io.scheduling.set_nice(9);
        assert_eq!(source.io.scheduling.nice(), 7);
    }
    #[test]
    fn inherited_nice_limit_authorizes_only_original_guest_priority_range() {
        let routes = IoRoutes::default();
        let source = task(&routes.directory, 10, 10, 1000);
        let mut vfs = trames_vfs::Vfs::default();
        let limits = crate::limits::Limits::new(&vfs);
        limits.set(13, (28, 40));
        source.io.bind_proc_limits(&limits);
        let mut memory = memory();
        assert_eq!(
            routes.scheduling(
                &source.io,
                4,
                140,
                [0, 0, (-8i32) as u32 as u64, 0, 0, 0],
                &mut memory
            ),
            Ok(0)
        );
        assert_eq!(
            routes.scheduling(
                &source.io,
                4,
                140,
                [0, 0, (-9i32) as u32 as u64, 0, 0, 0],
                &mut memory
            ),
            Err(Errno(13))
        );
        let child = limits.fork(&vfs);
        limits.set(13, (40, 40));
        assert_eq!(child.get(13), (28, 40));
        limits.bind(&mut vfs);
        assert_eq!(
            routes.scheduling(
                &source.io,
                4,
                140,
                [0, 0, (-20i32) as u32 as u64, 0, 0, 0],
                &mut memory
            ),
            Ok(0)
        );
    }
    #[test]
    fn namespace_selection_retirement_and_rekey_cannot_retarget_old_task_objects() {
        let mut vfs = trames_vfs::Vfs::default();
        vfs.unshare_pid().unwrap();
        let mut ns_vfs = vfs.clone();
        ns_vfs.activate_child_pid(100).unwrap();
        let mut child = ns_vfs.clone();
        child.activate_child_pid(200).unwrap();
        let routes = IoRoutes {
            namespace: ns_vfs.pid_namespace().clone(),
            ..Default::default()
        };
        let source = task(&routes.directory, 100, 100, 1000);
        let peer = task(&routes.directory, 200, 100, 1000);
        let outside = task(&routes.directory, 300, 100, 1000);
        let mut memory = memory();
        assert_eq!(
            routes.scheduling(&source.io, 4, 140, [2, 0, 5, 0, 0, 0], &mut memory),
            Ok(0)
        );
        assert_eq!(peer.io.scheduling.nice(), 5);
        assert_eq!(outside.io.scheduling.nice(), 0);
        let original = routes.schedule_target(&source.io, 2).unwrap();
        peer.io.exit();
        assert_eq!(
            routes.scheduling(&source.io, 4, 120, [2, 0, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        peer.presence.visibility().reap();
        assert_eq!(
            routes.scheduling(&source.io, 4, 120, [2, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(3))
        );
        let replacement = task(&routes.directory, 200, 100, 1000);
        original.scheduling.set_nice(19);
        assert_eq!(replacement.io.scheduling.nice(), 0);
        assert!(!Arc::ptr_eq(
            &original,
            &routes.schedule_target(&source.io, 2).unwrap()
        ));
        source.io.exit();
        routes
            .directory
            .publish(&replacement.io, 100, 100, 100, 1000, 1000);
        assert!(routes
            .directory
            .tasks(0, 200)
            .into_iter()
            .all(|t| !t.live()));
        assert_eq!(replacement.io.scheduling.nice(), 0);
    }
    #[test]
    fn concurrent_source_updates_only_touch_each_original_task() {
        let routes = IoRoutes::default();
        let source = task(&routes.directory, 1, 1, 0);
        let peer = task(&routes.directory, 2, 1, 1000);
        std::thread::scope(|scope| {
            for i in 0..8 {
                let routes = &routes;
                let source = &source;
                scope.spawn(move || {
                    let mut memory = memory();
                    for _ in 0..128 {
                        memory
                            .write(0x1000, &(1u64 << (i % 4)).to_le_bytes())
                            .unwrap();
                        assert_eq!(
                            routes.scheduling(
                                &source.io,
                                4,
                                122,
                                [2, 8, 0x1000, 0, 0, 0],
                                &mut memory
                            ),
                            Ok(0)
                        );
                        assert_eq!(
                            routes.scheduling(&source.io, 4, 140, [0, 2, i, 0, 0, 0], &mut memory),
                            Ok(0)
                        );
                    }
                });
            }
        });
        assert!(matches!(peer.io.scheduling.affinity(), 1 | 2 | 4 | 8));
        assert!((0..8).contains(&peer.io.scheduling.nice()));
        assert_eq!(source.io.scheduling.affinity(), 15);
    }
}
