// SPDX-License-Identifier: GPL-3.0-or-later
//! Source/owner scheduling ABI over original task identities and attributes.
use super::*;

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
            .find(|t| t.live())
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
            0 => {
                let id = if who == 0 {
                    source.pid.load(Ordering::Relaxed)
                } else {
                    self.namespace.global(who).ok_or(Errno(3))?
                };
                self.directory.tasks(0, id)
            }
            1 => {
                let id = if who == 0 {
                    source.group()
                } else {
                    self.namespace.global(who).ok_or(Errno(3))?
                };
                self.directory.tasks(2, id)
            }
            2 => {
                let uid = if who == 0 {
                    source.scheduling.authority().uid
                } else {
                    who
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
        tasks.retain(|t| t.live() && self.namespace.local(t.pid.load(Ordering::Relaxed)) != 0);
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
        if matches!(number, 125 | 126) {
            return match a[0] as u32 {
                1 | 2 => Ok(if number == 125 { 99 } else { 1 }),
                0 | 3 | 5 | 6 => Ok(0),
                _ => Err(Errno(22)),
            };
        }
        // Retain the existing unsupported interfaces as terminal ABI results,
        // without joining the cohort just to produce ENOSYS.
        if matches!(number, 127 | 274 | 275) {
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
                } else if !caller.privileged && nice < target.scheduling.nice() {
                    error = Some(Errno(13));
                } else {
                    target.scheduling.set_nice(nice);
                }
            }
            return error.map_or(Ok(0), Err);
        }
        let target = self.schedule_target(source, a[0] as u32)?;
        if matches!(number, 118 | 119 | 122) {
            let caller = source.scheduling.authority();
            let auth = target.scheduling.authority();
            if !caller.privileged
                && ((caller.euid != auth.uid && caller.euid != auth.euid)
                    || auth.permitted & !caller.permitted != 0)
            {
                return Err(Errno(1));
            }
        }
        match number {
            118 | 119 => {
                let pointer = if number == 118 { a[1] } else { a[2] };
                let priority =
                    i32::from_le_bytes(memory.read_array::<4>(pointer).map_err(|_| Errno(14))?);
                if number == 119 && !matches!(a[1] as u32, 0 | 3 | 5) {
                    return Err(Errno(if matches!(a[1] as u32, 1 | 2) { 95 } else { 22 }));
                }
                if priority != 0 {
                    return Err(Errno(22));
                }
                if number == 119 {
                    target.scheduling.set_policy(a[1] as u32);
                }
                Ok(0)
            }
            120 => Ok(target.scheduling.policy() as u64),
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
                if mask == 0 {
                    return Err(Errno(22));
                }
                *migration = target.lifecycle().affinity(&target, mask);
                Ok(0)
            }
            123 => {
                if a[1] < 8 {
                    return Err(Errno(22));
                }
                memory
                    .write_array(a[2], target.scheduling.affinity().to_le_bytes())
                    .map(|()| 8)
                    .map_err(|_| Errno(14))
            }
            _ => Err(Errno(38)),
        }
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
        for number in [127, 274, 275] {
            assert_eq!(call(number, [0; 6], &mut memory), Err(Errno(38)));
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
        source.io.scheduling.set_policy(3);
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
