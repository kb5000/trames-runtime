// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest senders use the same resource queues as timers, signalfd and FASYNC.
use super::*;

impl Signals {
    pub fn publish_policy(&self, namespace: &PidNamespace, can_kill: bool) {
        let _ = self.io.presence.set(Arc::downgrade(&self.presence));
        *self.io.policy.write().unwrap() = Some(Policy {
            actions: self.actions.shared(),
            namespace: namespace.clone(),
            can_kill,
        });
    }
}
impl IoRoutes {
    /// Stop/continue also mutate lifecycle state, so retain that explicit
    /// authority boundary until the lifecycle subsystem is shared.
    pub fn send(&self, source: &IoTask, number: u32, a: [u64; 6]) -> Option<Result<u64, Errno>> {
        let sig = a[if number == 131 { 2 } else { 1 }] as u32;
        if matches!(sig, 18..=22) {
            return None;
        }
        Some((|| {
            if sig > 64 {
                return Err(Errno(22));
            }
            let can_kill = source
                .policy
                .read()
                .unwrap()
                .as_ref()
                .expect("published sender policy")
                .can_kill;
            let mut groups = Vec::new();
            let thread = number != 129;
            if thread {
                let tid = a[if number == 131 { 1 } else { 0 }] as u32;
                if tid == 0
                    || tid > i32::MAX as u32
                    || number == 131 && (a[0] == 0 || a[0] > i32::MAX as u64)
                {
                    return Err(Errno(22));
                }
                let id = self.namespace.global(tid).ok_or(Errno(3))?;
                let tasks = self.directory.tasks(0, id);
                if tasks.is_empty() {
                    return Err(Errno(3));
                }
                if number == 131 && self.namespace.global(a[0] as u32) != Some(tasks[0].tgid()) {
                    return Err(Errno(3));
                }
                groups.push(tasks);
            } else {
                let target = a[0] as i32;
                if target > 0 {
                    let id = self.namespace.global(target as u32).ok_or(Errno(3))?;
                    let task = self
                        .directory
                        .tasks(0, id)
                        .into_iter()
                        .next()
                        .ok_or(Errno(3))?;
                    groups.push(self.directory.tasks(1, task.tgid()));
                } else {
                    let registered: Vec<_> = self
                        .directory
                        .groups
                        .lock()
                        .unwrap()
                        .keys()
                        .filter(|k| k.0 == 1)
                        .map(|k| k.1)
                        .collect();
                    for id in registered {
                        let tasks = self.directory.tasks(1, id);
                        let Some(t) = tasks.first() else { continue };
                        let visible = self.namespace.local(id);
                        if visible != 0
                            && (target == 0
                                && t.group.load(Ordering::Relaxed)
                                    == source.group.load(Ordering::Relaxed)
                                || target == -1 && visible != 1 && id != source.tgid()
                                || target < -1
                                    && self.namespace.local(t.group.load(Ordering::Relaxed))
                                        == target.unsigned_abs())
                        {
                            groups.push(tasks);
                        }
                    }
                }
            }
            let mut found = false;
            let mut allowed = false;
            for tasks in groups {
                let Some(target) = tasks.first() else {
                    continue;
                };
                found = true;
                if !can_kill
                    && ![self.uid, self.euid].iter().any(|id| {
                        *id == target.uid.load(Ordering::Relaxed)
                            || *id == target.suid.load(Ordering::Relaxed)
                    })
                {
                    continue;
                }
                allowed = true;
                if sig == 0 {
                    continue;
                }
                let live: Vec<_> = tasks
                    .iter()
                    .filter(|t| t.live.load(Ordering::Relaxed))
                    .collect();
                let Some(target) = live.first() else { continue };
                let queue = if thread {
                    &target.inbox
                } else {
                    target.process().as_ref()
                };
                let queued = {
                    let policy = target.policy.read().unwrap();
                    let policy = policy.as_ref().expect("published target policy");
                    policy.actions.with_action(sig, |action| {
                        let masked = live.iter().any(|t| t.mask() & (1u64 << (sig - 1)) != 0);
                        let init = policy.namespace.is_nested()
                            && policy.namespace.local(target.tgid()) == 1;
                        if init
                            && action.handler <= 1
                            && !masked
                            && !(sig == 9 && policy.namespace.local(source.tgid()) == 0)
                            || action.handler == 1 && !masked
                        {
                            return Ok(false);
                        }
                        queue.enqueue_quiet(
                            sig,
                            Info {
                                sender: source.tgid(),
                                uid: self.uid,
                                code: if thread { -6 } else { 0 },
                                ..Info::default()
                            },
                        )
                    })?
                };
                // No policy/sighand/queue lock may enter a readiness callback.
                if queued {
                    queue.changed();
                }
                if thread {
                    target.wake();
                } else if let Some(target) = live.iter().find(|t| t.ready()) {
                    target.wake();
                }
            }
            if allowed {
                Ok(0)
            } else {
                Err(Errno(if found { 1 } else { 3 }))
            }
        })())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn publish(directory: &Arc<IoDirectory>, id: u32, group: u32, uid: u32, suid: u32) -> Signals {
        let signals = Signals {
            io_directory: directory.clone(),
            mask: 1 << 9,
            ..Default::default()
        };
        signals.begin_io();
        signals.publish_policy(&PidNamespace::default(), false);
        directory.publish(&signals.io, id, id, group, uid, suid);
        signals
    }
    #[test]
    fn guest_routes_preserve_permissions_zombies_and_reaped_pid_incarnations() {
        let directory = Arc::new(IoDirectory::default());
        let source = publish(&directory, 42, 42, 1000, 1000);
        let target = publish(&directory, 77, 77, 2000, 3000);
        let routes = IoRoutes {
            directory: directory.clone(),
            uid: 1000,
            euid: 1000,
            ..Default::default()
        };
        assert_eq!(
            routes.send(&source.io, 129, [77, 0, 0, 0, 0, 0]),
            Some(Err(Errno(1)))
        );
        let allowed = IoRoutes {
            euid: 3000,
            ..routes
        };
        assert_eq!(
            allowed.send(&source.io, 131, [78, 77, 10, 0, 0, 0]),
            Some(Err(Errno(3)))
        );
        assert_eq!(
            allowed.send(&source.io, 131, [77, 77, 10, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(target.io.dequeue(u64::MAX).unwrap().1.code, -6);
        let reader = target.reader(&PidNamespace::default());
        target.io.exit();
        assert_eq!(
            allowed.send(&source.io, 129, [77, 0, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(
            allowed.send(&source.io, 129, [77, 10, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(target.io.pending_bits(), 0);
        drop(target);
        assert_eq!(
            allowed.send(&source.io, 129, [77, 0, 0, 0, 0, 0]),
            Some(Err(Errno(3)))
        );
        let replacement = publish(&directory, 77, 77, 2000, 3000);
        assert_eq!(
            allowed.send(&source.io, 129, [77, 10, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(replacement.io.pending_bits(), 1 << 9);
        assert_eq!(reader.poll(u64::MAX).0, 0);
    }
}
