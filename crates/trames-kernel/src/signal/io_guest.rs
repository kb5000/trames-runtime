// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest senders use the same resource queues as timers, signalfd and FASYNC.
use super::*;

impl Signals {
    pub fn publish_policy(&self, namespace: &PidNamespace, can_kill: bool) {
        self.io.inbox.namespace.get_or_init(|| namespace.clone());
        if let Some(process) = self.io.process.get() {
            process.namespace.get_or_init(|| namespace.clone());
        }
        let _ = self.io.presence.set(self.presence.visibility());
        self.io.credentials().publish_kill_permission(can_kill);
        *self.io.policy.write().unwrap() = Some(Policy {
            actions: self.actions.shared(),
            namespace: namespace.clone(),
        });
    }
}
impl IoTask {
    /// Host-authorized control of this original task, not its process group.
    /// Policy and the private inbox are shared with its running executor.
    pub fn host_signal(&self, signal: u32) {
        if !(1..=64).contains(&signal) || !self.live() {
            return;
        }
        let info = Info::default();
        if matches!(signal, 9 | 18..=22) {
            let _ = self.job_signal(signal, false, info, true);
            return;
        }
        let queued = {
            let policy = self.policy.read().unwrap();
            let enqueue = || self.inbox.enqueue_quiet(signal, info);
            policy.as_ref().map_or_else(enqueue, |policy| {
                policy.actions.with_action(signal, |action| {
                    let masked = self.mask() & (1 << (signal - 1)) != 0;
                    let init =
                        policy.namespace.is_nested() && policy.namespace.local(self.tgid()) == 1;
                    if !masked && (action.handler == 1 || init && action.handler <= 1) {
                        Ok(false)
                    } else {
                        enqueue()
                    }
                })
            })
        };
        if matches!(queued, Ok(true)) {
            self.inbox.changed();
        }
    }

    /// A trusted lifecycle producer, using the child's original policy/queues.
    /// No guest sender permission or owner Process projection is involved.
    pub(crate) fn lifecycle_signal(&self, signal: u32, info: Info) {
        if matches!(signal, 9 | 18..=22) {
            let _ = self.job_signal(signal, true, info, self.ancestor_sender(info.sender));
            return;
        }
        let queued = {
            let policy = self.policy.read().unwrap();
            let enqueue = || self.process().enqueue_quiet(signal, info);
            policy.as_ref().map_or_else(enqueue, |policy| {
                policy.actions.with_action(signal, |action| {
                    let masked = self.mask() & (1 << (signal - 1)) != 0;
                    let init =
                        policy.namespace.is_nested() && policy.namespace.local(self.tgid()) == 1;
                    if !masked && (action.handler == 1 || init && action.handler <= 1) {
                        return Ok(false);
                    }
                    enqueue()
                })
            })
        };
        if matches!(queued, Ok(true)) {
            self.process().changed();
        }
    }
}
impl IoRoutes {
    /// Guest and resource senders use the same original queues and group control.
    pub fn send(&self, source: &IoTask, number: u32, a: [u64; 6]) -> Option<Result<u64, Errno>> {
        self.send_info(source, number, a, None)
    }
    /// Queued signals retain the copied siginfo, original target permission and
    /// original task/group queues. No owner-thread projection is needed.
    pub fn send_queued(
        &self,
        source: &IoTask,
        number: u32,
        a: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        self.queued(source, number, a, memory, false)
    }
    pub fn pidfd_open(
        &self,
        factory: &trames_vfs::DescriptorFactory,
        pid: i32,
        flags: u32,
    ) -> Result<u64, Errno> {
        if pid <= 0 || flags & !(trames_vfs::O_NONBLOCK | trames_vfs::PIDFD_THREAD) != 0 {
            return Err(Errno(22));
        }
        let global = self.namespace.global(pid as u32).ok_or(Errno(3))?;
        let task = self.directory.proc_task(global).ok_or(Errno(3))?;
        if task.tgid() != global && flags & trames_vfs::PIDFD_THREAD == 0 {
            return Err(Errno(2));
        }
        let target = Self::task_pidfd(&task, global).ok_or(Errno(3))?;
        factory
            .reserve_pidfd(target, flags)?
            .publish()
            .map(u64::from)
    }

    fn task_pidfd(task: &IoTask, id: u32) -> Option<Arc<trames_vfs::PidFd>> {
        let target = if id == task.tgid() {
            task.lifecycle().pidfd()
        } else {
            task.thread_wait(id).map(|source| source.pidfd(id))
        }?;
        if let Some(namespace) = task.inbox.namespace.get() {
            target.bind_namespace(namespace);
        }
        Some(target)
    }

    pub fn pidfd_getfd(
        &self,
        caller: &IoTask,
        flags: &trames_vfs::FdFlags,
        into: &trames_vfs::DescriptorFactory,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        if a[2] as u32 != 0 {
            return Err(Errno(22));
        }
        let (pidfd, _) = flags.pidfd(a[0] as u32)?;
        let target = self.live_pidfd_target(&pidfd)?;
        let credentials = caller.credentials().read().clone();
        target
            .credentials()
            .receive_pidfd_file(
                &credentials,
                target.tgid() == caller.tgid(),
                a[1] as u32,
                into.files(),
                target.trace_requires_cap(caller.tgid(), self.namespace.ptrace_scope())?,
            )
            .map(u64::from)
    }

    fn live_pidfd_target(&self, pidfd: &Arc<trames_vfs::PidFd>) -> Result<Arc<IoTask>, Errno> {
        let target = self
            .directory
            .proc_task(pidfd.pid())
            .filter(|t| t.live())
            .ok_or(Errno(3))?;
        if !Self::task_pidfd(&target, pidfd.pid())
            .is_some_and(|current| Arc::ptr_eq(&current, pidfd))
        {
            return Err(Errno(3));
        }
        Ok(target)
    }

    pub fn pidfd_namespaces(
        &self,
        caller: &IoTask,
        pidfd: &Arc<trames_vfs::PidFd>,
        flags: u64,
    ) -> Result<trames_vfs::PidfdNamespaces, Errno> {
        let target = self.live_pidfd_target(pidfd)?;
        let credentials = caller.credentials().read().clone();
        target
            .credentials()
            .pidfd_namespaces(&credentials, target.tgid() == caller.tgid(), flags)
    }

    pub fn pidfd_send(
        &self,
        source: &IoTask,
        files: &trames_vfs::FdFlags,
        a: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Result<u64, Errno> {
        let scope = a[3] as u32;
        if !matches!(scope, 0 | 1 | 2 | 4) {
            return Err(Errno(22));
        }
        let (target, flags) = files.pidfd_flags(a[0] as u32)?;
        let global = target.pid();
        if self.namespace.local(global) == 0 {
            return Err(Errno(22));
        }
        let thread = scope == 1 || scope == 0 && flags & trames_vfs::PIDFD_THREAD != 0;
        let groups = if scope == 4 {
            let mut groups = std::collections::BTreeMap::<_, Vec<_>>::new();
            for task in self.directory.tasks(2, global) {
                groups.entry(task.tgid()).or_default().push(task);
            }
            groups.into_values().collect()
        } else {
            let task = self.directory.proc_task(global).ok_or(Errno(3))?;
            if !Self::task_pidfd(&task, global).is_some_and(|pid| Arc::ptr_eq(&pid, &target)) {
                return Err(Errno(3));
            }
            vec![if thread {
                vec![task]
            } else {
                self.directory.tasks(1, global)
            }]
        };
        let sig = a[1] as u32;
        let user = (a[2] != 0)
            .then(|| {
                let user = memory.read_array::<48>(a[2]).map_err(|_| Errno(14))?;
                Self::signal_info(
                    memory,
                    a[2],
                    user,
                    sig,
                    true,
                    scope != 4 && source.tid() == global,
                )
            })
            .transpose()?;
        self.deliver_signal(source, sig, thread, groups, user)
    }
    fn queued(
        &self,
        source: &IoTask,
        number: u32,
        a: [u64; 6],
        memory: &impl CpuMemory,
        check_signo: bool,
    ) -> Option<Result<u64, Errno>> {
        let (route, args, address) = if number == 138 {
            (129, a, a[2])
        } else {
            (131, a, a[3])
        };
        let sig = a[if number == 240 { 2 } else { 1 }] as u32;
        let target = a[if number == 240 { 1 } else { 0 }] as u32;
        Some((|| {
            let user = memory.read_array::<48>(address).map_err(|_| Errno(14))?;
            if number == 240 && (a[0] as i32 <= 0 || a[1] as i32 <= 0) {
                return Err(Errno(22));
            }
            let user = Self::signal_info(
                memory,
                address,
                user,
                sig,
                check_signo,
                self.namespace.local(source.tid()) == target,
            )?;
            if number == 138 && a[0] as i32 <= 0 {
                return Err(Errno(3));
            }
            self.send_info(source, route, args, Some(user))
                .expect("queued signal route")
        })())
    }
    fn signal_info(
        memory: &impl CpuMemory,
        address: u64,
        user: [u8; 48],
        sig: u32,
        check_signo: bool,
        to_self: bool,
    ) -> Result<[u8; 48], Errno> {
        let code = i32::from_le_bytes(user[8..12].try_into().unwrap());
        if check_signo && u32::from_le_bytes(user[..4].try_into().unwrap()) != sig {
            return Err(Errno(22));
        }
        let limit = match sig {
            4 => 11,
            5 => 6,
            7 => 5,
            8 => 15,
            11 => 10,
            17 | 29 => 6,
            31 => 2,
            _ => 6,
        };
        let known =
            (-7..=0).contains(&code) || code == -60 || code == 128 || code > 0 && code <= limit;
        if !known {
            let expansion = match address
                .checked_add(48)
                .and_then(|at| memory.read_array::<80>(at).ok())
            {
                Some(bytes) => bytes,
                None => return Err(Errno(14)),
            };
            if expansion.iter().any(|b| *b != 0) {
                return Err(Errno(7));
            }
        }
        if (code >= 0 || code == -6) && !to_self {
            return Err(Errno(1));
        }
        Ok(user)
    }
    fn send_info(
        &self,
        source: &IoTask,
        number: u32,
        a: [u64; 6],
        user: Option<[u8; 48]>,
    ) -> Option<Result<u64, Errno>> {
        let sig = a[if number == 131 { 2 } else { 1 }] as u32;
        Some((|| {
            if sig > 64 {
                return Err(Errno(22));
            }
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
                    let group = self
                        .directory
                        .tasks(0, id)
                        .first()
                        .map_or(id, |task| task.tgid());
                    let tasks = self.directory.tasks(1, group);
                    if tasks.is_empty() {
                        return Err(Errno(3));
                    }
                    groups.push(tasks);
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
                            && (target == 0 && t.group() == source.group()
                                || target == -1 && visible != 1 && id != source.tgid()
                                || target < -1
                                    && self.namespace.local(t.group()) == target.unsigned_abs())
                        {
                            groups.push(tasks);
                        }
                    }
                }
            }
            self.deliver_signal(source, sig, thread, groups, user)
        })())
    }
    fn deliver_signal(
        &self,
        source: &IoTask,
        sig: u32,
        thread: bool,
        groups: Vec<Vec<Arc<IoTask>>>,
        user: Option<[u8; 48]>,
    ) -> Result<u64, Errno> {
        if sig > 64 {
            return Err(Errno(22));
        }
        let (can_kill, domain) = {
            let credentials = source.credentials().read();
            (
                credentials.has_cap(trames_vfs::capabilities::KILL),
                credentials.landlock.clone(),
            )
        };
        let mut found = false;
        let mut allowed = false;
        for tasks in groups {
            let Some(target) = tasks.first() else {
                continue;
            };
            found = true;
            if !can_kill
                && !(sig == 18 && source.session() == target.session())
                && !{
                    let (matched, namespace) = {
                        let c = target.credentials().read();
                        (
                            [self.uid, self.euid]
                                .iter()
                                .any(|id| *id == c.uid || *id == c.suid),
                            c.user_namespace.clone(),
                        )
                    };
                    matched
                        || source
                            .credentials()
                            .read()
                            .has_ns_cap(&namespace, trames_vfs::capabilities::KILL)
                }
            {
                continue;
            }
            const SCOPE: u64 = trames_vfs::landlock::SIGNAL;
            if domain.scoped(SCOPE)
                && !domain.allows_scope(&target.credentials().read().landlock, SCOPE)
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
            if matches!(sig, 9 | 18..=22) {
                target.job_signal(
                    sig,
                    !thread,
                    Info {
                        user,
                        sender: source.tgid(),
                        uid: self.uid,
                        code: user.map_or(if thread { -6 } else { 0 }, |bytes| {
                            i32::from_le_bytes(bytes[8..12].try_into().unwrap())
                        }),
                        ..Default::default()
                    },
                    target.ancestor_sender(source.tgid()),
                )?;
                continue;
            }
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
                    let init =
                        policy.namespace.is_nested() && policy.namespace.local(target.tgid()) == 1;
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
                            user,
                            sender: source.tgid(),
                            uid: self.uid,
                            code: user.map_or(if thread { -6 } else { 0 }, |bytes| {
                                i32::from_le_bytes(bytes[8..12].try_into().unwrap())
                            }),
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
    fn host_signal_uses_original_private_inbox_and_live_init_policy() {
        let mut vfs = trames_vfs::Vfs::default();
        vfs.unshare_pid().unwrap();
        vfs.activate_child_pid(100).unwrap();
        for nested in [false, true] {
            let namespace = if nested {
                vfs.pid_namespace().clone()
            } else {
                PidNamespace::default()
            };
            for handler in [0, 1, 0x4000] {
                for masked in [false, true] {
                    let directory = Arc::new(IoDirectory::default());
                    let mut root = publish(&directory, 100, 100, 1000, 1000);
                    let peer = publish(&directory, 200, 100, 1000, 1000);
                    root.publish_policy(&namespace, false);
                    root.actions.set(
                        37,
                        Action {
                            handler,
                            ..Default::default()
                        },
                    );
                    root.set_mask(if masked { 1 << 36 } else { 0 });
                    root.io.host_signal(0);
                    root.io.host_signal(65);
                    root.io.host_signal(37);
                    let queued = masked || handler > 1 || handler == 0 && !nested;
                    assert_eq!(root.io.inbox.bits(), if queued { 1 << 36 } else { 0 });
                    assert_eq!(root.io.process().bits(), 0);
                    assert_eq!(peer.pending_bits(), 0);
                    if queued {
                        assert_eq!(root.take_signal(37, false).sender, 0);
                    }
                    let old = root.io.clone();
                    old.exit();
                    let replacement = publish(&directory, 100, 100, 0, 0);
                    old.host_signal(37);
                    assert_eq!(old.inbox.bits(), 0);
                    assert_eq!(replacement.pending_bits(), 0);
                }
            }
        }
    }
    #[test]
    fn continued_signal_uses_the_session_permission_exception_for_all_send_apis() {
        let directory = Arc::new(IoDirectory::default());
        let source = publish(&directory, 42, 42, 1000, 1000);
        let target = publish(&directory, 77, 77, 2000, 2000);
        source.io.set_session(42);
        target.io.set_session(42);
        let routes = IoRoutes {
            directory,
            uid: 1000,
            euid: 1000,
            ..Default::default()
        };
        for number in [129, 130, 131] {
            let args = |sig| {
                if number == 131 {
                    [77, 77, sig, 0, 0, 0]
                } else {
                    [77, sig, 0, 0, 0, 0]
                }
            };
            target.io.lifecycle().consume_stop(19, || true);
            assert_eq!(
                routes.send(&source.io, number, args(19)),
                Some(Err(Errno(1)))
            );
            assert_eq!(routes.send(&source.io, number, args(18)), Some(Ok(0)));
            assert!(!target.io.lifecycle().stopped());
            target.io.set_session(77);
            assert_eq!(
                routes.send(&source.io, number, args(18)),
                Some(Err(Errno(1)))
            );
            target.io.set_session(42);
        }
    }
    #[test]
    fn queued_signals_retain_payload_and_enforce_kernel_code_permissions() {
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let directory = Arc::new(IoDirectory::default());
        let source = publish(&directory, 42, 42, 1000, 1000);
        let target = publish(&directory, 77, 77, 1000, 1000);
        let routes = IoRoutes {
            directory,
            uid: 1000,
            euid: 1000,
            ..Default::default()
        };
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut user = [0; 48];
        user[8..12].copy_from_slice(&(-1i32).to_le_bytes());
        user[16..20].copy_from_slice(&42u32.to_le_bytes());
        user[20..24].copy_from_slice(&1000u32.to_le_bytes());
        user[24..32].copy_from_slice(&0x12345678abcdef01u64.to_le_bytes());
        for number in [138, 240] {
            memory.write_array(0x1000, user).unwrap();
            let args = if number == 138 {
                [77, 10, 0x1000, 0, 0, 0]
            } else {
                [77, 77, 10, 0x1000, 0, 0]
            };
            assert_eq!(
                routes.send_queued(&source.io, number, args, &memory),
                Some(Ok(0))
            );
            let (sig, info) = target.io.dequeue(1 << 9).unwrap();
            let mut out = [0; 128];
            write_siginfo(&mut out, sig, *info);
            user[..4].copy_from_slice(&10u32.to_le_bytes());
            assert_eq!(&out[..48], &user);
            assert_eq!(&out[48..], &[0; 80]);
            let fd = write_signalfd(sig, *info);
            assert_eq!(&fd[48..56], &user[24..32]);
            assert_eq!(&fd[12..16], &42u32.to_le_bytes());
            user[8..12].copy_from_slice(&0i32.to_le_bytes());
            memory.write_array(0x1000, user).unwrap();
            assert_eq!(
                routes.send_queued(&source.io, number, args, &memory),
                Some(Err(Errno(1)))
            );
            user[8..12].copy_from_slice(&(-1i32).to_le_bytes());
        }
        assert_eq!(
            routes.send_queued(&source.io, 138, [77, 10, 0x9000, 0, 0, 0], &memory),
            Some(Err(Errno(14)))
        );
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
