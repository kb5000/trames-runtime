// SPDX-License-Identifier: GPL-3.0-or-later
//! Live job-control authority over the original task, terminal and PID objects.
use super::*;
use trames_vfs::{Pty, TerminalAccess, TerminalSignals, TerminalTask};

struct TerminalRoute {
    original: Weak<TerminalRoute>,
    source: Weak<IoTask>,
    directory: Arc<IoDirectory>,
    namespace: PidNamespace,
}
impl IoDirectory {
    pub fn terminal_task(
        self: &Arc<Self>,
        source: &Arc<IoTask>,
        namespace: &PidNamespace,
    ) -> Arc<dyn TerminalTask> {
        Arc::new_cyclic(|original| TerminalRoute {
            original: original.clone(),
            source: Arc::downgrade(source),
            directory: self.clone(),
            namespace: namespace.clone(),
        })
    }
    fn terminal_members(&self, session: u32) -> Vec<Arc<IoTask>> {
        let index = self.groups.lock().unwrap();
        let mut seen = BTreeSet::new();
        index
            .iter()
            .filter(|(key, _)| key.0 == 1)
            .flat_map(|(_, group)| {
                group
                    .members
                    .read()
                    .unwrap()
                    .iter()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>()
            })
            .filter(|task| task.live() && task.session() == session && seen.insert(task.tgid()))
            .collect()
    }
    fn clear_terminal(&self, terminal: u32, session: u32) {
        // Take original references before locking any process's controlling
        // terminal. Never index -> controlling; source setsid uses the reverse.
        for task in self.terminal_members(session) {
            if let Some(original) = task.lifecycle().controlling() {
                let mut reference = original.lock();
                if task.session() == session && reference.id() == Some(terminal) {
                    reference.replace(None);
                }
            }
        }
    }
    fn terminal_signal(&self, session: u32, group: u32, signal: u32) {
        if session == 0 {
            return;
        }
        self.trusted_group(
            group,
            Some(session),
            signal,
            Info {
                code: 128,
                ..Default::default()
            },
        );
    }
    /// Host-authorized process-group control, over original live membership.
    pub fn host_signal_group(&self, group: u32, signal: u32) {
        if !(1..=64).contains(&signal) {
            return;
        }
        self.trusted_group(group, None, signal, Info::default());
    }
    fn trusted_group(&self, group: u32, session: Option<u32>, signal: u32, info: Info) {
        if group == 0 {
            return;
        }
        let members = self.tasks(2, group);
        let mut sent = BTreeSet::new();
        for task in members
            .iter()
            .filter(|t| t.live() && session.is_none_or(|session| t.session() == session))
        {
            if sent.insert(task.tgid()) {
                if matches!(signal, 9 | 18..=22) {
                    let _ = task.job_signal(signal, true, info, true);
                } else {
                    let queued = {
                        let policy = task.policy.read().unwrap();
                        let enqueue = || task.process().enqueue_quiet(signal, info);
                        policy.as_ref().map_or_else(enqueue, |p| {
                            p.actions.with_action(signal, |action| {
                                let masked = members.iter().any(|t| {
                                    t.live()
                                        && t.tgid() == task.tgid()
                                        && t.mask() & (1 << (signal - 1)) != 0
                                });
                                let init =
                                    p.namespace.is_nested() && p.namespace.local(task.tgid()) == 1;
                                if !masked && (action.handler == 1 || init && action.handler <= 1) {
                                    Ok(false)
                                } else {
                                    enqueue()
                                }
                            })
                        })
                    };
                    if matches!(queued, Ok(true)) {
                        task.process().changed();
                    }
                }
                // The shared inbox readiness normally wakes the process. A
                // handler may be runnable on another original group member.
                if let Some(ready) = members
                    .iter()
                    .find(|t| t.tgid() == task.tgid() && t.ready())
                {
                    ready.wake();
                }
            }
        }
    }
}
impl TerminalSignals for TerminalRoute {
    fn signal(&self, session: u32, group: u32, signal: u32) {
        self.directory.terminal_signal(session, group, signal);
    }
    fn clear_session(&self, terminal: u32, session: u32) {
        let members = self.directory.terminal_members(session);
        let family = members
            .iter()
            .find_map(|t| t.family().and_then(|f| f.registry()));
        if let Some(family) = family {
            family.terminal_change(|| self.directory.clear_terminal(terminal, session));
        }
    }
    fn hangup(&self, terminal: u32, session: u32, group: u32) {
        let members = self.directory.terminal_members(session);
        self.clear_session(terminal, session);
        // Hangup targets the original session leader and foreground group.
        // All callbacks run after the terminal/reference/index locks drop.
        for task in members
            .iter()
            .filter(|t| t.tgid() == session && t.group() != group)
        {
            task.parent_death(
                1,
                Info {
                    code: 128,
                    ..Default::default()
                },
            );
            let _ = task.job_signal(
                18,
                true,
                Info {
                    code: 128,
                    ..Default::default()
                },
                true,
            );
        }
        self.signal(session, group, 1);
        self.signal(session, group, 18);
    }
}
impl TerminalTask for TerminalRoute {
    fn namespace(&self) -> &PidNamespace {
        &self.namespace
    }
    fn access(&self) -> TerminalAccess {
        let task = self.source.upgrade();
        let (group, session) = task.as_ref().map_or((0, 0), |t| t.lifecycle().job_ids());
        TerminalAccess {
            session,
            group,
            controlling: task
                .as_ref()
                .and_then(|t| t.lifecycle().controlling())
                .and_then(|c| c.id()),
            ignore_ttou: false,
        }
    }
    fn ignored(&self, signal: u32) -> bool {
        self.source.upgrade().is_none_or(|task| {
            task.mask() & (1 << (signal - 1)) != 0
                || task
                    .policy
                    .read()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|p| p.actions.with_action(signal, |a| a.handler == 1))
        })
    }
    fn orphaned(&self) -> bool {
        self.source
            .upgrade()
            .is_none_or(|task| self.directory.orphaned(&task))
    }
    fn subscribe_job(&self, signal: &Arc<IoSignal>) -> Option<trames_vfs::IoSubscription> {
        Some(self.source.upgrade()?.lifecycle().subscribe_job(signal))
    }
    fn visible(&self, id: u32) -> u32 {
        self.namespace.local(id)
    }
    fn foreground(&self, session: u32, local: u32) -> Result<u32, Errno> {
        if local > i32::MAX as u32 {
            return Err(Errno(22));
        }
        let global = self.namespace.global(local).ok_or(Errno(3))?;
        let tasks = self.directory.tasks(2, global);
        if !tasks.iter().any(|t| t.session() == session) {
            return Err(Errno(1));
        }
        Ok(global)
    }
    fn acquire(
        &self,
        terminal: &Arc<Pty>,
        steal: bool,
        readable: bool,
        automatic: bool,
    ) -> Result<(), Errno> {
        let task = self.source.upgrade().ok_or(Errno(6))?;
        if !terminal.has_signal_route() {
            terminal.bind_signal_route(self.original.upgrade().expect("live terminal authority"));
        }
        if automatic
            && (!readable
                || task.tgid() != task.session()
                || task
                    .lifecycle()
                    .controlling()
                    .is_some_and(|c| c.id().is_some()))
        {
            return Ok(());
        }
        let family = task.family().and_then(|f| f.registry()).ok_or(Errno(6))?;
        family.terminal_change(|| {
            let mut tty = terminal.terminal.borrow_mut();
            if !terminal.master_alive.load(Ordering::Relaxed) {
                return Err(Errno(5));
            }
            let original = task.lifecycle().controlling().ok_or(Errno(6))?;
            let mut controlling = original.lock();
            let (group, session) = task.lifecycle().job_ids();
            if automatic
                && (task.tgid() != session
                    || controlling.id().is_some()
                    || tty.session != 0
                    || !readable)
            {
                return Ok(());
            }
            if !automatic && task.tgid() == session && tty.session == session {
                return Ok(());
            }
            if task.tgid() != session || controlling.id().is_some() {
                return Err(Errno(1));
            }
            let admin = task
                .credentials()
                .read()
                .has_cap(trames_vfs::capabilities::SYS_ADMIN);
            if tty.session != 0 && !(steal && admin) || !readable && !admin {
                return Err(Errno(1));
            }
            let previous = tty.session;
            tty.session = session;
            tty.foreground = group;
            terminal.retain_job_ids(&self.namespace, session, group);
            controlling.replace(Some((terminal.id, Some(terminal.clone()))));
            drop(controlling);
            if previous != 0 {
                self.directory.clear_terminal(terminal.id, previous);
            }
            Ok(())
        })
    }
    fn detach(&self, terminal: &Arc<Pty>, exiting: bool) -> Result<(), Errno> {
        let task = self.source.upgrade().ok_or(Errno(6))?;
        let family = task.family().and_then(|f| f.registry()).ok_or(Errno(6))?;
        let notice = family.terminal_change(|| {
            let mut tty = terminal.terminal.borrow_mut();
            let original = task.lifecycle().controlling().ok_or(Errno(25))?;
            let mut controlling = original.lock();
            if controlling.id() != Some(terminal.id) {
                return Err(Errno(25));
            }
            controlling.replace(None);
            drop(controlling);
            let session = task.session();
            if task.tgid() != session {
                return Ok(None);
            }
            let group = tty.foreground;
            tty.session = 0;
            tty.foreground = 0;
            self.directory.clear_terminal(terminal.id, session);
            terminal.retain_job_ids(&self.namespace, 0, 0);
            Ok(Some((session, group)))
        })?;
        if let Some((session, group)) = notice {
            self.signal(session, group, 1);
            if !exiting {
                self.signal(session, group, 18);
            }
        }
        Ok(())
    }
}
