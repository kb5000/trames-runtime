// SPDX-License-Identifier: GPL-3.0-or-later
//! PID namespace lifecycle and waitid, using stable scheduler identities.
use super::*;
impl<C: Cpu> Kernel<C> {
    pub(super) fn parent_thread_exited(
        &mut self,
        tid: u32,
        parent: &Process<C>,
        survivor: Option<u32>,
    ) {
        let successor = survivor.or_else(|| {
            self.processes.iter().find_map(|(&id, t)| {
                (id != tid && t.tgid == parent.tgid && !matches!(t.state, State::Zombie(_)))
                    .then_some(id)
            })
        });
        for child in self.processes.values_mut() {
            if child.parent_thread != tid || matches!(child.state, State::Zombie(_)) {
                continue;
            }
            let sig = child.pdeath_signal;
            if sig != 0 && Self::prepare_signal(child, sig, parent.tgid) {
                let _ = child.signals.io.process().enqueue(
                    sig,
                    Info {
                        sender: parent.tgid,
                        uid: parent.linux.vfs.credentials.uid,
                        status: 0,
                        code: 0,
                        timer: None,
                        fault: None,
                        poll: None,
                    },
                );
            }
            child.parent_thread = successor.unwrap_or(0);
        }
    }

    pub(super) fn reap_namespace_children(
        &mut self,
        pid: u32,
        namespace: &trames_vfs::PidNamespace,
        parent: u32,
    ) {
        if namespace.is_nested() && namespace.init() == pid && !namespace.is_dead() {
            // All workers have joined before a syscall. No child can commit a
            // pending syscall after its namespace init dies.
            namespace.terminate();
            let members: Vec<_> = self
                .processes
                .iter()
                .filter(|(&id, p)| id != pid && namespace.contains(p.linux.vfs.pid_namespace()))
                .map(|(&id, _)| id)
                .collect();
            for id in members {
                if let Some(mut child) = self.processes.remove(&id) {
                    if !matches!(child.state, State::Zombie(_)) {
                        self.exit_one(id, &mut child, 9);
                    }
                    // A setns-created child can have a parent outside this
                    // namespace. Preserve that parent's waitable zombie.
                    if !child.auto_reap
                        && child.parent != pid
                        && self
                            .processes
                            .get(&child.parent)
                            .is_some_and(|p| !namespace.contains(p.linux.vfs.pid_namespace()))
                    {
                        self.processes.insert(id, child);
                    }
                }
            }
            return;
        }
        // Reparent within this namespace, including nested namespace init
        // children. PR_SET_CHILD_SUBREAPER is scoped by the same ancestry.
        let mut reaper = namespace.init();
        let mut at = parent;
        for _ in 0..self.task_limit {
            let Some(ancestor) = self.processes.get(&at) else {
                break;
            };
            if ancestor.linux.vfs.pid_namespace().id() != namespace.id() {
                break;
            }
            if ancestor.subreaper && !matches!(ancestor.state, State::Zombie(_)) {
                reaper = ancestor.tgid;
                break;
            }
            if at == ancestor.parent {
                break;
            }
            at = ancestor.parent;
        }
        let mut zombies = Vec::new();
        for (&id, child) in &mut self.processes {
            if child.parent == pid {
                child.parent = reaper;
                child.parent_thread = reaper;
                if id == child.tgid {
                    if let State::Zombie(s) = child.state {
                        zombies.push((id, s));
                    }
                }
            }
        }
        for (id, status) in zombies {
            if self
                .processes
                .values()
                .any(|p| p.tgid == id && !matches!(p.state, State::Zombie(_)))
            {
                continue;
            }
            let auto = self.processes.get(&reaper).is_some_and(|p| {
                p.signals.actions.get(17).handler == 1 || p.signals.actions.get(17).flags & 2 != 0
            });
            self.notify(
                reaper,
                id,
                self.processes
                    .get(&id)
                    .map_or(0, |p| p.linux.vfs.credentials.uid),
                if status & 127 == 0 {
                    status >> 8
                } else {
                    status & 127
                },
                if status & 127 == 0 { 1 } else { 2 },
            );
            if auto {
                self.processes.remove(&id);
            }
        }
    }
    pub(super) fn waitid(&mut self, p: &mut Process<C>, a: [u64; 6]) -> Result<Option<u64>, Errno> {
        self.publish_children(Some(p));
        let request = trames_kernel::children::Wait::prepare(95, a)?;
        let result = p
            .children
            .wait(request, p.linux.vfs.pid_namespace(), p.group, &mut p.memory);
        if p.children.take_reaped() {
            self.reap_waited();
        }
        result
    }
}
