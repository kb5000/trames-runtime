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
                let _ = child.signals.shared_pending.borrow_mut().enqueue(
                    sig,
                    Info {
                        sender: parent.tgid,
                        uid: parent.linux.vfs.credentials.uid,
                        status: 0,
                        code: 0,
                        timer: None,
                        fault: None,
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
        for _ in 0..MAX_PROCESSES {
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
        let options = a[3];
        if options & !(1 | 2 | 4 | 8 | 0x01000000 | 0x40000000) != 0 || options & 14 == 0 {
            return Err(Errno(22));
        }
        if a[0] > 2 || a[0] != 0 && a[1] > i32::MAX as u64 || a[0] == 1 && a[1] == 0 {
            return Err(Errno(22));
        }
        if a[2] != 0 {
            Linux::check(&p.memory, a[2], 128, Access::Write)?;
        }
        if a[4] != 0 {
            Linux::check(&p.memory, a[4], 144, Access::Write)?;
        }
        let mut found = false;
        let mut ready = None;
        for (&id, child) in &self.processes {
            if child.parent != p.tgid || id != child.tgid {
                continue;
            }
            let local = p.linux.vfs.visible_pid(id);
            if a[0] == 1 && local != a[1] as u32
                || a[0] == 2
                    && (if a[1] == 0 {
                        child.group != p.group
                    } else {
                        p.linux.vfs.visible_pid(child.group) != a[1] as u32
                    })
            {
                continue;
            }
            found = true;
            let result = match child.state {
                State::Zombie(s)
                    if options & 4 != 0
                        && !self
                            .processes
                            .values()
                            .any(|t| t.tgid == id && !matches!(t.state, State::Zombie(_))) =>
                {
                    Some((s, if s & 127 == 0 { 1 } else { 2 }))
                }
                State::Stopped if options & 2 != 0 => child.wait_event.map(|s| (s, 5)),
                _ if options & 8 != 0 && child.wait_event == Some(0xffff) => Some((0xffff, 6)),
                _ => None,
            };
            if let Some((status, code)) = result {
                ready = Some((id, local, status, code, child.linux.vfs.credentials.uid));
                break;
            }
        }
        if !found {
            return Err(Errno(10));
        }
        if let Some((id, local, status, code, uid)) = ready {
            if a[2] != 0 {
                let mut out = [0; 128];
                events::write_siginfo(
                    &mut out,
                    17,
                    Info {
                        sender: local,
                        uid,
                        status: match code {
                            1 | 5 => status >> 8,
                            6 => 18,
                            _ => status & 127,
                        },
                        code,
                        timer: None,
                        fault: None,
                    },
                );
                out[20..24].copy_from_slice(&uid.to_le_bytes());
                p.memory.write(a[2], &out).map_err(|_| Errno(14))?;
            }
            if a[4] != 0 {
                p.memory.write(a[4], &[0; 144]).map_err(|_| Errno(14))?;
            }
            if options & 0x01000000 == 0 {
                if code == 1 || code == 2 {
                    self.processes.remove(&id);
                } else {
                    self.processes.get_mut(&id).expect("wait child").wait_event = None;
                }
            }
            return Ok(Some(0));
        }
        if options & 1 != 0 {
            if a[2] != 0 {
                p.memory.write(a[2], &[0; 128]).map_err(|_| Errno(14))?;
            }
            Ok(Some(0))
        } else {
            Ok(None)
        }
    }
}
