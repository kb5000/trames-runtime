// SPDX-License-Identifier: GPL-3.0-or-later
//! PID namespace lifecycle and waitid, using stable scheduler identities.
use super::*;
impl<C: Cpu> Kernel<C> {
    pub(super) fn parent_thread_exited(
        parent: &Process<C>,
        survivor: Option<(u32, Arc<trames_kernel::signal::IoTask>)>,
    ) {
        parent.signals.io_directory.parents.retire_with(
            &parent.signals.io,
            || survivor.or_else(|| parent.signals.io.lifecycle().survivor()),
            Info {
                sender: parent.tgid,
                uid: parent.linux.vfs.credentials.uid,
                ..Default::default()
            },
        );
    }

    pub(super) fn reap_namespace_children(
        &mut self,
        pid: u32,
        namespace: &trames_vfs::PidNamespace,
        family: &Arc<trames_kernel::family::Family>,
        parents: &trames_kernel::task_parent::Parents,
    ) {
        let plans = self.families.retire(family, parents);
        for victim in plans.victims {
            let Some(mut child) = self.processes.remove(&victim.id) else {
                continue;
            };
            if !Arc::ptr_eq(&child.family, &victim.family) {
                self.processes.insert(victim.id, child);
                continue;
            }
            // Keep the original waitable leader through complete group cleanup,
            // including a zombie leader whose original peers are still alive.
            if !matches!(child.state, State::Zombie(_))
                || child.signals.io.lifecycle().survivor().is_some()
            {
                self.exit(victim.id, &mut child, 9);
            }
            if !child.auto_reap
                && child.family.parent() != pid
                && self
                    .processes
                    .get(&child.family.parent())
                    .is_some_and(|p| !namespace.contains(p.linux.vfs.pid_namespace()))
            {
                self.processes.insert(victim.id, child);
            }
        }
        self.reap_waited();
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

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    #[test]
    fn namespace_shutdown_retires_complete_original_groups_even_after_leader_exit() {
        for leader_exited in [false, true] {
            let mut k = super::super::tests::kernel();
            let mut root = super::super::tests::process();
            let mut io = trames_linux::CapturedOutput::default();
            k.syscall(
                1,
                &mut root,
                220,
                [trames_vfs::CLONE_NEWPID | 17, 0, 0, 0, 0, 0],
                &mut io,
            )
            .unwrap();
            k.processes.insert(1, root);
            let mut init = k.processes.remove(&2).unwrap();
            k.syscall(2, &mut init, 220, [17, 0, 0, 0, 0, 0], &mut io)
                .unwrap();
            k.processes.insert(2, init);
            let mut child = k.processes.remove(&3).unwrap();
            k.syscall(3, &mut child, 220, [0x10f00, 0, 0, 0, 0, 0], &mut io)
                .unwrap();
            k.processes.insert(3, child);
            k.publish_io_tasks(None);
            let original = k.processes[&3].family.clone();
            let peer = k.processes[&4].signals.io.clone();
            if leader_exited {
                let mut child = k.processes.remove(&3).unwrap();
                k.exit_one(3, &mut child, 0);
                assert!(!child.auto_reap);
                k.processes.insert(3, child);
            }
            let mut init = k.processes.remove(&2).unwrap();
            k.exit_one(2, &mut init, 0);
            assert!(
                !original.live(),
                "namespace shutdown must finish the original group"
            );
            assert!(!peer.live());
            assert!(!k.processes.contains_key(&3) && !k.processes.contains_key(&4));
        }
    }
}
