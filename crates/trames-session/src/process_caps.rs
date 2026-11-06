// SPDX-License-Identifier: GPL-3.0-or-later
//! Serial/task-owner entry for the same credential ABI used by source workers.
use super::*;
impl<C: Cpu> Kernel<C> {
    pub(super) fn credential_call(
        &self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let namespace = p.linux.vfs.pid_namespace().clone();
        let local = namespace.local(pid);
        let directory = p.signals.io_directory.clone();
        let dumpable = p.linux.vfs.dumpable_state();
        let result = trames_linux::credential_call(
            &mut p.linux.vfs.credentials,
            &dumpable,
            local,
            number,
            a,
            &mut p.memory,
            |target| {
                let global = namespace.global(target).ok_or(Errno(3))?;
                let task = directory.proc_task(global).ok_or(Errno(3))?;
                let caps = task.credentials().read().caps.clone();
                Ok(caps)
            },
        )?;
        if result.changed {
            if result.sensitive {
                p.parentage.set_death_signal(0);
            }
            // Limits, signal targets, scheduling, proc and family notifications
            // all observe this same original credential record.
            p.signals.io.credentials().publish(&p.linux.vfs.credentials);
        }
        Ok(result.value)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use trames_vfs::{Credentials, ProcRefresh, ProcTask};

    #[test]
    fn source_credentials_reach_original_observers_before_owner_collection() {
        let parent = super::super::tests::process();
        let mut child = parent.fork();
        child.tgid = 2;
        child.family.set_parent(1);
        child.parentage.set_death_signal(10);
        let original = child.signals.io.clone();
        let wait_event = child.wait_event.clone();
        let dumpable = child.linux.vfs.dumpable_state();
        let mut k = super::super::tests::kernel();
        k.install_proc_source(&parent, None);
        k.processes.insert(1, parent);
        k.processes.insert(2, child);
        k.publish_io_tasks(None);
        let view = k
            .processes
            .get_mut(&2)
            .unwrap()
            .memory
            .parallel_view(&mut Default::default())
            .unwrap();
        let control = Arc::new(crate::workers::Control::new(1000));
        let mut job = k.capture_worker(
            2,
            Box::new(view),
            &control,
            &mut Default::default(),
            &mut Default::default(),
            &mut Default::default(),
        );
        job.work.credential_call(146, [1000, 0, 0, 0, 0, 0]);
        assert_eq!(job.work.cpu.x(0), 0);
        // The cold Process has not been collected or used to publish metadata.
        assert_eq!(k.processes.read(&2).linux.vfs.credentials.uid, 0);
        assert_eq!(original.credentials().read().uid, 1000);
        assert_eq!(wait_event.uid(), 1000);
        assert_eq!(k.processes.read(&2).parentage.death_signal(), 0);
        assert!(!dumpable.get());
        let observed = original.observe(ProcRefresh::Metadata, None).unwrap();
        assert_eq!(observed.credentials.uid, 1000);
        assert!(observed.nondumpable);
        let snapshot = job.work.syscalls.as_ref().unwrap();
        assert_eq!(snapshot.identities[2..4], [1000, 1000]);
        assert_eq!(
            (snapshot.io_routes.uid, snapshot.io_routes.euid),
            (1000, 1000)
        );
        assert_eq!(snapshot.limits.as_ref().unwrap().credentials.uid, 1000);
        let mut observer = k.limit_authority(1, &k.processes.read(&1));
        observer.credentials = Credentials::user(0, 0);
        observer.credentials.caps.effective = 0;
        let mut scratch = Memory::default();
        scratch
            .map(
                0x1000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RW,
            )
            .unwrap();
        assert_eq!(
            observer.call(261, [2, 7, 0, 0x1000, 0, 0], &mut scratch),
            Err(Errno(1))
        );
        scratch
            .write_array(0x1000, 0x20080522u32.to_le_bytes())
            .unwrap();
        scratch.write_array(0x1004, 2u32.to_le_bytes()).unwrap();
        let mut c = Credentials::default();
        let directory = k.processes.read(&1).signals.io_directory.clone();
        trames_linux::credential_call(
            &mut c,
            &Default::default(),
            1,
            90,
            [0x1000, 0x1100, 0, 0, 0, 0],
            &mut scratch,
            |id| {
                Ok(directory
                    .proc_task(id)
                    .unwrap()
                    .credentials()
                    .read()
                    .caps
                    .clone())
            },
        )
        .unwrap();
        assert_eq!(scratch.read_array::<24>(0x1100).unwrap(), [0; 24]);
        let state = job
            .work
            .syscalls
            .as_mut()
            .unwrap()
            .namespaces
            .take()
            .unwrap();
        k.processes
            .get_mut(&2)
            .unwrap()
            .linux
            .vfs
            .adopt_task_namespaces(state);
        assert_eq!(k.processes.read(&2).linux.vfs.credentials.uid, 1000);
        assert_eq!(k.processes.read(&1).linux.vfs.credentials.uid, 0);
    }
}
