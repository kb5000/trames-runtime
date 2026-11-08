// SPDX-License-Identifier: GPL-3.0-or-later
//! Task construction and publication on the original session resources.
//! Capturing this authority retains no Kernel, process-table view or CPU slot.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct Child<C: Cpu> {
    pub id: u32,
    pub process: Box<Process<C>>,
    pub value: Option<u64>,
}
impl<C: Cpu> Child<C> {
    /// Original membership is published before any executor can run the child.
    /// This transfers the completed body without a Kernel/table callback.
    pub(super) fn publish(self, directory: &tasks::Directory<C>) -> Option<u64> {
        directory.publish(self.id, self.process.into());
        self.value
    }
}
pub(super) struct Birth {
    ids: Arc<trames_kernel::task::Ids>,
    capacity: Arc<trames_kernel::task::Capacity>,
    resources: Arc<AtomicU64>,
    families: Arc<trames_kernel::family::Families>,
    limits: Arc<trames_kernel::limits::Directory>,
    proc_source: Option<Arc<crate::proc_views::Source>>,
    pub(super) started: Instant,
    pub(super) memory_limits: super::super::MemoryLimits,
}
impl Birth {
    pub(super) fn capture<C: Cpu>(kernel: &Kernel<C>) -> Self {
        Self {
            ids: kernel.task_ids.clone(),
            capacity: kernel.task_capacity.clone(),
            resources: kernel.next_resource.clone(),
            families: kernel.families.clone(),
            limits: kernel.limit_directory.clone(),
            proc_source: kernel.proc_source.clone(),
            started: kernel.started,
            memory_limits: kernel.memory_limits,
        }
    }
    pub(super) fn request_read(&self, memory: &Memory) {
        if let Some(source) = &self.proc_source {
            source.request_read(memory.memory_report());
        }
    }
    pub(super) fn resource_id(&self) -> u64 {
        self.resources
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("resource identity overflow")
    }
    pub(super) fn bind_task_cgroup<C: Cpu>(&self, id: u32, p: &Process<C>) {
        if !matches!(p.state, State::Zombie(_)) && p.signals.io.cgroup().is_none() {
            if let Some(task) = p.linux.vfs.cgroup_task(id) {
                p.signals.io.bind_cgroup(task);
            }
        }
    }
    /// Publish only this leader's original relationship. Birth calls the core
    /// publication inside Families::birth instead: reacquiring that graph here
    /// would deadlock its admission transaction.
    pub(super) fn publish_family<C: Cpu>(&self, id: u32, p: &Process<C>) {
        if id != p.tgid {
            return;
        }
        p.wait_event.bind_presence(&p.signals.presence);
        self.families.publish(
            &p.family,
            trames_kernel::family::Binding {
                id,
                group: p.group(),
                credentials: p.signals.io.credentials().clone(),
                namespace: p.linux.vfs.pid_namespace().clone(),
                child: p.wait_event.clone(),
                children: p.children.clone(),
                control: p.signals.io.lifecycle().clone(),
                presence: p.signals.presence.visibility(),
            },
        );
        if matches!(p.state, State::Zombie(_)) {
            if let Some(status) = p.signals.io.lifecycle().exit_status() {
                self.families.complete(&p.family, status);
            }
        }
    }
    pub(super) fn publish_task_core<C: Cpu>(&self, id: u32, p: &Process<C>) {
        p.seccomp.bind(&p.signals.io, id);
        self.publish_proc(id, p);
        p.signals
            .io
            .scheduling
            .publish_credentials(&p.linux.vfs.credentials);
        self.limits.publish(
            id,
            &p.signals.presence,
            &p.limits,
            p.signals.io.credentials(),
        );
        if matches!(p.state, State::Zombie(_)) {
            return;
        }
        p.bind_signals();
        p.signals.io.bind_family(&p.family);
        p.signals
            .io
            .bind_thread_addresses(p.linux.thread_addresses());
        p.signals
            .io_directory
            .parents
            .publish(&p.signals.io, id, &p.parentage);
        if p.signals.io.session() == 0 {
            p.signals.io.set_session(p.session());
        }
        p.signals
            .io
            .lifecycle()
            .bind_controlling(&p.linux.vfs.controlling_state());
        p.signals.io_directory.publish(
            &p.signals.io,
            id,
            p.tgid,
            p.group(),
            p.linux.vfs.credentials.uid,
            p.linux.vfs.credentials.suid,
        );
        p.linux.vfs.bind_terminal_task(|| {
            let task = p
                .signals
                .io_directory
                .terminal_task(&p.signals.io, p.linux.vfs.pid_namespace());
            p.signals.io.bind_terminal_task(&task);
            task
        });
    }
    pub(super) fn publish_proc<C: Cpu>(&self, pid: u32, p: &Process<C>) {
        let Some(source) = &self.proc_source else {
            return;
        };
        let mut info = p.info(
            pid,
            self.started,
            self.memory_limits,
            0,
            trames_vfs::ProcRefresh::Metadata,
            Vec::new(),
        );
        // These are the loaded image's host metadata, never live guest bytes.
        // The actual argv memory reader is a separate resource.
        info.arguments = p.linux.arguments.clone();
        info.environment = p.linux.environment.clone();
        info.auxiliary = p.linux.auxiliary.clone();
        p.signals.io.bind_proc_limits(&p.limits);
        p.signals.io.proc_view.bind_counters(&source.counters);
        p.signals.io.proc_view.publish_time(p.cpu_time);
        let memory = p.memory.memory_report();
        source.bind_reads(&memory);
        p.signals.io.proc_view.publish_with_memory(
            &info,
            p.linux.vfs.proc_resources(),
            Some(memory),
        );
        source
            .created
            .fetch_max(self.ids.created(), Ordering::Relaxed);
    }
    /// Complete the original birth transaction before making a child runnable.
    /// Host launch and guest clone use identical family/PID/cgroup admission.
    /// Resource notifications run after the family relationship guard drops.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_child<C: Cpu>(
        &self,
        parent: u32,
        parent_control: &trames_kernel::task_control::Group,
        id: u32,
        child: &mut Process<C>,
        threaded: bool,
        inherit_job: bool,
        host_terminal: Option<&Arc<trames_vfs::Pty>>,
    ) -> Result<(), Errno> {
        let family = child.family.clone();
        let mut cgroup_birth = None;
        let mut hung_up = false;
        let result = self.families.birth(&family, || {
            if !parent_control.permits_birth() {
                return Err(Errno(4));
            }
            if inherit_job && !threaded {
                let (group, session) = parent_control.job_ids();
                child.set_group(group);
                child.set_session(session);
                child
                    .linux
                    .vfs
                    .inherit_controlling(parent_control.controlling().as_deref());
            }
            let birth = child.linux.vfs.activate_child_birth(parent, id, child.tgid);
            let admitted = birth.result();
            cgroup_birth = Some(birth);
            admitted?;
            child.bind_signals();
            child.linux.vfs.set_process_context(id);
            self.publish_task_core(id, child);
            if let Some(pair) = host_terminal {
                // Original membership is visible before the master can signal
                // this session. Master close and attachment share the tty lock;
                // notifications happen after the family/tty transaction ends.
                let mut tty = pair.terminal.borrow_mut();
                if pair.master_alive.load(Ordering::Relaxed) {
                    tty.session = id;
                    tty.foreground = id;
                    pair.retain_job_ids(child.linux.vfs.pid_namespace(), id, id);
                } else {
                    child.linux.vfs.set_controlling_terminal(None)?;
                    hung_up = true;
                }
            }
            let binding = (!threaded).then(|| trames_kernel::family::Binding {
                id,
                group: child.group(),
                credentials: child.signals.io.credentials().clone(),
                namespace: child.linux.vfs.pid_namespace().clone(),
                child: child.wait_event.clone(),
                children: child.children.clone(),
                control: child.signals.io.lifecycle().clone(),
                presence: child.signals.presence.visibility(),
            });
            Ok((binding, ()))
        });
        if let Some(birth) = cgroup_birth {
            birth.notify();
        }
        result?;
        self.bind_task_cgroup(id, child);
        if hung_up {
            child.signals.io.lifecycle().request_exit(1);
        }
        Ok(())
    }
    pub(super) fn clone_task<C: Cpu>(
        &self,
        pid: u32,
        p: &mut Process<C>,
        a: [u64; 6],
    ) -> Result<Child<C>, Errno> {
        const ALLOWED: u64 = 0xff
            | 0xf00
            | 0x4000
            | 0x8000
            | 0x10000
            | 0xfc0000
            | 0x1000000
            | trames_vfs::CLONE_NEWUTS
            | trames_vfs::CLONE_NEWNS
            | trames_vfs::CLONE_NEWPID
            | trames_vfs::CLONE_NEWNET
            | trames_vfs::CLONE_NEWIPC
            | trames_vfs::CLONE_NEWCGROUP;
        let threaded = a[0] & 0x10000 != 0;
        let shared_vm = a[0] & 0x100 != 0;
        if a[0] & !ALLOWED != 0
            || (a[0] & trames_vfs::CLONE_NEWPID != 0 && a[0] & (0x10000 | 0x8000) != 0)
            || (threaded
                && p.linux.vfs.pid_namespace().id() != p.linux.vfs.pid_children_namespace().id())
            || (a[0] & 0x8000 != 0 && p.linux.vfs.visible_pid(p.tgid) == 1)
            || (a[0] & trames_vfs::CLONE_NEWNS != 0 && a[0] & 0x200 != 0)
            || (a[0] & trames_vfs::CLONE_NEWIPC != 0 && a[0] & 0x40000 != 0)
            || (!threaded && a[0] & 255 != 17)
            || (threaded && (a[0] & 0x900 != 0x900 || a[0] & 255 != 0))
            || (a[0] & 0x800 != 0 && !shared_vm)
        {
            return Err(Errno(22));
        }
        let slot = self.capacity.reserve().ok_or(Errno(11))?;
        let id = self.ids.allocate().ok_or(Errno(11))?;
        let memory = if shared_vm {
            p.memory.share()
        } else {
            p.memory.try_fork().map_err(|_| Errno(11))?
        };
        let mut child = p.fork_state(
            memory,
            a[0] & 0x400 != 0,
            a[0] & 0x200 != 0,
            a[0] & 0x800 != 0,
            Arc::new(slot.into_presence()),
        );
        if a[0] & trames_vfs::CLONE_NEWPID != 0 {
            child.linux.vfs.unshare_pid()?;
        }
        if a[0] & trames_vfs::CLONE_NEWUTS != 0 {
            child.linux.vfs.unshare_uts()?;
        }
        if a[0] & trames_vfs::CLONE_NEWNS != 0 {
            child.linux.vfs.unshare_mounts()?;
        }
        if a[0] & trames_vfs::CLONE_NEWNET != 0 {
            child.linux.vfs.unshare_net()?;
        }
        if a[0] & trames_vfs::CLONE_NEWIPC != 0 {
            child.linux.vfs.unshare_ipc()?;
        }
        if a[0] & trames_vfs::CLONE_NEWCGROUP != 0 {
            child.linux.vfs.unshare_cgroup()?;
        }
        // PID namespace init inherits its parent's PGID/SID/tty, as
        // Linux copy_process does. Ancestor-only IDs appear as zero
        // inside the new namespace; init can then establish setsid().
        let resource = self.resource_id();
        if shared_vm {
            child.membarrier_registered = p.membarrier_registered.clone();
            if a[0] & 0x4000 == 0 {
                child.signals.alt_stack = AltStack::default();
            }
        } else {
            child.vm_id = resource;
            child.linux.vfs.unshare_dumpable();
        }
        child.tgid = if threaded { p.tgid } else { id };
        if threaded {
            child.children = p.children.clone();
            child.wait_event = p.wait_event.clone();
            child.oom = Arc::new(p.oom.thread());
            child.share_process_context(p);
            child.family = p.family.clone();
            child.limits = p.limits.clone();
            child.limits.bind(&mut child.linux.vfs);
        }
        child
            .linux
            .fork_tid(if a[0] & 0x200000 != 0 { a[4] } else { 0 });
        if !threaded {
            child.family.set_parent(if a[0] & 0x8000 != 0 {
                p.family.parent()
            } else {
                p.tgid
            });
        }
        child
            .parentage
            .set_parent_thread(if threaded || a[0] & 0x8000 != 0 {
                p.parentage.parent_thread()
            } else {
                pid
            });
        child.cpu.set_x(0, 0);
        if a[1] != 0 {
            child.cpu.set_sp(a[1]);
        }
        if a[0] & 0x80000 != 0 {
            child.cpu.set_tls(a[3]);
        }
        child.wait_event.bind_presence(&child.signals.presence);
        // Source callers already admitted this resource without blocking their
        // executor. Joined/bootstrap callers use the same short transaction.
        let policy_group = p.seccomp.birth_group();
        let _policy = policy_group.write_owned().into_admission();
        // Publish credentials only: a new PID namespace is activated inside
        // admit_child; binding signal translations before that would retain
        // the parent's namespace in the child's immutable inbox authority.
        child
            .signals
            .io
            .scheduling
            .publish_credentials(&child.linux.vfs.credentials);
        child.seccomp.inherit(
            &p.seccomp,
            threaded,
            &child.signals.io,
            id,
            &child.linux.vfs.credentials.caps.no_new_privs,
            &p.linux.vfs.credentials.caps.no_new_privs,
        );
        self.admit_child(
            pid,
            p.signals.io.lifecycle(),
            id,
            &mut child,
            threaded,
            true,
            None,
        )?;
        // Linux stores these user TIDs after task birth and ignores
        // copyout faults. CHILD_CLEARTID only records its address.
        let parent_tid = p.linux.vfs.visible_pid(id);
        let child_tid = child.linux.vfs.visible_pid(id);
        if a[0] & 0x100000 != 0 {
            let _ = p.memory.write(a[2], &parent_tid.to_le_bytes());
        }
        if a[0] & 0x1000000 != 0 {
            let _ = child.memory.write(a[4], &child_tid.to_le_bytes());
        }
        let value = if a[0] & 0x4000 != 0 {
            let release = Arc::new(trames_kernel::vfork::Release::default());
            child.vfork = Some(release.clone());
            p.state = State::Completion(release);
            p.cpu.set_x(0, parent_tid as u64);
            None
        } else {
            Some(parent_tid as u64)
        };
        Ok(Child {
            id,
            process: child,
            value,
        })
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use trames_vfs::ProcSource;

    #[test]
    fn parallel_builders_publish_original_children_without_a_kernel() {
        let mut kernel = super::super::tests::kernel();
        let mut root = super::super::tests::admitted_process(&kernel);
        kernel.install_proc_source(&root, None);
        kernel.publish_task(1, &root);
        let first = Birth::capture(&kernel)
            .clone_task(1, &mut root, [17, 0, 0, 0, 0, 0])
            .unwrap();
        let source = kernel.proc_source.as_ref().unwrap().clone();
        let gate = Arc::new(std::sync::Barrier::new(2));
        let mut executors = Vec::new();
        for (pid, mut parent) in [(1, root), (first.id, first.process)] {
            let birth = Birth::capture(&kernel);
            let gate = gate.clone();
            executors.push(std::thread::spawn(move || {
                gate.wait();
                let mut children = Vec::new();
                for _ in 0..16 {
                    let mut child = birth
                        .clone_task(
                            pid,
                            &mut parent,
                            [17 | 0x100000 | 0x1000000, 0, 0x1000, 0, 0x1004, 0],
                        )
                        .unwrap();
                    assert_eq!(child.value, Some(child.id as u64));
                    assert_eq!(read_u32(&parent.memory, 0x1000).unwrap(), child.id);
                    assert_eq!(read_u32(&child.process.memory, 0x1004).unwrap(), child.id);
                    assert_eq!(child.process.family.parent(), pid);
                    assert!(Arc::ptr_eq(
                        &child.process.family.registry().unwrap(),
                        &birth.families
                    ));
                    assert_eq!(child.process.linux.vfs.process_context(), child.id);
                    let info = birth
                        .proc_source
                        .as_ref()
                        .unwrap()
                        .task(child.id)
                        .unwrap()
                        .observe(trames_vfs::ProcRefresh::Metadata, None)
                        .unwrap();
                    assert_eq!((info.pid, info.parent), (child.id, pid));
                    child
                        .process
                        .memory
                        .write(0x1800, &[child.id as u8])
                        .unwrap();
                    assert_eq!(parent.memory.read_array::<1>(0x1800).unwrap(), [0]);
                    children.push(child);
                }
                (parent, children)
            }));
        }
        // These production construction/publication methods cannot rendezvous
        // with a Kernel: its executor pool and task table no longer exist.
        drop(kernel);
        let completed: Vec<_> = executors.into_iter().map(|t| t.join().unwrap()).collect();
        let ids: std::collections::BTreeSet<_> = completed
            .iter()
            .flat_map(|(_, children)| children.iter().map(|child| child.id))
            .collect();
        assert_eq!(ids, (3..35).collect());
        for id in ids {
            assert!(source.task(id).unwrap().present());
        }
    }

    #[test]
    fn remote_vfork_uses_original_release_and_rolls_back_after_group_exit() {
        let mut kernel = super::super::tests::kernel();
        kernel.task_capacity = Arc::new(trames_kernel::task::Capacity::new(2));
        let mut parent = super::super::tests::admitted_process(&kernel);
        kernel.publish_task(1, &parent);
        let birth = Birth::capture(&kernel);
        drop(kernel);
        std::thread::spawn(move || {
            let mut child = birth
                .clone_task(
                    1,
                    &mut parent,
                    [17 | 0x100 | 0x4000 | 0x80000, 0x8000, 0, 0x7000, 0, 0],
                )
                .unwrap();
            assert_eq!(child.value, None);
            assert_eq!(parent.cpu.x(0), child.id as u64);
            assert_eq!(child.process.cpu.sp(), 0x8000);
            assert_eq!(child.process.cpu.architectural_state().tpidr_el0, 0x7000);
            child.process.memory.write(0x1000, b"vfork").unwrap();
            assert_eq!(parent.memory.read_array::<5>(0x1000).unwrap(), *b"vfork");
            let State::Completion(release) = &parent.state else {
                panic!("vfork parent wait");
            };
            assert!(!release.finished());
            Kernel::release_vfork(&mut child.process);
            assert!(release.finished());
            drop(child);
            parent.signals.io.lifecycle().request_exit(0);
            assert!(matches!(
                birth.clone_task(1, &mut parent, [17, 0, 0, 0, 0, 0]),
                Err(Errno(4))
            ));
            // Failed construction did not publish a child or retain its slot.
            assert!(birth.capacity.reserve().is_some());
        })
        .join()
        .unwrap();
    }
}

pub(super) struct HostChild<C: Cpu> {
    pub id: u32,
    pub process: Box<Process<C>>,
    parent: Arc<trames_kernel::task_control::Group>,
    terminal: Option<Arc<trames_vfs::Pty>>,
    pub host: Arc<trames_linux::HostProcess>,
}
impl Birth {
    pub(super) fn prepare_host<C: Cpu>(
        &self,
        root: &Process<C>,
        request: trames_linux::HostSpawn,
    ) -> Result<(HostChild<C>, exec::Request), Errno> {
        if request.process.cancelled() {
            return Err(Errno(125));
        }
        if request.argv.is_empty() {
            return Err(Errno(11));
        }
        let slot = self.capacity.reserve().ok_or(Errno(11))?;
        let id = self.ids.allocate().ok_or(Errno(11))?;
        let parent = root.signals.io.lifecycle().clone();
        let mut child = root.fork_state(
            Memory::default(),
            false,
            false,
            false,
            Arc::new(slot.into_presence()),
        );
        child
            .memory
            .inherit_total_limit(&root.memory)
            .map_err(|_| Errno(12))?;
        child.linux.vfs = request.vfs;
        child.limits.bind(&mut child.linux.vfs);
        child.linux.vfs.prepare_child_context(id);
        child.linux.fork_tid(0);
        child.family.set_parent(1);
        child.parentage.set_parent_thread(1);
        child.tgid = id;
        child.set_session(id);
        child.set_group(id);
        child.signals = Signals {
            presence: child.signals.presence.clone(),
            io_directory: root.signals.io_directory.clone(),
            ..Signals::default()
        };
        child.linux.vfs.set_controlling_terminal(None)?;
        let terminal = child
            .linux
            .vfs
            .pty(0)?
            .filter(|end| !end.master)
            .map(|end| end.pair.clone());
        if let Some(pair) = &terminal {
            child.linux.vfs.set_controlling_terminal(Some(pair.id))?;
        }
        let image = exec::Request::host(
            &child,
            request.argv,
            request.environment,
            self.memory_limits.per_process,
            self.started,
        );
        Ok((
            HostChild {
                id,
                process: child,
                parent,
                terminal,
                host: request.process,
            },
            image,
        ))
    }
    pub(super) fn finish_host<C: Cpu>(
        &self,
        mut child: HostChild<C>,
        mut image: exec::Image<C>,
    ) -> Result<HostChild<C>, Errno> {
        if child.host.cancelled() {
            return Err(Errno(125));
        }
        image
            .memory
            .inherit_total_limit(&child.process.memory)
            .map_err(|_| Errno(12))?;
        drop(Kernel::install_exec(
            &mut child.process,
            image,
            self.started,
        ));
        let p = &mut *child.process;
        p.family.bind_host_status(child.host.status_cell());
        p.vm_id = self.resource_id();
        p.wait_event.bind_presence(&p.signals.presence);
        self.admit_child(
            1,
            &child.parent,
            child.id,
            p,
            false,
            false,
            child.terminal.as_ref(),
        )?;
        let directory = p.signals.io_directory.clone();
        child.host.bind_control(Arc::new(move |group, signal| {
            directory.host_signal_group(group, signal)
        }));
        if let Some(pair) = &child.terminal {
            if let Some(task) = p.linux.vfs.terminal_task() {
                pair.bind_signal_route(task);
            }
        }
        Ok(child)
    }
}
