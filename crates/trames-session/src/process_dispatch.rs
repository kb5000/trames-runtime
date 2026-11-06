// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture original task/resource custody for initial and newly created jobs.
use super::*;
impl<C: Cpu> Kernel<C> {
    pub(super) fn capture_worker(
        &mut self,
        id: u32,
        view: Box<trames_memory::parallel::View>,
        control: &Arc<crate::workers::Control>,
        file_epoch: &mut trames_vfs::FileEpoch,
        uring_epoch: &mut trames_linux::UringEpoch,
        network_epoch: &mut trames_vfs::NetworkEpoch,
    ) -> Box<crate::run_queue::Job<C>> {
        Dispatch::capture(self).job(
            (
                id,
                self.processes
                    .directory()
                    .handle(&id)
                    .expect("dispatch task"),
            ),
            view,
            control,
            file_epoch,
            uring_epoch,
            network_epoch,
        )
    }
}

// Captures original shared authorities, never a Kernel/task-table projection.
pub(super) struct Dispatch {
    limits: Arc<trames_kernel::limits::Directory>,
    fixed: trames_kernel::limits::Fixed,
    timers: Arc<trames_kernel::timers::Timers>,
    futexes: crate::futex::Futexes,
    files: Arc<dyn trames_linux::FileExecutor>,
    layouts: Arc<trames_linux::FileLayouts>,
    gpu_budget: trames_vulkan::Budget,
    gpu_display: trames_vulkan::Display,
    started: Instant,
    cpus: usize,
    profile: bool,
    instructions: u64,
}
impl Dispatch {
    pub(super) fn capture<C: Cpu>(k: &Kernel<C>) -> Self {
        Self {
            limits: k.limit_directory.clone(),
            fixed: k.fixed_limits(),
            timers: k.timers.clone(),
            futexes: k.futexes.clone(),
            files: k.workers.file_executor(),
            layouts: k.file_layout_work(),
            gpu_budget: k.gpu_budget.clone(),
            gpu_display: k.gpu_display.clone(),
            started: k.started,
            cpus: k.cpu_count,
            profile: k.profile_syscalls,
            instructions: k.instructions,
        }
    }
    pub(super) fn job<C: Cpu>(
        &self,
        task: (u32, tasks::Handle<C>),
        view: impl Into<Option<Box<trames_memory::parallel::View>>>,
        control: &Arc<crate::workers::Control>,
        file_epoch: &mut trames_vfs::FileEpoch,
        uring_epoch: &mut trames_linux::UringEpoch,
        network_epoch: &mut trames_vfs::NetworkEpoch,
    ) -> Box<crate::run_queue::Job<C>> {
        let (id, task) = task;
        let mut custody = task.write();
        let p = &mut *custody;
        p.linux.vfs.sync_task_namespaces();
        let gpu = (accelerated(p, trames_vulkan::AUXV_KEY, trames_vulkan::PROFILE)
            || accelerated(p, trames_video::AUXV_KEY, trames_video::PROFILE))
        .then(|| crate::gpu::Authority {
            context: p.gpu_context(&self.gpu_budget, &self.gpu_display),
            video: p.video_context(),
            images: Some(p.linux.vfs.image_fds()),
            auth: p.linux.vfs.wayland_auth(),
            events: Some(p.linux.vfs.native_events()),
        });
        let audio = accelerated(p, trames_audio::AUXV_KEY, trames_audio::PROFILE).then(|| {
            crate::devices::Audio {
                context: p.audio_context(),
                events: p.linux.vfs.native_events(),
            }
        });
        let limits = trames_kernel::limits::Authority {
            directory: self.limits.clone(),
            limits: p.limits.clone(),
            namespace: p.linux.vfs.pid_namespace().clone(),
            pid: id,
            credentials: p.linux.vfs.credentials.clone(),
            fixed: self.fixed,
        };
        p.signals.begin_io();
        let source_io = p.worker_io_candidate(id);
        let waiting = if let State::Futex { wait, deadline } = &p.state {
            Some(crate::run_queue::WaitState::Futex {
                wait: wait.clone(),
                deadline: *deadline,
            })
        } else if let State::Sleep(deadline, remaining) = p.state {
            Some(crate::run_queue::WaitState::Sleep {
                deadline,
                remaining,
            })
        } else if let State::Sigwait {
            mask,
            info,
            deadline,
        } = p.state
        {
            Some(crate::run_queue::WaitState::Signal(
                crate::run_queue::SignalWait::new(trames_kernel::signal::SignalWait::Timed {
                    mask,
                    info,
                    deadline,
                }),
            ))
        } else if let State::Suspend(old) = p.state {
            p.signals.wait_mask = Some(old);
            p.signals.begin_io();
            Some(crate::run_queue::WaitState::Signal(
                crate::run_queue::SignalWait::new(trames_kernel::signal::SignalWait::Suspend {
                    mask: p.signals.mask,
                }),
            ))
        } else if let State::Blocked(number @ (95 | 260), args) = p.state {
            Some(crate::run_queue::WaitState::Child(
                crate::run_queue::ChildWait::new(trames_kernel::children::Wait { number, args }),
            ))
        } else if let State::Barrier(wait) = &p.state {
            Some(crate::run_queue::WaitState::Barrier(wait.clone()))
        } else if let State::Policy(wait) = &p.state {
            Some(crate::run_queue::WaitState::Policy(wait.clone()))
        } else if let State::Namespace(wait) = &p.state {
            Some(crate::run_queue::WaitState::Namespace(wait.clone()))
        } else if let State::Completion(release) = &p.state {
            Some(crate::run_queue::WaitState::Completion(
                crate::run_queue::CompletionWait::new(release.clone()),
            ))
        } else if !matches!(p.state, State::Ready) && !source_io && !p.worker_gpu_candidate() {
            Some(crate::run_queue::WaitState::OwnerEvent)
        } else {
            None
        };
        {
            let task = &mut *p;
            task.linux.vfs.set_lock_owner(task.tgid);
        }
        let namespaces = p.linux.vfs.task_namespaces();
        let c = &p.linux.vfs.credentials;
        let direct_files = if !p.linux.trace {
            file_epoch.capture(&p.linux.vfs, true)
        } else {
            Default::default()
        };
        let retained_files = if !p.linux.trace {
            file_epoch.capture_uring_rings(&p.linux.vfs, true, p.linux.uring_rings())
        } else {
            Default::default()
        };
        let work = crate::workers::Work::<C> {
            task: Some(task),
            gpu,
            audio,
            pid: id,
            cpu: std::mem::take(&mut p.cpu),
            memory: view.into(),
            control: control.clone(),
            syscalls: Some(crate::worker_syscalls::Snapshot {
                owner_syscalls: p.linux.trace,
                diagnostics: Some(p.linux.syscall_diagnostics(id)),
                membarrier_registered: Some(p.membarrier_registered.clone()),
                vfork_release: p.vfork.clone(),
                native_space: Some(p.space.clone()),
                namespaces: Some(namespaces),
                exit_files: Some(p.linux.vfs.file_table_owner()),
                exit_context: p.linux.vfs.context_owner(),
                children: p.children.clone(),
                limits: Some(limits),
                timers: Some(self.timers.clone()),
                saved_wait_mask: std::cell::Cell::new(p.signals.wait_mask),
                seccomp: p.seccomp.clone(),
                identities: [
                    p.linux.vfs.visible_pid(p.tgid) as u64,
                    p.linux.vfs.visible_pid(p.family.parent()) as u64,
                    c.uid as u64,
                    c.euid as u64,
                    c.gid as u64,
                    c.egid as u64,
                    p.linux.vfs.visible_pid(id) as u64,
                ],
                started: self.started,
                processor: p.last_cpu as u32,
                cpus: self.cpus,
                profile: self.profile,
                streams: p.linux.vfs.stream_descriptors(),

                fd_flags: p.linux.vfs.fd_flags_snapshot(),
                umask: p.linux.vfs.umask_capability(),
                actions: p.signals.actions.shared(),
                io_signals: p.signals.io.clone(),
                io_wake: None,
                io_routes: trames_kernel::signal::IoRoutes {
                    directory: p.signals.io_directory.clone(),
                    namespace: p.linux.vfs.pid_namespace().clone(),
                    uid: c.uid,
                    euid: c.euid,
                },
                program_break: p.linux.program_break(),
                uts: Some(p.linux.vfs.uts_capability()),
                direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                    .with_aio(p.linux.aio.clone(), p.linux.vfs.native_events())
                    .with_task_signal(p.signals.io.clone())
                    .with_local_identity([
                        p.tgid,
                        p.linux.vfs.credentials.uid,
                        p.linux.vfs.credentials.gid,
                    ])
                    .with_membership(p.linux.vfs.shared_files())
                    .with_paths(p.linux.vfs.path_queries())
                    .with_resources(p.linux.vfs.descriptor_factory())
                    .with_file_executor(self.files.clone())
                    .with_file_layouts(self.layouts.clone())
                    .with_kernel_log(p.linux.vfs.kernel_log_capability())
                    .with_urings(
                        uring_epoch
                            .capture_all(
                                &p.linux.vfs,
                                p.memory.instruction_identity().0,
                                id,
                                &direct_files,
                                &retained_files,
                            )
                            .with_actor(p.linux.uring_actor_root()),
                    )
                    .with_network(network_epoch.capture(&p.linux.vfs))
                    .with_clock(self.started)
                    .with_boot_clock(p.linux.boot_clock())
                    .with_terminal(trames_vfs::TerminalAccess {
                        session: p.session,
                        group: p.group,
                        controlling: p.linux.vfs.controlling_terminal,
                        ignore_ttou: p.signals.mask & (1 << 21) != 0
                            || p.signals.actions.get(22).handler == 1,
                    })
                    .with_files(direct_files)
                    .with_lock_context(p.linux.vfs.record_lock_context(p.tgid))
                    .with_signal_reader(p.signals.reader(p.linux.vfs.pid_namespace())),
                futex: crate::futex::Authority::new(self.futexes.clone(), p.vm_id),
            }),
        };
        let mut job = crate::run_queue::Job::<C>::new(
            work,
            p.signals.io.scheduling.affinity(),
            p.last_cpu,
            waiting,
        );
        if let State::Gpu {
            job: compile,
            pc,
            operation,
            began,
            retired: true,
            instructions,
            peer_instructions,
        } = p.state
        {
            job.gpu_pending = Some(crate::gpu::Pending::adopted(crate::gpu::Compile {
                call: crate::gpu::Call {
                    pc,
                    operation,
                    args: [operation, 0, 0],
                },
                job: compile,
                began,
                peer_instructions: peer_instructions
                    + self.instructions.saturating_sub(instructions),
            }));
        }
        let io_retry = match p.state {
            State::Blocked(number, args)
                if !matches!(job.waiting, Some(crate::run_queue::WaitState::Child(_))) =>
            {
                Some((number, args))
            }
            _ => None,
        };
        if let Some((number, args)) = io_retry {
            // A child wait owns its accepted request, not a second I/O
            // retry. Existing owner-event compatibility state still uses
            // its legacy envelope until that resource is migrated.
            // Re-arm against the new epoch target. The owner's notification
            // target cannot schedule a parked worker in this cohort.
            let previous = p.byte_wait.take();
            let tcp_liveness = previous
                .as_ref()
                .and_then(trames_linux::PendingIo::tcp_liveness)
                .or_else(|| p.tcp_liveness.take());
            let retained_socket = previous
                .as_ref()
                .and_then(|wait| wait.retained_socket.clone())
                .or_else(|| p.retained_socket.take());
            let retained_file = previous
                .as_ref()
                .and_then(trames_linux::PendingIo::file_pending)
                .or_else(|| p.retained_file.take());
            let retained_aio = previous
                .as_ref()
                .and_then(|wait| wait.aio.clone())
                .or_else(|| p.retained_aio.take());
            let retained_byte = previous
                .and_then(|wait| wait.retained_byte)
                .or_else(|| p.retained_byte.take());
            job.retry = Some(crate::run_queue::IoCall {
                aio: retained_aio,
                file: retained_file,
                file_checkpoint: p.file_checkpoint.take(),
                uring: p.uring_wait.take().map(|(submitted, ring, deadline)| {
                    trames_linux::UringEnter {
                        submitted,
                        ring,
                        deadline,
                    }
                }),
                flock: if p.flock_wait.as_ref().is_some_and(|(r, _)| r.retains_file()) {
                    // The parked owner must not delay a worker's final
                    // close/notification until the next cohort join.
                    p.flock_wait.take().map(|(request, _)| request)
                } else {
                    p.flock_wait.as_ref().map(|(request, _)| request.clone())
                },
                retained_byte,
                retained_socket,
                tcp_liveness,
                retained_poll: p.retained_poll.take(),
                number,
                args,
                deadline: if matches!(number, 63..=66 | 202 | 203 | 242) {
                    p.socket_deadline
                } else {
                    p.poll_deadline
                },
            });
        }
        job
    }
}

/// Prepare a complete quiescent cohort from original task and mapping resources.
/// The joined caller currently supplies custody; source admission must acquire
/// it without blocking a CPU slot before invoking this preparation path.
pub(super) fn prepare_views<C: Cpu>(
    tasks: &tasks::Directory<C>,
    registry: &mut trames_memory::parallel::Registry,
    chosen: &[(u32, usize)],
    reuse_retained: bool,
    backend_error: &mut Option<String>,
) -> Option<Vec<(u32, usize, Box<trames_memory::parallel::View>)>> {
    let mut views: Vec<(u32, usize, Box<trames_memory::parallel::View>)> =
        Vec::with_capacity(chosen.len());
    let mut published = BTreeMap::<u64, usize>::new();
    for &(id, slot) in chosen {
        let task = tasks.handle(&id).expect("selected process");
        let p = &mut *task.write();
        let (identity, _) = p.memory.coordinator_ownership();
        if !p.memory.admit_parallel_layouts() {
            return None;
        }
        let view = if let Some(&index) = published.get(&identity) {
            // Freeze one VM once per epoch. Backing checks of another VM
            // may advance a global epoch between selected CPU preparations;
            // they must not give this VM's peers different snapshots.
            registry.metrics.cache_hits += 1;
            views[index].2.clone()
        } else if reuse_retained && !p.memory.parallel_views_quiescent() {
            // This is a task-lifecycle-only checkpoint. All private execution
            // actors returned; retained guarded borrows still use exactly
            // these parent bytes. Fork isolated its child, CLONE_VM introduced no parent mapping
            // change, and exec installed a different mm without editing this one.
            let mut view = Box::new(p.memory.current_parallel_view()?);
            C::prepare_hardware_view(&mut view);
            published.insert(identity, views.len());
            view
        } else {
            if let Err(error) = C::prepare_hardware_memory(&mut p.memory, registry) {
                *backend_error = Some(error.to_string());
                return None;
            }
            let mut view = Box::new(p.memory.parallel_view(registry)?);
            C::prepare_hardware_view(&mut view);
            published.insert(identity, views.len());
            view
        };
        views.push((id, slot, view));
    }
    Some(views)
}
