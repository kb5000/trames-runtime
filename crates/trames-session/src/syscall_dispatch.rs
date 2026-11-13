// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted syscall dispatcher over the caller's actual CPU and memory.
//! Both warm View execution and cold original-mm custody use this same body.
use crate::run_queue::{Epoch, Job, WaitState};
use std::sync::Arc;
use std::time::{Duration, Instant};
use trames_engine::{Cpu, SliceOutcome};
use trames_memory::CpuMemory;

pub(crate) struct Step {
    pub outcome: Option<SliceOutcome>,
    pub thread_exit: Option<crate::worker_syscalls::Exit>,
    pub parked: Option<WaitState>,
    pub io: Option<trames_linux::PendingIo>,
    pub maintenance: bool,
    pub yielded: bool,
    pub scoped: bool,
    pub syscalls: u64,
    pub time: Duration,
}

#[inline(always)]
pub(crate) fn execute<C: Cpu>(
    job: &mut Job<C>,
    memory: &mut impl CpuMemory,
    epoch: Option<&Epoch<C>>,
    index: usize,
    resumed_policy: bool,
    result: SliceOutcome,
) -> Step {
    let work = &mut job.work;
    let domain = job.domain.as_ref();
    let mut thread_exit = None;
    let mut parked = None;
    let mut parked_io = None;
    let mut maintenance = false;
    let mut yielded = false;
    let mut vm_checkpoint = false;
    let mut syscalls = 0;
    let mut syscall_time = Duration::ZERO;
    let outcome = 'entry: {
        work.trace.begin_cpu(work.pid, &work.cpu);
        work.cpu.clear_exclusive();

        if let Some(snapshot) = &mut work.syscalls {
            let number = work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| work.cpu.x(i));
            let began = snapshot.profile.then(Instant::now);
            if !resumed_policy {
                job.seccomp_entry = None;
                snapshot.seccomp.begin_entry(number, work.cpu.pc(), args);
            }
            if let Some(began) = began {
                syscall_time += began.elapsed();
            }
            if let Some(entry) = snapshot.seccomp.denied_entry(number, work.cpu.pc(), args) {
                if let Some(value) = entry.completed() {
                    work.trace.finish(&mut work.cpu, value);
                    syscalls += 1;
                    break 'entry None;
                }
                if epoch.is_none() || snapshot.exit_files.is_none() {
                    job.seccomp_entry = Some(entry);
                    break 'entry Some(result);
                }
                syscalls += 1;
                if entry.action() == 0 {
                    if let Some(exit) =
                        snapshot.exit_thread(work.pid, entry.fatal_signal(), &mut *memory)
                    {
                        thread_exit = Some(exit);
                    } else {
                        job.seccomp_entry = Some(entry);
                        syscalls -= 1;
                    }
                    break 'entry Some(result);
                }
                if entry.action() == 0x0003_0000
                    && snapshot.io_signals.mask() & (1 << 30) == 0
                    && snapshot.actions.get(31).handler > 1
                {
                    snapshot.io_signals.inbox.discard(31);
                    let info = trames_kernel::signal::Info {
                        sender: entry.data(),
                        uid: 0xc000_00b7,
                        status: number as i32,
                        code: 1,
                        timer: None,
                        fault: Some(work.cpu.pc()),
                        poll: None,
                    };
                    if snapshot.io_signals.inbox.enqueue(31, info).is_ok() {
                        work.trace.trapped();
                        break 'entry None;
                    }
                }
                snapshot.io_signals.lifecycle().request_exit(31);
                break 'entry None;
            }
        }
        if work.cpu.x(8) as u32 == 283 {
            if let (Some(snapshot), Some(epoch), Some(domain)) =
                (work.syscalls.as_ref(), epoch.as_ref(), domain.as_ref())
            {
                if let Some(registered) = &snapshot.membarrier_registered {
                    let began = snapshot.profile.then(Instant::now);
                    let result = crate::barrier::prepare(registered, work.cpu.x(0), work.cpu.x(1));
                    syscalls += 1;
                    match result {
                        Ok(crate::barrier::Action::Complete(value)) => {
                            work.trace.finish(&mut work.cpu, value)
                        }
                        Err(error) => work
                            .trace
                            .finish(&mut work.cpu, 0u64.wrapping_sub(error.0 as u64)),
                        Ok(crate::barrier::Action::Fence(scope)) => {
                            let request = epoch.memory_barrier(
                                domain.id,
                                matches!(scope, crate::barrier::Scope::Global),
                                index,
                            );
                            if let Some(value) = request.finish() {
                                work.trace.finish(&mut work.cpu, value);
                            } else {
                                let wait = crate::barrier::Wait::new(request);
                                if let Some(signal) = &snapshot.io_wake {
                                    wait.bind(signal);
                                }
                                parked = Some(crate::run_queue::WaitState::Barrier(wait));
                                if let Some(began) = began {
                                    syscall_time += began.elapsed();
                                }
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                        }
                    }
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    break 'entry None;
                }
            }
        }
        if work
            .syscalls
            .as_ref()
            .is_some_and(|s| s.namespaces.is_some())
            && crate::process::seccomp::local_entry(
                work.cpu.x(8) as u32,
                std::array::from_fn(|i| work.cpu.x(i)),
            )
        {
            let number = work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| work.cpu.x(i));
            let snapshot = work.syscalls.as_ref().unwrap();
            let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
            if !entry.allowed() {
                if let Some(value) = entry.completed() {
                    work.trace.finish(&mut work.cpu, value);
                    syscalls += 1;
                    break 'entry None;
                }
                job.seccomp_entry = Some(entry);
                break 'entry Some(result);
            }
            let began = snapshot.profile.then(Instant::now);
            let attempt = work.policy_call(number, args, memory);
            if let Some(began) = began {
                syscall_time += began.elapsed();
            }
            syscalls += 1;
            match attempt {
                crate::process::seccomp::Attempt::Complete(value) => work.trace.finish(
                    &mut work.cpu,
                    value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                ),
                crate::process::seccomp::Attempt::Waiting(pending) => {
                    let wait = crate::run_queue::PolicyWait::new(*pending);
                    if let Some(wake) = work.syscalls.as_ref().and_then(|s| s.io_wake.as_ref()) {
                        wait.bind(wake);
                    }
                    parked = Some(crate::run_queue::WaitState::Policy(wait));
                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                }
            }
            break 'entry None;
        }
        if (matches!(work.cpu.x(8) as u32, 97 | 268)
            || work.cpu.x(8) as u32 == 436 && work.cpu.x(2) as u32 & 2 != 0)
            && work
                .syscalls
                .as_ref()
                .is_some_and(|s| s.namespaces.is_some())
        {
            let number = work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| work.cpu.x(i));
            let snapshot = work.syscalls.as_ref().unwrap();
            let began = snapshot.profile.then(Instant::now);
            let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
            if !entry.allowed() {
                job.seccomp_entry = Some(entry);
                break 'entry Some(result);
            }
            let attempt = work.namespace_work(number, args).run();
            if let Some(began) = began {
                syscall_time += began.elapsed();
            }
            syscalls += 1;
            match attempt {
                trames_vfs::TaskNamespaceAttempt::Complete(state, result) => {
                    work.finish_namespaces(state, result);
                    break 'entry None;
                }
                trames_vfs::TaskNamespaceAttempt::Waiting(pending) => {
                    let wait = crate::run_queue::NamespaceWait::new(pending);
                    if let Some(signal) = work.syscalls.as_ref().and_then(|s| s.io_wake.as_ref()) {
                        wait.bind(signal);
                    }
                    parked = Some(crate::run_queue::WaitState::Namespace(wait));
                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                }
            }
        }
        if !matches!(work.cpu.x(8) as u32, 174..=177)
            && work
                .syscalls
                .as_ref()
                .is_some_and(|s| s.namespaces.is_some())
            && trames_linux::credential_entry(
                work.cpu.x(8) as u32,
                std::array::from_fn(|i| work.cpu.x(i)),
            )
        {
            let number = work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| work.cpu.x(i));
            let snapshot = work.syscalls.as_ref().unwrap();
            let began = snapshot.profile.then(Instant::now);
            let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
            if !entry.allowed() {
                job.seccomp_entry = Some(entry);
                break 'entry Some(result);
            }
            work.credential_call(number, args, memory);
            if let Some(began) = began {
                syscall_time += began.elapsed();
            }
            syscalls += 1;
            break 'entry None;
        }
        if let Some(snapshot) = work
            .syscalls
            .as_ref()
            .filter(|s| work.cpu.x(8) as u32 == 139 && s.admit(&work.cpu))
        {
            match snapshot.return_io_signal(&mut work.cpu, &*memory) {
                Ok(()) => work.trace.record(work.cpu.x(0)),
                Err(error) => {
                    let _ = snapshot
                        .io_signals
                        .inbox
                        .enqueue(11, trames_kernel::signal::Info::default());
                    work.trace
                        .finish(&mut work.cpu, 0u64.wrapping_sub(error.0 as u64));
                }
            }
            syscalls += 1;
            break 'entry None;
        }
        if let Some(snapshot) = work.syscalls.as_ref().filter(|snapshot| {
            (snapshot.seccomp.mode() != 0
                || snapshot
                    .direct
                    .supports_binder(work.cpu.x(8) as u32, std::array::from_fn(|i| work.cpu.x(i))))
                && (trames_linux::DirectSyscalls::file_entry(
                    work.cpu.x(8) as u32,
                    std::array::from_fn(|i| work.cpu.x(i)),
                ) || snapshot.direct.supports_creation(work.cpu.x(8) as u32)
                    || snapshot
                        .direct
                        .supports_socket_control(work.cpu.x(8) as u32)
                    || snapshot
                        .direct
                        .supports_local_message(work.cpu.x(8) as u32, work.cpu.x(0) as u32)
                    || snapshot.direct.supports_path_query(work.cpu.x(8) as u32)
                    || snapshot.direct.supports_epoll_control(work.cpu.x(8) as u32)
                    || snapshot.direct.supports_ioctl(
                        work.cpu.x(8) as u32,
                        std::array::from_fn(|i| work.cpu.x(i)),
                    )
                    || matches!(work.cpu.x(8) as u32, 23 | 24 | 32 | 57 | 101 | 115 | 436)
                    || work.cpu.x(8) as u32 == 25 && matches!(work.cpu.x(1), 0 | 7 | 38 | 1030))
        }) {
            let began = snapshot.profile.then(Instant::now);
            let number = work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| work.cpu.x(i));
            let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
            if entry.allowed() {
                if let Some(epoch) = &epoch {
                    if snapshot.direct.supports_call(number, args)
                        || snapshot.direct.supports_ioctl(number, args)
                    {
                        let attempt = snapshot
                            .direct
                            .start(number, args, &mut *memory, work.pid, &epoch.io_target, None)
                            .unwrap_or(trames_linux::IoAttempt::Checkpoint);
                        if let Some(began) = began {
                            syscall_time += began.elapsed();
                        }
                        match attempt {
                            trames_linux::IoAttempt::HostError(error) => {
                                epoch.fail_host_io(error);
                                maintenance = true;
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::Complete(result) => {
                                if trames_linux::event_wait(number) {
                                    snapshot.finish_wait_mask();
                                }
                                work.trace.finish(
                                    &mut work.cpu,
                                    result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                                );
                                syscalls += 1;
                                break 'entry None;
                            }
                            trames_linux::IoAttempt::Blocked(pending) => {
                                if let Some(wait) = &pending.retained_poll {
                                    snapshot.begin_wait_mask(wait);
                                }
                                parked_io = Some(pending);
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::FileCheckpoint(file) => {
                                let call = crate::run_queue::IoCall::from_file_checkpoint(
                                    file, number, args,
                                );
                                for (i, value) in call.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, call.number as u64);
                                job.retry = Some(call);
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::ByteCheckpoint(file) => {
                                let call = crate::run_queue::IoCall::from_byte(file, number, args);
                                for (i, value) in call.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, call.number as u64);
                                job.retry = Some(call);
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::SocketCheckpoint(socket) => {
                                for (i, value) in socket.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, socket.number as u64);
                                job.retry = Some(crate::run_queue::IoCall::from_socket(socket));
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                                let call = crate::run_queue::IoCall::from_wait(wait);
                                for (i, value) in call.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, call.number as u64);
                                job.retry = Some(call);
                                break 'entry Some(SliceOutcome::Syscall { instructions: 0 });
                            }
                            trames_linux::IoAttempt::Checkpoint => {
                                job.seccomp_entry = Some(entry);
                                break 'entry Some(result);
                            }
                        }
                    }
                    if let Some(attempt) = snapshot.direct.start_file_call(
                        number,
                        args,
                        &mut *memory,
                        work.pid,
                        &epoch.io_target,
                    ) {
                        if let Some(began) = began {
                            syscall_time += began.elapsed();
                        }
                        match attempt {
                            trames_linux::IoAttempt::HostError(error) => {
                                epoch.fail_host_io(error);
                                maintenance = true;
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::Complete(value) => {
                                work.trace.finish(
                                    &mut work.cpu,
                                    value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                                );
                                syscalls += 1;
                                break 'entry None;
                            }
                            trames_linux::IoAttempt::Blocked(pending) => {
                                if let Some(wait) = &pending.retained_poll {
                                    snapshot.begin_wait_mask(wait);
                                }
                                parked_io = Some(pending);
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::FileCheckpoint(file) => {
                                job.retry = Some(crate::run_queue::IoCall::from_file_checkpoint(
                                    file, number, args,
                                ));
                                job.seccomp_entry = Some(entry);
                                break 'entry Some(result);
                            }
                            _ => unreachable!("typed file entry"),
                        }
                    }
                }
                if let Some(value) = snapshot.direct.invoke_epoll_control(number, args, &*memory) {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    work.trace.finish(
                        &mut work.cpu,
                        value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                    );
                    syscalls += 1;
                    break 'entry None;
                }
                if let Some(epoch) = &epoch {
                    if let Some(attempt) = snapshot.direct.start_socket_control(
                        number,
                        args,
                        &mut *memory,
                        work.pid,
                        &epoch.io_target,
                    ) {
                        if let Some(began) = began {
                            syscall_time += began.elapsed();
                        }
                        match attempt {
                            trames_linux::IoAttempt::HostError(error) => {
                                epoch.fail_host_io(error);
                                maintenance = true;
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::Complete(value) => {
                                work.trace.finish(
                                    &mut work.cpu,
                                    value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                                );
                                syscalls += 1;
                                break 'entry None;
                            }
                            trames_linux::IoAttempt::Blocked(pending) => {
                                if let Some(wait) = &pending.retained_poll {
                                    snapshot.begin_wait_mask(wait);
                                }
                                parked_io = Some(pending);
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::FileCheckpoint(file) => {
                                let call = crate::run_queue::IoCall::from_file_checkpoint(
                                    file, number, args,
                                );
                                for (i, value) in call.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, call.number as u64);
                                job.retry = Some(call);
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::ByteCheckpoint(file) => {
                                let call = crate::run_queue::IoCall::from_byte(file, number, args);
                                for (i, value) in call.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, call.number as u64);
                                job.retry = Some(call);
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::SocketCheckpoint(socket) => {
                                for (i, value) in socket.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, socket.number as u64);
                                job.retry = Some(crate::run_queue::IoCall::from_socket(socket));
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                                let call = crate::run_queue::IoCall::from_wait(wait);
                                for (i, value) in call.args.iter().enumerate() {
                                    work.cpu.set_x(i, *value);
                                }
                                work.cpu.set_x(8, call.number as u64);
                                job.retry = Some(call);
                                break 'entry Some(SliceOutcome::Syscall { instructions: 0 });
                            }
                            trames_linux::IoAttempt::Checkpoint => {
                                job.seccomp_entry = Some(entry);
                                break 'entry Some(result);
                            }
                        }
                    }
                }
                if snapshot
                    .direct
                    .supports_local_message(number, args[0] as u32)
                {
                    if let Some(epoch) = &epoch {
                        if let Some(attempt) = snapshot.direct.start(
                            number,
                            args,
                            &mut *memory,
                            work.pid,
                            &epoch.io_target,
                            None,
                        ) {
                            if let Some(began) = began {
                                syscall_time += began.elapsed();
                            }
                            match attempt {
                                trames_linux::IoAttempt::HostError(error) => {
                                    epoch.fail_host_io(error);
                                    maintenance = true;
                                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                                }
                                trames_linux::IoAttempt::Complete(value) => {
                                    work.trace.finish(
                                        &mut work.cpu,
                                        value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                                    );
                                    syscalls += 1;
                                    break 'entry None;
                                }
                                trames_linux::IoAttempt::Blocked(pending) => {
                                    if let Some(wait) = &pending.retained_poll {
                                        snapshot.begin_wait_mask(wait);
                                    }
                                    parked_io = Some(pending);
                                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                                }
                                trames_linux::IoAttempt::FileCheckpoint(file) => {
                                    let call = crate::run_queue::IoCall::from_file_checkpoint(
                                        file, number, args,
                                    );
                                    for (i, value) in call.args.iter().enumerate() {
                                        work.cpu.set_x(i, *value);
                                    }
                                    work.cpu.set_x(8, call.number as u64);
                                    job.retry = Some(call);
                                    break 'entry Some(result);
                                }
                                trames_linux::IoAttempt::ByteCheckpoint(file) => {
                                    let call =
                                        crate::run_queue::IoCall::from_byte(file, number, args);
                                    for (i, value) in call.args.iter().enumerate() {
                                        work.cpu.set_x(i, *value);
                                    }
                                    work.cpu.set_x(8, call.number as u64);
                                    job.retry = Some(call);
                                    break 'entry Some(result);
                                }
                                trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                                    let call = crate::run_queue::IoCall::from_wait(wait);
                                    for (i, value) in call.args.iter().enumerate() {
                                        work.cpu.set_x(i, *value);
                                    }
                                    work.cpu.set_x(8, call.number as u64);
                                    job.retry = Some(call);
                                    break 'entry Some(SliceOutcome::Syscall { instructions: 0 });
                                }
                                trames_linux::IoAttempt::Checkpoint => {
                                    job.seccomp_entry = Some(entry);
                                    break 'entry Some(result);
                                }
                                trames_linux::IoAttempt::SocketCheckpoint(_) => {
                                    unreachable!("Unix message start")
                                }
                            }
                        }
                    }
                    job.seccomp_entry = Some(entry);
                    break 'entry Some(result);
                }
                if let Some(value) =
                    snapshot
                        .direct
                        .invoke_socket_control(number, args, &mut *memory)
                {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    work.trace.finish(
                        &mut work.cpu,
                        value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                    );
                    syscalls += 1;
                    break 'entry None;
                }
                if let Some(value) = snapshot.direct.invoke_creation(number, args, &mut *memory) {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    work.trace.finish(
                        &mut work.cpu,
                        value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                    );
                    syscalls += 1;
                    break 'entry None;
                }
                if snapshot.direct.supports_path_query(number) {
                    let value = snapshot
                        .direct
                        .invoke_file(number, args, &mut *memory)
                        .or_else(|| snapshot.direct.invoke_path(number, args, &mut *memory));
                    if let Some(value) = value {
                        if let Some(began) = began {
                            syscall_time += began.elapsed();
                        }
                        work.trace.finish(
                            &mut work.cpu,
                            value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                        );
                        syscalls += 1;
                        break 'entry None;
                    }
                    job.seccomp_entry = Some(entry);
                    break 'entry Some(result);
                }

                if matches!(number, 101 | 115) {
                    if epoch.is_none() {
                        job.seccomp_entry = Some(entry);
                        break 'entry Some(result);
                    }
                    let waiting = crate::worker_syscalls::sleep_parameters(
                        &*memory,
                        number,
                        args,
                        snapshot.started,
                    );
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    syscalls += 1;
                    match waiting {
                        Ok((deadline, remaining)) => {
                            parked = Some(crate::run_queue::WaitState::Sleep {
                                deadline,
                                remaining,
                            });
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        Err(error) => {
                            work.trace
                                .finish(&mut work.cpu, 0u64.wrapping_sub(error.0 as u64));
                            break 'entry None;
                        }
                    }
                }
                if let Some(value) = snapshot.direct.invoke_membership(number, args) {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    work.trace.finish(
                        &mut work.cpu,
                        value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                    );
                    syscalls += 1;
                    break 'entry None;
                }
            }
            // Deferred entries and denials retain
            // their normal joined effects. The entry
            // token binds this exact ABI and policy.
            job.seccomp_entry = Some(entry);
            break 'entry Some(result);
        }
        if let Some(snapshot) = work.syscalls.as_ref().filter(|_| {
            trames_linux::memory_query_entry(
                work.cpu.x(8) as u32,
                std::array::from_fn(|i| work.cpu.x(i)),
            )
        }) {
            let number = work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| work.cpu.x(i));
            let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
            if !entry.allowed() {
                job.seccomp_entry = Some(entry);
                break 'entry Some(result);
            }
            let began = snapshot.profile.then(Instant::now);
            let attempt = trames_linux::memory_query(&mut *memory, number, args);
            if let Some(began) = began {
                syscall_time += began.elapsed();
            }
            if let Some(value) = attempt {
                work.trace.finish(
                    &mut work.cpu,
                    value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                );
                syscalls += 1;
                break 'entry None;
            }
            job.seccomp_entry = Some(entry);
        }
        // Decide before custody: pure policy errors need
        // neither mm quiescence nor an owner callback.
        // Carry an allowed/deferred decision exactly once.
        if epoch.as_ref().is_some_and(|epoch| epoch.local_vm)
            && work
                .syscalls
                .as_ref()
                .is_some_and(|snapshot| snapshot.seccomp.mode() != 0 || work.cpu.x(8) as u32 == 427)
            && crate::structural::Call::from_cpu(&work.cpu).is_some_and(|call| call.preflight())
            && !(work.cpu.x(8) as u32 == 214 && work.cpu.x(0) == 0)
        {
            let snapshot = work.syscalls.as_ref().expect("custody task");
            if snapshot.seccomp.mode() != 0 {
                let entry = snapshot.seccomp.entry_decision(
                    work.cpu.x(8) as u32,
                    work.cpu.pc(),
                    std::array::from_fn(|i| work.cpu.x(i)),
                );
                if let Some(value) = entry.completed() {
                    work.trace.finish(&mut work.cpu, value);
                    syscalls += 1;
                    break 'entry None;
                }
                job.seccomp_entry = Some(entry);
            }
            vm_checkpoint = true;
            break 'entry Some(result);
        }
        if let Some(snapshot) = &work.syscalls {
            if matches!(work.cpu.x(8) as u32, 132..=137)
                || epoch.is_some() && matches!(work.cpu.x(8) as u32, 95 | 260)
                || snapshot.signal_send(&work.cpu)
                || snapshot.thread_call(&work.cpu)
                || snapshot.limit_call(work.cpu.x(8) as u32)
            {
                let mut entry = snapshot.task_entry(&work.cpu);
                if let Some(decision) = entry.as_ref() {
                    if !decision.allowed() {
                        if let Some(value) = decision.completed() {
                            work.trace.finish(&mut work.cpu, value);
                            syscalls += 1;
                            break 'entry None;
                        }
                        job.seccomp_entry = entry.take();
                        break 'entry Some(result);
                    }
                }
                if work.cpu.x(8) as u32 == 142 {
                    let began = snapshot.profile.then(Instant::now);
                    let attempt = snapshot
                        .shutdown_guest(std::array::from_fn(|i| work.cpu.x(i)), epoch.is_some());
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    match attempt {
                        Some(Err(error)) => {
                            work.trace
                                .finish(&mut work.cpu, 0u64.wrapping_sub(error.0 as u64));
                            syscalls += 1;
                            break 'entry None;
                        }
                        Some(Ok(())) => {
                            syscalls += 1;
                            break 'entry None;
                        }
                        None => {
                            job.seccomp_entry = entry;
                            break 'entry Some(result);
                        }
                    }
                }
                if matches!(work.cpu.x(8) as u32, 93 | 94) {
                    let status = (work.cpu.x(0) as u8 as i32) << 8;
                    if work.cpu.x(8) as u32 == 94 {
                        snapshot.io_signals.lifecycle().request_exit(status);
                    }
                    if let Some(exit) = epoch
                        .as_ref()
                        .and_then(|_| snapshot.exit_thread(work.pid, status, &mut *memory))
                    {
                        thread_exit = Some(exit);
                        syscalls += 1;
                    } else {
                        job.seccomp_entry = entry;
                    }
                    break 'entry Some(result);
                }
                let began = snapshot.profile.then(Instant::now);
                let number = work.cpu.x(8) as u32;
                if matches!(number, 95 | 260) {
                    let request = match trames_kernel::children::Wait::prepare(
                        number,
                        std::array::from_fn(|i| work.cpu.x(i)),
                    ) {
                        Ok(request) => request,
                        Err(e) => {
                            work.trace
                                .finish(&mut work.cpu, 0u64.wrapping_sub(e.0 as u64));
                            syscalls += 1;
                            break 'entry None;
                        }
                    };
                    // Subscribe before checking: an exit between checking and
                    // parking cannot strand the accepted source wait.
                    let waiting = snapshot.begin_child_wait(request);
                    let attempt = snapshot.children.wait(
                        request,
                        &snapshot.io_routes.namespace,
                        snapshot.io_signals.group(),
                        &mut *memory,
                    );
                    if let Some(value) = attempt.transpose() {
                        work.trace.finish(
                            &mut work.cpu,
                            value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                        );
                        syscalls += 1;
                        break 'entry None;
                    }
                    parked = Some(waiting);
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    syscalls += 1;
                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                }
                if matches!(number, 133 | 137) {
                    let attempt = trames_kernel::signal::SignalWait::prepare(
                        number,
                        std::array::from_fn(|i| work.cpu.x(i)),
                        &*memory,
                    );
                    let request = match attempt {
                        Ok(r) => r,
                        Err(e) => {
                            work.trace
                                .finish(&mut work.cpu, 0u64.wrapping_sub(e.0 as u64));
                            syscalls += 1;
                            break 'entry None;
                        }
                    };
                    if let Some(value) = request.check(
                        &snapshot.io_signals,
                        &mut *memory,
                        &snapshot.io_routes.namespace,
                    ) {
                        work.trace.finish(
                            &mut work.cpu,
                            value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                        );
                        syscalls += 1;
                        break 'entry None;
                    }
                    parked = Some(snapshot.begin_signal_wait(request));
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    syscalls += 1;
                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                }
                if number == 122 {
                    let reply = snapshot.io_routes.scheduling_request(
                        &snapshot.io_signals,
                        snapshot.cpus,
                        number,
                        std::array::from_fn(|i| work.cpu.x(i)),
                        &mut *memory,
                    );
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    syscalls += 1;
                    match reply {
                        Err(e) => {
                            work.trace
                                .finish(&mut work.cpu, 0u64.wrapping_sub(e.0 as u64));
                            break 'entry None;
                        }
                        Ok((value, wait)) => {
                            work.trace.finish(&mut work.cpu, value);
                            if let (Some(_), Some(wait)) = (&epoch, wait.filter(|w| !w.finished()))
                            {
                                let waiting = crate::run_queue::CompletionWait::new(wait);
                                if let Some(signal) = &snapshot.io_wake {
                                    waiting.bind(&snapshot.io_signals, signal);
                                }
                                parked = Some(crate::run_queue::WaitState::Completion(waiting));
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            break 'entry None;
                        }
                    }
                }
                let value = if number == 167 {
                    let args = std::array::from_fn(|i| work.cpu.x(i));
                    crate::process::prctl::call(
                        &mut work.cpu,
                        &snapshot.name,
                        snapshot.io_signals.parentage().map(|p| &**p),
                        snapshot.io_signals.family().map(|p| &**p),
                        args,
                        &mut *memory,
                    )
                    .expect("original prctl capability")
                    .unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64))
                } else {
                    snapshot
                        .invoke(&work.cpu, &mut *memory)
                        .expect("shared task control")
                };
                if let Some(began) = began {
                    syscall_time += began.elapsed();
                }
                work.trace.finish(&mut work.cpu, value);
                syscalls += 1;
                break 'entry None;
            }
            if let Some(entry) = snapshot.timer_entry(&work.cpu) {
                if !entry.allowed() {
                    job.seccomp_entry = Some(entry);
                    break 'entry Some(result);
                }
                let began = snapshot.profile.then(Instant::now);
                let value = snapshot
                    .invoke(&work.cpu, &mut *memory)
                    .expect("shared timer authority");
                if let Some(began) = began {
                    syscall_time += began.elapsed();
                }
                work.trace.finish(&mut work.cpu, value);
                syscalls += 1;
                break 'entry None;
            }
            if let Some(entry) = snapshot.event_entry(&work.cpu) {
                if !entry.allowed() {
                    job.seccomp_entry = Some(entry);
                    break 'entry Some(result);
                }
                if let Some(epoch) = &epoch {
                    let number = work.cpu.x(8) as u32;
                    let args = std::array::from_fn(|i| work.cpu.x(i));
                    let began = snapshot.profile.then(Instant::now);
                    if let Some(attempt) = snapshot.direct.start(
                        number,
                        args,
                        &mut *memory,
                        work.pid,
                        &epoch.io_target,
                        None,
                    ) {
                        if let Some(began) = began {
                            syscall_time += began.elapsed();
                        }
                        match attempt {
                            trames_linux::IoAttempt::HostError(error) => {
                                epoch.fail_host_io(error);
                                maintenance = true;
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::Complete(value) => {
                                snapshot.finish_wait_mask();
                                work.trace.finish(
                                    &mut work.cpu,
                                    value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                                );
                                syscalls += 1;
                                break 'entry None;
                            }
                            trames_linux::IoAttempt::Blocked(pending) => {
                                if let Some(wait) = &pending.retained_poll {
                                    snapshot.begin_wait_mask(wait);
                                }
                                parked_io = Some(pending);
                                break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                            }
                            trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                                job.retry = Some(crate::run_queue::IoCall::from_wait(wait));
                                break 'entry Some(result);
                            }
                            trames_linux::IoAttempt::Checkpoint => {
                                job.seccomp_entry = Some(entry);
                                break 'entry Some(result);
                            }
                            _ => unreachable!("typed event wait"),
                        }
                    }
                }
                job.seccomp_entry = Some(entry);
                break 'entry Some(result);
            }
        }
        if let Some(snapshot) = work
            .syscalls
            .as_ref()
            .filter(|snapshot| snapshot.admit(&work.cpu))
        {
            let began = snapshot.profile.then(Instant::now);
            if let Some(epoch) = &epoch {
                if work.cpu.x(8) as u32 == 124 {
                    work.trace.finish(&mut work.cpu, 0);
                    syscalls += 1;
                    yielded = true;
                    break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                }
                if let Some(result) = snapshot.wait(&work.cpu, &mut *memory, work.pid, epoch) {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    syscalls += 1;
                    match result {
                        Ok(waiting) => {
                            parked = Some(waiting);
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        Err(error) => {
                            work.trace
                                .finish(&mut work.cpu, 0u64.wrapping_sub(error.0 as u64));
                            break 'entry None;
                        }
                    }
                }
            }
            if let Some(epoch) = &epoch {
                let number = work.cpu.x(8) as u32;
                let args = std::array::from_fn(|i| work.cpu.x(i));

                if let Some(attempt) = snapshot.direct.start_socket_control(
                    number,
                    args,
                    &mut *memory,
                    work.pid,
                    &epoch.io_target,
                ) {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    match attempt {
                        trames_linux::IoAttempt::HostError(error) => {
                            epoch.fail_host_io(error);
                            maintenance = true;
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        trames_linux::IoAttempt::Complete(value) => {
                            work.trace.finish(
                                &mut work.cpu,
                                value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                            );
                            syscalls += 1;
                            break 'entry None;
                        }
                        trames_linux::IoAttempt::Blocked(pending) => {
                            if let Some(wait) = &pending.retained_poll {
                                snapshot.begin_wait_mask(wait);
                            }
                            parked_io = Some(pending);
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        trames_linux::IoAttempt::FileCheckpoint(file) => {
                            let call =
                                crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
                            for (i, value) in call.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, call.number as u64);
                            job.retry = Some(call);
                            break 'entry Some(result);
                        }
                        trames_linux::IoAttempt::ByteCheckpoint(file) => {
                            let call = crate::run_queue::IoCall::from_byte(file, number, args);
                            for (i, value) in call.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, call.number as u64);
                            job.retry = Some(call);
                            break 'entry Some(result);
                        }
                        trames_linux::IoAttempt::SocketCheckpoint(socket) => {
                            for (i, value) in socket.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, socket.number as u64);
                            job.retry = Some(crate::run_queue::IoCall::from_socket(socket));
                            break 'entry Some(result);
                        }
                        trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                            let call = crate::run_queue::IoCall::from_wait(wait);
                            for (i, value) in call.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, call.number as u64);
                            job.retry = Some(call);
                            break 'entry Some(SliceOutcome::Syscall { instructions: 0 });
                        }
                        trames_linux::IoAttempt::Checkpoint => break 'entry Some(result),
                    }
                }
                if snapshot.direct.supports_call(number, args) {
                    let attempt = snapshot
                        .direct
                        .start(number, args, &mut *memory, work.pid, &epoch.io_target, None)
                        .expect("retained I/O");
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    match attempt {
                        trames_linux::IoAttempt::HostError(error) => {
                            epoch.fail_host_io(error);
                            maintenance = true;
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        trames_linux::IoAttempt::Complete(result) => {
                            work.trace.finish(
                                &mut work.cpu,
                                result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                            );
                            syscalls += 1;
                            break 'entry None;
                        }
                        trames_linux::IoAttempt::Blocked(pending) => {
                            if let Some(wait) = &pending.retained_poll {
                                snapshot.begin_wait_mask(wait);
                            }
                            parked_io = Some(pending);
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        trames_linux::IoAttempt::FileCheckpoint(file) => {
                            let call =
                                crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
                            for (i, value) in call.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, call.number as u64);
                            job.retry = Some(call);
                            break 'entry Some(result);
                        }
                        trames_linux::IoAttempt::ByteCheckpoint(file) => {
                            let call = crate::run_queue::IoCall::from_byte(file, number, args);
                            for (i, value) in call.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, call.number as u64);
                            job.retry = Some(call);
                            break 'entry Some(result);
                        }
                        trames_linux::IoAttempt::SocketCheckpoint(socket) => {
                            for (i, value) in socket.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, socket.number as u64);
                            job.retry = Some(crate::run_queue::IoCall::from_socket(socket));
                            break 'entry Some(result);
                        }
                        trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                            let call = crate::run_queue::IoCall::from_wait(wait);
                            for (i, value) in call.args.iter().enumerate() {
                                work.cpu.set_x(i, *value);
                            }
                            work.cpu.set_x(8, call.number as u64);
                            job.retry = Some(call);
                            break 'entry Some(SliceOutcome::Syscall { instructions: 0 });
                        }
                        trames_linux::IoAttempt::Checkpoint => break 'entry Some(result),
                    }
                }
                if let Some(attempt) = snapshot.direct.start_file_call(
                    number,
                    args,
                    &mut *memory,
                    work.pid,
                    &epoch.io_target,
                ) {
                    if let Some(began) = began {
                        syscall_time += began.elapsed();
                    }
                    match attempt {
                        trames_linux::IoAttempt::HostError(error) => {
                            epoch.fail_host_io(error);
                            maintenance = true;
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        trames_linux::IoAttempt::Complete(value) => {
                            work.trace.finish(
                                &mut work.cpu,
                                value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)),
                            );
                            syscalls += 1;
                            break 'entry None;
                        }
                        trames_linux::IoAttempt::Blocked(pending) => {
                            if let Some(wait) = &pending.retained_poll {
                                snapshot.begin_wait_mask(wait);
                            }
                            parked_io = Some(pending);
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                        trames_linux::IoAttempt::FileCheckpoint(file) => {
                            job.retry = Some(crate::run_queue::IoCall::from_file_checkpoint(
                                file, number, args,
                            ));
                            break 'entry Some(result);
                        }
                        _ => unreachable!("typed file entry"),
                    }
                }
            }
            if let Some(value) = snapshot.invoke(&work.cpu, &mut *memory) {
                if let Some(began) = began {
                    syscall_time += began.elapsed();
                }
                work.trace.finish(&mut work.cpu, value);
                syscalls += 1;
                break 'entry None;
            }
            if epoch.as_ref().is_some_and(|epoch| epoch.local_vm)
                && snapshot.seccomp.mode() == 0
                && work.cpu.x(8) as u32 == 222
                && trames_linux::Linux::mmap_is_additive(std::array::from_fn(|i| work.cpu.x(i)))
            {
                if let Some(task) = &work.task {
                    let began = Instant::now();
                    let attempt = crate::process::lifecycle::mapping::additive(
                        task,
                        work.pid,
                        std::array::from_fn(|i| work.cpu.x(i)),
                        &epoch.as_ref().unwrap().io_target,
                    );
                    match attempt {
                        Ok(value) => {
                            let elapsed = began.elapsed();
                            job.stats.additive_mmaps += 1;
                            job.stats.additive_time += elapsed;
                            if snapshot.profile {
                                syscall_time += elapsed;
                            }
                            work.trace.finish(&mut work.cpu, value);
                            syscalls += 1;
                            break 'entry None;
                        }
                        Err(wait) => {
                            job.seccomp_entry = Some(snapshot.seccomp.entry_decision(
                                work.cpu.x(8) as u32,
                                work.cpu.pc(),
                                std::array::from_fn(|i| work.cpu.x(i)),
                            ));
                            job.pending_cpu = Some(result);
                            parked = Some(crate::run_queue::WaitState::Custody(Arc::new(wait)));
                            break 'entry Some(SliceOutcome::Yield { instructions: 0 });
                        }
                    }
                }
                unreachable!("local VM execution requires original task custody");
            }
            if epoch.as_ref().is_some_and(|epoch| epoch.local_vm)
                && crate::structural::Call::from_cpu(&work.cpu).is_some()
            {
                if snapshot.seccomp.mode() != 0 {
                    job.seccomp_entry = Some(snapshot.seccomp.entry_decision(
                        work.cpu.x(8) as u32,
                        work.cpu.pc(),
                        std::array::from_fn(|i| work.cpu.x(i)),
                    ));
                }
                vm_checkpoint = true;
                break 'entry Some(result);
            }
            // A retained resource deferred before effects
            // for scheduling/SIGPIPE. Do not send the
            // same failed operation through RPC first.
            if snapshot
                .direct
                .supports(work.cpu.x(8) as u32, work.cpu.x(0) as u32)
            {
                break 'entry Some(result);
            }
        }
        Some(result)
    };
    Step {
        outcome,
        thread_exit,
        parked,
        io: parked_io,
        maintenance,
        yielded,
        scoped: vm_checkpoint,
        syscalls,
        time: syscall_time,
    }
}
