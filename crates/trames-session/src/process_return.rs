// SPDX-License-Identifier: GPL-3.0-or-later
//! Publish returned execution state to its original task; no guest operation runs here.
use super::*;
pub(super) struct Published {
    pub outcome: Option<SliceOutcome>,
    pub stats: crate::run_queue::Stats,
    pub groups: Vec<Arc<trames_kernel::task_control::Group>>,
}
pub(super) fn publish<C: Cpu>(
    p: &mut Process<C>,
    mut done: crate::workers::Done<C>,
    instructions: u64,
) -> Published {
    Kernel::<C>::log_worker_diagnostics(p, &done);
    p.linux.vfs.sync_task_namespaces();
    p.cpu = std::mem::take(&mut done.cpu);
    p.trace = std::mem::take(&mut done.trace);
    p.signals.finish_io();
    if let Some(entry) = done.seccomp_entry.take() {
        p.seccomp_entry = Some(entry);
    }
    p.retain_worker_flock(done.io.as_ref());
    p.retained_byte = done.io.as_ref().and_then(|call| call.retained_byte.clone());
    p.retained_socket = done
        .io
        .as_ref()
        .and_then(|call| call.retained_socket.clone());
    p.tcp_liveness = done.io.as_ref().and_then(|call| call.tcp_liveness.clone());
    p.retained_poll = done.io.as_ref().and_then(|call| call.retained_poll.clone());
    p.retained_file = done.io.as_ref().and_then(|call| call.file.clone());
    p.retained_aio = done.io.as_ref().and_then(|call| call.aio.clone());
    p.file_checkpoint = done
        .io
        .as_ref()
        .and_then(|call| call.file_checkpoint.clone());
    p.file_entry = done
        .io
        .as_ref()
        .filter(|call| call.file.is_some() || call.file_checkpoint.is_some())
        .map(|call| (p.cpu.pc(), call.number, call.args));
    p.state = if let Some(compile) = done.gpu_pending.take() {
        State::Gpu {
            retired: true,
            peer_instructions: compile.peer_instructions,
            job: compile.job,
            pc: compile.call.pc,
            operation: compile.call.operation,
            began: compile.began,
            instructions,
        }
    } else if let Some(call) = done.io.take() {
        if let Some(uring) = call.uring {
            p.uring_wait = Some((uring.submitted, uring.ring, uring.deadline));
        }
        if matches!(call.number, 63..=66 | 202 | 203 | 242) {
            p.socket_deadline = call.deadline;
        } else {
            p.poll_deadline = call.deadline;
        }
        State::Blocked(call.number, call.args)
    } else {
        if !matches!(done.waiting, Some(crate::run_queue::WaitState::OwnerEvent)) {
            p.poll_deadline = None;
        }
        done.waiting.take().map_or(State::Ready, |w| match w {
            crate::run_queue::WaitState::Futex { wait, deadline } => {
                State::Futex { wait, deadline }
            }
            crate::run_queue::WaitState::Sleep {
                deadline,
                remaining,
            } => State::Sleep(deadline, remaining),
            crate::run_queue::WaitState::Signal(wait) => match wait.request {
                trames_kernel::signal::SignalWait::Timed {
                    mask,
                    info,
                    deadline,
                } => State::Sigwait {
                    mask,
                    info,
                    deadline,
                },
                trames_kernel::signal::SignalWait::Suspend { .. } => {
                    State::Suspend(p.signals.wait_mask.take().expect("suspend restore mask"))
                }
            },
            crate::run_queue::WaitState::Child(wait) => {
                State::Blocked(wait.request.number, wait.request.args)
            }
            crate::run_queue::WaitState::Namespace(wait) => State::Namespace(wait),
            crate::run_queue::WaitState::Policy(wait) => State::Policy(wait),
            crate::run_queue::WaitState::Barrier(wait) => State::Barrier(wait),
            crate::run_queue::WaitState::Custody(_) => State::Ready,
            crate::run_queue::WaitState::Completion(wait) => {
                State::Completion(wait.release.clone())
            }
            crate::run_queue::WaitState::OwnerEvent => p.state.clone(),
        })
    };
    p.last_cpu = done.worker;
    p.cpu_time += done.elapsed;
    let outcome = done.outcome.take();
    if let Some(status) = done.thread_exit {
        p.state = State::Zombie(status);
    }
    let group = p.signals.io.lifecycle().clone();
    let mut groups = std::mem::take(&mut done.exit_groups);
    if group.termination().is_some() {
        groups.push(group);
    }
    Published {
        outcome,
        stats: done.take_stats(),
        groups,
    }
}
