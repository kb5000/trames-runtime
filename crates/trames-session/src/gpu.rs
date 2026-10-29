// SPDX-License-Identifier: GPL-3.0-or-later
//! GPU resource waits retain the original task and notify the shared run queue.
use std::{
    sync::{Arc, Weak},
    time::Instant,
};
use trames_accel::native::{Error, Return};
use trames_memory::CpuMemory;
use trames_vfs::{IoSignal, IoSubscription, IoWake, WaylandAuth};
use trames_vulkan::{Context, Invocation};

#[derive(Clone)]
pub(super) struct Authority {
    pub context: Context,
    pub auth: WaylandAuth,
}
impl From<Context> for Authority {
    fn from(context: Context) -> Self {
        Self {
            context,
            auth: Default::default(),
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Call {
    pub pc: u64,
    pub operation: u64,
    pub args: [u64; 3],
}
#[derive(Clone, Copy)]
pub(super) struct Compile {
    pub call: Call,
    pub job: u64,
    pub began: Instant,
    pub peer_instructions: u64,
}
pub(super) struct Pending {
    pub call: Call,
    pub compile: Option<Compile>,
    signal: Option<Arc<IoSignal>>,
    context_subscription: Option<IoSubscription>,
    task_subscription: Option<IoSubscription>,
    peer_started: u64,
}
pub(super) enum Attempt {
    Complete(Result<Return, Error>),
    Blocked(Pending),
    Checkpoint,
}
impl Pending {
    pub fn new(call: Call) -> Self {
        Self {
            call,
            compile: None,
            signal: None,
            context_subscription: None,
            task_subscription: None,
            peer_started: 0,
        }
    }
    pub fn adopted(compile: Compile) -> Self {
        Self {
            compile: Some(compile),
            ..Self::new(compile.call)
        }
    }
    pub fn signal(&self) -> &Arc<IoSignal> {
        self.signal.as_ref().expect("armed GPU wait")
    }
    pub fn waiting(&self) -> bool {
        // An adopted compile has not registered a wake yet. Give it a worker
        // turn to subscribe and poll before any VM checkpoint can park it.
        self.signal.as_ref().is_some_and(|signal| !signal.ready())
    }
    pub fn checkpoint(&self, peer: u64) -> Option<Compile> {
        self.compile.map(|mut c| {
            c.peer_instructions += peer.saturating_sub(self.peer_started);
            c
        })
    }
    fn arm(&mut self, pid: u32, target: &Weak<dyn IoWake>) {
        if self.signal.is_none() {
            self.signal = Some(IoSignal::new(pid, target.clone()));
        }
    }
    pub fn progress(
        mut self,
        authority: &Authority,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        stats: &mut crate::workers::GpuStats,
        peer: u64,
    ) -> Attempt {
        if let Some(signal) = &self.signal {
            signal.reset();
        }
        let mut lease = if let Some(lease) = authority.context.try_lock() {
            lease
        } else {
            self.arm(pid, target);
            self.context_subscription = Some(authority.context.subscribe(self.signal()));
            let Some(lease) = authority.context.try_lock() else {
                return Attempt::Blocked(self);
            };
            lease
        };
        // Do not wake ourselves on this lease's release. Only tasks still
        // waiting for the context subscribe to its unlock notification.
        self.context_subscription = None;
        if self.compile.is_none() {
            let authenticated =
                if matches!(self.call.operation, 110 | 111) && self.call.args[2] == 128 {
                    let Some(address) = self.call.args[1].checked_add(8) else {
                        return Attempt::Complete(Err(Error::InvalidEntry));
                    };
                    let fd = match memory.read_u64(address) {
                        Ok(fd) => fd,
                        Err(e) => return Attempt::Complete(Err(Error::Memory(e))),
                    };
                    let Some(authenticated) = u32::try_from(fd)
                        .ok()
                        .and_then(|fd| authority.auth.resolve(fd))
                    else {
                        // The owner may need to pump a newly transferred right.
                        // No backend or guest output effects have happened.
                        return Attempt::Checkpoint;
                    };
                    Some(authenticated)
                } else {
                    None
                };
            let (value, transfers) = lease.invoke(
                memory,
                self.call.operation,
                self.call.args[1],
                self.call.args[2],
                authenticated,
            );
            stats.record(self.call.pc, self.call.operation, &value, transfers);
            match value {
                Ok(Invocation::Complete(value)) => {
                    return Attempt::Complete(Ok(Return {
                        value,
                        fallback: false,
                    }))
                }
                Err(e) => return Attempt::Complete(Err(Error::Memory(e))),
                Ok(Invocation::Pending(job)) => {
                    stats.compiles += 1;
                    self.compile = Some(Compile {
                        call: self.call,
                        job,
                        began: Instant::now(),
                        peer_instructions: 0,
                    });
                    self.peer_started = peer;
                }
            }
        }
        self.arm(pid, target);
        let compile = self.compile.unwrap();
        // Subscription and the deciding result check share the same context
        // lease; publish/disconnect also wakes on panic or owner cancellation.
        self.task_subscription = lease.subscribe_compile(compile.job, self.signal());
        let value = lease.poll(memory, compile.job);
        match value {
            Ok(None) => Attempt::Blocked(self),
            value => {
                stats.wait_time += compile.began.elapsed();
                stats.peer_instructions +=
                    compile.peer_instructions + peer.saturating_sub(self.peer_started);
                let value = value
                    .map_err(Error::Memory)
                    .map(|v| v.expect("completed GPU result"));
                if let Ok(value) = value {
                    stats.record_error(self.call.pc, self.call.operation, value);
                }
                Attempt::Complete(value.map(|value| Return {
                    value,
                    fallback: false,
                }))
            }
        }
    }
}
