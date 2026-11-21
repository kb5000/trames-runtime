// SPDX-License-Identifier: GPL-3.0-or-later
//! A single retained batch owns its progress, current message and resolved target.
use super::*;
use std::sync::Mutex;

pub(super) struct Batch {
    state: Mutex<State>,
    receive: Option<crate::network_batch::Receive>,
}
#[derive(Default)]
struct State {
    completed: u64,
    active: Option<RetainedByte>,
    requested: u64,
    terminal: Option<Result<u64, Errno>>,
    finished: bool,
    pipe: bool,
}
impl Batch {
    pub fn new(number: u32, args: [u64; 6], memory: &impl CpuMemory) -> Result<Self, Errno> {
        if args[3] as u32 & 0x8000_0000 != 0 {
            return Err(Errno(22));
        }
        Ok(Self {
            state: Mutex::default(),
            receive: if number == 243 {
                Some(crate::network_batch::Receive::new(args, memory)?)
            } else {
                None
            },
        })
    }
    fn finish(
        &self,
        result: Result<u64, Errno>,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        self.receive
            .as_ref()
            .map_or(result, |receive| receive.finish(result, memory))
    }
    pub fn partial_receive(&self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        self.receive.as_ref()?;
        let mut state = self.state.lock().unwrap();
        if state.completed == 0 {
            return None;
        }
        let result = self.finish(Ok(state.completed), memory);
        state.terminal = Some(result);
        state.finished = true;
        Some(result)
    }
    pub fn pipe_signal(&self) -> bool {
        self.state.lock().unwrap().pipe
    }
    pub fn take_pipe_signal(&self) -> bool {
        std::mem::take(&mut self.state.lock().unwrap().pipe)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let state = self.state.lock().unwrap();
        if let Some(active) = &state.active {
            return active.subscribe(signal);
        }
        Vec::new()
    }

    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        let state = self.state.lock().unwrap();
        state
            .active
            .as_ref()
            .is_some_and(|f| f.shares_resources(fds))
    }

    /// This mutex belongs to this accepted syscall, not to Files/socket/queue
    /// resources. No other guest call is serialized by the progress record.
    pub fn progress(
        &self,
        direct: &DirectSyscalls,
        accepted: &AcceptedMessage,
        fd: &trames_vfs::DirectFd,
        memory: &mut impl CpuMemory,
        original_paths: Option<&trames_vfs::Vfs>,
    ) -> Option<Result<u64, Errno>> {
        let mut state = self.state.lock().unwrap();
        let a = accepted.args;
        let receive = self.receive.is_some();
        let operation = if receive { 212 } else { 211 };
        let count = if receive {
            a[2] as u32 as u64
        } else {
            (a[2] as u32).min(1024) as u64
        };
        loop {
            if let Some(result) = state.terminal {
                let result = if !state.finished {
                    self.finish(result, memory)
                } else {
                    result
                };
                state.finished = true;
                state.terminal = Some(result);
                return Some(result);
            }
            if state.completed == count {
                state.terminal = Some(Ok(count));
                continue;
            }
            let flags = if receive {
                crate::network_batch::Receive::flags(a[3] as u32, state.completed)
            } else {
                a[3] as u32
            };
            let mut deferred = false;
            let result = (|| {
                let header = a[1].checked_add(state.completed * 64).ok_or(Errno(14))?;
                let item_args = [a[0], header, flags as u64, 0, 0, 0];
                if state.active.is_none() {
                    if !receive {
                        state.requested = crate::network_batch::requested(memory, header)?;
                    }
                    match direct.prepare_local_context(
                        fd,
                        operation,
                        item_args,
                        memory,
                        (&accepted.factory, accepted.identity),
                        false, // sendmmsg publishes a short item and completes its batch.
                    ) {
                        Some(Ok(item)) => state.active = Some(item),
                        Some(Err(error)) => return Err(error),
                        None => {
                            deferred = true;
                            return Err(Errno(11));
                        }
                    }
                }
                let sent = direct
                    .transfer_retained(
                        state.active.as_ref().expect("accepted item"),
                        operation,
                        item_args,
                        memory,
                        original_paths,
                    )
                    .unwrap_or_else(|| {
                        deferred = true;
                        Err(Errno(11))
                    })?;
                // Match Linux: msg_len copyout follows transport effects.
                // A later EFAULT cannot undo delivery or replay this packet.
                memory
                    .write(
                        header.checked_add(56).ok_or(Errno(14))?,
                        &(sent as u32).to_le_bytes(),
                    )
                    .map_err(|_| Errno(14))?;
                Ok(sent)
            })();
            if deferred {
                return None;
            }
            match result {
                Ok(sent) => {
                    let short = !receive && sent < state.requested
                        || self.receive.as_ref().is_some_and(|r| r.expired());
                    state.completed += 1;
                    state.active = None;
                    if short {
                        state.terminal = Some(Ok(state.completed));
                    }
                }
                Err(Errno(11))
                    if state.completed == 0
                        || receive && flags & 0x40 == 0 && !fd.nonblocking() =>
                {
                    return Some(Err(Errno(11)))
                }
                Err(error) => {
                    if !receive
                        && error.0 == 32
                        && fd.local_kind() == 1
                        && a[3] as u32 & 0x4000 == 0
                    {
                        state.pipe = true;
                    }
                    state.terminal = Some(if state.completed == 0 {
                        Err(error)
                    } else {
                        Ok(state.completed)
                    });
                }
            }
        }
    }
}
