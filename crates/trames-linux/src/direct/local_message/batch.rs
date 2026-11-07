// SPDX-License-Identifier: GPL-3.0-or-later
//! A single retained batch owns its progress, current message and resolved target.
use super::*;
use std::sync::Mutex;

pub(super) struct Batch {
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    completed: u64,
    active: Option<RetainedByte>,
    requested: u64,
    terminal: Option<Result<u64, Errno>>,
    pipe: bool,
}
impl Batch {
    pub fn new(args: [u64; 6]) -> Result<Self, Errno> {
        if args[3] as u32 & 0x8000_0000 != 0 {
            return Err(Errno(22));
        }
        Ok(Self {
            state: Mutex::default(),
        })
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
        let count = (a[2] as u32).min(1024) as u64;
        loop {
            if let Some(result) = state.terminal {
                return Some(result);
            }
            if state.completed == count {
                state.terminal = Some(Ok(count));
                continue;
            }
            let mut deferred = false;
            let result = (|| {
                let header = a[1].checked_add(state.completed * 64).ok_or(Errno(14))?;
                let item_args = [a[0], header, a[3] as u32 as u64, 0, 0, 0];
                if state.active.is_none() {
                    state.requested = crate::network_batch::requested(memory, header)?;
                    match direct.prepare_local_context(
                        fd,
                        211,
                        item_args,
                        memory,
                        (&accepted.factory, accepted.identity),
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
                        211,
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
                    let short = sent < state.requested;
                    state.completed += 1;
                    state.active = None;
                    if short {
                        state.terminal = Some(Ok(state.completed));
                    }
                }
                Err(Errno(11)) if state.completed == 0 => return Some(Err(Errno(11))),
                Err(error) => {
                    if error.0 == 32 && fd.local_kind() == 1 && a[3] as u32 & 0x4000 == 0 {
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
