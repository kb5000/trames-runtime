// SPDX-License-Identifier: GPL-3.0-or-later
//! A single retained batch owns its progress, current message and resolved target.
use super::*;
use crate::network::unix::DatagramState;
use std::sync::Mutex;

pub(super) struct Batch {
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    completed: u64,
    active: Option<RetainedByte>,
    // Only an unaccepted owner-only item lacks a portable prepared message.
    // Earlier completed items and the full source OFD still remain accepted.
    owner_target: Option<DatagramState>,
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
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let state = self.state.lock().unwrap();
        if let Some(active) = &state.active {
            return active.subscribe(signal);
        }
        state
            .owner_target
            .as_ref()
            .and_then(|d| d.target.get())
            .map(|t| vec![t.subscribe(signal)])
            .unwrap_or_default()
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        let state = self.state.lock().unwrap();
        state
            .active
            .as_ref()
            .is_some_and(|f| f.shares_resources(fds))
            || state
                .owner_target
                .as_ref()
                .and_then(|d| d.target.get())
                .is_some_and(|t| t.shares_resources(fds))
    }
    /// This mutex belongs to this accepted syscall, not to Files/socket/queue
    /// resources. No other guest call is serialized by the progress record.
    pub fn progress(
        &self,
        direct: &DirectSyscalls,
        accepted: &AcceptedMessage,
        fd: &trames_vfs::DirectFd,
        memory: &mut impl CpuMemory,
        mut owner: Option<(&mut trames_vfs::Vfs, &std::rc::Rc<trames_vfs::LocalSocket>)>,
    ) -> Option<Result<u64, Errno>> {
        let mut state = self.state.lock().unwrap();
        let a = accepted.args;
        let count = (a[2] as u32).min(1024) as u64;
        loop {
            if let Some(result) = state.terminal {
                return if state.pipe && owner.is_none() {
                    None
                } else {
                    Some(result)
                };
            }
            if state.completed == count {
                state.terminal = Some(Ok(count));
                continue;
            }
            let mut deferred = false;
            let result = (|| {
                let header = a[1].checked_add(state.completed * 64).ok_or(Errno(14))?;
                let item_args = [a[0], header, a[3] as u32 as u64, 0, 0, 0];
                if state.active.is_none() && state.owner_target.is_none() {
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
                            if fd.is_addressed_datagram() {
                                state.owner_target = Some(DatagramState::new(
                                    fd.local_operation().expect("accepted datagram OFD"),
                                ));
                            }
                        }
                    }
                }
                let sent = if let Some(item) = &state.active {
                    if let Some((vfs, socket)) = owner.as_mut() {
                        let Transfer::Single { prepared, datagram } =
                            &item.message().expect("accepted item").transfer
                        else {
                            unreachable!()
                        };
                        crate::network::unix::progress_owned(
                            prepared,
                            vfs,
                            socket,
                            if fd.nonblocking() { 0x40 } else { 0 },
                            memory,
                            datagram.as_ref(),
                        )
                    } else {
                        // A path/ancillary fallback keeps this exact item and
                        // its target, rather than resending earlier messages.
                        direct
                            .transfer_retained(item, 211, item_args, memory)
                            .unwrap_or_else(|| {
                                deferred = true;
                                Err(Errno(11))
                            })
                    }
                } else if let Some((vfs, socket)) = owner.as_mut() {
                    crate::network::unix::batch_owner_message(
                        vfs,
                        socket,
                        item_args,
                        memory,
                        state.owner_target.as_ref(),
                    )
                } else {
                    deferred = true;
                    return Err(Errno(11));
                }?;
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
                    state.owner_target = None;
                    if short {
                        state.terminal = Some(Ok(state.completed));
                    }
                }
                Err(Errno(11)) if state.completed == 0 => return Some(Err(Errno(11))),
                Err(error) => {
                    if error.0 == 32 && a[3] as u32 & 0x4000 == 0 {
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
