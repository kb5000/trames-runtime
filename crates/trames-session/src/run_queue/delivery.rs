// SPDX-License-Identifier: GPL-3.0-or-later
//! A selected signal owns interrupted output through the original handler
//! entry. It never returns to a competing reader while a user copy is parked.
use super::{ChildWait, IoCall, WaitState};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use trames_kernel::signal::{Action, RetainedInfo};
use trames_memory::{CpuMemory, MemoryError, PageFault, PAGE_SIZE};
use trames_vfs::{Errno, IoSignal, IoSubscription};

pub(crate) struct Delivery {
    state: Mutex<Option<State>>,
    pending: Mutex<Option<PageFault>>,
    wake: Mutex<Option<(Arc<IoSignal>, IoSubscription)>>,
}
struct State {
    sig: u32,
    info: RetainedInfo,
    action: Action,
    finish: Finish,
}
enum Finish {
    Io(Box<IoCall>),
    Child(Arc<ChildWait>),
    Remainder {
        address: u64,
        bytes: [u8; 16],
        copied: usize,
    },
    Interrupted,
    Continue,
}
pub(crate) struct Completion {
    pub number: Option<u32>,
    pub args: [u64; 6],
    pub result: Result<u64, Errno>,
    pub restart: bool,
    pub account_io: bool,
}
pub(crate) struct Delivered {
    pub sig: u32,
    pub info: RetainedInfo,
    pub action: Action,
    pub completion: Option<Completion>,
}
impl Delivery {
    pub fn new(
        sig: u32,
        info: RetainedInfo,
        action: Action,
        waiting: Option<WaitState>,
        io: Option<IoCall>,
    ) -> Arc<Self> {
        let finish = if let Some(io) = io {
            Finish::Io(Box::new(io))
        } else {
            match waiting {
                Some(WaitState::Child(wait)) => Finish::Child(wait),
                Some(WaitState::Sleep {
                    deadline,
                    remaining,
                }) => remainder(
                    remaining,
                    deadline.saturating_duration_since(Instant::now()),
                ),
                Some(WaitState::ClockSleep(wait)) => {
                    let (address, left) = wait.interruption();
                    remainder(address, left)
                }
                Some(WaitState::Futex { wait, .. }) => {
                    wait.cancel();
                    Finish::Interrupted
                }
                Some(WaitState::Cgroup(_)) | None => Finish::Continue,
                Some(_) => Finish::Interrupted,
            }
        };
        Arc::new(Self {
            state: Mutex::new(Some(State {
                sig,
                info,
                action,
                finish,
            })),
            pending: Default::default(),
            wake: Default::default(),
        })
    }
    pub fn ready(&self) -> bool {
        self.pending
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|fault| fault.wait.ready())
    }
    pub fn external(&self) -> bool {
        self.pending.lock().unwrap().is_some()
    }
    pub fn cancel(&self) {
        let state = self.state.lock().unwrap().take();
        self.pending.lock().unwrap().take();
        self.wake.lock().unwrap().take();
        if let Some(State {
            finish: Finish::Io(io),
            ..
        }) = &state
        {
            if let Some(binder) = &io.binder {
                binder.cancel();
            }
            if let Some(uring) = &io.uring {
                uring.cancel();
            }
            if let Some(aio) = &io.aio {
                aio.cancel();
            }
            if let Some(file) = &io.file {
                file.cancel_import();
            }
            if let Some(call) = &io.file_checkpoint {
                call.cancel();
            }
        }
        drop(state);
    }
    pub fn bind(&self, signal: &Arc<IoSignal>) {
        let fault = self.pending.lock().unwrap().clone();
        if let Some(fault) = fault {
            let subscription = fault.wait.subscribe(signal);
            *self.wake.lock().unwrap() = Some((signal.clone(), subscription));
            if fault.wait.ready() {
                signal.notify();
            }
        }
    }
    pub fn progress(&self, memory: &mut impl CpuMemory) -> Option<Delivered> {
        let mut slot = self.state.lock().unwrap();
        let state = slot.as_mut()?;
        let mut fault = None;
        let completion = match &mut state.finish {
            Finish::Io(io) => {
                if let Some(binder) = &io.binder {
                    let result = binder.interrupted(memory);
                    fault = binder.copy_fault();
                    // Binder's native wait returns EINTR rather than a
                    // restart errno, including with SA_RESTART installed.
                    result.map(|result| Completion {
                        number: Some(io.number),
                        args: io.args,
                        result,
                        restart: false,
                        account_io: true,
                    })
                } else {
                    let result = if let Some(wait) = &io.retained_poll {
                        wait.finish(memory, Err(Errno(4)))
                    } else {
                        io.uring
                            .as_ref()
                            .map(trames_linux::UringEnter::interrupted)
                            .or_else(|| io.aio.as_ref().map(trames_linux::RetainedAio::interrupted))
                            .or_else(|| io.retained_byte.as_ref()?.interrupted(memory))
                            .or_else(|| io.retained_socket.as_ref()?.interrupted(memory))
                            .unwrap_or(Err(Errno(4)))
                    };
                    fault = trames_linux::DirectSyscalls::interrupted_copy_fault(
                        io.retained_byte.as_ref(),
                        io.retained_socket.as_ref(),
                        io.retained_poll.as_ref(),
                    );
                    Some(Completion {
                        number: Some(io.number),
                        args: io.args,
                        result,
                        restart: result == Err(Errno(4))
                            && io.deadline.is_none()
                            && restartable(io.number)
                            && state.action.flags & 0x1000_0000 != 0,
                        account_io: true,
                    })
                }
            }
            Finish::Child(wait) => {
                let (result, pending) = wait.interrupt(memory);
                fault = pending;
                result.map(|result| Completion {
                    number: Some(wait.number),
                    args: wait.args,
                    result,
                    restart: result == Err(Errno(4)) && state.action.flags & 0x1000_0000 != 0,
                    account_io: false,
                })
            }
            Finish::Remainder {
                address,
                bytes,
                copied,
            } => {
                let mut result = Err(Errno(4));
                while *copied < bytes.len() {
                    let Some(at) = address.checked_add(*copied as u64) else {
                        result = Err(Errno(14));
                        break;
                    };
                    let count = (bytes.len() - *copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
                    match memory.write(at, &bytes[*copied..*copied + count]) {
                        Ok(()) => *copied += count,
                        Err(MemoryError::Pending(pending)) => {
                            fault = Some(pending);
                            break;
                        }
                        Err(_) => {
                            result = Err(Errno(14));
                            break;
                        }
                    }
                }
                Some(Completion {
                    number: None,
                    args: [0; 6],
                    result,
                    restart: false,
                    account_io: false,
                })
            }
            Finish::Interrupted => Some(Completion {
                number: None,
                args: [0; 6],
                result: Err(Errno(4)),
                restart: false,
                account_io: false,
            }),
            Finish::Continue => None,
        };
        let pending = fault.is_some();
        *self.pending.lock().unwrap() = fault;
        if pending {
            drop(slot);
            let signal = self
                .wake
                .lock()
                .unwrap()
                .as_ref()
                .map(|(signal, _)| signal.clone());
            if let Some(signal) = signal {
                self.bind(&signal);
            }
            return None;
        }
        let state = slot.take().unwrap();
        drop(slot);
        self.wake.lock().unwrap().take();
        Some(Delivered {
            sig: state.sig,
            info: state.info,
            action: state.action,
            completion,
        })
    }
}
fn restartable(number: u32) -> bool {
    matches!(number, 25 | 29 | 32 | 56 | 63..=66 | 71 | 76..=77 | 95 | 260 | 202 | 242 | 206 | 207 | 211 | 212 | 243 | 269)
}
fn remainder(address: u64, left: Duration) -> Finish {
    if address == 0 {
        return Finish::Interrupted;
    }
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&left.as_secs().to_le_bytes());
    bytes[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_le_bytes());
    Finish::Remainder {
        address,
        bytes,
        copied: 0,
    }
}
