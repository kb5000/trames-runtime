// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux task signal ownership and ABI. Execution engines supply architectural
//! state only at delivery/return boundaries; ordinary execution is untouched.
mod actions;
mod alt_stack;
mod fault;
mod frame;
mod info;
mod pending;
pub use actions::{Action, Actions};
pub use alt_stack::{AltStack, SS_AUTODISARM, SS_DISABLE};
pub use fault::Fault;
pub use info::{write_siginfo, write_signalfd, Info};
pub use pending::Pending;
use std::{cell::RefCell, rc::Rc};
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;

pub const UNBLOCKABLE: u64 = (1 << 8) | (1 << 18);

#[derive(Default)]
pub struct Signals {
    pub actions: Actions,
    pub mask: u64,
    pub pending: Pending,
    pub shared_pending: Rc<RefCell<Pending>>,
    pub frames: u32,
    pub alt_stack: AltStack,
}
impl Signals {
    /// A fork starts with empty queues. CLONE_SIGHAND shares dispositions;
    /// CLONE_THREAD additionally adopts the existing process pending queue.
    pub fn fork(&self, shared_actions: bool) -> Self {
        Self {
            actions: if shared_actions {
                self.actions.shared()
            } else {
                self.actions.clone()
            },
            mask: self.mask,
            pending: Pending::default(),
            shared_pending: Rc::new(RefCell::new(Pending::default())),
            frames: self.frames,
            alt_stack: self.alt_stack,
        }
    }
    pub fn exec(&mut self) {
        self.actions = self.actions.exec();
        self.frames = 0;
        self.alt_stack = AltStack::default();
    }
    pub fn pending_bits(&self) -> u64 {
        self.pending.bits() | self.shared_pending.borrow().bits()
    }
    /// Linux selects a task's private queue before its process queue.
    pub fn next_signal(&self, mask: u64) -> Option<(u32, bool)> {
        self.pending.next(mask).map(|sig| (sig, false)).or_else(|| {
            self.shared_pending
                .borrow()
                .next(mask)
                .map(|sig| (sig, true))
        })
    }
    pub fn take_signal(&mut self, sig: u32, shared: bool) -> Info {
        if shared {
            self.shared_pending.borrow_mut().remove(&sig)
        } else {
            self.pending.remove(&sig)
        }
        .expect("selected pending signal")
    }
    pub fn signal_senders(&self) -> Vec<u32> {
        self.pending
            .values()
            .chain(self.shared_pending.borrow().values())
            .map(|i| i.sender)
            .collect()
    }
    pub fn discard(&mut self, sig: u32) {
        self.pending.discard(sig);
        self.shared_pending.borrow_mut().discard(sig);
    }
    pub fn clear_opposing(&mut self, sig: u32) {
        if sig == 18 {
            for stopped in 19..=22 {
                self.discard(stopped);
            }
        }
        if matches!(sig, 19..=22) {
            self.discard(18);
        }
    }
    pub fn should_queue(&self, sig: u32) -> bool {
        sig != 0
            && (matches!(sig, 9 | 19)
                || self.actions.get(sig as usize).handler != 1
                || self.mask & (1 << (sig - 1)) != 0)
    }
    /// rt_sigaction mutation plus task/process queue effects. The task-group
    /// owner must also discard the signal in the other threads' private queues.
    pub fn action_call(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<Option<Action>, Errno> {
        let action = self.actions.call(a, memory)?;
        if action.is_some_and(|x| ignored(a[0] as u32, x)) {
            self.discard(a[0] as u32);
        }
        Ok(action)
    }
    pub fn mask_call(&mut self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        if a[3] != 8 {
            return Err(Errno(22));
        }
        if a[2] != 0 {
            memory
                .check(a[2], 8, Access::Write)
                .map_err(|_| Errno(14))?;
        }
        let new = if a[1] != 0 {
            let bits = u64::from_le_bytes(memory.read_array(a[1]).map_err(|_| Errno(14))?);
            Some(
                match a[0] {
                    0 => self.mask | bits,
                    1 => self.mask & !bits,
                    2 => bits,
                    _ => return Err(Errno(22)),
                } & !UNBLOCKABLE,
            )
        } else {
            None
        };
        if a[2] != 0 {
            memory
                .write_array(a[2], self.mask.to_le_bytes())
                .map_err(|_| Errno(14))?;
        }
        if let Some(mask) = new {
            self.mask = mask;
        }
        Ok(0)
    }
}
pub fn ignored(sig: u32, action: Action) -> bool {
    action.handler == 1 || action.handler == 0 && matches!(sig, 17 | 23 | 28)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Terminate,
    Stop,
    Ignore,
    Handler,
}
pub fn disposition(sig: u32, action: Action) -> Disposition {
    if sig == 9 || action.handler == 0 && !matches!(sig, 17 | 18 | 23 | 28 | 19..=22) {
        Disposition::Terminate
    } else if sig == 19 || action.handler == 0 && matches!(sig, 20..=22) {
        Disposition::Stop
    } else if action.handler <= 1 {
        Disposition::Ignore
    } else {
        Disposition::Handler
    }
}
