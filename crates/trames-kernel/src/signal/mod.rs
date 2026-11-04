// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux task signal ownership and ABI. Execution engines supply architectural
//! state only at delivery/return boundaries; ordinary execution is untouched.
mod actions;
mod alt_stack;
mod control;
mod fault;
mod frame;
pub use frame::FrameState;
mod info;
mod io;
mod pending;
mod reader;
mod wait;
pub use actions::{Action, Actions};
pub use alt_stack::{AltStack, SS_AUTODISARM, SS_DISABLE};
pub use fault::Fault;
pub use info::{write_siginfo, write_signalfd, Info};
pub use io::{Inbox, IoContext, IoDirectory, IoRoutes, IoTask, TimerTarget};
pub use pending::Pending;
pub use reader::TaskReader;
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;
pub use wait::SignalWait;

pub const UNBLOCKABLE: u64 = (1 << 8) | (1 << 18);

#[derive(Default)]
pub struct Signals {
    pub presence: std::sync::Arc<()>,
    pub reader: std::sync::OnceLock<std::sync::Arc<TaskReader>>,
    pub io: std::sync::Arc<IoTask>,
    pub io_directory: std::sync::Arc<IoDirectory>,
    pub actions: Actions,
    pub mask: u64,
    pub wait_mask: Option<u64>,
    pub frames: u32,
    pub alt_stack: AltStack,
}
impl Signals {
    /// A fork starts with empty queues. CLONE_SIGHAND shares dispositions;
    /// CLONE_THREAD additionally adopts the existing process pending queue.
    pub fn fork(&self, shared_actions: bool) -> Self {
        Self {
            presence: Default::default(),
            reader: Default::default(),
            io: Default::default(),
            io_directory: self.io_directory.clone(),
            actions: if shared_actions {
                self.actions.shared()
            } else {
                self.actions.clone()
            },
            mask: self.mask,
            wait_mask: None,
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
        self.io.inbox.bits() | self.io.process().bits()
    }
    pub fn next_signal(&self, mask: u64) -> Option<(u32, bool)> {
        self.io.next(mask)
    }
    pub fn take_signal(&self, sig: u32, shared: bool) -> Info {
        self.io.take(sig, shared).expect("selected pending signal")
    }
    pub fn signal_senders(&self) -> Vec<u32> {
        let mut senders = self.io.inbox.senders();
        senders.extend(self.io.process().senders());
        senders
    }
    pub fn discard(&self, sig: u32) {
        self.io.inbox.discard(sig);
        self.io.process().discard(sig);
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
    /// rt_sigaction mutation and task/process queue effects share sighand.
    pub fn action_call(
        &mut self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<Option<Action>, Errno> {
        self.actions.call_with(a, memory, |action| {
            if ignored(a[0] as u32, action)
                && !self
                    .io_directory
                    .discard_process(self.io.tgid(), a[0] as u32)
            {
                self.discard(a[0] as u32);
            }
        })
    }
    pub fn mask_call(&mut self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        if let Some(mask) = control::update_mask(self.mask, a, memory)? {
            self.mask = mask;
            self.io.publish_mask(mask);
        }
        // Context custody is transferred only at begin_io/finish_io. An owner
        // query needs neither a context mutex nor a redundant mask publication.
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
