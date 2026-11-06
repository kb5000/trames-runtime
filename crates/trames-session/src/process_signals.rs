// SPDX-License-Identifier: GPL-3.0-or-later
//! Task-group routing and signalfd integration over common signal state.
use super::*;

impl<C: Cpu> Process<C> {
    pub(super) fn pending_bits(&self) -> u64 {
        self.signals.pending_bits()
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn next_signal(&self, mask: u64) -> Option<(u32, bool)> {
        self.signals.next_signal(mask)
    }
    pub(super) fn take_signal(&mut self, sig: u32, shared: bool) -> Option<Info> {
        let mut info = self.signals.io.take(sig, shared)?;
        if info.fault.is_none() && info.poll.is_none() {
            info.sender = self.linux.vfs.visible_pid(info.sender);
        }
        Some(*info)
    }
}

impl<C: Cpu> Kernel<C> {
    pub(super) fn signalfd(&self, p: &mut Process<C>, a: [u64; 6]) -> Result<Option<u64>, Errno> {
        p.linux.signalfd(a, &p.memory).map(Some)
    }
}
