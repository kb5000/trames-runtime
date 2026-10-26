// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::MemoryError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub signal: u32,
    pub code: i32,
    pub address: u64,
}
impl Fault {
    pub fn memory(pc: u64, error: &MemoryError) -> Self {
        use MemoryError as M;
        let (signal, code, address) = match error {
            M::Limit => (9, 0, pc),
            M::Bus(address) => (7, 2, *address),
            M::BackingIo(_) => (7, 3, pc),
            M::Alignment(address) => (7, 1, *address),
            M::Permission { address, .. } => (11, 2, *address),
            M::Unmapped(address) | M::AddressRange(address) => (11, 1, *address),
            _ => (11, 1, pc),
        };
        Self {
            signal,
            code,
            address,
        }
    }
}
impl Signals {
    /// A synchronous fault cannot remain ignored/masked. Return false when the
    /// task group must terminate. Preserve precise fault info over an earlier
    /// asynchronous signal of the same number, as the existing runtime does.
    pub fn force_fault(&mut self, fault: Fault) -> bool {
        let Fault {
            signal,
            code,
            address,
        } = fault;
        if self.actions.get(signal as usize).handler <= 1 || self.mask & (1 << (signal - 1)) != 0 {
            return false;
        }
        self.pending.discard(signal);
        let _ = self.pending.enqueue(
            signal,
            Info {
                code,
                fault: Some(address & 0x00ffffffffffffff),
                ..Default::default()
            },
        );
        true
    }
    pub fn select(&self, stopped: bool, defer_handlers: bool) -> Option<(u32, bool)> {
        if self.pending_bits() & (1 << 8) != 0 {
            return self.next_signal(1 << 8);
        }
        if let Some((&sig, _)) = self.pending.iter().find(|(_, info)| info.fault.is_some()) {
            return Some((sig, false));
        }
        let mut allowed = !self.mask | UNBLOCKABLE;
        if stopped {
            allowed &= 1 << 17;
        }
        if defer_handlers {
            allowed &= !self.actions.masks().1;
        }
        self.next_signal(allowed)
    }
}
