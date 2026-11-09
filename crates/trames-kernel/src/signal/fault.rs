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
    /// The original thread inbox owns precise synchronous fault information.
    /// Keep the same forced-fault policy for solo and source executors.
    pub fn queue(self, actions: &Actions, mask: u64, inbox: &Inbox) -> bool {
        let Self {
            signal,
            code,
            address,
        } = self;
        if actions.get(signal as usize).handler <= 1 || mask & (1 << (signal - 1)) != 0 {
            return false;
        }
        inbox.discard(signal);
        let _ = inbox.enqueue(
            signal,
            Info {
                code,
                fault: Some(address & 0x00ffffffffffffff),
                ..Default::default()
            },
        );
        true
    }
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
        fault.queue(&self.actions, self.mask, &self.io.inbox)
    }
    pub fn select(&self, stopped: bool, defer_handlers: bool) -> Option<(u32, bool)> {
        if self.pending_bits() & (1 << 8) != 0 {
            return self.next_signal(1 << 8);
        }
        if let Some(sig) = self.io.inbox.first_fault() {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_fault_replaces_only_its_thread_info_and_has_delivery_priority() {
        let task = IoTask::default();
        let actions = Actions::default();
        actions.set(
            11,
            Action {
                handler: 0x1000,
                ..Default::default()
            },
        );
        task.inbox.enqueue(2, Info::default()).unwrap();
        task.inbox
            .enqueue(
                11,
                Info {
                    code: 99,
                    ..Default::default()
                },
            )
            .unwrap();
        task.process()
            .enqueue(
                11,
                Info {
                    code: 77,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(Fault {
            signal: 11,
            code: 2,
            address: 0xab00000000003456
        }
        .queue(&actions, 0, &task.inbox));
        assert_eq!(task.next_delivery(u64::MAX), Some((11, false)));
        let info = task.inbox.peek(11).unwrap();
        assert_eq!((info.code, info.fault), (2, Some(0x3456)));
        assert_eq!(task.process().peek(11).unwrap().code, 77);
        task.process().enqueue(9, Info::default()).unwrap();
        assert_eq!(task.next_delivery(u64::MAX), Some((9, true)));
        task.process().discard(9);
        task.inbox.discard(11);
        assert_eq!(task.next_delivery(u64::MAX), Some((2, false)));
        for (mask, handler) in [(1 << 10, 0x1000), (0, 1), (0, 0)] {
            actions.set(
                11,
                Action {
                    handler,
                    ..Default::default()
                },
            );
            assert!(!Fault {
                signal: 11,
                code: 1,
                address: 0x6789
            }
            .queue(&actions, mask, &task.inbox));
            assert!(task.inbox.peek(11).is_none());
            assert!(task.inbox.peek(2).is_some());
        }
    }
}
