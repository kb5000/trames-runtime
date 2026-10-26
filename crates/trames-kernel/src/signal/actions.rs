// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared Linux sighand table. Pending queues and mutation side effects remain
//! with the task owner; query-only rt_sigaction can execute on a worker.
use super::UNBLOCKABLE;
use std::sync::{Arc, Mutex};
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Action {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

pub struct Actions(Arc<Mutex<[Action; 65]>>);
impl Default for Actions {
    fn default() -> Self {
        Self(Arc::new(Mutex::new([Action::default(); 65])))
    }
}
impl Clone for Actions {
    fn clone(&self) -> Self {
        Self(Arc::new(Mutex::new(*self.0.lock().unwrap())))
    }
}
impl Actions {
    pub fn shared(&self) -> Self {
        Self(self.0.clone())
    }
    pub fn get(&self, signal: usize) -> Action {
        self.0.lock().unwrap()[signal]
    }
    pub fn set(&self, signal: usize, action: Action) {
        self.0.lock().unwrap()[signal] = action;
    }
    pub fn masks(&self) -> (u64, u64) {
        self.0.lock().unwrap().iter().enumerate().skip(1).fold(
            (0, 0),
            |(ignored, caught), (signal, action)| {
                let bit = 1u64 << (signal - 1);
                (
                    ignored | if action.handler == 1 { bit } else { 0 },
                    caught | if action.handler > 1 { bit } else { 0 },
                )
            },
        )
    }
    pub fn exec(&self) -> Self {
        let mut table = *self.0.lock().unwrap();
        for action in &mut table {
            if action.handler != 1 {
                *action = Action::default();
            }
        }
        Self(Arc::new(Mutex::new(table)))
    }
    /// Same ABI and preflight order for the task owner and query-only workers.
    /// Mutation callers additionally clear ignored pending signals in their
    /// thread group; do not admit mutating calls without those shared queues.
    pub fn call(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<Option<Action>, Errno> {
        let signal = a[0] as u32;
        if signal == 0 || signal > 64 || signal == 9 || signal == 19 || a[3] != 8 {
            return Err(Errno(22));
        }
        if a[2] != 0 {
            memory
                .check(a[2], 32, Access::Write)
                .map_err(|_| Errno(14))?;
        }
        let new = if a[1] != 0 {
            let bytes = memory.read_array::<32>(a[1]).map_err(|_| Errno(14))?;
            let word = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
            // musl sign-extends int sa_flags; the kernel uses its low 32 bits.
            let flags = word(8) as u32 as u64;
            if flags & !0xdc000007 != 0 {
                return Err(Errno(22));
            }
            Some(Action {
                handler: word(0),
                flags,
                restorer: word(16),
                mask: word(24) & !UNBLOCKABLE,
            })
        } else {
            None
        };
        if let Some(action) = new {
            let mut table = self.0.lock().unwrap();
            // Import and output preflight already finished. Preserve the old
            // fault-without-mutation contract and keep old/new one transaction.
            Self::export(table[signal as usize], a[2], memory)?;
            table[signal as usize] = action;
        } else if a[2] != 0 {
            // Query-only workers never keep the table lock across guest bytes.
            Self::export(self.get(signal as usize), a[2], memory)?;
        }
        Ok(new)
    }
    fn export(old: Action, address: u64, memory: &mut impl CpuMemory) -> Result<(), Errno> {
        if address == 0 {
            return Ok(());
        }
        let mut bytes = [0; 32];
        for (part, value) in
            bytes
                .chunks_exact_mut(8)
                .zip([old.handler, old.flags, old.restorer, old.mask])
        {
            part.copy_from_slice(&value.to_le_bytes());
        }
        memory.write_array(address, bytes).map_err(|_| Errno(14))
    }
    pub fn query(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if a[1] != 0 {
            return None;
        }
        Some(self.call(a, memory).map(|_| 0))
    }
    pub fn set_handler(&self, signal: usize, handler: u64) {
        self.0.lock().unwrap()[signal].handler = handler;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    fn memory() -> Memory {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
    }
    #[test]
    fn shared_dispositions_fork_and_exec_keep_the_correct_domains() {
        let actions = Actions::default();
        let shared = actions.shared();
        let fork = actions.clone();
        actions.set(
            10,
            Action {
                handler: 0x4000,
                flags: 0x80000000,
                ..Default::default()
            },
        );
        actions.set_handler(12, 1);
        assert_eq!(shared.get(10), actions.get(10));
        assert_eq!(fork.get(10), Action::default());
        assert_eq!(shared.masks(), (1 << 11, 1 << 9));
        let exec = shared.exec();
        assert_eq!(exec.get(10), Action::default());
        assert_eq!(exec.get(12).handler, 1);
        assert_eq!(actions.get(10).handler, 0x4000);
        actions.set(10, Action::default());
        assert_eq!(shared.get(10).handler, 0);
        assert_eq!(shared.masks(), (1 << 11, 0));
    }
    #[test]
    fn common_abi_preserves_aliasing_faults_sign_extended_flags_and_query_admission() {
        let actions = Actions::default();
        let mut memory = memory();
        for (offset, word) in [
            (0, 0x4000u64),
            (8, 0xffffffff80000000),
            (16, 0x5000),
            (24, u64::MAX),
        ] {
            memory
                .write_array(0x1000 + offset, word.to_le_bytes())
                .unwrap();
        }
        assert_eq!(
            actions.call([10, 0x1000, 0x1ff0, 8, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(actions.get(10), Action::default());
        assert_eq!(
            actions.query([10, 0x1000, 0x1100, 8, 0, 0], &mut memory),
            None
        );
        assert_eq!(actions.get(10), Action::default());
        let new = actions
            .call([10, 0x1000, 0x1000, 8, 0, 0], &mut memory)
            .unwrap()
            .unwrap();
        assert_eq!(memory.read_array::<32>(0x1000).unwrap(), [0; 32]);
        assert_eq!(new.flags, 0x80000000);
        assert_eq!(new.mask & UNBLOCKABLE, 0);
        assert_eq!(
            actions.query([10, 0, 0x1100, 8, 0, 0], &mut memory),
            Some(Ok(0))
        );
        assert_eq!(memory.read_u64(0x1100).unwrap(), 0x4000);
        for signal in [0, 9, 19, 65] {
            assert_eq!(
                actions.query([signal, 0, 0, 8, 0, 0], &mut memory),
                Some(Err(Errno(22)))
            );
        }
        assert_eq!(
            actions.query([10, 0, 0, 16, 0, 0], &mut memory),
            Some(Err(Errno(22)))
        );
    }
    #[test]
    fn concurrent_exchanges_publish_whole_records_and_return_distinct_predecessors() {
        let actions = Actions::default();
        let mut old = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..4)
                .map(|id| {
                    let actions = &actions;
                    scope.spawn(move || {
                        let mut memory = memory();
                        (1..=64)
                            .map(|i| {
                                let value = id * 64 + i;
                                for offset in [0, 16, 24] {
                                    memory
                                        .write_array(0x1000 + offset, (value as u64).to_le_bytes())
                                        .unwrap();
                                }
                                actions
                                    .call([10, 0x1000, 0x1100, 8, 0, 0], &mut memory)
                                    .unwrap();
                                let before = memory.read_u64(0x1100).unwrap();
                                assert_eq!(memory.read_u64(0x1110).unwrap(), before);
                                assert_eq!(memory.read_u64(0x1118).unwrap(), before & !UNBLOCKABLE);
                                before
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            threads
                .into_iter()
                .flat_map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        old.push(actions.get(10).handler);
        old.sort_unstable();
        assert_eq!(old, (0..=256).collect::<Vec<_>>());
    }
}
