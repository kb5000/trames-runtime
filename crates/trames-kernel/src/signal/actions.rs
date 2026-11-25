// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared Linux sighand table. Disposition updates serialize only with sends
//! and queue-discard effects on this original task group's resources.
use super::UNBLOCKABLE;
use std::sync::{Arc, Mutex};
use trames_memory::CpuMemory;
use trames_vfs::Errno;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Action {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

impl Action {
    pub(super) fn encode(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (part, value) in
            bytes
                .chunks_exact_mut(8)
                .zip([self.handler, self.flags, self.restorer, self.mask])
        {
            part.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
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
    /// Claim the actual handler and signal under their original sighand lock.
    /// A later installation survives this accepted handler's copy waits.
    pub fn take_handler(
        &self,
        task: &super::IoTask,
        signal: u32,
        shared: bool,
    ) -> Option<(Action, super::RetainedInfo)> {
        if !(1..=64).contains(&signal) {
            return None;
        }
        let mut table = self.0.lock().unwrap();
        let action = table[signal as usize];
        if action.handler <= 1 {
            return None;
        }
        let info = task.take(signal, shared)?;
        if action.flags & 0x8000_0000 != 0 {
            table[signal as usize].handler = 0;
        }
        Some((action, info))
    }
    pub(super) fn accept_handler(&self, signal: u32, action: Action) {
        if !(1..=64).contains(&signal) || action.flags & 0x8000_0000 == 0 {
            return;
        }
        let mut table = self.0.lock().unwrap();
        if table[signal as usize] == action {
            table[signal as usize].handler = 0;
        }
    }
    /// Native forced delivery over the original sighand and thread. Preserve
    /// standard-signal coalescing; only the forced disposition/mask may change.
    pub fn force_frame_signal(
        &self,
        task: &super::IoTask,
        signal: Option<u32>,
        fault: super::Fault,
    ) {
        debug_assert_eq!(fault.signal, 11);
        let mut table = self.0.lock().unwrap();
        let action = &mut table[11];
        let bit = 1u64 << 10;
        let mut context = task.context.lock().unwrap();
        let mask = task.mask();
        let blocked = mask & bit != 0;
        if signal == Some(11) || blocked || action.handler == 1 {
            action.handler = 0;
        }
        if blocked {
            context.mask = mask & !bit;
            task.publish_mask(context.mask);
        }
        drop(context);
        let _ = task.inbox.enqueue_quiet(
            11,
            super::Info {
                code: fault.code,
                fault: Some(fault.address),
                ..Default::default()
            },
        );
        drop(table);
        // Wake only after sighand and queue locks: an executor may inspect
        // that same sighand while holding its existing run-queue lock.
        task.inbox.changed();
    }
    pub fn failed_frame(&self, task: &super::IoTask, signal: u32) {
        self.force_frame_signal(
            task,
            Some(signal),
            super::Fault {
                signal: 11,
                code: 128,
                address: 0,
            },
        );
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
    /// Import before taking sighand; export the captured predecessor after
    /// releasing it. A failed output does not undo an installed disposition.
    pub fn call(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<Option<Action>, Errno> {
        self.call_with(a, memory, |_| {})
    }
    pub fn call_with(
        &self,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        changed: impl FnOnce(Action),
    ) -> Result<Option<Action>, Errno> {
        let (signal, new) = Self::import(a, memory)?;
        let old = self.exchange(signal, new, changed);
        if a[2] != 0 {
            memory
                .write_array(a[2], old.encode())
                .map_err(|_| Errno(14))?;
        }
        Ok(new)
    }
    pub(super) fn import(
        a: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Result<(usize, Option<Action>), Errno> {
        if a[3] != 8 {
            return Err(Errno(22));
        }
        let new = if a[1] != 0 {
            let bytes = memory.read_array::<32>(a[1]).map_err(|_| Errno(14))?;
            let word = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
            Some(Action {
                handler: word(0),
                flags: word(8) as u32 as u64 & 0xdc000007,
                restorer: word(16),
                mask: word(24) & !UNBLOCKABLE,
            })
        } else {
            None
        };
        let signal = a[0] as u32;
        if signal == 0 || signal > 64 || new.is_some() && matches!(signal, 9 | 19) {
            return Err(Errno(22));
        }
        Ok((signal as usize, new))
    }
    pub(super) fn exchange(
        &self,
        signal: usize,
        new: Option<Action>,
        changed: impl FnOnce(Action),
    ) -> Action {
        let mut table = self.0.lock().unwrap();
        let old = table[signal];
        if let Some(action) = new {
            table[signal] = action;
            changed(action);
        }
        old
    }
    pub fn query(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if a[1] != 0 {
            return None;
        }
        Some(self.call(a, memory).map(|_| 0))
    }
    pub fn with_action<R>(&self, sig: u32, body: impl FnOnce(Action) -> R) -> R {
        let table = self.0.lock().unwrap();
        body(table[sig as usize])
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
        assert_eq!(
            actions.get(10),
            Action {
                handler: 0x4000,
                flags: 0x80000000,
                restorer: 0x5000,
                mask: !UNBLOCKABLE
            }
        );
        actions.set(10, Action::default());
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
        for signal in [9, 19] {
            assert_eq!(
                actions.query([signal, 0, 0x1100, 8, 0, 0], &mut memory),
                Some(Ok(0))
            );
            assert_eq!(memory.read_array::<32>(0x1100).unwrap(), [0; 32]);
            assert_eq!(
                actions.call([signal, 0x1000, 0, 8, 0, 0], &mut memory),
                Err(Errno(22))
            );
        }
        for signal in [0, 65] {
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
    fn unsupported_flag_probes_install_handlers_and_report_only_supported_bits() {
        let actions = Actions::default();
        let mut memory = memory();
        memory.write_array(0x1000, 0x4000u64.to_le_bytes()).unwrap();
        // SA_SIGINFO | SA_UNSUPPORTED | SA_EXPOSE_TAGBITS | an unknown bit.
        memory
            .write_array(0x1008, 0x00000e04u64.to_le_bytes())
            .unwrap();
        let installed = actions
            .call([11, 0x1000, 0, 8, 0, 0], &mut memory)
            .unwrap()
            .unwrap();
        assert_eq!(installed.handler, 0x4000);
        assert_eq!(installed.flags, 4);
        actions.call([11, 0, 0x1100, 8, 0, 0], &mut memory).unwrap();
        assert_eq!(memory.read_u64(0x1100).unwrap(), 0x4000);
        assert_eq!(memory.read_u64(0x1108).unwrap(), 4);
        // Unknown bits are accepted even without SA_UNSUPPORTED, as in Linux.
        memory.write_array(0x1008, 0x200u64.to_le_bytes()).unwrap();
        assert_eq!(
            actions
                .call([11, 0x1000, 0, 8, 0, 0], &mut memory)
                .unwrap()
                .unwrap()
                .flags,
            0
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
