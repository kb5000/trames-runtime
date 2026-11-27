// SPDX-License-Identifier: GPL-3.0-or-later
//! Futex2 inputs belong to one accepted entry, including across backing faults.
//! Queue comparison remains live and atomic with publication in the keyed table.
use crate::{futex, run_queue::WaitState};
use std::{
    sync::Weak,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trames_memory::{CopiedInput, CpuMemory, MemoryError, PageFault, ADDRESS_LIMIT};
use trames_vfs::Errno;

pub(super) enum Error {
    Page(PageFault),
    Errno(Errno),
}
impl From<Errno> for Error {
    fn from(error: Errno) -> Self {
        Self::Errno(error)
    }
}
impl From<MemoryError> for Error {
    fn from(error: MemoryError) -> Self {
        match error {
            MemoryError::Pending(fault) => Self::Page(fault),
            _ => Self::Errno(Errno(14)),
        }
    }
}
impl Error {
    pub fn errno(self) -> Errno {
        match self {
            Self::Errno(error) => error,
            Self::Page(_) => Errno(14),
        }
    }
}
pub(super) enum Ready {
    Wait(WaitState),
    Queue(futex::Effect),
}
struct Word {
    address: u64,
    value: u32,
    flags: u32,
}
pub(super) struct Call {
    pub number: u32,
    args: [u64; 6],
    input: CopiedInput,
    words: Vec<Word>,
    deadline: Option<Option<Instant>>,
}
fn flags(flags: u32, value: u64) -> Result<(), Errno> {
    // The advertised ABI supports the same U32 private/shared form as Linux
    // v6.12. Other word sizes and optional NUMA policies are not advertised.
    if flags & !0x83 != 0 || flags & 3 != 2 || value > u32::MAX as u64 {
        return Err(Errno(22));
    }
    Ok(())
}
fn key(memory: &impl CpuMemory, vm: u64, address: u64, flags: u32) -> Result<futex::Key, Error> {
    if address & 3 != 0 {
        return Err(Errno(22).into());
    }
    let address = address & 0x00ff_ffff_ffff_ffff;
    if address > ADDRESS_LIMIT - 4 {
        return Err(Errno(14).into());
    }
    let private = flags & 128 != 0;
    if !private {
        if let Some(key) = memory.shared_futex_key(address)? {
            return Ok(key);
        }
    }
    Ok((if private { 0 } else { 2 }, vm, address))
}
impl Call {
    pub fn new(number: u32, args: [u64; 6]) -> Self {
        Self {
            number,
            args,
            input: Default::default(),
            words: Vec::new(),
            deadline: None,
        }
    }
    fn timeout(
        &mut self,
        memory: &impl CpuMemory,
        address: u64,
        clock: u32,
        started: Instant,
    ) -> Result<Option<Instant>, Error> {
        if let Some(deadline) = self.deadline {
            return Ok(deadline);
        }
        let deadline = if address == 0 {
            None
        } else {
            if !matches!(clock, 0 | 1) {
                return Err(Errno(22).into());
            }
            let mut bytes = [0; 16];
            self.input.read(memory, address, &mut bytes)?;
            let seconds = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let nanos = u64::from_le_bytes(bytes[8..].try_into().unwrap());
            if seconds > i64::MAX as u64 || nanos >= 1_000_000_000 {
                return Err(Errno(22).into());
            }
            let now = if clock == 0 {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Errno(5))?
            } else {
                started.elapsed()
            };
            Some(
                Instant::now()
                    .checked_add(Duration::new(seconds, nanos as u32).saturating_sub(now))
                    .ok_or(Errno(22))?,
            )
        };
        self.deadline = Some(deadline);
        Ok(deadline)
    }
    fn vector(&mut self, memory: &impl CpuMemory, count: usize) -> Result<(), Error> {
        while self.words.len() < count {
            let address = self.args[0]
                .checked_add(self.words.len() as u64 * 24)
                .ok_or(Errno(14))?;
            let mut bytes = [0; 24];
            self.input.read(memory, address, &mut bytes)?;
            let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let f = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
            if bytes[20..24] != [0; 4] {
                return Err(Errno(22).into());
            }
            flags(f, value)?;
            self.words.push(Word {
                address: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                value: value as u32,
                flags: f,
            });
        }
        Ok(())
    }
    pub fn progress(
        &mut self,
        table: &futex::Futexes,
        memory: &impl CpuMemory,
        caller: (u64, u32),
        started: Instant,
        target: Option<Weak<dyn futex::Wake>>,
    ) -> Result<Ready, Error> {
        let (vm, pid) = caller;
        let a = self.args;
        match self.number {
            449 => {
                let count = a[1] as u32;
                if a[2] as u32 != 0 || !(1..=128).contains(&count) || a[0] == 0 {
                    return Err(Errno(22).into());
                }
                let deadline = self.timeout(memory, a[3], a[4] as u32, started)?;
                self.vector(memory, count as usize)?;
                let keys = self
                    .words
                    .iter()
                    .map(|word| key(memory, vm, word.address, word.flags))
                    .collect::<Result<Vec<_>, _>>()?;
                let wait = table.wait_vector(&keys, pid, target, || {
                    for word in &self.words {
                        if u32::from_le_bytes(memory.read_array::<4>(word.address)?) != word.value {
                            return Err(Errno(11).into());
                        }
                    }
                    Ok::<_, Error>(())
                })?;
                Ok(Ready::Wait(WaitState::Futex { wait, deadline }))
            }
            455 => {
                let f = a[3] as u32;
                flags(f, a[1])?;
                flags(f, a[2])?;
                let deadline = self.timeout(memory, a[4], a[5] as u32, started)?;
                if a[2] == 0 {
                    return Err(Errno(22).into());
                }
                let key = key(memory, vm, a[0], f)?;
                let wait = table.wait_target(key, pid, a[2] as u32, target, || {
                    if u32::from_le_bytes(memory.read_array::<4>(a[0])?) != a[1] as u32 {
                        return Err(Errno(11).into());
                    }
                    Ok::<_, Error>(())
                })?;
                Ok(Ready::Wait(WaitState::Futex { wait, deadline }))
            }
            454 => {
                flags(a[3] as u32, a[1])?;
                if a[1] == 0 {
                    return Err(Errno(22).into());
                }
                let key = key(memory, vm, a[0], a[3] as u32)?;
                // Linux compares the number woken after selecting a waiter;
                // a negative int therefore wakes one, while strict zero wakes none.
                let count = if (a[2] as i32) < 0 { 1 } else { a[2] as u32 };
                Ok(Ready::Queue(table.wake_regular(key, count, a[1] as u32)?))
            }
            456 => {
                if a[1] as u32 != 0 || a[0] == 0 {
                    return Err(Errno(22).into());
                }
                self.vector(memory, 2)?;
                // Current Linux mandates identical per-word flags for requeue.
                if self.words[0].flags != self.words[1].flags {
                    return Err(Errno(22).into());
                }
                if (a[2] as i32) < 0 || (a[3] as i32) < 0 {
                    return Err(Errno(22).into());
                }
                let old = key(memory, vm, self.words[0].address, self.words[0].flags)?;
                let new = key(memory, vm, self.words[1].address, self.words[1].flags)?;
                let effect = table.requeue_regular(old, new, a[2] as u32, a[3] as u32, || {
                    if u32::from_le_bytes(memory.read_array::<4>(self.words[0].address)?)
                        != self.words[0].value
                    {
                        return Err(Errno(11).into());
                    }
                    Ok::<_, Error>(())
                })?;
                Ok(Ready::Queue(effect))
            }
            _ => unreachable!("accepted futex2 entry"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use trames_memory::{Access, Memory, PageWait, Permissions, PAGE_SIZE};
    struct Faults {
        memory: Memory,
        at: u64,
        wait: Arc<PageWait>,
    }
    impl CpuMemory for Faults {
        fn async_faults_possible(&self) -> bool {
            true
        }
        fn mapped_at_or_after(&self, a: u64) -> bool {
            self.memory.mapped_at_or_after(a)
        }
        fn read(&self, a: u64, out: &mut [u8]) -> Result<(), MemoryError> {
            if a <= self.at && self.at < a + out.len() as u64 && !self.wait.ready() {
                return Err(self.wait.fault(self.at));
            }
            self.memory.read(a, out)
        }
        fn write(&mut self, a: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.memory.write(a, bytes)
        }
        fn check(&self, a: u64, n: usize, access: Access) -> Result<(), MemoryError> {
            self.memory.check(a, n, access)
        }
        fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
            self.memory.check_translation(a)
        }
        fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
            self.memory.fetch_u32(a)
        }
        fn instruction_identity(&self) -> (u64, u64, u64) {
            self.memory.instruction_identity()
        }
        fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
            self.memory.instruction_page_identity(a)
        }
        fn atomic_update<T>(
            &mut self,
            a: u64,
            n: usize,
            update: impl FnOnce(&mut [u8]) -> (T, bool),
        ) -> Result<T, MemoryError> {
            self.memory.atomic_update(a, n, update)
        }
        fn exclusive_read(&mut self, a: u64, out: &mut [u8]) -> Result<u128, MemoryError> {
            self.memory.exclusive_read(a, out)
        }
        fn exclusive_write(
            &mut self,
            a: u64,
            bytes: &[u8],
            token: Option<u128>,
        ) -> Result<bool, MemoryError> {
            self.memory.exclusive_write(a, bytes, token)
        }
    }
    fn memory() -> Memory {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
        memory
    }
    fn woken(state: &WaitState) -> bool {
        matches!(state, WaitState::Futex { wait, .. } if wait.woken())
    }
    fn word(memory: &mut Memory, at: u64, address: u64, private: bool) {
        memory.write_array(at, 0u64.to_le_bytes()).unwrap();
        memory.write_array(at + 8, address.to_le_bytes()).unwrap();
        memory
            .write_array(
                at + 16,
                (2u32 | if private { 128 } else { 0 }).to_le_bytes(),
            )
            .unwrap();
        memory.write_array(at + 20, 0u32.to_le_bytes()).unwrap();
    }
    fn waiter(
        table: &futex::Futexes,
        memory: &impl CpuMemory,
        address: u64,
        private: bool,
    ) -> WaitState {
        match Call::new(
            455,
            [address, 0, 1, 2 | if private { 128 } else { 0 }, 0, 0],
        )
        .progress(table, memory, (7, 1), Instant::now(), None)
        {
            Ok(Ready::Wait(wait)) => wait,
            _ => panic!("resident futex_wait"),
        }
    }
    #[test]
    fn requeue_rejects_mixed_flags_without_consuming_a_waiter() {
        for source_private in [false, true] {
            let table = futex::Futexes::default();
            let mut memory = memory();
            word(&mut memory, 0x1000, 0x3000, source_private);
            word(&mut memory, 0x1018, 0x3004, !source_private);
            let wait = waiter(&table, &memory, 0x3000, source_private);
            assert!(matches!(
                Call::new(456, [0x1000, 0, 0, 1, 0, 0]).progress(
                    &table,
                    &memory,
                    (7, 2),
                    Instant::now(),
                    None
                ),
                Err(Error::Errno(Errno(22)))
            ));
            assert!(!woken(&wait));
            let source = key(&memory, 7, 0x3000, 2 | if source_private { 128 } else { 0 })
                .ok()
                .unwrap();
            let destination = key(
                &memory,
                7,
                0x3004,
                2 | if !source_private { 128 } else { 0 },
            )
            .ok()
            .unwrap();
            assert_eq!(table.wake(destination, 1, 1), 0);
            assert_eq!(table.wake(source, 1, 1), 1);
            assert!(woken(&wait));
        }
    }
    #[test]
    fn strict_zero_and_negative_wake_counts_follow_linux_selection() {
        let table = futex::Futexes::default();
        let memory = memory();
        let first = waiter(&table, &memory, 0x3000, true);
        let second = waiter(&table, &memory, 0x3000, true);
        for (count, expected) in [(0, 0), (u64::MAX, 1), (u64::MAX, 1), (u64::MAX, 0)] {
            let Ok(Ready::Queue(effect)) = Call::new(454, [0x3000, 1, count, 130, 0, 0]).progress(
                &table,
                &memory,
                (7, 2),
                Instant::now(),
                None,
            ) else {
                panic!("strict futex wake");
            };
            assert_eq!(effect.total(), expected);
        }
        assert!(woken(&first) && woken(&second));
    }
    #[test]
    fn vector_record_prefix_survives_a_backing_page_wait_without_early_publication() {
        let table = futex::Futexes::default();
        let mut m = memory();
        word(&mut m, 0x1ff8, 0x3000, true);
        let memory = Faults {
            memory: m,
            at: 0x2000,
            wait: Arc::new(PageWait::default()),
        };
        let mut call = Call::new(449, [0x1ff8, 1, 0, 0, 1, 0]);
        assert!(matches!(
            call.progress(&table, &memory, (7, 1), Instant::now(), None),
            Err(Error::Page(_))
        ));
        assert_eq!(table.wake((0, 7, 0x3000), 1, 1), 0);
        let mut memory = memory;
        memory
            .memory
            .write_array(0x1ff8, 99u64.to_le_bytes())
            .unwrap();
        memory.wait.finish();
        let Ok(Ready::Wait(wait)) = call.progress(&table, &memory, (7, 1), Instant::now(), None)
        else {
            panic!("original copied value must remain zero");
        };
        assert_eq!(table.wake((0, 7, 0x3000), 1, 1), 1);
        assert!(woken(&wait));
    }
    #[test]
    fn live_value_fault_retains_vector_identity_and_absolute_timeout() {
        let table = futex::Futexes::default();
        let mut m = memory();
        word(&mut m, 0x1000, 0x3000, true);
        m.write_array(0x1100, 10u64.to_le_bytes()).unwrap();
        let mut memory = Faults {
            memory: m,
            at: 0x3000,
            wait: Arc::new(PageWait::default()),
        };
        let started = Instant::now();
        let mut call = Call::new(449, [0x1000, 1, 0, 0x1100, 1, 0]);
        assert!(matches!(
            call.progress(&table, &memory, (7, 1), started, None),
            Err(Error::Page(_))
        ));
        word(&mut memory.memory, 0x1000, 0x3004, true);
        memory
            .memory
            .write_array(0x1100, 1000u64.to_le_bytes())
            .unwrap();
        memory.wait.finish();
        let Ok(Ready::Wait(wait)) = call.progress(&table, &memory, (7, 1), started, None) else {
            panic!("original vector");
        };
        assert!(
            matches!(&wait, WaitState::Futex { deadline: Some(deadline), .. } if *deadline < started + Duration::from_secs(11))
        );
        assert_eq!(table.wake((0, 7, 0x3004), 1, 1), 0);
        assert_eq!(table.wake((0, 7, 0x3000), 1, 1), 1);
        assert!(woken(&wait));
    }
    #[test]
    fn requeue_metadata_wait_keeps_the_original_source_but_comparison_stays_live() {
        for changed in [false, true] {
            let table = futex::Futexes::default();
            let mut m = memory();
            word(&mut m, 0x1000, 0x3000, true);
            word(&mut m, 0x1018, 0x3004, true);
            let mut memory = Faults {
                memory: m,
                at: 0x1018,
                wait: Arc::new(PageWait::default()),
            };
            let original = waiter(&table, &memory, 0x3000, true);
            let mut call = Call::new(456, [0x1000, 0, 0, 1, 0, 0]);
            assert!(matches!(
                call.progress(&table, &memory, (7, 2), Instant::now(), None),
                Err(Error::Page(_))
            ));
            assert!(!woken(&original));
            word(&mut memory.memory, 0x1000, 0x3010, true);
            if changed {
                memory
                    .memory
                    .write_array(0x3000, 1u32.to_le_bytes())
                    .unwrap();
            }
            memory.wait.finish();
            let result = call.progress(&table, &memory, (7, 2), Instant::now(), None);
            if changed {
                assert!(matches!(result, Err(Error::Errno(Errno(11)))));
                assert_eq!(table.wake((0, 7, 0x3004), 1, 1), 0);
                assert_eq!(table.wake((0, 7, 0x3000), 1, 1), 1);
            } else {
                assert!(matches!(result, Ok(Ready::Queue(effect)) if effect.total() == 1));
                assert_eq!(table.wake((0, 7, 0x3000), 1, 1), 0);
                assert_eq!(table.wake((0, 7, 0x3004), 1, 1), 1);
            }
            assert!(woken(&original));
        }
    }
}
