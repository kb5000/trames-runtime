// SPDX-License-Identifier: GPL-3.0-or-later
//! One timer input, one native state change, then its retained user output.
use super::*;
use crate::user_copy::{Copies, CopyError, Output};
use trames_memory::{MemoryError, PageFault};
#[cfg(test)]
mod tests;

pub(super) enum Input {
    Interval(Option<(Duration, Duration)>),
    Create(Option<[u8; 64]>),
    Posix(Option<(Duration, Duration)>),
}
impl Input {
    pub(super) fn import(
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Result<Self, Errno> {
        match number {
            102 => Ok(Self::Interval(None)),
            103 => Ok(Self::Interval(Some(if args[1] == 0 {
                (Duration::ZERO, Duration::ZERO)
            } else {
                times(memory, args[1], true)?
            }))),
            107 => Ok(Self::Create(if args[1] == 0 {
                None
            } else {
                Some(memory.read_array::<64>(args[1]).map_err(|_| Errno(14))?)
            })),
            110 => {
                if args[2] == 0 {
                    return Err(Errno(22));
                }
                Ok(Self::Posix(Some(times(memory, args[2], false)?)))
            }
            108 | 109 | 111 => Ok(Self::Posix(None)),
            _ => Err(Errno(38)),
        }
    }
}
fn times(
    memory: &impl CpuMemory,
    address: u64,
    micros: bool,
) -> Result<(Duration, Duration), Errno> {
    let bytes = memory.read_array::<32>(address).map_err(|_| Errno(14))?;
    let decode = |offset: usize| {
        let seconds = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let sub = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        if seconds > i64::MAX as u64 || sub >= if micros { 1_000_000 } else { 1_000_000_000 } {
            return Err(Errno(22));
        }
        Ok(Duration::new(
            seconds,
            sub as u32 * if micros { 1000 } else { 1 },
        ))
    };
    Ok((decode(0)?, decode(16)?))
}
pub(super) fn ktime(value: Duration) -> Duration {
    if value.as_secs() >= i64::MAX as u64 / 1_000_000_000 {
        Duration::from_nanos(i64::MAX as u64)
    } else {
        value
    }
}
pub(super) struct Prepared {
    pub output: Output,
    pub create: Option<Create>,
    pub value: u64,
}
pub(super) struct Create {
    registry: Arc<RwLock<Registry>>,
    reserved: bool,
    pub id: i32,
    clock: u32,
    tgid: u32,
    pub signal: u32,
    pub value: u64,
    pub target: Option<TimerTarget>,
}
impl Create {
    pub(super) fn reserve(
        registry: Arc<RwLock<Registry>>,
        clock: u32,
        tgid: u32,
    ) -> Result<Self, Errno> {
        let id = {
            let mut entries = registry.write().unwrap();
            if entries.timers.keys().filter(|id| **id > 0).count() + entries.reserved.len() >= 32 {
                return Err(Errno(11));
            }
            let id = entries.next_id;
            entries.next_id = id.checked_add(1).ok_or(Errno(11))?;
            entries.reserved.insert(id);
            id
        };
        Ok(Self {
            registry,
            reserved: true,
            id,
            clock,
            tgid,
            signal: 0,
            value: 0,
            target: None,
        })
    }
    pub(super) fn publish(mut self, caller: &IoTask, directory: &IoDirectory) -> Result<(), Errno> {
        // Linux performs the clock-specific create hook after copying the ID.
        let cpu = if self.clock >= 2 {
            Some(CpuClock::new(
                self.clock,
                self.signal != 0,
                caller,
                directory,
            )?)
        } else {
            None
        };
        let timer = Arc::new(Timer {
            tgid: self.tgid,
            clock: self.clock,
            cpu,
            signal: self.signal,
            value: self.value,
            target: self.target.take(),
            state: Default::default(),
        });
        let mut registry = self.registry.write().unwrap();
        assert!(registry.reserved.remove(&self.id));
        registry.timers.insert(self.id, timer);
        self.reserved = false;
        drop(registry);
        Ok(())
    }
}
impl Drop for Create {
    fn drop(&mut self) {
        if self.reserved {
            self.registry.write().unwrap().reserved.remove(&self.id);
        }
    }
}
struct Owner {
    timers: Arc<Timers>,
    caller: Arc<IoTask>,
    directory: Arc<IoDirectory>,
    namespace: PidNamespace,
}
pub struct Call {
    owner: Option<Owner>,
    number: u32,
    args: [u64; 6],
    started: Instant,
    input: Copies,
    prepared: Option<Prepared>,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl Call {
    pub fn new(
        timers: Arc<Timers>,
        number: u32,
        args: [u64; 6],
        started: Instant,
        caller: Arc<IoTask>,
        directory: Arc<IoDirectory>,
        namespace: PidNamespace,
    ) -> Self {
        Self {
            owner: Some(Owner {
                timers,
                caller,
                directory,
                namespace,
            }),
            number,
            args,
            started,
            input: Default::default(),
            prepared: None,
            fault: None,
            result: None,
        }
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.clone()
    }
    pub fn ready(&self) -> bool {
        self.fault.as_ref().is_none_or(|fault| fault.wait.ready())
    }
    pub fn cancel(&mut self) {
        let _ = self.finish(Err(Errno(4)));
    }
    fn finish(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.prepared = None;
        self.owner = None;
        self.input = Default::default();
        self.fault = None;
        self.result = Some(result);
        Some(result)
    }
    pub fn check(&mut self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if let Some(result) = self.result {
            return Some(result);
        }
        self.fault = None;
        match self.progress(memory) {
            Ok(value) => self.finish(Ok(value)),
            Err(CopyError::Error(error)) => self.finish(Err(error)),
            Err(CopyError::Page(fault)) => {
                self.fault = Some(fault);
                None
            }
        }
    }
    fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<u64, CopyError> {
        let owner = self.owner.as_ref().unwrap();
        if self.prepared.is_none() {
            let input = self
                .input
                .run(memory, |view| Input::import(self.number, self.args, view))?;
            self.prepared = Some(
                owner
                    .timers
                    .prepare(
                        self.number,
                        self.args,
                        input,
                        self.started,
                        &owner.caller,
                        &owner.directory,
                        &owner.namespace,
                    )
                    .map_err(CopyError::Error)?,
            );
            self.input = Default::default();
        }
        let prepared = self.prepared.as_mut().unwrap();
        prepared
            .output
            .progress(memory)
            .map_err(|error| match error {
                MemoryError::Pending(fault) => CopyError::Page(fault),
                _ => CopyError::Error(Errno(14)),
            })?;
        if let Some(create) = prepared.create.take() {
            create
                .publish(&owner.caller, &owner.directory)
                .map_err(CopyError::Error)?;
        }
        Ok(prepared.value)
    }
}
