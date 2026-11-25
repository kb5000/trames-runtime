// SPDX-License-Identifier: GPL-3.0-or-later
//! Submit imports retain their original IOCB bytes, OFD and aio_key copy cursor.
//! No request reaches a provider until its accepted prefix has finished import.
use super::*;
use trames_memory::PageWait;
#[derive(Default)]
pub(super) struct Header {
    bytes: file_input::Bytes,
    timeout: Option<Option<Duration>>,
    deadline: Option<Option<Instant>>,
    mask: Option<Option<u64>>,
    bound: bool,
    lease: Option<Arc<dyn trames_vfs::TemporaryMask>>,
    reader: Option<Arc<dyn trames_vfs::SignalReader>>,
    finished: Option<bool>,
}
pub(super) enum Parameters {
    Ready(Option<Instant>),
    NeedsTask,
}
impl Drop for Header {
    fn drop(&mut self) {
        self.finish(false);
    }
}
impl Header {
    pub(super) fn native_mask(&self) -> bool {
        self.lease.is_some()
    }
    pub(super) fn import(
        &mut self,
        source: &DirectSyscalls,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        deadline: Option<Instant>,
    ) -> std::result::Result<Result<bool, Errno>, trames_memory::PageFault> {
        if self.timeout.is_none() || self.mask.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let imported = (|| {
                let timeout = if deadline.is_some() || args[4] == 0 {
                    None
                } else {
                    let bytes = reader.read_array::<16>(args[4]).map_err(|_| Errno(14))?;
                    // do_io_getevents uses timespec64_to_ktime/ktime_set,
                    // including raw signed fields and the positive cap.
                    let nanos = crate::uring::time::raw_ktime(bytes);
                    Some(Duration::from_nanos(nanos.max(0) as u64))
                };
                let mask = if number == 292 && args[5] != 0 {
                    let bytes = reader.read_array::<16>(args[5]).map_err(|_| Errno(14))?;
                    let pointer = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                    let size = u64::from_le_bytes(bytes[8..].try_into().unwrap());
                    if pointer == 0 {
                        None
                    } else {
                        if size != 8 {
                            return Err(Errno(22));
                        }
                        Some(
                            u64::from_le_bytes(
                                reader.read_array::<8>(pointer).map_err(|_| Errno(14))?,
                            ) & !((1 << 8) | (1 << 18)),
                        )
                    }
                } else {
                    None
                };
                Ok((timeout, mask))
            })();
            if let Some(fault) = reader.fault() {
                return Err(fault);
            }
            match imported {
                Ok((timeout, mask)) => {
                    self.timeout = Some(timeout);
                    self.mask = Some(mask);
                }
                Err(error) => return Ok(Err(error)),
            }
            if deadline.is_some() {
                self.deadline = Some(deadline);
            }
        }
        if !self.bound {
            if let Some(mask) = self.mask.flatten() {
                let Some(lease) = source
                    .task_signal
                    .clone()
                    .and_then(|task| task.temporary_mask(mask))
                else {
                    return Ok(Ok(false));
                };
                self.lease = Some(lease);
            }
            self.reader = source.signal_reader.clone();
            self.bound = true;
        }
        Ok(Ok(true))
    }
    pub(super) fn progress(
        &mut self,
        source: &DirectSyscalls,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        deadline: Option<Instant>,
    ) -> std::result::Result<Result<Parameters, Errno>, trames_memory::PageFault> {
        match self.import(source, number, args, memory, deadline)? {
            Ok(true) => {}
            Ok(false) => return Ok(Ok(Parameters::NeedsTask)),
            Err(error) => return Ok(Err(error)),
        }
        if let Some(deadline) = self.deadline {
            return Ok(Ok(Parameters::Ready(deadline)));
        }
        // Relative timeout starts after lookup acquired the original context.
        let deadline = match self.timeout.unwrap() {
            Some(timeout) => match Instant::now().checked_add(timeout) {
                Some(deadline) => Some(deadline),
                None => return Ok(Err(Errno(22))),
            },
            None => None,
        };
        self.deadline = Some(deadline);
        Ok(Ok(Parameters::Ready(deadline)))
    }
    pub(super) fn finish(&mut self, interrupted: bool) -> bool {
        if let Some(interrupted) = self.finished {
            return interrupted;
        }
        let interrupted = interrupted
            || self
                .reader
                .as_ref()
                .is_some_and(|reader| reader.interrupted())
            || self
                .lease
                .as_ref()
                .is_some_and(|lease| lease.signal_pending());
        if let Some(lease) = self.lease.take() {
            if interrupted {
                lease.interrupted();
            } else {
                lease.finish();
            }
        }
        self.finished = Some(interrupted);
        interrupted
    }
}

struct Import {
    address: u64,
    bytes: file_input::Bytes,
    raw: Option<[u8; 64]>,
    reserved: bool,
    accepted: Option<Iocb>,
    prepared: Option<(Request, Work)>,
    key: crate::copy_replay::Replay,
}
impl Import {
    fn progress(
        &mut self,
        direct: &DirectSyscalls,
        context: &Context,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<Arc<PageWait>>, Errno> {
        if self.raw.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let imported = DirectSyscalls::iocb_bytes(self.address, &reader);
            if let Some(fault) = reader.fault() {
                return Ok(Some(fault.wait));
            }
            self.raw = Some(imported?);
        }
        if !self.reserved {
            let mut state = context.state.lock().unwrap();
            if state.active.len() + context.pending(context.head(), state.tail) >= state.capacity {
                return Err(Errno(11));
            }
            // Native requests have separate identities even when users reuse
            // the same iocb address. This is a count, not a uniqueness gate.
            state.active.insert(self.address);
            self.reserved = true;
        }
        if self.accepted.is_none() {
            self.accepted = Some(direct.bind_iocb(self.address, self.raw.unwrap())?);
            self.key.capture(
                self.address.checked_add(8).ok_or(Errno(14))?,
                &0u32.to_le_bytes(),
            );
        }
        match self.key.progress(memory) {
            Ok(()) => {}
            Err(trames_memory::MemoryError::Pending(fault)) => return Ok(Some(fault.wait)),
            Err(_) => return Err(Errno(14)),
        }
        if self.prepared.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let imported = direct.import_aio(self.accepted.as_ref().unwrap(), &reader);
            if let Some(fault) = reader.fault() {
                return Ok(Some(fault.wait));
            }
            self.prepared = Some(imported?);
        }
        Ok(None)
    }
}
#[allow(clippy::large_enum_variant)] // Move the original request/work without a per-IOCB box.
pub(super) enum Next {
    Ready(Request, Work),
    Wait(Arc<PageWait>),
    Done(Result<u64, Errno>),
}
pub(super) struct Submit {
    context: Arc<Context>,
    pointers: file_input::Bytes,
    current: Option<Import>,
    index: u64,
    done: Option<Result<u64, Errno>>,
    wait: Option<Arc<PageWait>>,
}
impl Drop for Submit {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl Submit {
    pub(super) fn cancel(&mut self) {
        self.discard();
        self.done = Some(Err(Errno(4)));
        self.wait = None;
    }
    pub(super) fn new(context: Arc<Context>) -> Self {
        Self {
            context,
            pointers: Default::default(),
            current: None,
            index: 0,
            done: None,
            wait: None,
        }
    }
    fn discard(&mut self) {
        if let Some(current) = self.current.take() {
            let reserved = current.reserved;
            let object = current.address;
            drop(current);
            if reserved {
                self.context.state.lock().unwrap().active.remove(&object);
                self.context.notify();
            }
        }
    }
    fn finish(&mut self, error: Option<Errno>) -> Next {
        self.discard();
        self.wait = None;
        let result = if self.index != 0 {
            Ok(self.index)
        } else {
            error.map_or(Ok(0), Err)
        };
        self.done = Some(result);
        Next::Done(result)
    }
    pub(super) fn accepted(&mut self) {
        self.index += 1;
        self.pointers = Default::default();
        self.wait = None;
    }
    pub(super) fn next(
        &mut self,
        direct: &DirectSyscalls,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        exiting: bool,
    ) -> Next {
        if let Some(result) = self.done {
            return Next::Done(result);
        }
        if self.index >= args[1].min(self.context.slots as u64) {
            return self.finish(None);
        }
        if self.wait.as_ref().is_some_and(|wait| !wait.ready()) {
            return if exiting {
                self.finish(Some(Errno(14)))
            } else {
                Next::Wait(self.wait.as_ref().unwrap().clone())
            };
        }
        self.wait = None;
        if self.current.is_none() {
            let reader = file_input::Reader::new(memory, &self.pointers);
            let pointer = args[2].checked_add(self.index * 8).ok_or(Errno(14));
            let address = pointer.and_then(|at| reader.read_u64(at).map_err(|_| Errno(14)));
            if let Some(fault) = reader.fault() {
                if exiting {
                    return self.finish(Some(Errno(14)));
                }
                self.wait = Some(fault.wait.clone());
                return Next::Wait(fault.wait);
            }
            let address = match address {
                Ok(address) => address,
                Err(error) => return self.finish(Some(error)),
            };
            self.current = Some(Import {
                address,
                bytes: Default::default(),
                raw: None,
                reserved: false,
                accepted: None,
                prepared: None,
                key: Default::default(),
            });
        }
        match self
            .current
            .as_mut()
            .unwrap()
            .progress(direct, &self.context, memory)
        {
            Ok(Some(wait)) => {
                if exiting {
                    self.finish(Some(Errno(14)))
                } else {
                    self.wait = Some(wait.clone());
                    Next::Wait(wait)
                }
            }
            Err(error) => self.finish(Some(error)),
            Ok(None) => {
                let (request, work) = self.current.take().unwrap().prepared.take().unwrap();
                Next::Ready(request, work)
            }
        }
    }
}
