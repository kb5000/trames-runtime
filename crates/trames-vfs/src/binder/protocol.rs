// SPDX-License-Identifier: GPL-3.0-or-later
//! Original ioctl, command and reply cursors survive faults on user pages.
use super::input::Reader;
use super::*;
use trames_memory::{CopiedInput, CopiedOutput, CpuMemory, MemoryError, PageFault};
mod control;
mod import;
mod read;
mod write;
use import::Import;
use read::{Item, Read};
use write::Command;

#[allow(clippy::large_enum_variant)]
pub enum Started {
    Complete(u64),
    Read(Ioctl),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Control,
    Header,
    Write,
    Read,
    ReadDone,
    Publish,
    Done,
}
enum After {
    Noop,
    Item(Item),
}
pub struct Ioctl {
    file: SharedFd,
    process: Arc<Connection>,
    factory: DescriptorFactory,
    tid: u32,
    uid: u32,
    cmd: u32,
    address: u64,
    header: [u8; 48],
    phase: Phase,
    input: CopiedInput,
    output: CopiedOutput,
    command: Option<Command>,
    read: Read,
    after: Option<After>,
    result: Option<Result<u64>>,
    fault: Option<PageFault>,
}
fn read(memory: &impl CpuMemory, address: u64, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0; len];
    memory.read(address, &mut bytes).map_err(|_| Errno(14))?;
    Ok(bytes)
}
fn checked_len(value: u64, limit: usize) -> Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|v| *v <= limit)
        .ok_or(Errno(22))
}
impl Ioctl {
    pub fn start(
        file: SharedFd,
        factory: DescriptorFactory,
        tid: u32,
        cmd: u32,
        address: u64,
        memory: &mut impl CpuMemory,
    ) -> Result<Started> {
        let Some(events::SharedControl::Binder(process)) = &file.open.control else {
            return Err(Errno(25));
        };
        let process = process.clone();
        if file.open.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        file.open.check_device_ioctl(cmd)?;
        process.check_owner(factory.local_sender_credentials()[0])?;
        let uid = factory.local_credentials().euid;
        let mut request = Self {
            file,
            process,
            factory,
            tid,
            uid,
            cmd,
            address,
            header: [0; 48],
            phase: if cmd == WRITE_READ {
                Phase::Header
            } else {
                Phase::Control
            },
            input: CopiedInput::default(),
            output: CopiedOutput::default(),
            command: None,
            read: Read::default(),
            after: None,
            result: None,
            fault: None,
        };
        match request.drive(memory, true)? {
            Some(value) => Ok(Started::Complete(value)),
            None => Ok(Started::Read(request)),
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.process.subscribe(signal)
    }
    pub fn take_fault(&mut self) -> Option<PageFault> {
        self.fault.take()
    }
    pub fn interruptible(&self) -> bool {
        self.phase == Phase::Read
            && self.read.noop
            && self.output.is_empty()
            && self.after.is_none()
            && self.fault.is_none()
    }
    pub fn interrupt(&mut self, memory: &mut impl CpuMemory) -> Result<Option<u64>> {
        if self.interruptible() {
            self.result = Some(Err(Errno(4)));
            self.phase = Phase::Publish;
        }
        self.finish(memory)
    }
    pub fn finish(&mut self, memory: &mut impl CpuMemory) -> Result<Option<u64>> {
        self.drive(memory, false)
    }
    fn copied<T, M: CpuMemory>(
        &mut self,
        memory: &M,
        action: impl FnOnce(&mut Self, &Reader<'_, M>) -> Result<T>,
    ) -> Result<Option<T>> {
        let input = std::mem::take(&mut self.input);
        let reader = Reader::new(memory, &input);
        let result = action(self, &reader);
        self.fault = reader.fault();
        drop(reader);
        self.input = input;
        if self.fault.is_some() {
            Ok(None)
        } else {
            result.map(Some)
        }
    }
    fn failed_output(&mut self) -> Result<()> {
        self.output = CopiedOutput::default();
        self.after.take();
        self.result = Some(Err(Errno(14)));
        if self.phase == Phase::Done {
            return Err(Errno(14));
        }
        self.phase = Phase::Publish;
        Ok(())
    }
    fn drive(&mut self, memory: &mut impl CpuMemory, stop_at_read: bool) -> Result<Option<u64>> {
        self.fault = None;
        loop {
            if !self.output.is_empty() {
                match self.output.progress(memory) {
                    Err(MemoryError::Pending(fault)) => {
                        self.fault = Some(fault);
                        return Ok(None);
                    }
                    Err(_) => {
                        self.failed_output()?;
                        continue;
                    }
                    Ok(()) => {}
                }
                self.output = CopiedOutput::default();
                if let Some(after) = self.after.take() {
                    let result = match after {
                        After::Noop => {
                            self.read.noop = true;
                            self.read.cursor = self.read.cursor.wrapping_add(4);
                            Ok(())
                        }
                        After::Item(item) => item.commit(self),
                    };
                    if let Err(error) = result {
                        self.result = Some(Err(error));
                        self.phase = Phase::Publish;
                    }
                }
            }
            match self.phase {
                Phase::Control => {
                    match self.copied(memory, |request, reader| request.control(reader))? {
                        None => return Ok(None),
                        Some(output) => {
                            if let Some(output) = output {
                                self.output
                                    .push_slice(self.address, &output.bytes[..output.len]);
                            }
                            self.result = Some(Ok(0));
                            self.phase = Phase::Done;
                        }
                    }
                }
                Phase::Header => {
                    match self.copied(memory, |request, reader| {
                        reader
                            .read_array::<48>(request.address)
                            .map_err(|_| Errno(14))
                    })? {
                        None => return Ok(None),
                        Some(header) => {
                            self.header = header;
                            self.input.clear();
                            self.phase = Phase::Write;
                        }
                    }
                }
                Phase::Write => {
                    match self.copied(memory, |request, reader| request.write_one(reader)) {
                        Ok(None) => return Ok(None),
                        Ok(Some(false)) => {}
                        Ok(Some(true)) => {
                            self.command = None;
                            self.phase = Phase::Read;
                        }
                        Err(error) => {
                            put(&mut self.header, 32, 0);
                            self.command = None;
                            self.result = Some(Err(error));
                            self.phase = Phase::Publish;
                        }
                    }
                }
                Phase::Read => {
                    if stop_at_read {
                        return Ok(None);
                    }
                    match self.read_one() {
                        Ok(false) => return Ok(None),
                        Ok(true) => {}
                        Err(error) => {
                            self.result = Some(Err(error));
                            self.phase = Phase::Publish;
                        }
                    }
                }
                Phase::ReadDone => self.read_done(),
                Phase::Publish => {
                    self.output.push_slice(self.address, &self.header);
                    self.phase = Phase::Done;
                }
                Phase::Done => return self.result.unwrap().map(Some),
            }
        }
    }
    fn capture_fd(&self, fd: u32) -> Result<SharedFd> {
        let file = self.factory.files.query_lookup(fd).ok_or(Errno(95))??;
        // A Binder device is not an Android data-buffer transport. Avoid
        // creating an OFD -> queued transfer -> same OFD lifetime cycle.
        if file.open.flags.get() & O_PATH != 0
            || matches!(file.open.control, Some(events::SharedControl::Binder(_)))
        {
            return Err(Errno(1));
        }
        Ok(file)
    }
    fn pop_call(&self, call: &Arc<Call>) {
        let mut state = self.process.state.lock().unwrap();
        let thread = state.threads.entry(self.tid).or_default();
        if thread.stack.last().is_some_and(|c| Arc::ptr_eq(c, call)) {
            thread.stack.pop();
        }
    }
}
fn validate_parent(
    parents: &BTreeMap<usize, (usize, usize, usize, usize)>,
    last: Option<(usize, usize)>,
    parent: usize,
    offset: usize,
) -> Result<()> {
    let Some((mut current, end)) = last else {
        return Err(Errno(22));
    };
    if current == parent {
        return if offset >= end {
            Ok(())
        } else {
            Err(Errno(22))
        };
    }
    while let Some((_, _, ancestor, parent_offset)) = parents.get(&current) {
        if *ancestor == parent {
            return if offset >= parent_offset + 8 {
                Ok(())
            } else {
                Err(Errno(22))
            };
        }
        if *ancestor == usize::MAX {
            break;
        }
        current = *ancestor;
    }
    Err(Errno(22))
}

impl Vfs {
    pub fn task_pid(&self) -> u32 {
        self.pid
    }
    pub fn binder_file(&self, fd: u32) -> Result<Option<SharedFd>> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        Ok(
            matches!(open.control, Some(events::SharedControl::Binder(_)))
                .then(|| SharedFd::new(open.shared.clone())),
        )
    }
    pub fn binder_exit(&self, tid: u32, last: bool) {
        self.binder.exit(self.lock_owner, tid, last);
    }
}
impl Drop for Ioctl {
    fn drop(&mut self) {
        if let Some(thread) = self
            .process
            .state
            .lock()
            .unwrap()
            .threads
            .get_mut(&self.tid)
        {
            thread.waiting = false;
        }
    }
}
impl DescriptorFactory {
    pub fn binder_file(&self, fd: u32) -> Option<Result<SharedFd>> {
        let file = match self.files.query_lookup(fd)? {
            Ok(file) => file,
            Err(_) => return None,
        };
        matches!(file.open.control, Some(events::SharedControl::Binder(_))).then_some(Ok(file))
    }
    pub fn binder_exit(&self, tid: u32, last: bool) {
        self.binder
            .exit(self.local_sender_credentials()[0], tid, last);
    }
}
