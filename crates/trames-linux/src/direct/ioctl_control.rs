// SPDX-License-Identifier: GPL-3.0-or-later
//! One original ioctl: input, one provider effect, then its actual user copies.
use super::*;
use trames_memory::{CopiedOutput, MemoryError, PageFault};
use trames_vfs::{DescriptorFactory, PathQueries, SharedFd, TerminalIo, TerminalTask};
#[cfg(test)]
#[path = "ioctl_control_tests.rs"]
mod tests;

enum Backend {
    Direct,
    Binder {
        _file: Arc<trames_vfs::binder::Connection>,
        factory: DescriptorFactory,
    },
    Status(trames_vfs::StatusControl),
    General,
    Perf(Arc<trames_vfs::perf::Event>),
    Fuse(Arc<trames_vfs::fuse::Device>),
    Sync {
        file: Arc<trames_vfs::sync_file::File>,
        control: trames_vfs::sync_file::Control,
    },
}
pub struct IoctlControl {
    args: [u64; 6],
    file: Option<SharedFd>,
    direct: Option<trames_vfs::DirectFd>,
    factory: Option<DescriptorFactory>,
    paths: Option<PathQueries>,
    task: Option<Arc<dyn TerminalTask>>,
    status: Option<trames_vfs::StatusControl>,
    backend: Option<Backend>,
    entry_checked: bool,
    job_checked: bool,
    job_waiting: bool,
    joined: bool,
    ethtool: Option<u64>,
    input: file_input::Bytes,
    output: CopiedOutput,
    value: Option<Result<u64, Errno>>,
    actor: Option<trames_vfs::FileActorSnapshot>,
}
enum Step {
    Page(PageFault),
    Authority,
    Stopped,
    Binder,
    Reply(Result<u64, Errno>),
}
impl IoctlControl {
    fn new(source: &DirectSyscalls, args: [u64; 6]) -> Option<Result<Box<Self>, Errno>> {
        if matches!(args[1] as u32, 0x8901..=0x8904) {
            return None;
        }
        let mut args = args;
        args[1] = u64::from(args[1] as u32);
        let paths = source.paths.as_ref().map(PathQueries::retain_context);
        let factory = source
            .resources
            .clone()
            .or_else(|| paths.as_ref().map(PathQueries::control_factory));
        // Slot controls have no capability in a bare fixed-byte binding. Leave
        // that before-effects call to its owner instead of checkpointing with
        // an unfillable original slot token.
        if factory.is_none() && matches!(args[1] as u32, 0x5421 | 0x5450..=0x5452) {
            return None;
        }
        let (file, direct, status) = if let Some(factory) = &factory {
            let control = match factory.descriptor_control(args[0] as u32) {
                Ok(control) => control,
                Err(error) => return Some(Err(error)),
            };
            let file = control.shared_file();
            let direct = source.descriptors.byte_file(file.clone());
            (
                Some(file),
                direct,
                matches!(args[1] as u32, 0x5421 | 0x5450..=0x5452)
                    .then(|| control.status_control()),
            )
        } else {
            let direct = source.descriptors.get(args[0] as u32)?;
            (direct.shared_file(), Some(direct), None)
        };
        Some(Ok(Box::new(Self {
            args,
            file,
            direct,
            factory,
            paths,
            task: source.terminal_task.clone(),
            status,
            backend: None,
            entry_checked: false,
            job_checked: false,
            job_waiting: false,
            joined: false,
            ethtool: None,
            input: Default::default(),
            output: Default::default(),
            value: None,
            actor: trames_vfs::FileActorScope::frozen(),
        })))
    }
    fn initialize(&mut self) -> Result<bool, Errno> {
        let request = self.args[1] as u32;
        if !self.entry_checked {
            if let Some(file) = &self.file {
                file.check_ioctl(request)?;
            } else if let Some(fd) = &self.direct {
                fd.check_device_ioctl(request)?;
            }
            if let Some(error) = self
                .direct
                .as_ref()
                .and_then(|fd| DirectSyscalls::terminal_probe(self.args, fd))
            {
                return Err(error);
            }
            self.entry_checked = true;
        }
        if let Some(file) = self.file.as_ref().and_then(SharedFd::binder_file) {
            let Some(factory) = &self.factory else {
                return Ok(false);
            };
            self.backend = Some(Backend::Binder {
                _file: file,
                factory: factory.clone(),
            });
        } else if matches!(request, 0x5421 | 0x5450..=0x5452) {
            let Some(status) = self.status.take() else {
                return Ok(false);
            };
            self.backend = Some(Backend::Status(status));
        } else if let Some(file) = self.file.as_ref().and_then(SharedFd::sync_file) {
            let Some(factory) = &self.factory else {
                return Ok(false);
            };
            let control = trames_vfs::sync_file::Control::new(&file, factory, request)?;
            self.backend = Some(Backend::Sync { file, control });
        } else if let Some(event) = self.file.as_ref().and_then(SharedFd::perf_event) {
            self.backend = Some(Backend::Perf(event));
        } else if request == trames_vfs::fuse::CLONE
            && self.file.as_ref().and_then(SharedFd::fuse_device).is_some()
        {
            if self.factory.is_none() {
                return Ok(false);
            }
            self.backend = Some(Backend::Fuse(
                self.file.as_ref().unwrap().fuse_device().unwrap(),
            ));
        } else if self
            .direct
            .as_ref()
            .is_some_and(|fd| DirectSyscalls::supports_fd_call(29, self.args, fd))
        {
            self.backend = Some(Backend::Direct);
        } else {
            if self.paths.is_none() {
                return Ok(false);
            }
            self.backend = Some(Backend::General);
        }
        Ok(true)
    }
    pub(super) fn interruptible(&self) -> bool {
        self.job_waiting
    }
    fn progress(&mut self, memory: &mut impl CpuMemory) -> Step {
        let _actor = self
            .actor
            .as_ref()
            .map(trames_vfs::FileActorSnapshot::enter);
        self.job_waiting = false;
        if self.backend.is_none() {
            match self.initialize() {
                Ok(true) => {}
                Ok(false) => return Step::Authority,
                Err(error) => return Step::Reply(Err(error)),
            }
        }
        if matches!(self.backend, Some(Backend::Binder { .. })) {
            return Step::Binder;
        }
        if self.value.is_none() {
            if matches!(self.backend, Some(Backend::Direct)) {
                if let (Some(fd), Some(task)) = (&self.direct, &self.task) {
                    if let Some(end) = fd.pty_endpoint() {
                        if !self.job_checked {
                            match crate::pty::terminal_check_job(
                                end,
                                self.args[1] as u32,
                                task.as_ref(),
                            ) {
                                TerminalIo::Complete(Ok(())) => self.job_checked = true,
                                TerminalIo::Complete(Err(error)) => return Step::Reply(Err(error)),
                                TerminalIo::Stopped => {
                                    self.job_waiting = true;
                                    return Step::Stopped;
                                }
                            }
                        }
                    }
                }
            }
            // ETHTOOL_GET_TS_INFO accepts its device between importing ifreq
            // and reading the nested command. Retain that decision across a
            // nested page wait instead of resolving a replacement interface.
            if matches!(self.backend, Some(Backend::General))
                && self.args[1] as u32 == 0x8946
                && self
                    .file
                    .as_ref()
                    .is_some_and(|file| file.kind() == trames_vfs::FdKind::Socket)
            {
                let reader = file_input::Reader::new(memory, &self.input);
                if self.ethtool.is_none() {
                    let body = reader.read_array::<40>(self.args[2]);
                    if let Some(fault) = reader.fault() {
                        return Step::Page(fault);
                    }
                    let body = match body {
                        Ok(body) => body,
                        Err(_) => return Step::Reply(Err(Errno(14))),
                    };
                    let result = self.paths.as_ref().unwrap().retained_control(
                        self.file.clone().unwrap(),
                        |view, _| {
                            let end = body[..16].iter().position(|byte| *byte == 0).unwrap_or(16);
                            if !view
                                .network_devices()
                                .iter()
                                .any(|device| device.name == body[..end])
                            {
                                return Err(Errno(19));
                            }
                            Ok(u64::from_le_bytes(body[16..24].try_into().unwrap()))
                        },
                    );
                    self.ethtool = Some(match result {
                        Ok(pointer) => pointer,
                        Err(error) => return Step::Reply(Err(error)),
                    });
                }
                let command = reader.read_array::<4>(self.ethtool.unwrap());
                if let Some(fault) = reader.fault() {
                    return Step::Page(fault);
                }
                self.value = Some(match command {
                    Ok(raw) if u32::from_le_bytes(raw) == 0x41 => {
                        let mut info = [0; 44];
                        info[..4].copy_from_slice(&raw);
                        info[8..12].copy_from_slice(&(-1i32).to_le_bytes());
                        self.output.push_slice(self.ethtool.unwrap(), &info);
                        Ok(0)
                    }
                    Ok(_) => Err(Errno(95)),
                    Err(_) => Err(Errno(14)),
                });
            } else {
                let reader = file_input::Reader::new(memory, &self.input);
                let mut view = Capture {
                    reader,
                    output: &mut self.output,
                    scalar: scalar_output(self.args[1] as u32),
                    scalar_address: (self.args[1] as u32 == 0x8912).then_some(self.args[2]),
                };
                let result = match self.backend.as_mut().unwrap() {
                    Backend::Binder { .. } => unreachable!("typed original Binder ioctl"),
                    Backend::Status(status) => status.ioctl_accepted(
                        self.args[0] as u32,
                        self.args[1] as u32,
                        self.args[2],
                        &mut view,
                        &FlagOwners,
                    ),
                    Backend::Sync { file, control } => file.prepare_ioctl(
                        control,
                        self.args[1] as u32,
                        self.args[2],
                        &view.reader,
                        view.output,
                    ),
                    Backend::Perf(event) => {
                        if self.args[1] as u32 == 0x2405 {
                            let Some(factory) = &self.factory else {
                                return Step::Authority;
                            };
                            (|| {
                                let target = if self.args[2] as u32 as i32 == -1 {
                                    None
                                } else {
                                    Some(
                                        factory
                                            .descriptor_control(self.args[2] as u32)?
                                            .perf_event()?
                                            .ok_or(Errno(9))?,
                                    )
                                };
                                event.set_output(target.as_ref())
                            })()
                        } else {
                            event.ioctl(self.args[1] as u32, self.args[2], &mut view)
                        }
                    }
                    Backend::Fuse(device) => (|| {
                        let fd = u32::from_le_bytes(
                            view.read_array::<4>(self.args[2]).map_err(|_| Errno(14))?,
                        );
                        let control = self
                            .factory
                            .as_ref()
                            .unwrap()
                            .descriptor_control(fd)
                            .map_err(|_| Errno(22))?;
                        if control.flags() & trames_vfs::O_PATH != 0 {
                            return Err(Errno(22));
                        }
                        let original = control.shared_file().fuse_device().ok_or(Errno(22))?;
                        device.attach_clone(original.as_ref())?;
                        Ok(0)
                    })(),
                    Backend::General => self.paths.as_ref().unwrap().retained_control(
                        self.file.clone().unwrap(),
                        |vfs, fd| {
                            crate::ioctl::call_accepted(
                                vfs,
                                [fd as u64, self.args[1], self.args[2], 0, 0, 0],
                                &mut view,
                            )
                        },
                    ),
                    Backend::Direct => match direct(
                        self.direct.as_ref().unwrap(),
                        self.args,
                        &self.factory,
                        &self.paths,
                        &self.task,
                        &mut view,
                    ) {
                        Some(result) => result,
                        None if self.joined => Err(Errno(25)),
                        None => return Step::Authority,
                    },
                };
                if let Some(fault) = view.reader.fault() {
                    return Step::Page(fault);
                }
                self.value = Some(result);
            }
            self.input = Default::default();
        }
        match self.output.progress(memory) {
            Err(MemoryError::Pending(fault)) => return Step::Page(fault),
            Err(_) => return Step::Reply(Err(Errno(14))),
            Ok(()) => {}
        }
        let value = self.value.take().unwrap();
        if value.is_ok() {
            if let Some(Backend::Sync { control, .. }) = self.backend.take() {
                return Step::Reply(control.finish());
            }
        }
        Step::Reply(value)
    }
    pub fn resume_joined(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        vfs: &trames_vfs::Vfs,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if self.factory.is_none() {
            self.factory = Some(vfs.descriptor_factory());
        }
        if self.paths.is_none() {
            self.paths = Some(vfs.path_queries());
        }
        if self.task.is_none() {
            self.task = vfs.terminal_task();
        }
        self.joined = true;
        self.resume(source, memory, pid, target)
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = self
            .task
            .as_ref()
            .and_then(|task| task.subscribe_job(&signal))
            .into_iter()
            .collect();
        match self.progress(memory) {
            Step::Page(fault) => {
                let args = self.args;
                source.park_input(
                    file_input::Accepted::Ioctl(self),
                    fault,
                    29,
                    args,
                    pid,
                    target,
                )
            }
            Step::Binder => {
                let _actor = self
                    .actor
                    .as_ref()
                    .map(trames_vfs::FileActorSnapshot::enter);
                let Some(Backend::Binder { _file: _, factory }) = self.backend.take() else {
                    unreachable!()
                };
                source.start_original_binder(
                    self.file.take().unwrap(),
                    factory,
                    self.args,
                    memory,
                    pid,
                    target,
                )
            }
            Step::Authority => IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                file::FileBoundary::Ioctl(self),
            )),
            Step::Stopped => {
                let args = self.args;
                let mut attempt = source.park_resource_input(
                    file_input::Accepted::Ioctl(self),
                    29,
                    args,
                    signal,
                    subscriptions,
                    target,
                );
                if let IoAttempt::Blocked(pending) = &mut attempt {
                    pending.terminal_job = true;
                }
                attempt
            }
            Step::Reply(value) => {
                source.record_fd_control();
                source.complete(29, self.args, value)
            }
        }
    }
}
impl DirectSyscalls {
    pub(super) fn invoke_ioctl_control(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Option<Result<u64, Errno>>> {
        if self.file_prepared(29, args) {
            return Some(None);
        }
        let mut call = match IoctlControl::new(self, args)? {
            Ok(call) => call,
            Err(error) => {
                self.record_fd_control();
                return Some(Some(Err(error)));
            }
        };
        Some(match call.progress(memory) {
            Step::Reply(value) => {
                self.record_fd_control();
                self.completed.set(self.completed.get() + 1);
                Some(value)
            }
            Step::Page(fault) => {
                self.prepare_input(file_input::Accepted::Ioctl(call), fault, 29, args);
                None
            }
            Step::Authority | Step::Stopped | Step::Binder => {
                self.prepare_checkpoint(
                    file::FileCheckpoint::new(file::FileBoundary::Ioctl(call)),
                    29,
                    args,
                );
                None
            }
        })
    }
    pub(super) fn start_ioctl_control(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if self.file_prepared(29, args) {
            return self.start_prepared_file(29, args, memory, pid, target);
        }
        Some(match IoctlControl::new(self, args)? {
            Ok(call) => call.resume(self, memory, pid, target),
            Err(error) => {
                self.record_fd_control();
                self.complete(29, args, Err(error))
            }
        })
    }
}
#[allow(clippy::large_enum_variant)] // Cold retained syscall state avoids another allocation for its wait.
pub(crate) enum Solo {
    Io(PendingIo),
    Checkpoint(file::FileCheckpoint),
}
impl Solo {
    pub(crate) fn cancel(&self) {
        match self {
            Self::Io(wait) => wait.cancel_copies(),
            Self::Checkpoint(call) => call.cancel(),
        }
    }
}
struct SoloWake;
impl IoWake for SoloWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
impl Linux {
    pub(crate) fn ioctl_progress(
        &mut self,
        args: [u64; 6],
        memory: &mut trames_memory::Memory,
        task: u32,
    ) -> Option<Result<u64, Errno>> {
        let original = self.ioctl_calls.remove(&task);
        let mut source = DirectSyscalls::new(self.vfs.direct_descriptors())
            .with_paths(self.vfs.path_queries())
            .with_resources(self.vfs.descriptor_factory())
            .with_terminal_task(self.vfs.terminal_task());
        if let Some(executor) = &self.file_executor {
            source = source.with_file_executor(executor.clone());
        }
        if let Some(layouts) = &self.file_layouts {
            source = source.with_file_layouts(layouts.clone());
        }
        let tid = if task == 0 { self.vfs.task_pid() } else { task };
        let _actor = trames_vfs::FileActorScope::enter_if_absent(
            || self.vfs.credentials.clone(),
            tid,
            source.sync_executor(),
        );
        let wake: Arc<dyn IoWake> = Arc::new(SoloWake);
        let target = Arc::downgrade(&wake);
        let attempt = match original {
            Some(Solo::Io(wait)) => source.resume(wait, memory),
            Some(Solo::Checkpoint(call)) => match call.take() {
                file::FileBoundary::Ioctl(call) => {
                    call.resume_joined(&source, &self.vfs, memory, tid, &target)
                }
                file::FileBoundary::Signal { value } => IoAttempt::Complete(value),
                _ => unreachable!("original ioctl boundary"),
            },
            None => match source.start(29, args, memory, tid, &target, None) {
                Some(attempt) => attempt,
                None => return Some(crate::ioctl::call(&mut self.vfs, args, memory)),
            },
        };
        let wait = match attempt {
            IoAttempt::Complete(result) => return Some(result),
            IoAttempt::Blocked(wait) => Solo::Io(wait),
            IoAttempt::FileCheckpoint(call) => Solo::Checkpoint(call),
            IoAttempt::HostError(_) => return Some(Err(Errno(5))),
            _ => unreachable!("owned ioctl retains its original capabilities"),
        };
        self.ioctl_calls.insert(task, wait);
        None
    }
    pub fn take_ioctl_wait(&mut self, task: u32) -> Option<PendingIo> {
        if !matches!(self.ioctl_calls.get(&task)?, Solo::Io(_)) {
            return None;
        }
        let Solo::Io(wait) = self.ioctl_calls.remove(&task)? else {
            unreachable!()
        };
        Some(wait)
    }
    pub fn take_ioctl_checkpoint(&mut self, task: u32) -> Option<file::FileCheckpoint> {
        if !matches!(self.ioctl_calls.get(&task)?, Solo::Checkpoint(_)) {
            return None;
        }
        let Solo::Checkpoint(call) = self.ioctl_calls.remove(&task)? else {
            unreachable!()
        };
        Some(call)
    }
}
// These status requests never resolve or observe signal ownership.
struct FlagOwners;
impl trames_vfs::AsyncOwners for FlagOwners {
    fn resolve(&self, _: u32, _: u32) -> Result<Arc<dyn trames_vfs::AsyncOwner>, Errno> {
        unreachable!("flag-only ioctl")
    }
    fn visible(&self, _: u32) -> u32 {
        unreachable!("flag-only ioctl")
    }
}
fn scalar_output(request: u32) -> bool {
    matches!(
        request,
        0x5411
            | 0x541b
            | 0x540f
            | 0x5429
            | 0x80045430
            | 0x80045438
            | 0x80045439
            | 0x800454cf
            | 0x80082407
            | 0xb704
            | 0x8905
    )
}
fn direct(
    fd: &trames_vfs::DirectFd,
    args: [u64; 6],
    factory: &Option<DescriptorFactory>,
    paths: &Option<PathQueries>,
    task: &Option<Arc<dyn TerminalTask>>,
    memory: &mut impl CpuMemory,
) -> Option<Result<u64, Errno>> {
    let request = args[1] as u32;
    if fd.is_entropy_device() {
        return fd.entropy_control();
    }
    if request == 0x5441 {
        let end = fd.pty_endpoint()?;
        let flags = args[2] as u32;
        return Some(
            match paths {
                Some(paths) => paths.open_pty_peer(end, flags),
                None => factory.as_ref()?.open_pty_peer(end, flags),
            }
            .map(u64::from),
        );
    }
    if crate::pty_control_request(request) {
        return Some(crate::pty_control(
            fd.pty_endpoint()?,
            request,
            args[2],
            memory,
        ));
    }
    if let (Some(end), Some(task)) = (fd.pty_endpoint(), task) {
        return Some(
            match crate::pty::terminal_control_prechecked(
                end,
                request,
                args[2],
                u32::from(fd.check_read_access().is_err()),
                task.as_ref(),
                memory,
            ) {
                TerminalIo::Complete(value) => value,
                TerminalIo::Stopped => unreachable!("accepted job-control check"),
            },
        );
    }
    let bytes = if request == 0x5411 {
        (fd.local_outgoing_bytes()? as u32).to_le_bytes().to_vec()
    } else if request == 0x541b {
        (fd.readable_bytes().min(i32::MAX as usize) as i32)
            .to_le_bytes()
            .to_vec()
    } else {
        fd.terminal_query(request)?
    };
    Some(
        memory
            .write(args[2], &bytes)
            .map(|()| 0)
            .map_err(|_| Errno(14)),
    )
}
struct Capture<'a, M> {
    reader: file_input::Reader<'a, M>,
    output: &'a mut CopiedOutput,
    scalar: bool,
    scalar_address: Option<u64>,
}
impl<M: CpuMemory> CpuMemory for Capture<'_, M> {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.reader.mapped_at_or_after(address)
    }
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.reader.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.scalar || self.scalar_address == Some(address) && bytes.len() == 4 {
            self.output.push_scalar(address, bytes);
        } else {
            self.output.push_slice(address, bytes);
        }
        Ok(())
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.reader.check(address, len, access)
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.reader.check_translation(address)
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.reader.fetch_u32(address)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.reader.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.reader.instruction_page_identity(address)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("ioctl copy")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("ioctl copy")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("ioctl copy")
    }
}
