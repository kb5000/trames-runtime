// SPDX-License-Identifier: GPL-3.0-or-later
//! A pending lookup has not acquired a context; accepted calls own one user.
use super::*;

pub struct Lookup {
    aio: Aio,
    number: u32,
    args: [u64; 6],
    deadline: Option<Instant>,
    bytes: file_input::Bytes,
    header: Option<input::Header>,
    resources: trames_vfs::CgroupResourceContext,
}
impl Lookup {
    pub(super) fn new(
        aio: Aio,
        number: u32,
        args: [u64; 6],
        deadline: Option<Instant>,
        resources: trames_vfs::CgroupResourceContext,
    ) -> Self {
        Self {
            aio,
            number,
            args,
            deadline,
            bytes: Default::default(),
            header: matches!(number, 4 | 292).then(input::Header::default),
            resources,
        }
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let _resources = self.resources.enter();
        if self.number == 2 && self.args[1] > i64::MAX as u64 {
            return IoAttempt::Complete(Err(Errno(22)));
        }
        if let Some(header) = &mut self.header {
            match header.import(source, self.number, self.args, memory, self.deadline) {
                Ok(Ok(true)) => {}
                Ok(Ok(false)) => {
                    return IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                        file::FileBoundary::AioLookup(self),
                    ))
                }
                Ok(Err(error)) => return IoAttempt::Complete(Err(error)),
                Err(fault) => {
                    let (number, args) = (self.number, self.args);
                    return source.park_input(
                        file_input::Accepted::AioLookup(self),
                        fault,
                        number,
                        args,
                        pid,
                        target,
                    );
                }
            }
        }
        let reader = file_input::Reader::new(memory, &self.bytes);
        let imported = (|| {
            if self.number == 3 {
                let key = self.args[1].checked_add(8).ok_or(Errno(14))?;
                if u32::from_le_bytes(reader.read_array(key).map_err(|_| Errno(14))?) != 0 {
                    return Err(Errno(22));
                }
            }
            let slot = u32::from_le_bytes(reader.read_array(self.args[0]).map_err(|_| Errno(22))?);
            self.aio.context_slot(self.args[0], slot)
        })();
        if let Some(fault) = reader.fault() {
            let (number, args) = (self.number, self.args);
            return source.park_input(
                file_input::Accepted::AioLookup(self),
                fault,
                number,
                args,
                pid,
                target,
            );
        }
        let call = imported.and_then(|context| {
            RetainedAio::accepted(
                context,
                self.number,
                self.args,
                self.deadline,
                self.header
                    .take()
                    .map(|header| Arc::new(Mutex::new(header))),
                self.resources.clone(),
            )
        });
        match call {
            Ok(call) => source.start_retained_aio(call, memory, pid, target),
            Err(error) => IoAttempt::Complete(Err(error)),
        }
    }
}

pub(super) struct User {
    context: Arc<Context>,
    active: std::sync::atomic::AtomicBool,
    exiting: std::sync::atomic::AtomicBool,
    destroy: bool,
    // Old syscall snapshots share logical completion. They must not keep a
    // deleted controller alive after this one user has actually retired.
    resources: Mutex<Option<trames_vfs::CgroupResourceContext>>,
}
impl User {
    pub(super) fn resource_scope(&self) -> Option<trames_vfs::CgroupResourceScope> {
        self.resources
            .lock()
            .unwrap()
            .as_ref()
            .map(|resources| resources.enter())
    }
    pub(super) fn active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(super) fn exiting(&self) -> bool {
        self.exiting.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(super) fn begin_exit(&self) {
        self.exiting
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub(super) fn setup(context: Arc<Context>) -> Arc<Self> {
        context.state.lock().unwrap().users += 1;
        Arc::new(Self {
            context,
            active: true.into(),
            exiting: false.into(),
            destroy: false,
            resources: Mutex::new(Some(trames_vfs::CgroupResourceContext::capture())),
        })
    }
    pub(super) fn release(&self) {
        // Snapshot clones represent one call, not independent context users.
        // Completion releases that user even while a retired snapshot exists.
        if self
            .active
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            let mut state = self.context.state.lock().unwrap();
            if self.destroy {
                state.destroyers -= 1;
            } else {
                state.users -= 1;
            }
            drop(state);
            let resources = self.resources.lock().unwrap().take();
            drop(resources);
            self.context.notify();
        }
    }
}
impl Drop for User {
    fn drop(&mut self) {
        self.release();
    }
}
impl RetainedAio {
    fn accepted(
        context: Arc<Context>,
        number: u32,
        args: [u64; 6],
        deadline: Option<Instant>,
        header: Option<Arc<Mutex<input::Header>>>,
        resources: trames_vfs::CgroupResourceContext,
    ) -> Result<Self, Errno> {
        let user = {
            let mut state = context.state.lock().unwrap();
            if state.dead {
                return Err(Errno(22));
            }
            if number == 1 {
                state.destroyers += 1;
            } else {
                state.users += 1;
            }
            Some(Arc::new(User {
                context: context.clone(),
                active: true.into(),
                exiting: false.into(),
                destroy: number == 1,
                resources: Mutex::new(Some(resources)),
            }))
        };
        Ok(Self {
            context,
            user,
            destroyed: false,
            batch: None,
            import: None,
            header,
            events: None,
            reaped: 0,
            number,
            args,
            deadline,
        })
    }
}
