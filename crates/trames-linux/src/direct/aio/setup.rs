// SPDX-License-Identifier: GPL-3.0-or-later
//! Setup retains its original context and handle copy until commit or cleanup.
use super::*;
#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;

pub struct SetupInput {
    aio: Aio,
    args: [u64; 6],
    bytes: file_input::Bytes,
    imported: bool,
    allocation: Option<Allocation>,
    result: Option<Result<u64, Errno>>,
}
pub(super) struct Allocation {
    aio: Aio,
    context: Arc<Context>,
    user: Arc<lookup::User>,
    mapping: Option<trames_memory::MappingLease>,
    pub(super) copy: crate::copy_replay::Replay,
    published: bool,
    cleanup_required: Option<bool>,
}
impl Allocation {
    pub(super) fn new(
        aio: Aio,
        context: Arc<Context>,
        mapping: trames_memory::MappingLease,
        output: u64,
        address: u64,
    ) -> Self {
        let mut copy = crate::copy_replay::Replay::default();
        copy.capture(output, &address.to_le_bytes());
        Self {
            aio,
            user: lookup::User::setup(context.clone()),
            context,
            mapping: Some(mapping),
            copy,
            published: false,
            cleanup_required: None,
        }
    }
    fn kill(&mut self) -> bool {
        if let Some(required) = self.cleanup_required {
            return required;
        }
        let required = {
            let mut state = self.context.state.lock().unwrap();
            let required = !state.dead;
            state.dead = true;
            required
        };
        let mut contexts = self.aio.0.contexts.lock().unwrap();
        if contexts
            .get(&self.context.slot)
            .is_some_and(|current| Arc::ptr_eq(current, &self.context))
        {
            self.aio
                .0
                .retiring
                .lock()
                .unwrap()
                .push(Arc::downgrade(&self.context));
            contexts.remove(&self.context.slot);
        }
        drop(contexts);
        self.context.notify();
        self.cleanup_required = Some(required);
        required
    }
    pub(super) fn commit(&mut self) {
        self.mapping.take().unwrap().commit();
        self.published = true;
        self.user.release();
    }
    pub(super) fn cancel(&mut self, memory: &mut trames_memory::Memory) -> Result<bool, Errno> {
        if !self.kill() {
            if let Some(mapping) = self.mapping.take() {
                mapping.commit();
            }
            self.user.release();
            return Ok(true);
        }
        if !self
            .mapping
            .as_mut()
            .unwrap()
            .cancel(memory)
            .map_err(Linux::memory_errno)?
        {
            return Ok(false);
        }
        self.mapping = None;
        self.user.release();
        Ok(true)
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.published && !self.kill() {
            if let Some(mapping) = self.mapping.take() {
                mapping.commit();
            }
        }
        self.user.release();
        // An armed lease queues the original context's native unmap rule.
        // Task/mm retirement drains it without a destructor-side mapping edit.
    }
}
impl SetupInput {
    pub(super) fn new(aio: Aio, args: [u64; 6]) -> Self {
        Self {
            aio,
            args,
            bytes: Default::default(),
            imported: false,
            allocation: None,
            result: None,
        }
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if !self.imported {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let imported = reader.read_u64(self.args[1]).map_err(|_| Errno(14));
            if let Some(fault) = reader.fault() {
                let args = self.args;
                return source.park_input(
                    file_input::Accepted::AioSetup(self),
                    fault,
                    0,
                    args,
                    pid,
                    target,
                );
            }
            match imported {
                Ok(0) => {}
                Ok(_) => return IoAttempt::Complete(Err(Errno(22))),
                Err(error) => return IoAttempt::Complete(Err(error)),
            }
            if let Err(error) = Aio::setup_count(self.args[0] as u32) {
                return IoAttempt::Complete(Err(error));
            }
            self.imported = true;
        }
        if self.allocation.is_none() {
            let Some(owner) = memory.mapping_owner() else {
                return IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                    file::FileBoundary::AioSetup(self),
                ));
            };
            self.allocation = Some(
                match self.aio.allocate(self.args[0] as u32, self.args[1], owner) {
                    Ok(allocation) => allocation,
                    Err(error) => return IoAttempt::Complete(Err(error)),
                },
            );
        }
        if self.result.is_none() {
            match self.allocation.as_mut().unwrap().copy.progress(memory) {
                Ok(()) => {
                    self.allocation.as_mut().unwrap().commit();
                    return IoAttempt::Complete(Ok(0));
                }
                Err(trames_memory::MemoryError::Pending(fault)) => {
                    let args = self.args;
                    return source.park_input(
                        file_input::Accepted::AioSetup(self),
                        fault,
                        0,
                        args,
                        pid,
                        target,
                    );
                }
                Err(_) => self.result = Some(Err(Errno(14))),
            }
        }
        let Some(owner) = memory.mapping_owner() else {
            return IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                file::FileBoundary::AioSetup(self),
            ));
        };
        match self.allocation.as_mut().unwrap().cancel(owner) {
            Ok(true) => IoAttempt::Complete(self.result.unwrap()),
            Ok(false) => IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                file::FileBoundary::AioSetup(self),
            )),
            Err(error) => IoAttempt::Complete(Err(error)),
        }
    }
}
