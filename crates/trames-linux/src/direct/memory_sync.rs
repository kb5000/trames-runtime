// SPDX-License-Identifier: GPL-3.0-or-later
//! Original writeback admissions chain through existing layout/disk resources.
use super::*;
use trames_memory::SyncResource;
#[cfg(test)]
#[path = "memory_sync_tests.rs"]
mod tests;

struct SyncTask {
    current: Arc<dyn SyncResource>,
    remaining: std::vec::IntoIter<Arc<dyn SyncResource>>,
    layouts: Weak<crate::FileLayouts>,
    result: Option<Arc<FileResult>>,
    close_value: Option<u64>,
    notify: Option<Box<dyn FnOnce() + Send>>,
    registration: Option<crate::file_layouts::SyncRegistration>,
}
fn finish(result: &FileResult, value: u64) {
    result.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
        resources: Default::default(),
        result: Ok(trames_vfs::FileValue::Count(value)),
        file_size_signal: false,
        scratch: None,
    }));
}
impl Drop for SyncTask {
    fn drop(&mut self) {
        drop(self.registration.take());
        // A closed native pool or callback unwind completes the accepted wait.
        // No guest pointer/FD is replayed and remaining backings are released.
        if let Some(result) = self.result.take() {
            self.current
                .failed(trames_memory::MemoryError::BackingIo(5));
            for resource in self.remaining.by_ref() {
                resource.failed(trames_memory::MemoryError::BackingIo(5));
            }
            if let Some(value) = self.close_value {
                finish(&result, value);
            } else {
                result.fail(5);
            }
        }
        if let Some(notify) = self.notify.take() {
            notify();
        }
    }
}
impl crate::HostFileTask for SyncTask {
    fn layout(&self) -> Option<Arc<crate::HostFileLayout>> {
        self.current.layout()
    }
    fn run(mut self: Box<Self>, admission: Option<crate::HostFileAdmission>) {
        // This task has already left the queue with native admission. Retiring
        // its layout owner cannot cancel accepted host work. Only an async
        // provider which still needs that executor must retire its callback.
        let layouts = self.layouts.upgrade();
        self.registration = layouts
            .as_ref()
            .map(|layouts| layouts.retain_sync(&self.current));
        let current = self.current.clone();
        match current.sync_async(self) {
            Ok(()) => {
                drop(admission);
                if layouts.is_none() {
                    current.failed(trames_memory::MemoryError::BackingIo(5));
                }
            }
            Err(completion) => {
                let value = current.sync();
                drop(admission);
                completion.complete(value);
            }
        }
    }
    fn fail(self: Box<Self>) {
        drop(self);
    }
}
impl trames_memory::SyncCompletion for SyncTask {
    fn retry(mut self: Box<Self>) {
        drop(self.registration.take());
        if let Some(layouts) = self.layouts.upgrade() {
            layouts.submit_host(self);
        }
    }
    fn complete(mut self: Box<Self>, value: Result<(), trames_memory::MemoryError>) {
        drop(self.registration.take());
        // Release this actual backing before requesting the next. A later
        // alias must not wait on a ticket retained by its own completed job.
        let result = self.result.take().expect("accepted sync result");
        match value {
            Err(_) if self.close_value.is_some() => self.advance(result),
            Err(error) => result.fail(Linux::memory_errno(error).0),
            Ok(()) => self.advance(result),
        }
    }
}
impl SyncTask {
    fn advance(mut self: Box<Self>, result: Arc<FileResult>) {
        if let Some(next) = self.remaining.next() {
            self.current = next;
            self.result = Some(result);
            if let Some(layouts) = self.layouts.upgrade() {
                layouts.submit_host(self);
            }
        } else {
            finish(&result, self.close_value.unwrap_or(0));
        }
    }
}
impl crate::FileLayouts {
    /// VMA close has no error return. The inode records writeback failures;
    /// the structural syscall keeps its already-completed original result.
    pub fn close_mappings(
        self: &Arc<Self>,
        resources: Vec<Arc<dyn SyncResource>>,
        value: u64,
    ) -> Arc<FileResult> {
        self.close_mappings_notify(resources, value, None)
    }
    pub fn close_mappings_notify(
        self: &Arc<Self>,
        resources: Vec<Arc<dyn SyncResource>>,
        value: u64,
        notify: Option<Box<dyn FnOnce() + Send>>,
    ) -> Arc<FileResult> {
        let result = Arc::new(FileResult::default());
        let mut remaining = resources.into_iter();
        if let Some(current) = remaining.next() {
            self.submit_host(Box::new(SyncTask {
                current,
                remaining,
                layouts: Arc::downgrade(self),
                result: Some(result.clone()),
                close_value: Some(value),
                notify,
                registration: None,
            }));
        } else {
            finish(&result, value);
            if let Some(notify) = notify {
                notify();
            }
        }
        result
    }
}

impl DirectSyscalls {
    pub(super) fn start_memory_sync(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let work = match crate::memory_sync::prepare(memory, args)? {
            Ok(work) => work,
            Err(error) => return Some(self.complete(227, args, Err(error))),
        };
        if work.is_empty() {
            return Some(self.complete(227, args, Ok(0)));
        }
        let layouts = self.file_layouts.as_ref()?;
        let result = Arc::new(FileResult::default());
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![result.subscribe(&signal)];
        let mut remaining = work.into_resources().into_iter();
        let current = remaining.next().expect("nonempty sync");
        layouts.submit_host(Box::new(SyncTask {
            current,
            remaining,
            layouts: Arc::downgrade(layouts),
            result: Some(result.clone()),
            close_value: None,
            notify: None,
            registration: None,
        }));
        Some(self.resume_file(
            FilePending::new(result, FileOutput::None, None),
            227,
            args,
            signal,
            subscriptions,
            memory,
            target,
        ))
    }
    /// Called after one completed structural mutation, before re-entering
    /// guest execution. The pending object owns no old mapping addresses.
    #[allow(clippy::too_many_arguments)]
    pub fn start_mapping_close(
        &self,
        resources: Vec<Arc<dyn SyncResource>>,
        value: u64,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let result = self
            .file_layouts
            .as_ref()
            .expect("original file layout executor")
            .close_mappings(resources, value);
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = vec![result.subscribe(&signal)];
        self.resume_file(
            FilePending::new(result, FileOutput::None, None),
            number,
            args,
            signal,
            subscriptions,
            memory,
            target,
        )
    }
}
