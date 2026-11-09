// SPDX-License-Identifier: GPL-3.0-or-later
//! Original writeback admissions chain through existing layout/disk resources.
use super::*;
use trames_memory::PageBacking;
#[cfg(test)]
#[path = "memory_sync_tests.rs"]
mod tests;

struct SyncTask {
    current: Arc<dyn PageBacking>,
    remaining: std::vec::IntoIter<Arc<dyn PageBacking>>,
    layouts: Weak<crate::FileLayouts>,
    result: Option<Arc<FileResult>>,
}
impl Drop for SyncTask {
    fn drop(&mut self) {
        // A closed native pool or callback unwind completes the accepted wait.
        // No guest pointer/FD is replayed and remaining backings are released.
        if let Some(result) = self.result.take() {
            result.fail(5);
        }
    }
}
impl crate::HostFileTask for SyncTask {
    fn layout(&self) -> Option<Arc<crate::HostFileLayout>> {
        self.current.layout()
    }
    fn run(mut self: Box<Self>, admission: Option<crate::HostFileAdmission>) {
        let value = self.current.sync();
        // Release this actual backing before requesting the next. A later
        // alias must not wait on a ticket retained by its own completed job.
        drop(admission);
        let result = self.result.take().expect("accepted sync result");
        match value {
            Err(error) => result.fail(Linux::memory_errno(error).0),
            Ok(()) => {
                if let Some(next) = self.remaining.next() {
                    if let Some(layouts) = self.layouts.upgrade() {
                        self.current = next;
                        self.result = Some(result);
                        layouts.submit_host(self);
                    } else {
                        result.fail(5);
                    }
                } else {
                    result.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
                        result: Ok(trames_vfs::FileValue::Count(0)),
                        file_size_signal: false,
                        scratch: None,
                    }));
                }
            }
        }
    }
    fn fail(self: Box<Self>) {
        drop(self);
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
        let mut remaining = work.into_backings().into_iter();
        let current = remaining.next().expect("nonempty sync");
        layouts.submit_host(Box::new(SyncTask {
            current,
            remaining,
            layouts: Arc::downgrade(layouts),
            result: Some(result.clone()),
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
}
