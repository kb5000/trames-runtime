// SPDX-License-Identifier: GPL-3.0-or-later
//! A native overlay open waits on its original inode and unpublished FD slot.
use super::*;

pub(crate) struct Request {
    pub(crate) entry: ResolvedEntry,
    pub(crate) flags: u32,
    pub(crate) mode: u32,
    pub(crate) path_truncate: bool,
    pub(crate) denied: u64,
    pub(crate) publication: Option<DirectFiles>,
    pub(crate) reservation: Option<fd_table::ReservedFd>,
    pub(crate) _access: Option<executable::WriteAccess>,
}
impl FileWork {
    pub(super) fn publish_open(&mut self, result: Result<FileValue>) -> Result<FileValue> {
        result.and_then(|value| match self.open.take() {
            Some(open) => open
                .publish(&self.paths)
                .map(|fd| FileValue::Count(fd as u64)),
            None => Ok(value),
        })
    }
    pub(crate) fn resource_open(
        vfs: &Vfs,
        request: ResourceOpen,
        wait: Arc<trames_memory::PageWait>,
    ) -> Self {
        Self {
            // The operation lives in resource_open, before descriptor dispatch.
            // It must not enter the all-filesystem sync queue of sync_all.
            command: FileCommand::TruncateOpen,
            resource_open: Some(Box::new(request)),
            resource_wait: Some(wait),
            ..Self::sync_all(vfs.path_queries())
        }
    }
    pub(super) fn run_resource_open(mut self) -> FileOutcome {
        let mut request = self.resource_open.take().unwrap();
        let (result, deferred, next) = {
            let mut view = self.paths.view.borrow_mut();
            view.query.as_ref().unwrap().clear_deferred();
            let result = if request.path_truncate {
                view.open_reserved_phase::<true, true>(
                    request.entry.clone(),
                    request.flags,
                    request.mode,
                    request.publication.as_ref(),
                    &mut request.reservation,
                    request.denied,
                )
            } else {
                view.open_reserved_phase::<false, true>(
                    request.entry.clone(),
                    request.flags,
                    request.mode,
                    request.publication.as_ref(),
                    &mut request.reservation,
                    request.denied,
                )
            };
            let query = view.query.as_ref().unwrap();
            let deferred = query.take_deferred();
            let next = if deferred {
                query.prepared.borrow_mut().work.take()
            } else {
                None
            };
            (result, deferred, next)
        };
        if let Some(next) = next {
            return FileOutcome::Waiting(next.into_inner().unwrap());
        }
        if deferred {
            // Copy-up finished and O_TRUNC still needs the ordinary original
            // provider/layout boundary. The same reservation follows it.
            if let Some(work) = self.paths.take_open_work() {
                return work.run();
            }
        }
        FileOutcome::Complete(FileReply {
            result: if deferred {
                Err(Errno(5))
            } else {
                result.map(|fd| FileValue::Count(fd as u64))
            },
            resources: Default::default(),
            file_size_signal: false,
            scratch: None,
        })
    }
}
