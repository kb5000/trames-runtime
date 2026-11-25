// SPDX-License-Identifier: GPL-3.0-or-later
//! An accepted SQE imports each successful user fragment once. File and fixed
//! buffer capabilities already reached before a fault survive registration or
//! numeric-FD replacement; the original source drives its page wait.
use super::*;
use crate::direct::file_input::{Bytes, Reader};
use trames_memory::{CpuMemory, PageWait, PinnedBuffer};
use trames_vfs::UringFile;

// Reserve the largest iovec and pathname import while a request is incomplete,
// so completing metadata cannot grow beyond the ring's accepted batch budget.
pub(crate) const RESERVED_METADATA: usize = 512 + 1024 * 16 + 4096;
pub(crate) trait Resources {
    fn fixed_file(&self, index: usize) -> Option<UringFile>;
    fn buffer(&self, index: usize) -> Option<Arc<PinnedBuffer>>;
}
impl Resources for UringState {
    fn fixed_file(&self, index: usize) -> Option<UringFile> {
        self.files.as_ref()?.get(index)?.clone()
    }
    fn buffer(&self, index: usize) -> Option<Arc<PinnedBuffer>> {
        self.buffers.as_ref()?.get(index).cloned()
    }
}
pub(crate) struct Pending {
    bytes: Box<Bytes>,
    pub(crate) wait: Arc<PageWait>,
    file: Option<UringFile>,
    buffer: Option<Arc<PinnedBuffer>>,
    clock: Instant,
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture(
    sqe: UringSqe,
    sequence: u64,
    resources: &impl Resources,
    memory: &impl CpuMemory,
    task: u32,
    dependency: Option<(u64, bool)>,
    clock: Instant,
    accept: impl FnMut(u32) -> Option<Result<UringFile>>,
) -> Option<(UringRequest, Option<Pending>)> {
    if !memory.async_faults_possible() {
        return Some((
            import_request(
                sqe, sequence, resources, memory, task, dependency, clock, accept,
            )?,
            None,
        ));
    }
    let bytes = Box::<Bytes>::default();
    let reader = Reader::new(memory, &bytes);
    let mut request = import_request(
        sqe, sequence, resources, &reader, task, dependency, clock, accept,
    )?;
    let fault = reader.fault();
    let pending = if let Some(fault) = fault.filter(|_| request.error == Some(Errno(14))) {
        request.error = None;
        request.import_pending = true;
        request.copy_pending = true;
        // The request carries the original file through ring graph admission.
        // Copy it into the pending import only at accept_import/bind, so a
        // rejected batch never closes an extra original OFD under the ring lock.
        Some(Pending {
            bytes,
            wait: fault.wait,
            file: None,
            buffer: request.buffer.clone(),
            clock,
        })
    } else {
        None
    };
    Some((request, pending))
}
struct Original<'a> {
    pending: &'a Pending,
    ring: &'a Uring,
}
impl Resources for Original<'_> {
    fn fixed_file(&self, index: usize) -> Option<UringFile> {
        self.pending
            .file
            .clone()
            .or_else(|| self.ring.state.lock().unwrap().fixed_file(index))
    }
    fn buffer(&self, index: usize) -> Option<Arc<PinnedBuffer>> {
        self.pending
            .buffer
            .clone()
            .or_else(|| self.ring.state.lock().unwrap().buffer(index))
    }
}
impl Pending {
    pub(crate) fn bind(&mut self, request: &UringRequest) {
        self.file = request.file.clone();
    }
    pub(crate) fn replay(
        &mut self,
        request: &UringRequest,
        ring: &Uring,
        memory: &impl CpuMemory,
        mut accept: impl FnMut(u32) -> Option<Result<UringFile>>,
    ) -> Option<Option<UringRequest>> {
        let reader = Reader::new(memory, &self.bytes);
        let result = import_request(
            request.sqe.clone(),
            request.sequence,
            &Original {
                pending: self,
                ring,
            },
            &reader,
            request.task,
            request.dependency,
            self.clock,
            |fd| {
                self.file
                    .clone()
                    .map(Ok)
                    .map(Some)
                    .unwrap_or_else(|| accept(fd))
            },
        )?;
        // A relative pathname can fault before reaching dirfd. Preserve that
        // capability as soon as a resumed import actually accepts it.
        let fault = reader.fault();
        if let Some(fault) = fault.filter(|_| result.error == Some(Errno(14))) {
            self.wait = fault.wait;
            if self.file.is_none() {
                self.file = result.file;
            }
            if self.buffer.is_none() {
                self.buffer = result.buffer;
            }
            Some(None)
        } else {
            Some(Some(result))
        }
    }
}
