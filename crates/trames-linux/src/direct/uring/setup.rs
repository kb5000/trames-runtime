// SPDX-License-Identifier: GPL-3.0-or-later
//! Setup publishes its one reserved FD only after the original parameter copy.
use super::*;
pub(in crate::direct) struct Setup {
    paths: trames_vfs::PathQueries,
    args: [u64; 6],
    bytes: file_input::Bytes,
    prepared: Option<trames_vfs::PreparedDescriptor>,
    output: crate::copy_replay::Replay,
}
impl Setup {
    pub(in crate::direct) fn new(paths: trames_vfs::PathQueries, args: [u64; 6]) -> Self {
        Self {
            paths,
            args,
            bytes: Default::default(),
            prepared: None,
            output: Default::default(),
        }
    }
    pub(in crate::direct) fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
    ) -> std::result::Result<Result<u64>, trames_memory::PageFault> {
        if self.prepared.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let parameters = crate::uring::setup_parameters(self.args, &reader);
            if let Some(fault) = reader.fault() {
                return Err(fault);
            }
            let (entries, cq_entries, bytes) = match parameters {
                Ok(value) => value,
                Err(error) => return Ok(Err(error)),
            };
            self.prepared = Some(match self.paths.prepare_uring(entries, cq_entries) {
                Ok(value) => value,
                Err(error) => return Ok(Err(error)),
            });
            self.output.capture(self.args[1], &bytes);
        }
        match self.output.progress(memory) {
            Ok(()) => Ok(self.prepared.take().unwrap().publish().map(u64::from)),
            Err(trames_memory::MemoryError::Pending(fault)) => Err(fault),
            Err(_) => Ok(Err(Errno(14))),
        }
    }
}
