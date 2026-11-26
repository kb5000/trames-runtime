// SPDX-License-Identifier: GPL-3.0-or-later
//! Setup publishes its one reserved FD only after the original parameter copy.
use super::*;
pub(in crate::direct) struct Setup {
    paths: trames_vfs::PathQueries,
    args: [u64; 6],
    bytes: file_input::Bytes,
    prepared: Option<trames_vfs::PreparedDescriptor>,
    ring: Option<trames_vfs::UringPreparation>,
    output: crate::copy_replay::Replay,
    resources: trames_vfs::CgroupResourceContext,
}
impl Setup {
    pub(in crate::direct) fn new(paths: trames_vfs::PathQueries, args: [u64; 6]) -> Self {
        Self {
            paths,
            args,
            bytes: Default::default(),
            prepared: None,
            ring: None,
            output: Default::default(),
            resources: trames_vfs::CgroupResourceContext::capture(),
        }
    }
    pub(in crate::direct) fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
    ) -> std::result::Result<Result<u64>, trames_memory::PageFault> {
        let _resources = self.resources.enter();
        if self.ring.is_none() && self.prepared.is_none() {
            let reader = file_input::Reader::new(memory, &self.bytes);
            let parameters = crate::uring::setup_parameters(self.args, &reader);
            if let Some(fault) = reader.fault() {
                return Err(fault);
            }
            let (entries, cq_entries, bytes) = match parameters {
                Ok(value) => value,
                Err(error) => return Ok(Err(error)),
            };
            self.ring = Some(match self.paths.begin_uring(entries, cq_entries) {
                Ok(value) => value,
                Err(error) => return Ok(Err(error)),
            });
            self.output.capture(self.args[1], &bytes);
        }
        if self.prepared.is_none() {
            let ring = self.ring.as_mut().unwrap();
            match ring.progress() {
                Ok(Some((prepared, _))) => self.prepared = Some(prepared),
                Ok(None) => {
                    return Err(trames_memory::PageFault {
                        address: self.args[1],
                        wait: ring.wait().unwrap().clone(),
                    })
                }
                Err(error) => return Ok(Err(error)),
            }
        }
        match self.output.progress(memory) {
            Ok(()) => Ok(self.prepared.take().unwrap().publish().map(u64::from)),
            Err(trames_memory::MemoryError::Pending(fault)) => Err(fault),
            Err(_) => Ok(Err(Errno(14))),
        }
    }
}
