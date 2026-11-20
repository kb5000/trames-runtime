// SPDX-License-Identifier: GPL-3.0-or-later
//! One msync ABI imports the original mapped backing graph before native I/O.
use crate::Linux;
use trames_memory::{CpuMemory, SyncRange, PAGE_SIZE};
use trames_vfs::Errno;

pub(crate) fn prepare(memory: &impl CpuMemory, args: [u64; 6]) -> Option<Result<SyncRange, Errno>> {
    let start = crate::memory_queries::untag_mapping(args[0]);
    if !start.is_multiple_of(PAGE_SIZE) || args[2] & !7 != 0 || args[2] & 5 == 5 {
        return Some(Err(Errno(22)));
    }
    if args[1] == 0 {
        return Some(Ok(SyncRange::default()));
    }
    let length = match Linux::page_length(args[1]) {
        Ok(length) => length,
        Err(error) => return Some(Err(error)),
    };
    if args[2] & 2 != 0 && memory.range_locked(start, length) {
        return Some(Err(Errno(16)));
    }
    Some(
        memory
            .prepare_sync(start, length)?
            .map_err(Linux::memory_errno),
    )
}
