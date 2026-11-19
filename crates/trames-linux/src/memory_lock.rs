// SPDX-License-Identifier: GPL-3.0-or-later
use super::Linux;
use trames_memory::{Memory, ADDRESS_LIMIT, PAGE_SIZE};
use trames_vfs::{capabilities, Errno};
type Result<T> = std::result::Result<T, Errno>;

impl Linux {
    fn memlock_limit(&self) -> u64 {
        if self.vfs.credentials.has_cap(capabilities::IPC_LOCK) {
            u64::MAX
        } else {
            self.vfs.memory_resource_limits().locked()
        }
    }
    pub(super) fn admit_locked_mapping(
        &self,
        memory: &Memory,
        addr: u64,
        len: u64,
        explicit: bool,
    ) -> Result<Option<bool>> {
        let mode = if explicit {
            Some(false)
        } else {
            memory.future_lock()
        };
        if mode.is_some() {
            let limit = self.memlock_limit();
            if limit == 0 && explicit {
                return Err(Errno(1));
            }
            if limit != u64::MAX
                && memory.locked_bytes_in(0, ADDRESS_LIMIT) - memory.locked_bytes_in(addr, len)
                    + len
                    > limit
            {
                return Err(Errno(11));
            }
        }
        Ok(mode)
    }
    pub(super) fn admit_lock_growth(&self, memory: &Memory, additional: u64) -> Result<()> {
        if memory
            .locked_bytes_in(0, ADDRESS_LIMIT)
            .saturating_add(additional)
            > self.memlock_limit()
        {
            Err(Errno(11))
        } else {
            Ok(())
        }
    }
    pub(super) fn memory_lock(&self, n: u64, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let limit = self.memlock_limit();
        match n {
            230 => {
                let flags = a[0] as u32;
                if flags & !7 != 0 || flags & 3 == 0 {
                    return Err(Errno(22));
                }
                if limit == 0 {
                    return Err(Errno(1));
                }
                if flags & 1 != 0 && memory.virtual_bytes() > limit {
                    return Err(Errno(12));
                }
                memory.set_all_locks(flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
            }
            231 => memory.set_all_locks(false, false, false),
            _ => {
                if n == 284 && a[2] as u32 & !1 != 0 {
                    return Err(Errno(22));
                }
                if n != 229 && limit == 0 {
                    return Err(Errno(1));
                }
                let addr = a[0] & 0x00ff_ffff_ffff_ffff;
                let start = addr & !(PAGE_SIZE - 1);
                let end = addr
                    .checked_add(a[1])
                    .and_then(|end| end.checked_add(PAGE_SIZE - 1))
                    .map(|end| end & !(PAGE_SIZE - 1))
                    .filter(|end| *end <= ADDRESS_LIMIT)
                    .ok_or(Errno(12))?;
                let len = end - start;
                if len == 0 {
                    return Ok(0);
                }
                if n != 229
                    && limit != u64::MAX
                    && memory.locked_bytes_in(0, ADDRESS_LIMIT) - memory.locked_bytes_in(start, len)
                        + len
                        > limit
                {
                    return Err(Errno(12));
                }
                memory
                    .set_range_lock(
                        start,
                        len,
                        (n != 229).then_some(n == 284 && a[2] as u32 & 1 != 0),
                    )
                    .map_err(|_| Errno(12))?;
            }
        }
        Ok(0)
    }
}
