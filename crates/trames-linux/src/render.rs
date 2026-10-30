// SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery ABI for Trames' own virtual render node; no DRM command submission.
use crate::state::Linux;
use trames_memory::Memory;
use trames_vfs::Errno;
impl Linux {
    pub(super) fn render_ioctl(
        &self,
        request: u64,
        at: u64,
        memory: &mut Memory,
    ) -> Result<u64, Errno> {
        if request != 0xc0406400 {
            return Err(Errno(25));
        }
        let mut record = memory.read_array::<64>(at).map_err(|_| Errno(14))?;
        for (offset, text) in [
            (16, b"trames".as_slice()),
            (32, b"20261031".as_slice()),
            (48, b"Trames virtual render device".as_slice()),
        ] {
            let capacity = u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap());
            let address = u64::from_le_bytes(record[offset + 8..offset + 16].try_into().unwrap());
            let count = capacity.min(text.len() as u64) as usize;
            if count != 0 {
                memory
                    .write(address, &text[..count])
                    .map_err(|_| Errno(14))?;
            }
            record[offset..offset + 8].copy_from_slice(&(text.len() as u64).to_le_bytes());
        }
        record[..12].fill(0);
        record[..4].copy_from_slice(&1u32.to_le_bytes());
        memory.write(at, &record).map_err(|_| Errno(14))?;
        Ok(0)
    }
}
