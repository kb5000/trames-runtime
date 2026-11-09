// SPDX-License-Identifier: GPL-3.0-or-later
//! File-cache hints share original descriptor metadata and one source/solo ABI.
use trames_vfs::Errno;

pub(crate) fn entry(number: u32) -> bool {
    matches!(number, 213 | 223)
}
pub(crate) fn call(
    number: u32,
    args: [u64; 6],
    stat: Result<[u8; 128], Errno>,
) -> Result<u64, Errno> {
    let stat = stat?;
    if u32::from_le_bytes(stat[16..20].try_into().expect("mode")) & 0o170000 != 0o100000 {
        return Err(Errno(22));
    }
    if args[1] > i64::MAX as u64 || number == 223 && (args[2] > i64::MAX as u64 || args[3] > 5) {
        return Err(Errno(22));
    }
    // Preserve the existing optional-advice policy. No data transfer, cache
    // population/eviction, file-position update or guest-byte access occurs.
    Ok(0)
}

#[cfg(test)]
#[path = "file_advice_tests.rs"]
mod tests;
