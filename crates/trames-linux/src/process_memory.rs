// SPDX-License-Identifier: GPL-3.0-or-later
//! Same-mm process_vm transfers use the executing task's original memory.
//! Cross-mm transfers need a retained target-mm admission and remain unsupported.
use trames_memory::{CpuMemory, PAGE_SIZE};
use trames_vfs::Errno;

pub fn process_vm_local(
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    if a[5] != 0 || a[2] > 1024 || a[4] > 1024 {
        return Err(Errno(22));
    }
    fn vectors(
        memory: &impl CpuMemory,
        address: u64,
        count: u64,
    ) -> Result<Vec<(u64, u64)>, Errno> {
        let mut total = 0u64;
        (0..count)
            .map(|i| {
                let address = address.checked_add(i * 16).ok_or(Errno(14))?;
                let bytes = memory.read_array::<16>(address).map_err(|_| Errno(14))?;
                let base = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                let length = u64::from_le_bytes(bytes[8..].try_into().unwrap());
                total = total
                    .checked_add(length)
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or(Errno(22))?;
                Ok((base, length))
            })
            .collect()
    }
    let local = vectors(memory, a[1], a[2])?;
    if local.iter().all(|v| v.1 == 0) {
        return Ok(0);
    }
    let remote = vectors(memory, a[3], a[4])?;
    let (source, dest) = if number == 270 {
        (remote, local)
    } else {
        (local, remote)
    };
    let (mut si, mut di, mut so, mut offset) = (0, 0, 0, 0);
    let mut copied = 0;
    let mut buffer = [0; PAGE_SIZE as usize];
    while si < source.len() && di < dest.len() {
        if so == source[si].1 {
            si += 1;
            so = 0;
            continue;
        }
        if offset == dest[di].1 {
            di += 1;
            offset = 0;
            continue;
        }
        let result = (|| {
            let src = source[si].0.checked_add(so).ok_or(Errno(14))?;
            let dst = dest[di].0.checked_add(offset).ok_or(Errno(14))?;
            let n = (source[si].1 - so)
                .min(dest[di].1 - offset)
                .min(PAGE_SIZE - src % PAGE_SIZE)
                .min(PAGE_SIZE - dst % PAGE_SIZE) as usize;
            memory.read(src, &mut buffer[..n]).map_err(|_| Errno(14))?;
            memory.write(dst, &buffer[..n]).map_err(|_| Errno(14))?;
            Ok::<_, Errno>(n as u64)
        })();
        match result {
            Ok(n) => {
                copied += n;
                so += n;
                offset += n;
            }
            Err(error) => return if copied == 0 { Err(error) } else { Ok(copied) },
        }
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn scatter_gather_reverse_and_partial_page_fault_use_original_permissions() {
        let mut m = Memory::default();
        m.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        for (address, base, len) in [
            (0x1000, 0x1800u64, 3u64),
            (0x1010, 0x1900, 5),
            (0x1100, 0x2ffc, 8),
        ] {
            m.write_array(address, base.to_le_bytes()).unwrap();
            m.write_array(address + 8, len.to_le_bytes()).unwrap();
        }
        m.write(0x2ffc, b"abcd").unwrap();
        assert_eq!(
            process_vm_local(270, [1, 0x1000, 2, 0x1100, 1, 0], &mut m),
            Ok(4)
        );
        assert_eq!(m.read_array::<3>(0x1800).unwrap(), *b"abc");
        assert_eq!(m.read_array::<1>(0x1900).unwrap(), *b"d");
        m.write_array(0x1108, 4u64.to_le_bytes()).unwrap();
        m.write(0x1800, b"xyz").unwrap();
        assert_eq!(
            process_vm_local(271, [1, 0x1000, 2, 0x1100, 1, 0], &mut m),
            Ok(4)
        );
        assert_eq!(m.read_array::<4>(0x2ffc).unwrap(), *b"xyzd");
        m.protect(0x2000, PAGE_SIZE, Permissions::NONE).unwrap();
        assert_eq!(
            process_vm_local(270, [1, 0x1000, 2, 0x1100, 1, 0], &mut m),
            Err(Errno(14))
        );
        assert_eq!(
            process_vm_local(270, [1, 0, 1025, 0, 0, 0], &mut m),
            Err(Errno(22))
        );
        assert_eq!(process_vm_local(270, [1, 0, 0, 0, 1, 0], &mut m), Ok(0));
        assert_eq!(
            process_vm_local(270, [1, 0, 0, 0, 0, 1], &mut m),
            Err(Errno(22))
        );
    }
}
