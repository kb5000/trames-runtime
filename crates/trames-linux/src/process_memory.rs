// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux process_vm vector import and page-bounded copies.
use trames_memory::{CpuMemory, PAGE_SIZE};
use trames_vfs::Errno;

pub fn process_vm_local(
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    process_vm_transfer(number, a, memory, || Ok(()))
}

/// Import the caller's vectors before resolving the target. An empty transfer
/// neither references another task nor acquires a target address space.
pub fn process_vm_transfer(
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    admit_local_mm: impl FnOnce() -> Result<(), Errno>,
) -> Result<u64, Errno> {
    let Some((local, remote)) = import(a, memory)? else {
        return Ok(0);
    };
    admit_local_mm()?;
    copy_local(number, local, remote, memory)
}

pub(crate) type Vectors = Vec<(u64, u64)>;
pub(crate) fn import(
    a: [u64; 6],
    memory: &impl CpuMemory,
) -> Result<Option<(Vectors, Vectors)>, Errno> {
    if a[5] != 0 {
        return Err(Errno(22));
    }
    fn vectors(
        memory: &impl CpuMemory,
        address: u64,
        count: u64,
    ) -> Result<Vec<(u64, u64)>, Errno> {
        if count > 1024 {
            return Err(Errno(22));
        }
        (0..count)
            .map(|i| {
                let address = address.checked_add(i * 16).ok_or(Errno(14))?;
                let bytes = memory.read_array::<16>(address).map_err(|_| Errno(14))?;
                let base = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                let length = i64::from_le_bytes(bytes[8..].try_into().unwrap());
                Ok((base, u64::try_from(length).map_err(|_| Errno(22))?))
            })
            .collect()
    }
    let mut local = vectors(memory, a[1], a[2])?;
    let max_rw_count = i32::MAX as u64 & !(PAGE_SIZE - 1);
    let mut remaining = max_rw_count;
    for (base, length) in &mut local {
        // Linux imports a single local segment as a capped ubuf. With multiple
        // segments it checks the original user ranges before capping the sum.
        let checked = if a[2] == 1 {
            (*length).min(remaining)
        } else {
            *length
        };
        let address = *base & 0x00ff_ffff_ffff_ffff;
        if address
            .checked_add(checked)
            .is_none_or(|end| end > trames_memory::ADDRESS_LIMIT)
        {
            return Err(Errno(14));
        }
        *length = (*length).min(remaining);
        remaining -= *length;
    }
    if remaining == max_rw_count {
        return Ok(None);
    }
    let remote = vectors(memory, a[3], a[4])?;
    if remote.iter().all(|v| v.1 == 0) {
        return Ok(None);
    }
    Ok(Some((local, remote)))
}
pub(crate) fn copy_local(
    number: u32,
    local: Vectors,
    remote: Vectors,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let (source, dest) = if number == 270 {
        (remote, local)
    } else {
        (local, remote)
    };
    let mut source = source.into_iter().filter(|v| v.1 != 0);
    let mut dest = dest.into_iter().filter(|v| v.1 != 0);
    let (mut from, mut to) = (source.next(), dest.next());
    let mut copied = 0;
    let mut buffer = [0; PAGE_SIZE as usize];
    // Keep the current address and remaining length in each cursor. Long
    // vectors advance by page without looking the vector up again.
    while let (Some((src, src_len)), Some((dst, dst_len))) = (from, to) {
        let n = src_len
            .min(dst_len)
            .min(PAGE_SIZE - src % PAGE_SIZE)
            .min(PAGE_SIZE - dst % PAGE_SIZE) as usize;
        if memory.read(src, &mut buffer[..n]).is_err() || memory.write(dst, &buffer[..n]).is_err() {
            return if copied == 0 {
                Err(Errno(14))
            } else {
                Ok(copied)
            };
        }
        let n = n as u64;
        copied += n;
        from = if n == src_len {
            source.next()
        } else {
            src.checked_add(n).map(|next| (next, src_len - n))
        };
        to = if n == dst_len {
            dest.next()
        } else {
            dst.checked_add(n).map(|next| (next, dst_len - n))
        };
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn import_order_and_empty_vectors_do_not_require_a_target() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1010, 0x1100u64.to_le_bytes()).unwrap();
        m.write_array(0x1018, 1u64.to_le_bytes()).unwrap();
        for (args, expected) in [
            ([99, 1, 1, 0, 0, 1], Err(Errno(22))),
            ([99, 0x1000, 1, 1, 1025, 0], Ok(0)),
            ([99, 1, 1, 0, 0, 0], Err(Errno(14))),
            ([99, 0x1010, 1, 0x1000, 1, 0], Ok(0)),
            ([99, 0x1010, 1, 1, 1025, 0], Err(Errno(22))),
        ] {
            for number in [270, 271] {
                assert_eq!(
                    process_vm_transfer(number, args, &mut m, || panic!(
                        "target lookup before vector import"
                    )),
                    expected
                );
            }
        }
        assert_eq!(
            process_vm_transfer(271, [99, 0x1010, 1, 0x1010, 1, 0], &mut m, || Err(Errno(3))),
            Err(Errno(3))
        );
    }

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
