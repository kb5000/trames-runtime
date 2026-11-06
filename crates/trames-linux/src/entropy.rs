// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest entropy uses the host CSPRNG on the calling executor. No guest entropy
//! pool, task state, coordinator transaction or additional memory fence exists.
use trames_memory::{Access, CpuMemory};
use trames_vfs::Errno;

pub fn getrandom(a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
    // Linux's flags argument is unsigned int. Keep the supported flags and
    // transfer bound; GRND_INSECURE is not implemented by this userspace kernel.
    if a[2] as u32 & !3 != 0 {
        return Err(Errno(22));
    }
    let count = a[1].min(crate::MAX_WRITE as u64) as usize;
    // Preserve the existing whole-output preflight and fault behavior. This is
    // the same CpuMemory path used by the CPU/native executor's original View.
    crate::Linux::check(memory, a[0], count, Access::Write)?;
    let mut bytes = vec![0; count];
    crate::fill_entropy(&mut bytes)?;
    memory.write(a[0], &bytes).map_err(|_| Errno(14))?;
    Ok(count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};

    #[test]
    fn original_output_permissions_and_whole_range_faults_are_preserved() {
        let mut memory = Memory::new(2 * PAGE_SIZE as usize);
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x1ff0, &[0x55; 16]).unwrap();
        assert_eq!(
            getrandom([0x1ff0, 32, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(memory.read_array::<16>(0x1ff0).unwrap(), [0x55; 16]);
        assert_eq!(
            getrandom([u64::MAX, 1, 4, 0, 0, 0], &mut memory),
            Err(Errno(22))
        );
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(
            getrandom([0x1000, 16, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(
            getrandom([u64::MAX, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(getrandom([0, 0, 0, 0, 0, 0], &mut memory), Ok(0));
    }
}
