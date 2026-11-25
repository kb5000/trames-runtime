// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared UTS ABI, used by owner syscalls and executing workers alike.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, UtsAccess};

pub fn uts_call(
    uts: &UtsAccess,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    uts_call_with_release(uts, false, number, a, memory)
}

pub fn uts_call_for_task(
    uts: &UtsAccess,
    personality: &crate::TaskPersonality,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    uts_call_with_release(
        uts,
        number == 160 && personality.uname26(),
        number,
        a,
        memory,
    )
}

fn uts_call_with_release(
    uts: &UtsAccess,
    uname26: bool,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    if number == 160 {
        Linux::check(memory, a[0], 390, Access::Write)?;
        let fields = fields(uts, uname26);
        memory.write(a[0], &fields).map_err(|_| Errno(14))?;
    } else {
        debug_assert!(matches!(number, 161 | 162));
        uts.writable()?;
        let length = a[1] as u32 as i32;
        if !(0..=64).contains(&length) {
            return Err(Errno(22));
        }
        let mut name = vec![0; length as usize];
        memory.read(a[0], &mut name).map_err(|_| Errno(14))?;
        uts.set(number == 162, &name)?;
    }
    Ok(0)
}
pub(crate) fn fields(uts: &UtsAccess, uname26: bool) -> [u8; 390] {
    let [hostname, domainname] = uts.names();
    let mut fields = [0; 390];
    for (i, text) in [
        b"Linux".as_slice(),
        hostname.as_slice(),
        if uname26 {
            b"2.6.60-trames"
        } else {
            b"6.0.0-trames"
        },
        b"#1 Trames compatibility runtime",
        b"aarch64",
        domainname.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        fields[i * 65..i * 65 + text.len()].copy_from_slice(text);
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn uname_release_tracks_the_calling_task() {
        let access = trames_vfs::Vfs::default().uts_capability();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let parent = crate::TaskPersonality::default();
        let child = parent.fork();
        let worker = child.clone();
        assert_eq!(worker.call(0x0002_0000), Ok(0));
        assert_eq!(worker.call(8), Err(Errno(22)));
        assert_eq!(child.call(u64::MAX), Ok(0x0002_0000));
        for (task, expected) in [
            (&parent, b"6.0.0-trames".as_slice()),
            (&child, b"2.6.60-trames".as_slice()),
        ] {
            uts_call_for_task(&access, task, 160, [0x1000, 0, 0, 0, 0, 0], &mut memory).unwrap();
            let release = memory.read_array::<65>(0x1000 + 130).unwrap();
            assert_eq!(release.split(|&b| b == 0).next(), Some(expected));
        }
    }

    #[test]
    fn uts_abi_checks_faults_lengths_and_permission_without_changing_names() {
        let mut v = trames_vfs::Vfs::default();
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let access = v.uts_capability();
        memory.write(0x1000, b"valid").unwrap();
        assert_eq!(
            uts_call(&access, 161, [0x1000, 5, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        assert_eq!(
            uts_call(&access, 161, [0x1fff, 2, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(
            uts_call(&access, 162, [0, 65, 0, 0, 0, 0], &mut memory),
            Err(Errno(22))
        );
        memory.write(0x1fff, &[0x55]).unwrap();
        assert_eq!(
            uts_call(&access, 160, [0x1fff, 0, 0, 0, 0, 0], &mut memory),
            Err(Errno(14))
        );
        assert_eq!(memory.read_array::<1>(0x1fff).unwrap(), [0x55]);
        assert_eq!(access.names()[0], b"valid");
        v.credentials = trames_vfs::Credentials::user(1000, 1000);
        let denied = v.uts_capability();
        assert_eq!(
            uts_call(&denied, 161, [0x1000, 5, 0, 0, 0, 0], &mut memory),
            Err(Errno(1))
        );
        // uname remains available without CAP_SYS_ADMIN.
        assert_eq!(
            uts_call(&denied, 160, [0x1000, 0, 0, 0, 0, 0], &mut memory),
            Ok(0)
        );
        assert_eq!(memory.read_array::<6>(0x1000 + 65).unwrap(), *b"valid\0");
    }
}
