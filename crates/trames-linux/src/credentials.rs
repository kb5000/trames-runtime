// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared credential ABI. Only a successful prepared mutation replaces a task's
//! value; original objective publication and lifecycle effects belong to callers.
use trames_memory::{Access, CpuMemory};
use trames_vfs::{capabilities, Credentials, Dumpable, Errno};
type Result<T> = std::result::Result<T, Errno>;

pub fn credential_entry(number: u32, a: [u64; 6]) -> bool {
    matches!(number, 90 | 91 | 143..=152 | 158 | 159 | 174..=177)
        || number == 167 && matches!(a[0], 3 | 4 | 7 | 8 | 23 | 24 | 27 | 28 | 38 | 39 | 47)
}
pub fn credential_mutation(number: u32, a: [u64; 6]) -> bool {
    matches!(number, 91 | 143..=147 | 149 | 151 | 152 | 159)
        || number == 167 && (matches!(a[0], 8 | 24 | 28 | 38) || a[0] == 47 && a[1] != 1)
}
pub struct CredentialResult {
    pub value: u64,
    pub changed: bool,
    pub sensitive: bool,
}
pub fn credential_call(
    credentials: &mut Credentials,
    dumpable: &Dumpable,
    local: u32,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    remote: impl FnOnce(u32) -> Result<capabilities::Capabilities>,
) -> Result<CredentialResult> {
    if number == 167 && matches!(a[0], 3 | 4) {
        if a[0] == 4 {
            if a[1] > 1 {
                return Err(Errno(22));
            }
            dumpable.set(a[1] != 0);
        }
        return Ok(CredentialResult {
            value: if a[0] == 3 {
                u64::from(dumpable.get())
            } else {
                0
            },
            changed: false,
            sensitive: false,
        });
    }
    let mut next = credential_mutation(number, a).then(|| credentials.clone());
    let value = invoke(
        next.as_mut().unwrap_or(credentials),
        local,
        number,
        a,
        memory,
        remote,
    )?;
    let changed = next.as_ref().is_some_and(|next| next != credentials);
    let sensitive = next.as_ref().is_some_and(|next| {
        next.fs_identity() != credentials.fs_identity()
            || next.caps.permitted & !credentials.caps.permitted != 0
    });
    if changed {
        if sensitive {
            dumpable.set(false);
        }
        *credentials = next.unwrap();
    }
    Ok(CredentialResult {
        value,
        changed,
        sensitive,
    })
}
fn read(memory: &impl CpuMemory, address: u64) -> Result<u32> {
    memory
        .read_array::<4>(address)
        .map(u32::from_le_bytes)
        .map_err(|_| Errno(14))
}
fn write(memory: &mut impl CpuMemory, address: u64, value: u32) -> Result<()> {
    memory
        .write_array(address, value.to_le_bytes())
        .map_err(|_| Errno(14))
}
fn invoke(
    c: &mut Credentials,
    local: u32,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    remote: impl FnOnce(u32) -> Result<capabilities::Capabilities>,
) -> Result<u64> {
    match number {
        174..=177 => Ok([c.uid, c.euid, c.gid, c.egid][(number - 174) as usize] as u64),
        144 | 146 => c.set_id(number == 144, a[0] as u32).map(|()| 0),
        143 | 145 => c
            .set_re_ids(number == 143, a[0] as u32, a[1] as u32)
            .map(|()| 0),
        147 | 149 => c
            .set_res_ids(number == 149, [a[0] as u32, a[1] as u32, a[2] as u32])
            .map(|()| 0),
        148 | 150 => {
            let values = if number == 148 {
                [c.uid, c.euid, c.suid]
            } else {
                [c.gid, c.egid, c.sgid]
            };
            for (pointer, value) in a[..3].iter().zip(values) {
                write(memory, *pointer, value)?;
            }
            Ok(0)
        }
        151 | 152 => Ok(c.set_fs_id(number == 152, a[0] as u32) as u64),
        158 | 159 => {
            let count = a[0] as u32 as usize;
            if number == 158 {
                if (count as i32) < 0 {
                    return Err(Errno(22));
                }
                if count == 0 {
                    return Ok(c.groups.len() as u64);
                }
                if count < c.groups.len() {
                    return Err(Errno(22));
                }
                for (i, value) in c.groups.iter().enumerate() {
                    write(
                        memory,
                        a[1].checked_add((i * 4) as u64).ok_or(Errno(14))?,
                        *value,
                    )?;
                }
                Ok(c.groups.len() as u64)
            } else {
                if !c.has_cap(capabilities::SETGID) {
                    return Err(Errno(1));
                }
                if count > 65536 {
                    return Err(Errno(22));
                }
                let mut groups = Vec::with_capacity(count);
                for i in 0..count {
                    let value = read(memory, a[1].checked_add((i * 4) as u64).ok_or(Errno(14))?)?;
                    if value == u32::MAX {
                        return Err(Errno(22));
                    }
                    groups.push(value);
                }
                groups.sort_unstable();
                c.groups = groups;
                Ok(0)
            }
        }
        167 => c.caps.prctl(a),
        90 | 91 => {
            let set = number == 91;
            let words = match read(memory, a[0])? {
                0x1998_0330 => 1,
                0x2007_1026 | 0x2008_0522 => 2,
                _ => {
                    write(memory, a[0], 0x2008_0522)?;
                    return if !set && a[1] == 0 {
                        Ok(0)
                    } else {
                        Err(Errno(22))
                    };
                }
            };
            let target = read(memory, a[0].checked_add(4).ok_or(Errno(14))?)? as i32;
            if !set && target < 0 {
                return Err(Errno(22));
            }
            if set && target != 0 && target as u32 != local {
                return Err(Errno(1));
            }
            if !set && a[1] == 0 {
                return Ok(0);
            }
            if set {
                memory
                    .check(a[1], words * 12, Access::Read)
                    .map_err(|_| Errno(14))?;
                let mut masks = [0u64; 3];
                for word in 0..words {
                    for (field, mask) in masks.iter_mut().enumerate() {
                        *mask |= (read(memory, a[1] + (word * 12 + field * 4) as u64)? as u64)
                            << (word * 32);
                    }
                }
                c.caps.set(masks[0], masks[1], masks[2])?;
            } else {
                let caps = if target == 0 || target as u32 == local {
                    c.caps.clone()
                } else {
                    remote(target as u32)?
                };
                memory
                    .check(a[1], words * 12, Access::Write)
                    .map_err(|_| Errno(14))?;
                for word in 0..words {
                    for (field, mask) in [caps.effective, caps.permitted, caps.inheritable]
                        .iter()
                        .enumerate()
                    {
                        write(
                            memory,
                            a[1] + (word * 12 + field * 4) as u64,
                            (mask >> (word * 32)) as u32,
                        )?;
                    }
                }
            }
            Ok(0)
        }
        _ => Err(Errno(38)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};

    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m
    }
    fn call(
        c: &mut Credentials,
        d: &Dumpable,
        m: &mut Memory,
        n: u32,
        a: [u64; 6],
    ) -> Result<CredentialResult> {
        credential_call(c, d, 7, n, a, m, |_| Err(Errno(3)))
    }
    #[test]
    fn invalid_fsids_are_queries_and_resid_noop_preserves_filesystem_identity() {
        let (mut c, d, mut m) = (Credentials::default(), Dumpable::default(), memory());
        for (n, id) in [(151, 1000), (152, 1001)] {
            assert!(
                call(&mut c, &d, &mut m, n, [id, 0, 0, 0, 0, 0])
                    .unwrap()
                    .changed
            );
            let original = c.clone();
            d.set(true);
            let query = call(&mut c, &d, &mut m, n, [u32::MAX as u64, 0, 0, 0, 0, 0]).unwrap();
            assert_eq!(query.value, id);
            assert!(!query.changed && d.get());
            assert_eq!(c, original);
        }
        let none = u32::MAX as u64;
        for n in [147, 149] {
            assert!(
                !call(&mut c, &d, &mut m, n, [none, none, none, 0, 0, 0])
                    .unwrap()
                    .changed
            );
        }
        assert_eq!((c.fsuid, c.fsgid), (1000, 1001));
        for n in [145, 143] {
            assert!(
                call(&mut c, &d, &mut m, n, [none, none, 0, 0, 0, 0])
                    .unwrap()
                    .changed
            );
        }
        assert_eq!((c.fsuid, c.fsgid), (0, 0));
    }
    #[test]
    fn denied_or_faulting_mutations_do_not_publish_partial_credentials() {
        let (mut c, d, mut m) = (Credentials::default(), Dumpable::default(), memory());
        m.write_array(0x1ffc, 17u32.to_le_bytes()).unwrap();
        assert_eq!(
            call(&mut c, &d, &mut m, 159, [2, 0x1ffc, 0, 0, 0, 0]).err(),
            Some(Errno(14))
        );
        assert_eq!(c, Credentials::default());
        c = Credentials::user(1000, 1000);
        c.euid = 1001;
        c.suid = 1002;
        let original = c.clone();
        for (n, a) in [
            (146, [1001, 0, 0, 0, 0, 0]),
            (145, [1002, u32::MAX as u64, 0, 0, 0, 0]),
        ] {
            assert_eq!(call(&mut c, &d, &mut m, n, a).err(), Some(Errno(1)));
            assert_eq!(c, original);
            assert!(d.get());
        }
    }
    #[test]
    fn capget_resolves_original_target_before_copyout_and_supports_version_queries() {
        let (mut c, d, mut m) = (Credentials::default(), Dumpable::default(), memory());
        m.write_array(0x1000, 0x20080522u32.to_le_bytes()).unwrap();
        m.write_array(0x1004, 42u32.to_le_bytes()).unwrap();
        assert_eq!(
            call(&mut c, &d, &mut m, 90, [0x1000, 0x8000, 0, 0, 0, 0]).err(),
            Some(Errno(3))
        );
        assert_eq!(
            call(&mut c, &d, &mut m, 90, [0x1000, 0, 0, 0, 0, 0])
                .unwrap()
                .value,
            0
        );
        let caps = capabilities::Capabilities::for_uid(1000);
        credential_call(
            &mut c,
            &d,
            7,
            90,
            [0x1000, 0x1100, 0, 0, 0, 0],
            &mut m,
            |pid| {
                assert_eq!(pid, 42);
                Ok(caps)
            },
        )
        .unwrap();
        assert_eq!(m.read_array::<24>(0x1100).unwrap(), [0; 24]);
    }
    #[test]
    fn groups_sort_atomically_and_sensitive_commits_clear_shared_dumpability_only() {
        let (mut c, d, mut m) = (Credentials::default(), Dumpable::default(), memory());
        let shared = d.clone();
        let fork = d.fork();
        for (i, gid) in [11u32, 7, 11].into_iter().enumerate() {
            m.write_array(0x1000 + i as u64 * 4, gid.to_le_bytes())
                .unwrap();
        }
        let result = call(&mut c, &d, &mut m, 159, [3, 0x1000, 0, 0, 0, 0]).unwrap();
        assert!(result.changed && !result.sensitive && d.get());
        assert_eq!(c.groups, [7, 11, 11]);
        let result = call(&mut c, &d, &mut m, 146, [1000, 0, 0, 0, 0, 0]).unwrap();
        assert!(result.changed && result.sensitive);
        assert!(!shared.get());
        assert!(fork.get());
        assert_eq!(c.caps.effective, 0);
    }
}
