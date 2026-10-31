// SPDX-License-Identifier: GPL-3.0-or-later
//! One flock ABI for owner Memory and worker Views; deferral precedes effects.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, RecordLock};
type Result<T> = std::result::Result<T, Errno>;

pub(crate) fn call(
    memory: &mut impl CpuMemory,
    command: u64,
    address: u64,
    normalize: impl FnOnce(u16, u16, i64, i64) -> Option<Result<RecordLock>>,
    conflict: impl FnOnce(RecordLock) -> Result<Option<RecordLock>>,
    set: impl FnOnce(RecordLock) -> Result<()>,
    visible_pid: impl FnOnce(u32) -> u32,
) -> Option<Result<u64>> {
    let parameters = (|| {
        Linux::check(memory, address, 32, Access::Read)?;
        if matches!(command, 5 | 36) {
            Linux::check(memory, address, 32, Access::Write)?;
        }
        memory.read_array::<32>(address).map_err(|_| Errno(14))
    })();
    let mut bytes = match parameters {
        Ok(bytes) => bytes,
        Err(e) => return Some(Err(e)),
    };
    if matches!(command, 36..=38) && bytes[24..28] != [0; 4] {
        return Some(Err(Errno(22)));
    }
    let kind = u16::from_le_bytes(bytes[..2].try_into().unwrap());
    let requested = normalize(
        kind,
        u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
    )?;
    Some((|| {
        let requested = requested?;
        if matches!(command, 5 | 36) {
            if kind == 2 {
                return Err(Errno(22));
            }
            if let Some(conflict) = conflict(requested)? {
                bytes[..2].copy_from_slice(&conflict.kind.to_le_bytes());
                bytes[2..4].copy_from_slice(&0u16.to_le_bytes());
                bytes[8..16].copy_from_slice(&conflict.start.to_le_bytes());
                bytes[16..24].copy_from_slice(
                    &(if conflict.end == u64::MAX {
                        0
                    } else {
                        conflict.end - conflict.start
                    })
                    .to_le_bytes(),
                );
                bytes[24..28].copy_from_slice(
                    &(if conflict.owner & trames_vfs::OFD_LOCK_OWNER != 0 {
                        u32::MAX
                    } else {
                        visible_pid(conflict.owner as u32)
                    })
                    .to_le_bytes(),
                );
            } else {
                bytes[..2].copy_from_slice(&2u16.to_le_bytes());
            }
            memory.write_array(address, bytes).map_err(|_| Errno(14))?;
        } else {
            set(requested)?;
        }
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::{FileEpoch, AT_FDCWD, O_PATH};

    fn memory() -> Memory {
        let mut memory = Memory::new(8 * PAGE_SIZE as usize);
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
    }
    fn flock(kind: u16, whence: u16, start: i64, length: i64) -> [u8; 32] {
        let mut bytes = [0x5a; 32];
        bytes[..2].copy_from_slice(&kind.to_le_bytes());
        bytes[2..4].copy_from_slice(&whence.to_le_bytes());
        bytes[8..16].copy_from_slice(&start.to_le_bytes());
        bytes[16..24].copy_from_slice(&length.to_le_bytes());
        bytes
    }
    fn owner_call(
        linux: &Linux,
        memory: &mut impl CpuMemory,
        fd: u32,
        command: u64,
        address: u64,
    ) -> Result<u64> {
        call(
            memory,
            command,
            address,
            |kind, whence, start, length| {
                Some(linux.vfs.normalize_lock(fd, kind, whence, start, length))
            },
            |r| linux.vfs.record_lock_conflict(fd, r),
            |r| linux.vfs.record_lock_set(fd, r),
            |owner| linux.vfs.visible_pid(owner),
        )
        .unwrap()
    }
    #[test]
    fn owner_and_worker_share_flock_abi_access_errors_and_range_rules() {
        for (command, kind, whence, start, length, expected) in [
            (6, 1, 0, 4, 8, Ok(0)),
            (6, 0, 2, -4, -8, Ok(0)),
            (5, 1, 1, 0, 0, Ok(0)),
            (5, 2, 0, 0, 0, Err(Errno(22))),
            (6, 1, 0, -1, 0, Err(Errno(22))),
            (6, 1, 0, i64::MAX, 2, Err(Errno(75))),
            (6, 1, 3, 0, 0, Err(Errno(22))),
            (6, 3, 0, 0, 0, Err(Errno(22))),
        ] {
            let mut outputs = Vec::new();
            for worker in [false, true] {
                let mut linux = Linux::new(0x8000);
                linux.vfs.import_file(b"/data", vec![0; 24]).unwrap();
                let fd = linux.vfs.open_at(AT_FDCWD, b"/data", 2, 0).unwrap();
                let mut m = memory();
                m.write_array(0x1000, flock(kind, whence, start, length))
                    .unwrap();
                let mut epoch = FileEpoch::default();
                let direct = crate::DirectSyscalls::new(linux.vfs.direct_descriptors())
                    .with_files(epoch.capture(&linux.vfs, true))
                    .with_lock_context(linux.vfs.record_lock_context(1));
                let result = if worker {
                    let mut registry = trames_memory::parallel::Registry::default();
                    let mut view = m.parallel_view(&mut registry).unwrap();
                    let result = direct
                        .invoke_file(25, [fd as u64, command, 0x1000, 0, 0, 0], &mut view)
                        .unwrap();
                    drop(view);
                    m.commit_parallel().unwrap();
                    result
                } else {
                    owner_call(&linux, &mut m, fd, command, 0x1000)
                };
                assert_eq!(result, expected);
                outputs.push(m.read_array::<32>(0x1000).unwrap());
                epoch.finish();
            }
            assert_eq!(outputs[0], outputs[1]);
        }
    }
    #[test]
    fn worker_conflict_pid_and_faults_match_owner_without_partial_effects() {
        let mut linux = Linux::new(0x8000);
        let fd = linux.vfs.open_at(AT_FDCWD, b"/data", 0x42, 0o600).unwrap();
        let read_only = linux.vfs.open_at(AT_FDCWD, b"/data", 0, 0).unwrap();
        let path = linux.vfs.open_at(AT_FDCWD, b"/data", O_PATH, 0).unwrap();
        let mut epoch = FileEpoch::default();
        let direct = crate::DirectSyscalls::new(linux.vfs.direct_descriptors())
            .with_files(epoch.capture(&linux.vfs, true))
            .with_lock_context(linux.vfs.record_lock_context(2));
        let request = linux.vfs.normalize_lock(fd, 1, 0, 4, 8).unwrap();
        linux.vfs.record_lock_set(fd, request).unwrap();
        let mut m = memory();
        m.write_array(0x1000, flock(1, 0, 4, 8)).unwrap();
        assert_eq!(
            direct.invoke_file(25, [fd as u64, 5, 0x1000, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        let bytes = m.read_array::<32>(0x1000).unwrap();
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 1);
        assert_eq!(&bytes[4..8], &[0x5a; 4]);
        assert_eq!(&bytes[28..32], &[0x5a; 4]);
        assert_eq!(
            direct.invoke_file(25, [fd as u64, 6, 0x1000, 0, 0, 0], &mut m),
            Some(Err(Errno(11)))
        );
        assert_eq!(
            direct.invoke_file(25, [read_only as u64, 6, 0x1000, 0, 0, 0], &mut m),
            Some(Err(Errno(9)))
        );
        for command in [5, 6] {
            // File controls use invoke_file, not the blocking byte-I/O state
            // machine (which requires a byte descriptor and treats EAGAIN as wait).
            assert!(!direct.supports_call(25, [fd as u64, command, 0x1000, 0, 0, 0]));
            assert_eq!(
                direct.invoke_file(25, [fd as u64, command, 0x1ff0, 0, 0, 0], &mut m),
                Some(Err(Errno(14)))
            );
            assert_eq!(
                direct.invoke_file(25, [path as u64, command, 0x2000, 0, 0, 0], &mut m),
                Some(Err(Errno(9)))
            );
        }
        assert_eq!(
            direct.invoke_file(25, [fd as u64, 7, 0x1000, 0, 0, 0], &mut m),
            None
        );
        assert!(!direct.supports_call(25, [fd as u64, 7, 0, 0, 0, 0]));
        assert_eq!(
            linux
                .vfs
                .record_lock_conflict(
                    fd,
                    trames_vfs::RecordLock {
                        owner: 2,
                        ..request
                    }
                )
                .unwrap(),
            Some(request)
        );
        epoch.finish();
    }
}
