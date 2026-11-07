// SPDX-License-Identifier: GPL-3.0-or-later
//! Same guest memory and metadata ABI on execution workers. None defers before
//! any guest output; errno values are ordinary Linux operation results.
use crate::Linux;
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, PathQueries, AT_FDCWD};
type Result<T> = std::result::Result<T, Errno>;
pub(super) fn call(
    q: &PathQueries,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Option<Result<u64>> {
    match number {
        61 => {
            let count = a[2].min(crate::MAX_WRITE as u64) as usize;
            let bytes = q.getdents(a[0] as u32, count, || {
                Linux::check(memory, a[1], count, Access::Write)
            })?;
            Some(bytes.and_then(|bytes| {
                memory.write(a[1], &bytes).map_err(|_| Errno(14))?;
                Ok(bytes.len() as u64)
            }))
        }
        62 => Some(q.seek_fd(a[0] as u32, a[1] as i64, a[2] as u32)),
        27 => {
            let path = match Linux::path(memory, a[1]) {
                Ok(path) => path,
                Err(error) => return Some(Err(error)),
            };
            Some(
                q.inotify_add(a[0] as u32, &path, a[2] as u32)?
                    .map(|wd| wd as u64),
            )
        }
        79 => {
            let path = match Linux::stat_parameters(a, memory) {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            let stat = if path.is_empty() && a[3] & 0x1000 != 0 {
                q.stat_fd(a[0] as u32)
            } else {
                q.stat_at(a[0] as i32, &path, a[3] & 0x100 != 0)
            }?;
            Some(Linux::finish_stat(a, memory, stat))
        }
        80 => {
            let stat = q.stat_fd(a[0] as u32)?;
            Some(stat.and_then(|stat| {
                Linux::check(memory, a[1], 128, Access::Write)?;
                memory.write(a[1], &stat).map_err(|_| Errno(14))?;
                Ok(0)
            }))
        }
        78 => {
            let path = match (|| {
                if a[3] == 0 {
                    return Err(Errno(22));
                }
                Linux::path(memory, a[1])
            })() {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            let target = q.readlink_at(a[0] as i32, &path)?;
            Some(target.and_then(|target| {
                let count = (a[3] as usize).min(target.len());
                Linux::check(memory, a[2], count, Access::Write)?;
                memory
                    .write(a[2], &target[..count])
                    .map_err(|_| Errno(14))?;
                Ok(count as u64)
            }))
        }
        48 | 439 => {
            let flags = if number == 439 { a[3] } else { 0 };
            let path = match (|| {
                if a[2] & !7 != 0 {
                    return Err(Errno(22));
                }
                let path = Linux::path(memory, a[1])?;
                if flags & !0x300 != 0 {
                    return Err(Errno(22));
                }
                Ok(path)
            })() {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            Some(
                q.access_at(
                    a[0] as i32,
                    &path,
                    a[2] as u32,
                    flags & 0x200 != 0,
                    flags & 0x100 != 0,
                )?
                .map(|()| 0),
            )
        }
        291 => {
            let flags = a[2] as u32;
            let path = match (|| {
                if flags & !0x7900 != 0 || flags & 0x6000 == 0x6000 || a[3] as u32 & 0x80000000 != 0
                {
                    return Err(Errno(22));
                }
                Linux::check(memory, a[4], 256, Access::Write)?;
                if a[1] == 0 && flags & 0x1000 != 0 {
                    Ok(Vec::new())
                } else {
                    Linux::path(memory, a[1])
                }
            })() {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            let empty = path.is_empty() && flags & 0x1000 != 0;
            let fd = a[0] as i32;
            let metadata = if empty && fd != AT_FDCWD {
                q.stat_fd_with_mount(a[0] as u32)?
            } else {
                let path = if empty { b".".as_slice() } else { &path };
                q.stat_at_with_mount(fd, path, flags & 0x100 != 0)?
            };
            Some(metadata.and_then(|(stat, mount)| Linux::finish_statx(a, memory, stat, mount)))
        }
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapturedOutput;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn worker_abi_matches_owner_for_paths_empty_fds_errors_and_buffers() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.import_file(b"/file", b"data".to_vec()).unwrap();
        linux.vfs.symlink_at(b"file", AT_FDCWD, b"/alias").unwrap();
        let fd = linux.vfs.open_at(AT_FDCWD, b"/file", 0, 0).unwrap() as u64;
        let queries = linux.vfs.path_queries();
        let cases = [
            (
                79,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0x1400, 0, 0, 0],
                b"/file\0".as_slice(),
            ),
            (
                79,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0x1400, 0x100, 0, 0],
                b"/alias\0",
            ),
            (79, [fd, 0x1ffd, 0x1400, 0x1000, 0, 0], b"\0"),
            (79, [0, 0x1ffd, 0x1400, 1, 0, 0], b"/file\0"),
            (
                79,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0x9000, 0, 0, 0],
                b"/file\0",
            ),
            (80, [fd, 0x1400, 0, 0, 0, 0], b"/file\0"),
            (80, [u32::MAX as u64, 0x1400, 0, 0, 0, 0], b"/file\0"),
            (
                78,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0x1400, 2, 0, 0],
                b"/alias\0",
            ),
            (
                78,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0x9000, 4, 0, 0],
                b"/alias\0",
            ),
            (
                78,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0x1400, 0, 0, 0],
                b"/alias\0",
            ),
            (48, [AT_FDCWD as i64 as u64, 0x1ffd, 4, 0, 0, 0], b"/file\0"),
            (
                439,
                [AT_FDCWD as i64 as u64, 0x1ffd, 8, 0, 0, 0],
                b"/file\0",
            ),
            (
                439,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0, 1, 0, 0],
                b"/file\0",
            ),
            (
                291,
                [AT_FDCWD as i64 as u64, 0x1ffd, 0, 0x7ff, 0x1400, 0],
                b"/file\0",
            ),
            (291, [fd, 0, 0x1000, 0, 0x1400, 0], b"\0"),
            (291, [fd, 0, 0x7000, 0, 0x1400, 0], b"\0"),
            (291, [fd, 0, 0x1000, 0x80000000, 0x1400, 0], b"\0"),
            (291, [fd, 0, 0x1000, 0, 0x9000, 0], b"\0"),
        ];
        for (number, args, path) in cases {
            let mut a = Memory::new(16384);
            a.map(0x1000, 8192, Permissions::RW).unwrap();
            a.write(0x1ffd, path).unwrap();
            a.write(0x1400, &[0x55; 256]).unwrap();
            let mut b = a.clone();
            let actual =
                call(&queries, number, args, &mut a).expect("ordinary query must not defer");
            let expected =
                linux.syscall(number as u64, args, &mut b, &mut CapturedOutput::default());
            assert_eq!(actual, expected, "syscall {number} args {args:?}");
            assert_eq!(
                a.read_array::<256>(0x1400).unwrap(),
                b.read_array::<256>(0x1400).unwrap(),
                "syscall {number}"
            );
        }
    }
    #[test]
    fn directory_abi_matches_owner_errors_cookies_and_output_preflight() {
        let mut linux = Linux::new(0x10000);
        linux.vfs.mkdir_at(AT_FDCWD, b"/dir", 0o755).unwrap();
        let fd = linux.vfs.open_at(AT_FDCWD, b"/dir", 0, 0).unwrap() as u64;
        let path = linux
            .vfs
            .open_at(AT_FDCWD, b"/dir", trames_vfs::O_PATH, 0)
            .unwrap() as u64;
        let file = linux.vfs.memfd_create(b"file", 0).unwrap() as u64;
        let q = linux.vfs.path_queries();
        for args in [
            [fd, 0x1400, 48, 0, 0, 0],
            [fd, 0x1400, 23, 0, 0, 0],
            [fd, 0x1400, 0, 0, 0, 0],
            [fd, 0x9000, 48, 0, 0, 0],
            [999, 0x9000, 48, 0, 0, 0],
            [path, 0x1400, 48, 0, 0, 0],
            [file, 0x1400, 48, 0, 0, 0],
        ] {
            let mut a = Memory::new(8192);
            a.map(0x1000, 4096, Permissions::RW).unwrap();
            a.write(0x1400, &[0x55; 256]).unwrap();
            let mut b = a.clone();
            linux.vfs.seek(fd as u32, 0, 0).unwrap();
            let actual = call(&q, 61, args, &mut a).unwrap();
            let cursor = linux.vfs.seek(fd as u32, 0, 1).unwrap();
            linux.vfs.seek(fd as u32, 0, 0).unwrap();
            let expected = linux.syscall(61, args, &mut b, &mut CapturedOutput::default());
            assert_eq!(actual, expected, "getdents64 {args:?}");
            assert_eq!(cursor, linux.vfs.seek(fd as u32, 0, 1).unwrap());
            assert_eq!(
                a.read_array::<256>(0x1400).unwrap(),
                b.read_array::<256>(0x1400).unwrap()
            );
        }
    }
    #[test]
    fn deferred_pseudo_queries_do_not_write_guest_memory() {
        let mut linux = Linux::new(0x10000);
        linux
            .vfs
            .set_runtime_info(1, trames_vfs::RuntimeInfo::default());
        let queries = linux.vfs.path_queries();
        let mut memory = Memory::new(8192);
        memory.map(0x1000, 4096, Permissions::RW).unwrap();
        memory.write(0x1000, b"/proc/self/status\0").unwrap();
        memory.write(0x1400, &[0x55; 256]).unwrap();
        for (number, args) in [
            (79, [AT_FDCWD as i64 as u64, 0x1000, 0x1400, 0, 0, 0]),
            (291, [AT_FDCWD as i64 as u64, 0x1000, 0, 0x7ff, 0x1400, 0]),
        ] {
            assert!(call(&queries, number, args, &mut memory).is_none());
            assert_eq!(memory.read_array::<256>(0x1400).unwrap(), [0x55; 256]);
        }
    }
}
