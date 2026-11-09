// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace ABI is imported once; original VFS algorithms own all semantics.
use super::*;
use trames_vfs::NamespaceCall as Call;

pub(crate) fn supported(number: u32) -> bool {
    matches!(number, 5..=17 | 33..=41 | 43 | 44 | 49..=55 | 88 | 276 | 279 | 452)
}
pub(super) fn import(
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<(Call, FileOutput), Errno> {
    let output = FileOutput::None;
    let call = match number {
        279 => Call::Memfd(trames_vfs::MemfdParameters::new(
            Linux::path(memory, a[0])?,
            a[1] as u32,
        )?),
        39 => Call::Umount {
            target: Linux::path(memory, a[0])?,
            flags: a[1],
        },
        40 => {
            let optional = |ptr| {
                if ptr == 0 {
                    Ok(None)
                } else {
                    Linux::path(memory, ptr).map(Some)
                }
            };
            Call::Mount {
                source: optional(a[0])?,
                target: Linux::path(memory, a[1])?,
                kind: optional(a[2])?,
                flags: a[3],
                data: optional(a[4])?,
            }
        }
        41 => Call::PivotRoot {
            new_root: Linux::path(memory, a[0])?,
            put_old: Linux::path(memory, a[1])?,
        },
        33 => Call::Mknod {
            fd: a[0] as i32,
            path: Linux::path(memory, a[1])?,
            mode: a[2] as u32,
            device: a[3],
        },
        34 => Call::Mkdir {
            fd: a[0] as i32,
            path: Linux::path(memory, a[1])?,
            mode: a[2] as u32,
        },
        35 => {
            if a[2] & !0x200 != 0 {
                return Err(Errno(22));
            }
            Call::Unlink {
                fd: a[0] as i32,
                path: Linux::path(memory, a[1])?,
                directory: a[2] != 0,
            }
        }
        36 => Call::Symlink {
            target: Linux::path(memory, a[0])?,
            fd: a[1] as i32,
            path: Linux::path(memory, a[2])?,
        },
        37 => {
            if a[4] & !0x400 != 0 {
                return Err(Errno(22));
            }
            Call::Link {
                oldfd: a[0] as i32,
                old: Linux::path(memory, a[1])?,
                newfd: a[2] as i32,
                new: Linux::path(memory, a[3])?,
            }
        }
        38 | 276 => Call::Rename {
            oldfd: a[0] as i32,
            old: Linux::path(memory, a[1])?,
            newfd: a[2] as i32,
            new: Linux::path(memory, a[3])?,
            flags: if number == 276 { a[4] as u32 } else { 0 },
        },
        49 => Call::Chdir(Linux::path(memory, a[0])?),
        50 => Call::Fchdir(a[0] as u32),
        51 => Call::Chroot(Linux::path(memory, a[0])?),
        52 => Call::Chmod {
            fd: a[0] as i32,
            path: None,
            mode: a[1] as u32,
            nofollow: false,
            empty: false,
        },
        53 => Call::Chmod {
            fd: a[0] as i32,
            path: Some(Linux::path(memory, a[1])?),
            mode: a[2] as u32,
            nofollow: false,
            empty: false,
        },
        54 => {
            if a[4] & !0x1100 != 0 {
                return Err(Errno(22));
            }
            let path = Linux::path(memory, a[1])?;
            Call::Chown {
                fd: a[0] as i32,
                path: (!(path.is_empty() && a[4] & 0x1000 != 0)).then_some(path),
                uid: a[2] as u32,
                gid: a[3] as u32,
                nofollow: a[4] & 0x100 != 0,
                empty: a[4] & 0x1000 != 0,
            }
        }
        55 => Call::Chown {
            fd: a[0] as i32,
            path: None,
            uid: a[1] as u32,
            gid: a[2] as u32,
            nofollow: false,
            empty: false,
        },
        88 => {
            if a[3] & !0x100 != 0 {
                return Err(Errno(22));
            }
            let path = if a[1] == 0 {
                None
            } else {
                Some(Linux::path(memory, a[1])?)
            };
            let times = if a[2] == 0 {
                None
            } else {
                Linux::check(memory, a[2], 32, Access::Read)?;
                let mut values = [[0; 2]; 2];
                for (i, pair) in values.iter_mut().enumerate() {
                    for (j, value) in pair.iter_mut().enumerate() {
                        *value = memory
                            .read_u64(a[2] + (i * 16 + j * 8) as u64)
                            .map_err(|_| Errno(14))? as i64;
                    }
                }
                Some(values)
            };
            Call::Times {
                fd: a[0] as i32,
                path,
                times,
                flags: a[3] as u32,
            }
        }
        452 => {
            if a[3] & !0x1100 != 0 {
                return Err(Errno(22));
            }
            let path = if a[1] == 0 && a[3] & 0x1000 != 0 {
                Vec::new()
            } else {
                Linux::path(memory, a[1])?
            };
            let empty = path.is_empty() && a[3] & 0x1000 != 0;
            Call::Chmod {
                fd: a[0] as i32,
                path: if empty && a[0] as i32 == trames_vfs::AT_FDCWD {
                    Some(b".".to_vec())
                } else {
                    (!empty).then_some(path)
                },
                mode: a[2] as u32,
                nofollow: a[3] & 0x100 != 0,
                empty,
            }
        }
        17 => {
            return Ok((
                Call::Cwd,
                FileOutput::Buffer {
                    address: a[0],
                    capacity: a[1],
                    query_size: false,
                    zero: false,
                },
            ))
        }
        43 | 44 => {
            return Ok((
                Call::Statfs {
                    fd: if number == 43 {
                        trames_vfs::AT_FDCWD
                    } else {
                        a[0] as i32
                    },
                    path: if number == 43 {
                        Some(Linux::path(memory, a[0])?)
                    } else {
                        None
                    },
                },
                FileOutput::Buffer {
                    address: a[1],
                    capacity: 120,
                    query_size: false,
                    zero: true,
                },
            ))
        }
        5..=16 => {
            let variant = (number - 5) % 3;
            let path = if variant == 2 {
                None
            } else {
                Some(Linux::path(memory, a[0])?)
            };
            let fd = if variant == 2 {
                a[0] as i32
            } else {
                trames_vfs::AT_FDCWD
            };
            let follow = variant != 1;
            let list = (11..=13).contains(&number);
            let name = if list {
                Vec::new()
            } else {
                memory.read_c_string(a[1], 256).map_err(|e| {
                    if e == trames_memory::MemoryError::Limit {
                        Errno(34)
                    } else {
                        Errno(14)
                    }
                })?
            };
            if number <= 7 {
                if a[3] > 65536 {
                    return Err(Errno(7));
                }
                Linux::check(memory, a[2], a[3] as usize, Access::Read)?;
                let mut value = vec![0; a[3] as usize];
                memory.read(a[2], &mut value).map_err(|_| Errno(14))?;
                Call::Xattr {
                    fd,
                    path,
                    follow,
                    name,
                    value: Some(value),
                    flags: a[4] as u32,
                }
            } else if number <= 13 {
                let (address, capacity) = if list { (a[1], a[2]) } else { (a[2], a[3]) };
                return Ok((
                    Call::GetXattr {
                        fd,
                        path,
                        follow,
                        name: (!list).then_some(name),
                    },
                    FileOutput::Buffer {
                        address,
                        capacity,
                        query_size: true,
                        zero: false,
                    },
                ));
            } else {
                Call::Xattr {
                    fd,
                    path,
                    follow,
                    name,
                    value: None,
                    flags: 0,
                }
            }
        }
        _ => unreachable!("namespace ABI classified before import"),
    };
    Ok((call, output))
}
impl DirectSyscalls {
    pub(super) fn invoke_namespace(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if self.file_prepared(number, args) {
            return None;
        }
        let paths = self.paths.as_ref()?;
        let (call, output) = match import(number, args, memory) {
            Ok(call) => call,
            Err(error) => return Some(Err(error)),
        };
        match paths.namespace_attempt(call) {
            trames_vfs::NamespaceAttempt::Complete(result) => {
                self.completed.set(self.completed.get() + 1);
                self.file_completed.set(self.file_completed.get() + 1);
                Some(output.apply(result, memory))
            }
            trames_vfs::NamespaceAttempt::Retained(work) => {
                self.prepare_filesystem_work(number, args, work, output, memory)
            }
        }
    }
}

/// The joined compatibility entry uses the identical importer/output ABI.
pub(crate) fn owner(
    number: u32,
    args: [u64; 6],
    memory: &mut impl CpuMemory,
    vfs: &mut trames_vfs::Vfs,
) -> Result<u64, Errno> {
    let (call, output) = import(number, args, memory)?;
    output.apply(call.execute(vfs), memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[test]
    fn worker_namespace_lifecycle_has_original_error_order_output_and_live_context() {
        let v = trames_vfs::Vfs::default();
        let direct = DirectSyscalls::default().with_paths(v.path_queries());
        let mut memory = Memory::default();
        memory.map(0x1000, 8192, Permissions::RW).unwrap();
        memory.write(0x1000, b"/directory\0").unwrap();
        memory.write(0x1100, b"/directory/file\0").unwrap();
        memory.write(0x1200, b"user.name\0").unwrap();
        memory.write(0x1300, b"value\0").unwrap();
        let cwd = trames_vfs::AT_FDCWD as i64 as u64;
        for (number, args, expected) in [
            (34, [cwd, 0x1000, 0o755, 0, 0, 0], Ok(0)),
            (34, [cwd, 0x1000, 0o755, 0, 0, 0], Err(Errno(17))),
            (35, [0, 0x9000, 1, 0, 0, 0], Err(Errno(22))),
            (33, [cwd, 0x1100, 0o100600, 0, 0, 0], Ok(0)),
            (5, [0x1100, 0x1200, 0x1300, 5, 0, 0], Ok(0)),
            (8, [0x1100, 0x1200, 0x9000, 0, 0, 0], Ok(5)),
            (8, [0x1100, 0x1200, 0x1400, 4, 0, 0], Err(Errno(34))),
            (8, [0x1100, 0x1200, 0x1400, 5, 0, 0], Ok(5)),
            (53, [cwd, 0x1100, 0o644, 0, 0, 0], Ok(0)),
            (49, [0x1000, 0, 0, 0, 0, 0], Ok(0)),
            (17, [0x1500, 11, 0, 0, 0, 0], Ok(11)),
            (17, [0x9000, 1, 0, 0, 0, 0], Err(Errno(34))),
            (17, [0x9000, 100, 0, 0, 0, 0], Err(Errno(14))),
            (14, [0x1100, 0x1200, 0, 0, 0, 0], Ok(0)),
            (35, [cwd, 0x1100, 0, 0, 0, 0], Ok(0)),
        ] {
            assert_eq!(
                direct.invoke_path(number, args, &mut memory),
                Some(expected),
                "namespace syscall {number}"
            );
        }
        assert_eq!(memory.read_array::<5>(0x1400).unwrap(), *b"value");
        assert_eq!(memory.read_array::<11>(0x1500).unwrap(), *b"/directory\0");
        assert_eq!(v.cwd().unwrap(), b"/directory");
        assert_eq!(v.stat_at(trames_vfs::AT_FDCWD, b"file"), Err(Errno(2)));
    }
}
