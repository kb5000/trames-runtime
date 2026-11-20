# Mount-root attributes and current directory reporting on ARM64

## Behavior

`statx` reports support for `STATX_ATTR_MOUNT_ROOT` in the attribute mask even on ordinary files. It sets the attribute on the root of the particular mount used for the lookup. Bind-mounting a regular file therefore produces different attribute values at the source and destination. A retained descriptor still reports its original mount ID and root status after lazy detach. Guest-backed files use the existing resolved inode and mount. A host-directory query uses the device and inode from its existing native stat result. The ordinary and io_uring statx entry points use the same ABI encoder. [Linux stat implementation](https://codebrowser.dev/linux/linux/fs/stat.c.html#296)

Linux's raw `getcwd` can return a path prefixed with `(unreachable)` when a process keeps a linked working directory outside its new root. A deleted working directory returns ENOENT. Trames captures root and cwd together from the existing fs_struct before rendering their relative location. Strict path resolution continues to use its original visibility rules. When both locations belong to the private root mount, its directory index already contains the names. The calling worker returns the result directly, including on disk-backed volumes. Other mount types retain their existing scheduling path. The syscall enforces the Linux pathname length limit including the terminating NUL. [Linux getcwd implementation](https://codebrowser.dev/linux/linux/fs/d_path.c.html#412)

## Conformance

The previous Mac runtime (`de6d7ee`) reproduced one original failure in `ChrootTest.CreatesNewRoot` and 19 skipped statx tests. The final candidate passed all 20 on Mac hardware and on the ARM64 interpreter running on the Mac. The original binary and its feature probe were unchanged. All five tested mount types (bind, overlay, procfs, sysfs and tmpfs) passed for both paths and open descriptors.

The broader Mac run included the complete stat, statfs, chdir and fchdir suites and the original failing chroot case. Each of the 78 rows matched the recorded native Linux classification. There were 77 XML-confirmed passes, zero failures and one skip (`FstatfsTest.BlocksFree`). The cumulative inventory replaces just these rows and now has 2,944 passes, 113 failures, 79 skips, 25 timeouts, one fixture failure and one missing result in 3,163 cases.

The same standalone ARM64 io_uring probe queried the root and a regular file by pathname and by descriptor, on native Linux, Mac HVF and the interpreter. Local VFS tests also exercised an external host share with a hard link, a single-file bind mount, a retained FD after detach, and a working directory removed after chroot. Runtime CI passed on macOS ARM64. The iPad FFI compiled for the physical-device target.

## Paired timings

The previous and final Mac binaries ran identical workloads against the same isolated store. The order alternated over two warmup and 16 measured pairs. Medians are in guest elapsed milliseconds. Positive changes indicate longer elapsed time.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| statx path | 20.66 | 20.74 | +0.39% |
| statx empty fd | 7.17 | 7.23 | +0.77% |
| getcwd | 91.63 | 5.97 | -93.48% |
| getuid | 103.28 | 103.57 | +0.28% |
| ordinary stat | 19.31 | 19.20 | -0.57% |
| ordinary open | 74.90 | 74.23 | -0.89% |
| memory | 176.18 | 178.87 | +1.53% |
| mmap fault unmap | 133.85 | 135.47 | +1.20% |
| file pread pwrite | 94.78 | 95.83 | +1.10% |
| fork wait | 19.44 | 19.32 | -0.61% |

The probes and per-sample results are in the iPad checkout under `target/gvisor-mount-stat-20261120`.
