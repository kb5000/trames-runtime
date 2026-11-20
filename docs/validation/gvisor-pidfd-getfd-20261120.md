# PID file descriptor transfers on ARM64

Linux pidfd_getfd duplicates an open file description from a target task and sets FD_CLOEXEC on the new descriptor. The caller's generic ptrace access check uses PTRACE_MODE_ATTACH_REALCREDS. [pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html) and [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Trames uses the calling worker, the original pidfd identity and the target's current file table. The target publishes a weak table reference and its mm dumpability alongside its objective credentials at birth, exec and file-table changes. An accepted transfer retains the complete open file description. It releases the source table lock before installing the descriptor in the caller's table. This also allows self-transfers. Existing numeric descriptors and ordinary I/O use their existing paths.

The guest permission check admits the same thread group and recognizes CAP_SYS_PTRACE in the target user namespace. Ordinary cross-process access checks dumpability, the real/effective/saved user and group IDs, the user namespace and the permitted capability sets. The check is performed before looking up the requested target descriptor. It uses the guest's common capability model.

## Compatibility

The previous Mac runtime de6e649 failed five upstream cases at the missing syscall. The final Mac build passed all 113 selected cases, including those five, all 11 dup cases and all 97 fcntl cases. The recorded native ARM64 Linux reference and the Mac-hosted iPad interpreter also passed the same five pidfd cases. An earlier wider candidate run covered all 142 cases in the three suites and returned 131 passes, seven skips and four failures. The remaining four failures involve namespace changes through a pidfd.

The five corrected cases are GetfdWorks, GetfdUnknown, GetfdInvalidFlags, GetfdFailsWhenUnprivileged and InvalidPidfd. An independent guest program verified shared file position, independent descriptor flags and lifetime after closing the original. A second program verified that a parent can follow its child's exec and unshare(CLONE_FILES), retrieve the new open file at the reused descriptor number and still read the old retained copy. It also verified ESRCH after reaping. Both programs ran on the Mac hardware executor and the iPad interpreter. A VFS regression checks permitted versus effective capabilities, real versus filesystem IDs and nondumpable targets. The device-target iPad FFI compiled. No physical iPad was used.

Updating only the final 113 verified cases gives 3,024 passes, 107 failures, 82 skips, 25 timeouts, one fixture failure and one missing result across 3,240 cases.

## Paired measurements

Two warmup pairs preceded 16 measured pairs in alternating runner order on the same Mac and guest environment. Times are median guest elapsed milliseconds. The descriptor workload measures 15,000 ordinary dup/close pairs.

| Workload | Before (ms) | After (ms) | Elapsed time change |
| --- | ---: | ---: | ---: |
| ordinary_dup_close | 32.14 | 32.42 | +0.85% |
| memory | 176.96 | 176.04 | -0.52% |
| mmap_fault_unmap | 133.79 | 129.66 | -3.09% |
| file_pread_pwrite | 95.24 | 93.90 | -1.41% |
| fork_wait | 19.18 | 18.88 | -1.58% |
| getuid | 103.02 | 102.95 | -0.08% |
| ordinary_stat | 19.07 | 18.97 | -0.50% |
| ordinary_open | 72.90 | 75.09 | +3.01% |

Ordinary open was 3.01% slower in the first set. A 32-pair repeat measured +0.30% for open, −0.21% for stat and −0.05% for getuid. Local XML, probe programs and individual samples are under `target/gvisor-pidfd-files-20261120` in the iPad worktree.
