# gVisor Landlock ABI 1–6

The November 23 gap ledger selects 38 Landlock cases from the unchanged
November 17 ARM64 binaries. All 38 passed on the Linux 7.0.0-43-generic
native ARM64 reference. The
previous Trames interpreter skipped all 38 at the Landlock version probe.
The new runners execute the original assertions in separate Alpine stores
with two guest CPUs. The interpreter enables guest loopback for the TCP cases.
The Mac runner uses an isolated internal bridge. The suite runs in the
original harness mode because the upstream cases skip in gVisor mode.

| ABI | Cases | Mac HVF | Interpreter |
| --- | ---: | ---: | ---: |
| 1 | 23 | 23 passed | 23 passed |
| 2 | 2 | 2 passed | 2 passed |
| 3 | 2 | 2 passed | 2 passed |
| 4 | 5 | 5 passed | 5 passed |
| 5 | 2 | 2 passed | 2 passed |
| 6 | 4 | 4 passed | 4 passed |
| Total | 38 | 38 passed | 38 passed |

The three syscalls create an anonymous ruleset FD, add inode or TCP-port
rules, and enforce a ruleset on the calling thread. Applying a ruleset
snapshots its rules. Children inherit the current policy, and each additional
layer can only narrow access. File truncation and device ioctl permission
follow the open file description. The guest kernel also checks cross-directory
moves and links, mount topology changes, process inspection, abstract Unix
sockets, and direct and asynchronous signals.

The VFS regressions cover ruleset snapshots, pre-existing file descriptions,
cross-directory privilege gain, mount operations with and without filesystem
rules, and the original hard link used by FD-based execution and proc FD
reopening. The Mac runner passed 112 original regression cases spanning
links, unlink, FUSE, ptrace, rename, abstract and pathname Unix sockets, and
truncate. That run preceded the final mount and exec permission checks.

Path rules on FUSE apply through the mount root and its guest ancestors.
Rules for individual FUSE daemon entries require stable guest inode identities
for those entries. This run covers the fixed 38-case inventory. Physical iPad
validation remains separate from the ARM64 iOS FFI build check.

The local macOS Runtime CI completed all eight steps, with 1,930 tests
passed and 31 ignored. All 18 harness unit tests and the ARM64 iOS FFI
build check passed.

The Mac performance fixture alternated runner versions and used 32 measured
samples per runner after two warmups. Values are median guest elapsed times
in milliseconds.

| Workload | Previous | Landlock | Change |
| --- | ---: | ---: | ---: |
| Memory access | 178.626 | 178.684 | +0.03% |
| mmap, fault and unmap | 141.276 | 140.143 | -0.80% |
| File pread and pwrite | 100.504 | 100.037 | -0.47% |
| Fork and wait | 20.340 | 20.199 | -0.69% |

The tested runner SHA-256 fingerprints are
`4a3cfc2a00ddb3df5391e1a0e3a4ba28b8d276e1623ee945231101ec55f1fdba` for Mac HVF and
`4b374236121b6dce8be0ffb2c13d1d7d071544f446c88dfaf702001d52436630` for the interpreter.

The Linux reference for the ABI and effective access checks is
[Linux 6.12 Landlock](https://docs.kernel.org/6.12/userspace-api/landlock.html).
