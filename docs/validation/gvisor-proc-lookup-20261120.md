# Procfs directory operations

Linux procfs supplies the directory entries that a process can look up. When a prospective name is missing, creating a directory, FIFO, symlink or regular file returns ENOENT. Existing entries return EEXIST on exclusive creation. Opening an existing readable file with O_CREAT can succeed. Link and rename observe destination lookup errors before attempting the mutation. Rename on an explicitly read-only bind mount still returns EROFS. The runtime uses the resolved mount, including procfs accessed through a directory descriptor or a bind. A tmpfs mounted over a procfs directory retains its own namespace and component-length rules.

The guest now exposes the `/proc/fs` directory in lookups and directory listings. The VFS unit assertions for missing procfs entries now expect ENOENT. A separate test keeps a directory descriptor on a procfs bind mount and checks both it and the overmounted tmpfs, including a long component.

## Upstream results

All four cases failed on Mac at runtime `62da06c` and passed with this change. The saved ARM64 Linux reference and the Mac-hosted iPad interpreter passed the same four original cases. The iOS FFI target compiled. Physical iPad execution was not measured.

| Upstream proc case | Coverage |
| --- | --- |
| ProcTest.Create | Creation and lookup across ordinary, per-task, descriptor and sysctl directories, including existing targets and unprivileged checks |
| ProcTest.CreateReadOnly | Missing and existing dentries on a read-only bind mount, plus rename |
| ProcTest.LinkDestinationLookup | Existing source, cross-mount and directory sources, missing and existing destinations |
| ProcTest.LinkAndRenameMissing | Missing and overlong names, NOREPLACE, same-inode rename and parent permissions |

The Mac hardware executor ran 180 cases, each with a fresh store. There were 172 passes, five failures and three skips. The scope included all link, mkdir, mknod, open, open_create, rename and symlink cases and the six ProcTest cases. All 172 passing results have original XML. The five remaining failures retained their previous classifications: protected hardlinks, access mode 3 on open, two sysfs same-path renames on a read-only mount, and access time when following a symlink.

Updating the cumulative inventory with those 180 results gives 2,893 passes, 124 failures, 119 skips, 25 timeouts, one missing result and one fixture failure across 3,163 cases.

## Paired performance measurements

Old and new Mac binaries ran alternately, reversing the order each pair. Each median uses 16 samples following two warmups per binary. Each sample measures elapsed guest workload time in milliseconds. The missing-entry benchmark admits both versions' error codes when measuring the cost of a failed mkdir. The upstream tests above check the exact result.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| Private open/close, 8,000 | 148.56 | 148.03 | -0.36% |
| Private stat, 8,000 | 37.49 | 37.59 | +0.28% |
| tmpfs create/unlink, 4,000 | 49.24 | 49.13 | -0.23% |
| Missing procfs mkdir, 2,000 | 48.19 | 47.60 | -1.24% |
| Memory access | 175.87 | 175.25 | -0.35% |
| Map, fault and unmap | 131.19 | 133.21 | +1.54% |
| Private pread/pwrite | 94.76 | 94.78 | +0.02% |
| Fork and wait | 19.24 | 19.31 | +0.34% |

Raw XML, inventory, benchmark sources and timing samples are in `target/gvisor-proc-lookup-20261120` in the iPad checkout.
