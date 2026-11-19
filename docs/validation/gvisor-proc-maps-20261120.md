# Procfs mapping reports on ARM64, 2026-11-20

The Mac hardware executor passed 84 of 160 upstream `proc` cases, up from
75 on runtime `7dab8e0` with the same binaries, runner settings and rootfs.
Five previous failures and four previous skips now pass. The other 151
classifications match. The two remaining timeouts were
`ProcPidStatusTest.StateSleeping` and `ProcTask.KilledThreadsDisappear`.

| Mac coverage | Baseline | Updated |
| --- | --- | --- |
| Full proc suite | 75 pass, 77 fail, 6 skip, 2 timeout | 84 pass, 72 fail, 2 skip, 2 timeout |
| Ten maps cases within proc | 5 fail, 5 skip | 9 pass, 1 upstream native-platform skip |
| mremap | 34 pass | 34 pass |
| proc_pid_smaps | 3 fail, 1 skip | 3 fail, 1 skip |

The ten maps, 34 mremap and four smaps cases were also rerun individually.
Each passing row was matched to its original GoogleTest XML. The local ARM64
interpreter passed the same nine maps cases and all 34 mremap cases, with one
maps skip. The native ARM64 Linux reference also skipped that case.
No physical iPad was used.

## Behavior

- The original address space owns one maps renderer and cached report for
  both live observations and the session's process information. It emits
  Linux address fields, requested permissions and stack labels. ARM write-only
  mappings retain their hardware read behavior while procfs reports `-w-`.
- Sparse copy-on-write metadata distinguishes shared anonymous memory, mapped
  files, named private memory and ordinary private VMAs. Splitting, unmapping,
  replacing, remapping, aliasing and forking carry the appropriate surviving
  metadata and offsets. File paths with newline bytes use Linux procfs escaping.
  Ordinary guest loads and stores do not consult this metadata.
- `PR_SET_VMA_ANON_NAME` sets or clears names on private anonymous and shared
  shmem mappings, including the distinction between an empty name and clearing
  the name. File-backed mappings reject the operation with EBADF. Focused
  tests cover names across holes, permission boundaries, aliases and fork.

The regular VFS file mapping provider records file identity and the opened
pathname when the mapping is created. Dynamic pathname updates after rename
or unlink are not covered. Device-specific mapping providers can lack file
labels. The missing per-VMA residency, dirty and physical sharing accounting
for `/proc/PID/smaps` remains separate work.

Formatting and mapping semantics follow the [Linux procfs documentation](https://docs.kernel.org/filesystems/proc.html).

## Performance and regression checks

Two independent comparisons used the same two-CPU guest and benchmark, with
16 measured samples per build after two warmup pairs in each comparison.
Columns below are medians across all 32 measured samples per build.

| Guest elapsed time | Before (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 173.002 | 172.544 | -0.26% |
| Map, fault and unmap | 132.508 | 130.474 | -1.54% |
| Private file pread/pwrite | 95.656 | 95.097 | -0.58% |
| Fork and wait | 19.800 | 19.380 | -2.12% |

An initial implementation copied a tree of mapping attributes along with the
permission list. Map/fault/unmap medians were 1.67% and 4.96% slower in two
comparisons. The final version shares the attribute spans across original
address-space snapshots and only copies them when these attributes change.

Shared runtime CI passed eight steps. Kernel conformance passed 500 cases
with three ignored. The iOS FFI and ARM64 Linux musl session targets compiled.

The former 3,003-case inventory excluded the entire 160-case proc binary.
Adding that binary brings coverage to 3,163 cases. On the expanded scope,
baseline and updated passes are 2,679 and 2,688, and failures are 344 and 339.
The updated inventory also has 121 skips, 12 timeouts, two cases without a
result and one fixture failure. This round reran 198 distinct cases. Evidence
and timing samples are under `target/gvisor-proc-maps-20261120`.
