# Enumerating the guest mount tree with findmnt

Debian's stock util-linux 2.41.5 `findmnt --kernel=listmount` now enumerates guest mounts and filters by exact mountpoint or unique ID. The tested tree contains a tmpfs, a nested tmpfs and a bind of a subdirectory. The output of the modern and `/proc/self/mountinfo` backends agrees for all three mounts on `TARGET,FSTYPE,ID,PARENT,FSROOT`. The same command was exercised on native ARM64 Linux, the Mac hardware executor and the product interpreter. Native and interpreter traces confirm that the modern command uses `listmount` and `statmount`.

## ABI and ownership

- `listmount` enumerates IDs in either direction using an exclusive cursor. An explicit mount ID limits the result to its descendants. `LSMT_ROOT` limits it to the caller's visible tree. Results are bounded by the actual namespace membership and the caller's requested count.
- `statmount` supplies the Linux v6.12 fixed fields and NUL-terminated strings, along with the later `STATMOUNT_SB_SOURCE` field. Request masks select each field. Legacy IDs match the procfs columns. Unique IDs occupy a separate numeric range and match `statx(STATX_MNT_ID_UNIQUE)`. Bind aliases and namespace copies get distinct IDs. Attaching a detached tree preserves its ID. Numeric queries return only mounts installed in the selected namespace.
- The caller's chroot determines visibility and relative mountpoint paths. Explicit queries of a different live guest namespace require administrative capability in that namespace's owner. The lookup uses weak references registered at namespace creation and released at retirement. Existing topology administration serializes readers against a move, attach or detach. Ordinary pathname operations do not take this lease or consult the namespace ID index.
- A request for unique `statx` identity on an anonymous descriptor with no represented mount leaves that result bit unset. This prevents a synthetic legacy ID from aliasing a visible mount. Unix and procfs consumers of legacy IDs keep their existing result.

The ABI follows [Linux v6.12 mount queries](https://github.com/torvalds/linux/blob/v6.12/fs/namespace.c) and [the mount UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/mount.h). This batch uses the 24- and 32-byte request formats. Newer FD-selected query modes and option arrays are separate extensions. Linux v6.12 returns `ENOENT` on an unauthorized foreign namespace lookup. The native Linux 7.0 reference returns `EPERM` for that lookup. Both deny access.

## Verification

The [AArch64 guest fixture](../../tests/fixtures/mount-query.c) exercises bidirectional pagination, subtree selection, legacy and unique ID round trips, raw paths with spaces, short buffers, malformed requests, chroot filtering, cross-namespace permissions, detached mount lifetime and anonymous FD identity. Build on Linux ARM64 with `cc -static -O2 -Wall -Wextra -Werror tests/fixtures/mount-query.c -o /tmp/mount-query` and run as root in a disposable guest or private mount namespace.

The 238 original gVisor cases cover `chroot`, `mount`, `mount_fd`, `stat` and `statfs`. Case names, binary hashes and the original Google Test XML were checked against the fixed reference.

| Executor | Pass | Fail | Skip |
| --- | ---: | ---: | ---: |
| Native ARM64 reference | 234 | 0 | 4 |
| Mac hardware executor | 232 | 0 | 6 |
| Product interpreter on Mac | 231 | 1 | 6 |

The Mac outcomes match the rolling baseline. This run reproduced the sysfs user-namespace permission failure in `MountTest.UserNamespaceSysfsMountOverEmptyDir`. The [fixture follow-up](interpreter-fixtures-20261123.md) restores that case with the same guest setup used by the Mac harness.

All eight runtime CI stages and ARM64 iOS FFI compilation passed. Local traces, original XML, hashes and performance samples are under `target/mount-query` in the iPad checkout. Final Trames case artifacts are in `paired/` and the CI record is in `ci-paired/summary.json`.

## Ordinary workload timings

The prior and final Mac runners used the same guest probe. Each version had two warmups and 32 timed runs in alternating order. Values are median milliseconds.

| Workload | Prior | Final | Change |
| --- | ---: | ---: | ---: |
| `memory` | 177.307 | 176.776 | -0.30% |
| `mmap_fault_unmap` | 140.260 | 140.561 | +0.21% |
| `file_pread_pwrite` | 100.774 | 99.616 | -1.15% |
| `fork_wait` | 20.241 | 20.172 | -0.34% |

The executable hashes and raw samples are in `paired/verified.json` and `paired/performance-final.json`.
