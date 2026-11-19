# Process, file, memory and message IPC compatibility — 2026-11-19

This batch follows runtime `6d3491f`. It adds common clone3 creation, cold fork
inheritance policy and System V message queues, and repairs file open/status,
access/ACL, child-wait and zombie-priority semantics. Mac HVF and the iPad
interpreter use the same implementation; no coordinator or service thread is
introduced. This is a selected core-API inventory, not a new whole-project
Linux compatibility percentage.

## Original gVisor results

The unchanged upstream ARM64 binaries are from gVisor
`89cacadae21eca4270a8f7c79281d0426d33ac5f`. The selection contains **137 complete
groups / 2,998 cases**, covering files/descriptors/I/O, processes/signals,
memory/mappings and synchronization/IPC, plus their namespace/capability/limit
dependencies. Binary hashes and original GoogleTest XML remain authoritative;
no upstream assertion or expected errno was changed.

The initial raw baseline had 2,129 passes. All 111 ACL cases initially failed
before reaching ACL operations because the disposable Trames image lacked the
native host's `/dev/shm` tmpfs fixture. Re-running that complete group with the
same frozen baseline binary and an explicit mode-1777 tmpfs produced 82 passes,
16 failures and 13 skips. These 82 passes are fixture recovery, **not runtime
improvements**. Both sides below use that equivalent fixture.

| Outcome | Baseline | Final |
|---|---:|---:|
| Pass | 2,211 | 2,312 |
| Assertion failure | 630 | 536 |
| Skip | 126 | 120 |
| Timeout | 27 | 26 |
| Missing result | 4 | 4 |

On the **2,903 native-passing cases**, Trames passes **2,309 (79.54%)**, compared
with **2,208 (76.06%)**: **101 additional passes, zero old-pass regressions**.
One additional pass was previously a timeout (OpenTest's argument-restart loop);
this observation alone does not establish a general timeout/stability guarantee.
Skips, timeouts and missing XML remain non-passing outcomes.

| Complete group | Cases | Baseline pass | Final pass |
|---|---:|---:|---:|
| access | 19 | 3 | 19 |
| fork, including clone3 | 24 | 14 | 24 |
| madvise | 18 | 15 | 18 |
| System V msgqueue | 36 | 0 | 36 |
| fcntl | 97 | 84 | 86 |
| open | 42 | 35 | 38 |
| POSIX ACL | 111 | 82 | 95 |
| wait | 64 | 35 | 47 |
| priority | 19 | 14 | 14 |
| xattr | 47 | 39 | 41 |

The full candidate sweep ran all 2,998 cases. Its exposed edge cases were fixed
together, then **nine complete affected groups / 414 cases** were re-run: access,
msgqueue, open, open_create, openat2, overlay, posix_acl, priority and xattr.
The final record reuses only unaffected groups from the full sweep. Both runner
identities, source manifests, the final source delta and separate raw XML sets
are retained. The aggregate's 2,312 unique passing cases each have original XML
evidence; it is not presented as one final-binary invocation of every case.

## Implementation and limits

- clone3 shares original birth/admission, namespace ordering, stack/TLS/TID and
  signal handling with clone. CLEAR_SIGHAND precedes publication. pidfds,
  caller-selected PIDs and CLONE_INTO_CGROUP remain unsupported; non-SIGCHLD
  process exit-signal coverage is not completed by this batch. __WALL now reaches
  the existing child-event path. Zombie priority authority persists until reap.
- VMA policy implements DONTFORK/DOFORK and WIPEONFORK/KEEPONFORK, including
  unmap, fixed replacement, remap, fork accounting and sparse ranges. Ordinary
  guest memory access is unchanged. mlock/mlock2/mlockall and expanded mremap
  semantics remain gaps.
- System V queues implement namespace-local creation/lookup, permissions,
  IPC_SET/STAT/RMID/INFO, MSG_INFO/STAT/STAT_ANY, typed/negative/except selection,
  zero-length messages, truncation, MSG_COPY, blocking/nonblocking transfer and
  removal/interrupt behavior. Waits retain original resources, not numeric IDs.
  Standard defaults are MSGMAX=8192, MSGMNB=16384 and MSGMNI=32000; writable IPC
  sysctls, IPC-ID recycling and full /proc/sysvipc reporting are not added here.
  POSIX mq, System V semaphores and System V shared memory remain unimplemented.
- Files repair read-only open-time truncation, ARM64 status flags, noexec access,
  xattr error/permission handling and ACL clear/remove/version/setgid behavior.
  O_DIRECT is a guest cache hint, not a host-cache-bypass guarantee. The three
  remaining ACL failures concern stacked lower overlays and device-node copy-up.
  Async descriptor notification, other overlay edges and the remaining broad
  inventory failures are still tracked, rather than hidden or force-passed.

The architecture and ownership boundaries are recorded in
[coordination-boundaries](../architecture/coordination-boundaries.md#107-process-file-vma-and-message-ipc-abi-batch--2026-11-19).
ABI references include Linux [clone](https://man7.org/linux/man-pages/man2/clone.2.html),
[message transfer](https://man7.org/linux/man-pages/man2/msgop.2.html) and
[message control](https://man7.org/linux/man-pages/man2/msgctl.2.html).

## Local verification and deployment boundary

Detailed final gate results and source/runner digests are recorded in
[the machine-readable summary](gvisor-core-apis-20261119.json). Raw evidence is
under the ignored `target/gvisor-core-apis-20261119` directory in the iPad product
checkout; native Linux workflow logs are under its local-CI output mount.
The Linux feature-union test harness uses its established 8 MiB Rust test stack;
this is not a production execution-stack change.

The source batch has focused regressions for original queue lifetime and wakeup,
namespace/ID replacement, copyout faults, concurrent transfer, fork quota and
policy propagation, read-only truncate authority, versioned clone3 import and
unreaped priority targets. No controlled throughput or Firefox-latency gain is
claimed. Existing host-memory reclaim gates remain enabled.

Installed Mac Stable/Dev applications and environments are not replaced or
restarted. The physical iPad is not contacted, captured, woken or installed.
Only isolated Mac runners and disposable test stores are used. The harness
enforces a 20 GiB free-space floor; no large Android or CTS downloads are needed.
