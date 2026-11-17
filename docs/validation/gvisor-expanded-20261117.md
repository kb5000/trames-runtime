# Broad gVisor syscall coverage — 2026-11-17

Follow-up results are tracked in the [network ABI repair](gvisor-network-abi-fixes-20261117.md),
[ancillary completion](gvisor-unix-ancillary-20261117.md), and
[multi-area compatibility batch](gvisor-multi-area-20261117.md). The original
full-sweep totals below remain a historical baseline.

The current Mac Dev runner completed **14,530 enabled cases across 254 groups**
from unmodified pinned upstream sources. **8,575 pass**, 4,836 have assertion
failures, 268 fail a global fixture prerequisite, 96 abort/exit without usable
XML, 205 time out, and 550 are skipped. No case remains unrun because of the
wall budget or disk floor. Every reported pass was independently checked against
its saved XML identity and exit status.

The original 11-group pilot was rerun: **400 pass / eight skip**, unchanged from
the repaired checkpoint. The broader scope reveals additional gaps. This is not
full gVisor/Linux conformance or a performance benchmark.

## Reference comparison

The identical static ARM64 ELFs ran on native Linux: **13,864 pass, 35 assertion
failures, 593 skips, 29 abnormal/no-result exits, and nine timeouts**. The 666
native-nonpassing cases are not passing oracles. Some require fixtures outside
this isolated setup; nonterminating/long-running stress targets also remain
separate from passes.

Among the **13,864 native-passing cases**, Trames has:

| Outcome | Cases |
| --- | ---: |
| Pass | 8,526 |
| Assertion failure | 4,681 |
| Global fixture failure | 263 |
| Abnormal/no XML | 93 |
| Timeout | 197 |
| Additional skip | 104 |

Strict matching coverage is **8,526 / 13,864 = 61.50%**. The 49 other Trames
passes remain in the full results, but do not inflate this fraction. A skip,
missing report, timeout or failed prerequisite is never a pass.

## Status by area

Only native-passing cases appear in this table. File names determine the family
labels; these are case counts, not counts of distinct implementation bugs.

| Area | Native-passing cases | Trames pass | Assertion fail | Fixture / abort | Timeout | Skip |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Networking and sockets | 10,339 | 6,228 | 3,676 | 269 | 164 | 2 |
| Files, descriptors and I/O | 1,796 | 1,359 | 387 | 0 | 18 | 32 |
| Processes, signals and scheduling | 345 | 234 | 105 | 0 | 2 | 4 |
| Clocks and timers | 79 | 65 | 14 | 0 | 0 | 0 |
| Memory and mappings | 325 | 284 | 38 | 1 | 1 | 1 |
| Isolation, security and procfs | 793 | 281 | 354 | 86 | 12 | 60 |
| Synchronization and IPC | 187 | 75 | 107 | 0 | 0 | 5 |

The [compact JSON](gvisor-expanded-20261117.json) contains all 254 individual
group counts and ELF hashes. The [complete paired CSV](gvisor-expanded-20261117.csv)
retains every enabled case, both statuses and timings. These timings are not
CPU-performance scores.

## Independently reproduced gaps

Twenty-five representative nonpassing cases, each passing on native Linux,
were repeated individually with clean stores and at least 20 seconds. All remain
nonpassing: 23 assertion failures, one fixture failure and one guest assertion
abort/no XML. This confirms examples, not every failure in the sweep.

| Area | Observations |
| --- | --- |
| Socket receive ABI | recvmmsg returns ENOSYS for Unix and UDP examples; 132 native-passing assertion records mention it. |
| TCP / dual stack | TCP_INFO is unavailable; IPv4/IPv6 mismatch, INADDR_ANY and time-wait behavior differ. A selected active-close connection returns EACCES. |
| Unix ancillary data | SCM_CREDENTIALS yields PID 0 and UID/GID 65534 instead of the sender credentials. |
| Namespace queries / netfilter fixture | /proc/self/uid_map returns ENOENT. All 268 netfilter cases fail the original global environment before nftables behavior is tested; 263 pass on Linux. |
| cgroup2 fixture | 86 cases abort while querying the initial user namespace, mostly at the same prerequisite. This is not 86 independent cgroup bugs. |
| Processes | clone3 returns ENOSYS in the selected case and 25 assertion records. pidfd validation and process_vm behavior also differ. |
| Files / FD controls | Directory POSIX locks, pipe flock, openat2 BENEATH magic-link precedence, ACL execution, inotify attributes and copy_file_range validation need work. |
| Memory | MADV_DONTFORK validation, mremap zero-old-size/copy behavior and mlock state fail. The original 118 mmap cases still pass; all 20 mlock cases fail. |
| SysV/POSIX IPC | mq, semaphore, shared-memory and message-queue groups expose missing calls/behavior. All 67 original futex cases still pass. |
| Seccomp | 16/19 native-passing cases pass. Two RET_LOG cases incorrectly kill. Restart after group stop exits normally instead of being filtered with SIGSYS. |

The seccomp findings leave specific enforcement semantics unresolved; basic
BPF/filter success is not full seccomp coverage. Namespace prerequisites must
be corrected before blocked nftables/cgroup2 bodies can be assessed. No syscall
implementation was changed during this coverage expansion.

A useful next batch is the complete socket ABI class and its namespace/proc
prerequisites: batched receive, metadata/options, credentials, dual-stack/
loopback/error and closing behavior. Seccomp LOG/restart semantics deserve an
early focused correction. Follow with process/pidfd/clone3, file/lock controls,
memory edges and IPC as whole dependency classes.

## Provenance and execution

- gVisor revision: 89cacadae21eca4270a8f7c79281d0426d33ac5f. Archive, dependency,
  compiler and binary hashes are in the JSON. No upstream assertion/source changes.
- The pinned Linux BUILD has 263 candidate C++ targets: 258 build, 254 list
  enabled GTest cases. 32bit, socketopt, time and vsyscall build but list no
  enabled cases in this configuration.
- Five build blockers are explicit: fpsig_mut, fpstate_stop and arch_prctl have
  no ARM64 source; prctl needs the original Go test_app runfile; rseq needs its
  original no-libc helper/build dependency. **28 upstream DISABLED cases** remain
  disabled. The graph records Ubuntu fortify's compiler-only compatibility
  adjustment for sticky's intentional missing-mode errno probe.
- Native: ARM64 Linux 7.0.0-43-generic, static glibc/libstdc++, six-CPU / 8 GiB
  disposable CI VM, four workers. Every case owns fresh mount/PID/UTS/IPC/network
  namespaces. A tiny init owns PID/session/group 1; tests run as PID 2, with only
  loopback up. Searchable temporary ancestors permit intentional UID drops.
  Earlier fixture-diagnostic runs are superseded and excluded. The VM was stopped.
- Trames: Mac Dev 1.5.5 test build, production revision
  7143bacd36327cc0d05b6fd7226a42058648fb02; two CPUs and lazy 8 GiB per guest,
  four workers. GPU/audio/thunking/host interop are disabled. Internal bridges
  have NAT disabled; test listeners do not bind host ports.
- The 408-case rerun preserves the pilot configuration. Broad runs use clean
  APFS-cloned imported stores per invocation and original GTest chunks of at
  most 50 cases. Aborted prefixes are re-executed for strict XML. Stdout guides
  retries only. Previously completed singleton evidence is reused only after
  checking runtime/ELF/rootfs/network/CPU/runfile identities.
- Base active-case allowance: five seconds, extended for native-passing slow
  cases by max(base, min(90, 3 * native_seconds + 2)); alarm/itimer get 65/95 s.
  A timeout means this bounded run, not proof a function is absent. Individual
  confirmations use at least 20 s.
- All four final workers succeed. The 30-minute per-worker budget and 8 GiB disk
  floor leave no unrun cases. Host free space remains about 13 GiB; the exported
  test/cache area is about 1.4 GiB. No full Bazel/Go build was required.
- All 8,575 passes were XML-audited. 268 old mismatched-XML classifications are
  refined to fixture_failed: the original XML has a global NonTestSuiteFailure.
  Original XML, stderr, assertions and executables remain untouched.
- Nine harness evidence tests pass, guarding identities, abnormal exits, global
  fixture failures, failure-over-skip precedence, stdout-only false positives,
  complete partitions and reuse. Product sources are unchanged; unrelated
  CPU/GPU/Linux checks are reused rather than rebuilt.

See [the build/reference/Trames entry](../../tests/gvisor/README.md#broad-linuxarm64-coverage).
Raw evidence stays in ignored target/gvisor-expanded-20261117 and
target/local-ci/io/gvisor-expanded-20261117. The JSON records runner/rootfs,
raw-result and final analysis-harness hashes. Binaries and guest stores are not
committed. Only disposable registries were used; installed environments stayed
running.

## Still unverified

- iPad interpreter and physical-iPad execution of this corpus.
- Native BSD host-network path; this sweep uses the internal stack.
- Helper-dependent, ARM64-inapplicable and upstream disabled groups above.
- gVisor-only sentry/save-restore modes and other architectures/platforms.
- Behavior behind failed namespace prerequisites; independent confirmation of
  every individual broad-sweep failure/timeout.
