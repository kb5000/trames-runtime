# Full gVisor ARM64 rerun, 2026-11-23

All **14,530 enabled cases across 254 groups** ran again on Mac HVF, the
interpreter on the Mac, and native Linux `7.0.0-43-generic`. After the
documented fixture and single-case follow-ups, **both Trames executors passed
all 13,965 cases that passed on the refreshed native reference**. No case is
unrun because of a worker error, disk floor or wall budget. The
[machine-readable summary](gvisor-full-20261123.json) retains the complete
initial and verified counts and the execution profiles.

This supersedes the earlier cross-revision rolling comparison. It verifies
this fixed ARM64 selection, rather than every Linux interface or kernel
behavior. Native failures, skips and timeouts remain outside the passing
oracle. The interpreter ran on the development Mac, not a physical iPad.

## Initial full-run results

| Executor | Pass | Assertion | Timeout | No result | Skip |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native Linux | 13965 | 36 | 4 | 0 | 525 |
| Mac HVF, initial full run | 13982 | 37 | 4 | 0 | 507 |
| Interpreter, initial full run | 13926 | 84 | 8 | 5 | 507 |

The initial Mac run used four harness workers and the interpreter used two.
Each guest had two CPUs. Original GTest chunks held at most 50 selected
cases, with fresh stores per process and isolated retries for abnormal
chunks. Affinity, isolated loopback and TUN/TAP cases retained separate
processes. All enabled cases were selected; upstream assertions and binaries
were unchanged. Every reported pass was audited against completed original
XML with the exact case identity and a consistent process exit status.

## Follow-ups and native comparison

| Executor | Refreshed native-passing cases | Passed after follow-ups | Remaining gap |
| --- | ---: | ---: | ---: |
| Mac HVF | 13,965 | 13,965 | 0 |
| Interpreter on Mac | 13,965 | 13,965 | 0 |

The raw first-run results remain available independently of the follow-ups:

- Mac: nine of ten selected differences passed in fresh single-case stores.
  These were eight persistent-listener stress cases with `EADDRINUSE` in
  their initial chunks, and `Inotify.EpollNoDeadlock`, which passed with
  the longer isolated allowance. The PIDFD_THREAD case still selected an
  older-kernel errno expectation from the guest release string.
- Both executors passed the 23 preselected original cases in the upstream
  userspace-kernel mode, including that PIDFD_THREAD case. This mode is an
  explicit profile, rather than a change to the guest release or assertions.
- The interpreter passed 33 of 34 selected differences in fresh stores with
  full guest-fabric permissions. Loopback-only policy had rejected guest
  bridge, route and TUN traffic. Five Unix datagram cases also passed outside
  their earlier chunks. Its remaining PIDFD_THREAD difference passed in the
  userspace profile above.
- `AffinityTest.NewThread` needs at least three guest CPUs. Both executors
  passed it with four CPUs, replacing their initial conditional skips.
- The refreshed native fixture enabled additional UDP interface assertions.
  The interpreter passed both complete external-networking UDP groups,
  **38 IPv4 and eight IPv6 cases**, with full guest-fabric permissions.
  The Mac internal bridge already permitted this traffic.

The Mac test network was guest-only with NAT and host interoperability
disabled. The interpreter's full profile uses its isolated virtual fabric;
the initial interpreter run used loopback-only policy. Bash and its original
loader/libraries were present for the original interpreter-script fixture.
FUSE control, writable sysfs, inherited terminal and original runfile
fixtures are recorded in the plans. Native cases ran as PID 2 in fresh
mount, PID, IPC, UTS and network namespaces in the disposable six-CPU Linux VM.

## Source and evidence

The gVisor revision is `89cacadae21eca4270a8f7c79281d0426d33ac5f`.
The same checksum-pinned November 17 static ARM64 ELFs ran on all executors.
Four built ARM64 targets list no enabled cases; the five original build
blockers and 28 upstream disabled cases remain outside this selection.

The tested production Runtime is `ede0384f3ccb3d62a893c3e5e068d8bdea58e069`.
The existing runners were built at `9a20d6a`; the only intervening changes
were regression tests behind `cfg(test)` and validation prose. The production
source identity was checked before reusing these executables. SHA-256:

- Mac: `44973bc238b9d95031a7d1641c8863f18a75662e9ad1f8eabf8b18946bad6390`.
- Interpreter: `bef22c3be435a7274ce95f235ef2496037bc6d85e78b18cac9f3d2c8dd514275`.

This follow-up changes only the test harness and records. Interpreter chunks
reuse the Mac harness's strict XML auditor and split abnormal results into
isolated retries. All **19 harness evidence tests** passed, including a guard
that refuses passing XML from an abnormally exited interpreter chunk. The
163-case interpreter smoke selection had 159 passes and four original skips.
Unchanged production CI, guest artifacts and performance evidence are reused.

Raw plans, stdout, stderr, XML, audited results and profile histories are under
`target/gvisor-full-20261123`. The refreshed native evidence is under
`target/local-ci/io/gvisor-full-native-20261123-final`. The failed initial
native setup and interrupted singleton interpreter attempt are retained as
diagnostics and excluded from the completed full-run totals. No previous
passing Trames outcome was reused for this rerun.
