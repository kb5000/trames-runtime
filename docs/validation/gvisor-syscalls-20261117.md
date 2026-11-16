# gVisor syscall pilot on Mac Dev — 2026-11-17

See [the fix-and-rerun checkpoint](#fix-and-rerun-checkpoint) for the current result.

The unmodified upstream syscall tests can run under Trames. This checkpoint
builds **11 groups / 408 enabled cases**, not the complete upstream test tree.
A standalone CMake build avoids downloading/building runsc, Go or Bazel. Test
sources, utilities, errno-preserving allocator and expectations remain original.

## Provenance and isolation

- gVisor source: `89cacadae21eca4270a8f7c79281d0426d33ac5f`.
- Abseil `20260817.0`, GoogleTest `1.18.0`, Benchmark `1.10.0` match its module
  pins. All source/archive hashes are in the build entry's `upstream.json`.
- Native reference: existing ARM64 Ubuntu CI instance, kernel `7.0.0-43-generic`,
  GCC 13.3.0, static glibc/libstdc++. Six CPUs, 8 GiB VM memory.
- Trames: installed Mac Dev 1.5.5, runtime
  `7f4cae8c5fabeb0d05362359f770af12ba231bc4`. Six CPUs, lazy 8 GiB budget,
  verified Alpine rootfs and the exact same static ARM64 ELF hashes.
- Root/PID 1 test contexts; each native case has fresh namespaces, each Trames
  case a fresh runtime process. GPU/audio/network/host interoperability disabled.
  Existing Stable/Dev product registries and running guests were not restarted.
- Passed/skipped pilot cases were reused only after matching executable and
  environment identities. Failing cases were rerun. Individual case timeout 20 s.

## Results

Native: **401 passed, 7 upstream skips**. The first reference run had six
`PipeFdCount` setup failures because the invoking process inherited a low FD
limit. Those six original cases were rerun with `RLIMIT_NOFILE=1048576` and all
passed. Trames already has that limit and passes all six. The reusable driver
now sets the reference process limit itself; no kernel-global limit is changed.

Trames: **335 passed, 49 assertion failures, 16 abnormal/no-XML exits, 8 skips**.
Against the 401 native-passing cases: 335 pass (**83.54%**), 49 fail, 16 abort
and one additional skip. That skip is `EventfdTest.BigWriteFails`, whose original
version gate skips kernels older than 6.9; Trames advertises `6.0.0-trames`. No skip
or missing report is counted as success. There were no case timeouts.

| Group | Cases | Native pass / skip | Trames pass / fail / abort / skip |
|---|---:|---:|---:|
| brk | 1 | 1 / 0 | 1 / 0 / 0 / 0 |
| clock_getres | 1 | 1 / 0 | 1 / 0 / 0 / 0 |
| clock_gettime | 10 | 9 / 1 | 7 / 1 / 1 / 1 |
| dup | 11 | 11 / 0 | 10 / 1 / 0 / 0 |
| eventfd | 11 | 9 / 2 | 8 / 0 / 0 / 3 |
| getrandom | 1 | 1 / 0 | 1 / 0 / 0 / 0 |
| pipe | 160 | 156 / 4 | 141 / 9 / 6 / 4 |
| epoll | 24 | 24 / 0 | 23 / 1 / 0 / 0 |
| mmap | 118 | 118 / 0 | 97 / 15 / 6 / 0 |
| futex | 67 | 67 / 0 | 42 / 22 / 3 / 0 |
| uname | 4 | 4 / 0 | 4 / 0 / 0 / 0 |

"Abort" includes guest assertion aborts, guest memory faults and runtime errors
without a GoogleTest XML report; it does not mean the macOS machine crashed.
Full case names, assertion messages, stderr and binary hashes are preserved in
[the machine-readable baseline](../../tests/gvisor/baselines/mac-20261117.json).

## Concentrated gaps

| Area | Nonpassing cases | Observations |
|---|---:|---|
| Futex | 25 | robust-list calls return ENOSYS; wake-op zero-wake semantics and PI paths differ; robust mutex/wake-zero paths can end without an event source. |
| mmap | 21 | `/dev/zero` mappings return ENODEV; ARM64 write-only mappings are treated too strictly; partial EOF pages, DATA/AS limits and huge-range boundary cases differ. |
| Pipe/FIFO | 15 | partial writes with the read end closed lose progress; FIFO descriptor flags, offset-call errno and pipe statfs fields differ. Six cases terminate with no event source. |
| CPU clocks | 2 | process CPU clock and encoded per-thread clock IDs return EINVAL; thread-clock support alone is insufficient. |
| FD/sysctl | 1 | `/proc/sys/fs/nr_open` remains read-only, blocking the corresponding rlimit test. |
| Special-file epoll | 1 | registering `/dev/random` is rejected with EPERM. |

These primarily expose Linux ABI/lifetime gaps, not evidence that the CPU is
simply too slow. The Mac memory-fault paths also need execution-backend diagnosis;
this result does not establish identical iPad behavior. Fixes should preserve direct worker/resource ownership and be
batched by complete dependency class, especially futex, pipe readiness and VM
mapping semantics. No production kernel fix or coordinator fallback was added
in this testing checkpoint.

## Reproduction and scope

Use [the checksum-pinned build/reference/Trames entry](../../tests/gvisor/README.md).
The exported static binaries total about 41 MiB; the source/cache plus scoped
build are small compared with a full Bazel build. The existing Linux CI VM was
reused. Builds/results remain under ignored `target/gvisor-20261117` and
`target/local-ci/io/gvisor-20261117`; no test binaries are committed.

The same binaries are suitable for later iPad interpreter testing; no physical
iPad result is claimed. Only the test harness and reports changed, so unrelated
CPU/Linux/graphics acceptance and application deployment were not repeated.

## Fix-and-rerun checkpoint

The same **408 original cases / 11 groups** now produce **400 passes, zero
assertion failures, zero abnormal exits/timeouts, and eight skips** on the final
Mac Dev candidate. The native reference remains **401 passes / seven skips**;
its source/compiler/ELF identities did not change, so it was reused rather than
rebuilt. No upstream test source, expectation or executable was modified.

| Result | Initial Mac Dev | Fixed candidate |
|---|---:|---:|
| Passed | 335 | 400 |
| Assertion failures | 49 | 0 |
| Abnormal/no-XML exits | 16 | 0 |
| Skipped | 8 | 8 |

All **65 previous failures/aborts** pass. Strict coverage against the 401
native-passing cases is **400/401 = 99.75%**. The remaining difference is the
unchanged upstream version skip `EventfdTest.BigWriteFails`: Trames reports
`6.0.0-trames`, below the test's Linux 6.9 gate. A skip is still not a pass.

### Complete dependency classes corrected

- **Futex:** distinct private and shared-anonymous keys; zero/negative legacy
  wake counts; private wake-op keys without a guest-word read; robust-list
  registration/query and bounded exit-list processing; PI guest-word ownership,
  contention, handoff, try-lock and ordinary/PI queue validation. Compare,
  enqueue, atomic update and handoff use the original keyed buckets. Wakes run
  after releasing bucket locks. Waiting tasks surrender existing execution slots.
- **VM ABI:** fresh anonymous `/dev/zero` mappings, ARM64 write-implies-read
  permissions for mmap/mprotect, ENOMEM on length-rounding overflow, writable
  DATA/AS limit state and the tested brk/mmap enforcement. The apparent partial
  EOF-page crashes also disappeared with the ARM64 permission correction; no
  separate file-EOF workaround was needed. Lazy memory budgets remain separate
  from Linux virtual-address policy, with no preallocation for a larger limit.
- **Pipes/FIFOs:** retained scalar/vector write progress through blocking,
  reader close, interruption and executor migration; SIGPIPE even when that
  write returns positive progress; named-FIFO O_LARGEFILE, ESPIPE precedence and
  pipefs name-length metadata. Small ordinary writes keep their existing path.
- **Task time:** encoded CPU-clock IDs and process totals including retired
  original threads. This uses the existing task assignment-time accounting,
  not unrelated host-process or stopped-task wall time.
- **Descriptor policy:** `/proc/sys/fs/nr_open` is an environment-owned writable
  capability shared by existing limit objects and fresh worker control views.
  The default remains 1,048,576; increasing it changes sparse numeric limits,
  not descriptor allocation. `/dev/random` is accepted by epoll.

Linux's private-key/wake ordering was checked against the primary
[futex key implementation](https://github.com/torvalds/linux/blob/master/kernel/futex/core.c)
and [wake implementation](https://github.com/torvalds/linux/blob/master/kernel/futex/waitwake.c).
No coordinator, resource service, polling bus or host-wide synchronization was
introduced. Shared changes compile for the iPad interpreter composition.

### Validation and limits

- Full runtime workflow on macOS: formatting, all-target/all-feature Clippy,
  workspace tests, release build and reclaim-footprint example. Workspace tests
  report **1,615 passes / 31 pre-existing ignores**.
- Interpreter kernel conformance: **490 passes / three ignores** on final source;
  its all-target Clippy also passes. A pause/resume timing check failed once in
  a busy concurrent run, then passed alone and in the final complete run.
- Mac workflow checks/tests plus native terminal/window fixtures pass. Production
  product pins/boundaries are checked after committing the shared source.
- iPad ARM64 FFI compile check passes with the Xcode iPhoneOS SDK. This is not a
  physical-iPad execution result; no installed iPad or Mac app is replaced.
- Added regressions cover source-opened sysctl propagation, retired process CPU
  time, robust-list fork/exec reset, and scalar/vector pipe progress without
  duplicated bytes. Internal fixtures were updated where they had encoded the
  formerly unsupported calls, fixed descriptor ceiling or aliased futex keys;
  the external gVisor oracle and assertions stayed unchanged.

This remains a scoped compatibility checkpoint, not full Linux/gVisor
conformance. PI here covers the tested guest ownership/wait ABI; it does not
claim real-time priority donation or complete robust-PI/requeue-PI semantics.
DATA/AS coverage concerns the tested brk/mmap paths, not a claim that every
address-space operation or rlimit is complete. Rootfs/device permissions are
unchanged outside the tested Linux ABI corrections.

The [fixed baseline](../../tests/gvisor/baselines/mac-20261117-fixed.json)
records all passing names, the additional skip, ELF hashes, final runner hash
and exact changed-source hashes. Reproduce with the existing gVisor entry and
native reference. Final evidence is in ignored `target/gvisor-20261117/`:
`trames-audited`, `comparison-audited`, `runtime-ci`, `mac-ci`,
`conformance-final.log` and `ios-check.log`. Per-case Trames registries are
removed after each complete run; existing product environments stay running.
