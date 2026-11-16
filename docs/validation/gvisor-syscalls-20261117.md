# gVisor syscall pilot on Mac Dev — 2026-11-17

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
