# cgroup physical resources and retained I/O — 2026-11-27

Status: functional delivery completed in `8bfc0948`; the cold-read performance follow-up has been implemented and validated in the [closeout record](cgroup-closeout-20261127.md). The original +7.72% observation and its raw evidence remain below as history.

## Scope and behavior

Physical anon/file/shmem allocations keep their first owner across aliases, fork/COW, migration and asynchronous completion. Storage capacity remains separate from physical-memory accounting. Clean reconstructible cache can release actual bytes; dirty/pinned pages retain their leases. Pressure resumes bounded writeback and original-mm pin retirement before retry/OOM. A peer that reloads and dirties a new canonical page keeps those new bytes when an old mm retires its former pin.

Hierarchical IO admission precedes actual private-disk backend operations. `io.max` configuration changes, partial completion, cancellation and refunds preserve the original resource and progress. Ordinary file work, mappings, copy/splice, AIO/io_uring, executable input/ELF/stack/vDSO stages, live host import/export/edit and overlay/private metadata transactions use retained work. A resource wait releases task/mm/layout/CPU execution custody and resumes on existing workers/native events.

Wayland SHM retains the original client, bytes and ancillary FDs across admission waits. Close monitoring uses the existing event loop: Linux poll metadata and Apple-only kqueue APIs behind target cfg. The last functional fixes handle live memory-policy checkpoints without interpreting them as clone, and collect peer cgroup policy before acquiring a mutable task body.

The private disk is exposed as guest device `253:1`. The CLI's `--memory` option remains the explicitly bounded ephemeral test backend; arbitrary host input `Vec` capacity is not guest resident memory. The batch does not introduce a general host-heap accounting policy or a cross-sidecar/manifest crash-atomicity guarantee.

## Evidence and identities

Local artifacts: `target/validation-cgroup-20261127` in the iPad repository; Linux artifacts: `target/local-ci/io/cgroup-20261127`. Each stage records argv, duration, exit status and a bounded timeout. Exact test processes have a 30-second watchdog and isolated process groups. Missing XML, crashes and timeouts never count as passes.

- `runtime-source-v9.json`: first full workspace test checkpoint.
- `runtime-source-v10.json`: final functional lifecycle repairs; `runtime-source-v11.json` only changes conformance fixtures. `release-source-equivalence.json` verifies equal production source after stripping the explicitly gated test modules.
- `runtime-source-v12.json`: main integration checkpoint; v13 changes only a test fixture, with production equality checked in `integrated-release-source-equivalence.json`. Release runner manifests contain SHA-256 and the source manifest. The source and binary identities are recorded rather than inferred from a dirty branch name.

## Consolidated checks

Before main integration, Runtime Apple: 2,766 passed / 31 ignored; Linux: 2,777 passed / 15 ignored, no failures/timeouts. All workspace test executables, including integration targets, were inventoried and run. These counts are not gVisor counts. Final integrated inventory coverage is Apple 2,773 passed / 31 ignored (2,804 identities), Linux 2,784 passed / 15 ignored (2,799 identities). Affected modules reran 1,395 / 1,403 passes respectively; unchanged passing evidence was reused. Both final inventories have zero uncovered cases and no obsolete evidence. Interpreter-kernel conformance is separately 546 passed / 3 ignored on each host, with no failures/timeouts.

FFI: 32/32 passed at the final cgroup functional checkpoint; its unaffected tests are reused after desktop main integration. Final Runtime strict all-target/all-feature Clippy passed on Apple and Linux; product core/CLI/FFI strict Clippy, Linux FFI all-target/all-feature compile, formatting and execution-boundary checks also passed. The final main-integrated, source-checked ARM64 iOS static archive built successfully. No unrelated Swift WIP was packaged/deployed. Apple and Linux documentation tests were checked separately from executable libtest inventories.

Actual memory-footprint example passed on Apple and Linux: three cycles populate 64 MiB, leave one host granule in every arena, verify retained data and release over 48 MiB of actual host charge per cycle; final guest resident bytes are zero. Apple used 16 KiB host granules; Linux 4 KiB.

## Original gVisor cases

The immutable upstream ELF set and original native plan come from `target/local-ci/io/gvisor-expanded-20261117`. Selected suites: aio, fallocate, mmap, open, preadv, preadv2, pwritev2, readv, memfd, cgroup2. There are 348 exact original identities: 345 native passes and 3 native skips. Both final main-integrated executors: 346 passed / 2 skipped. The additional memfd pass corresponds to a native-skipped case and is not added to the strict native-passing denominator. The earlier final interpreter cgroup2 subset was 85 passed / 2 original skips; both integrated 348-case runs subsequently passed independently. `gvisor-audit-integrated.json` verifies all original identities, ELF hashes and the complete 345-case native-passing subset.

HVF's first fallocate failure was `socket(AF_INET, SOCK_DGRAM)` denied by the test environment's network=none. The identical original case passed with an isolated internal network; the subsequent full 348-case HVF run also passed. Internal networking does not permit host NAT.

Historical full-ledger totals remain 14,014 passed per executor and strict native-passing coverage 13,965/13,965. This is a targeted batch, not a newly run full gVisor suite.

## Actual limits and OOM

The static ARM64 C workload in [`cgroup-resources.c`](../../tests/fixtures/cgroup-resources.c) (the validated artifact was named `cgroup-probe.c`) creates its own child groups, saves/restores original membership, touches 2 MiB anonymous memory, writes 64 KiB plus fsync under `wbps=32768`, then forks a child limited to 64 KiB and verifies SIGKILL plus `memory.events` oom_kill=1. Native Linux, interpreter and HVF all reached `CGROUP_ACCEPTANCE_PASS`.

Linux requires its partition's parent disk `253:0` for io.max (the partition key returns ENODEV). The guest private device uses `253:1`; all three execute the same v2 static ELF. Native IO: 2.012 s / 65,536 wbytes / 1 wios. Final integrated interpreter: 3.869 s / 187,856 wbytes / 18 wios; final integrated HVF: 3.878 s / 188,062 wbytes / 18 wios. Guest counts include actual charged private metadata writes, so these timings are not a performance ranking against ext4. Anonymous memory.current grew from 0 to 2,097,152 in both guest executors.

## Ordinary workloads

Paired baseline: immutable modern-mount closeout runners. The exact same static ARM64 [`cgroup-normal-workload.c`](../../tests/fixtures/cgroup-normal-workload.c) fixture performs checked write/fsync/pread, pathname metadata and pipe work in disposable private stores with no cgroup limits. Four alternating paired blocks, three samples per block; CLOCK_MONOTONIC measures fixed guest work and excludes archive import/startup. Short and long sample evidence is retained, including outliers; short 1–3 ms pipe samples were expanded rather than used as conclusive evidence.

The first long samples overlapped compilation: interpreter IO +6.30%, metadata +4.44%, pipe +3.19%; HVF IO +4.43%, metadata −2.40%, pipe −0.19%. Some interpreter paired blocks varied by 25–36%. Those contaminated samples do not establish performance equivalence. The final integrated comparison waited for this batch’s build/strict/conformance processes to finish before measuring. Results: interpreter IO +1.16%, metadata +1.70%, pipe +2.34%; HVF IO +7.72%, metadata +0.48%, pipe +0.57%. HVF file IO increased from 39.586 ms to 42.644 ms, and all four paired blocks increased (+8.56%, +4.90%, +12.11%, +6.71%). This fixed 16 MiB write/fsync/pread workload has a reproducible measured cost; its cause is not yet profiled. Keep it as a performance optimization item rather than describe it as noise or general application equivalence. All contents, checksums, sample orders and binary hashes are in `ordinary-performance-integrated/results.json`.

## Reproducing the native load fixtures

Build each committed fixture with `gcc -O2 -Wall -Wextra -Werror -static SOURCE -o OUTPUT` on Linux ARM64. Run the resource fixture as root in a disposable cgroup-v2 machine; its optional first argument is the real parent block device (`253:0` in the reference VM). Guest runs use the actual private device from fstat and need no override. The fixture restores membership and removes its own groups on success. The ordinary workload uses `/tmp`, validates a 16 MiB file checksum and prints JSON times; its loops are fixed, not elapsed-time loops. For the interpreter long workload set `--max-instructions 200000000000`; the default small instruction budget is insufficient. Use disposable private disk stores, two guest CPUs and loopback-only networking, and keep rootfs/executable import outside timing.

## Delivery

Direct main commits/pushes pair this Runtime with iPad host-transfer callers and both product pins; final commit identities are recorded in the product roadmap and local delivery manifest. Unrelated allocator, debugger, storage-durability, idle-memory, legal/security and Swift WIP remain outside this batch.
