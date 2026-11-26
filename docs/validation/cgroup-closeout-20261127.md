# cgroup closeout — 2026-11-27

The physical-memory/IO functionality delivered in `8bfc0948` is retained. This follow-up completes the cold-read performance investigation and its implementation batch. No production coordinator/service thread, global pool lock or ordinary guest-memory barrier was added. The remaining measured difference against the pre-cgroup binary is reported below, rather than called zero overhead.

## Problem and implementation

The original fixed 16 MiB write/fsync/pread comparison showed HVF IO +7.72%. Splitting the same IO work into phases located the difference in cold reads: pre-cgroup read 8.447 ms, `8bfc0948` read 11.209 ms; write and fsync did not show the same increase.

The first candidate reused full-page input buffers and stopped cache eviction traversal after satisfying the requested release. Its six-order comparison improved HVF IO by only 1.18% against `8bfc0948` and still measured +6.53% against the pre-cgroup baseline. That candidate and its raw results are retained; it was not presented as closure.

The final batch additionally:

- Recycles only retired cache metadata proven exclusive with `Arc::get_mut` at the page, mapped-resident and shared-charge levels. Any strong or weak observer of those metadata cells prevents reuse. Old bytes are dropped and new bytes receive a fresh canonical identity; old physical-lease pins keep their original group. The cache remains bounded at the same 256-page working set.
- Registers each physical fill's original lease directly with the cache reclaimer. Root-owned fills avoid allocating a per-page weak-resource vector. Mapped providers retain their separate persistent registrations, and every later physical fill registers its actual owner again.
- Reads the host clock only when limited token admission needs it. Fully delivered IO records the original hierarchical byte/operation counts without taking a policy lock or doing a zero-byte refund. Short completion, issued errors and cancellation retain the original refund/notification behavior.

There is no unsafe-code addition. A partial page still zero-fills the tail. Reclamation continues to check original ownership, dirty state and byte/mapping pins before releasing actual bytes. New regressions cover partial reclamation without over-eviction, capacity churn across groups with old byte retirement, and full IO completion while an unrelated configuration holder owns the policy lock.

## Validation

Final affected libraries: Apple **1,546 passed / 4 ignored**, Linux **1,556 passed / 4 ignored**, zero failures/timeouts. This includes the complete affected memory and VFS libraries. Their all-target/all-feature strict Clippy passed on both hosts; shared-source formatting and execution-boundary checks also passed. The final source-checked iOS ARM64 Rust static archive built successfully. No unrelated Swift work was packaged.

Both final executors ran the same **348 original gVisor identities: 346 passed / 2 original skips**, covering all 345 native-passing identities with unchanged ELF hashes. Suites and the native reference are inherited from the [functional delivery record](cgroup-resources-20261127.md). Historical full-ledger counts remain 14,014 per executor and strict native-passing coverage 13,965/13,965; this follow-up does not add full-ledger passes.

The unchanged actual resource fixture passed on interpreter and HVF: a new 2 MiB allocation is charged, real private-disk IO waits under io.max, and the limited child is killed with oom_kill=1. Actual backend byte/operation totals remain recorded in the local logs. Unchanged conformance, FFI, native Linux reference and footprint evidence from the previous batch is reused.

The combined inventory, reusing unchanged project results, covers Apple 2,776 passes / 31 ignored and Linux 2,787 passes / 15 ignored. These are unit/integration identities, not gVisor additions.

## Final ordinary-load comparison

Three immutable runner versions execute the exact same static ARM64 ELF (SHA-256 `a2af3de581021459d4c7b4b0a5fb3a8023ad1596330711e4e1f16177ebc6e0c1`). Each variant uses an APFS clone of the same imported seed. Six paired blocks cover all six variant orders, with three samples per block and two guest CPUs. All own compilation, strict checks and functional runs finished before measuring. Guest CLOCK_MONOTONIC times fixed work; imports and startup are outside timing. All output checksums are checked.

| Executor / workload | Pre-cgroup ms | 8bfc094 ms | Closeout ms | vs pre-cgroup | vs 8bfc094 |
|---|---:|---:|---:|---:|---:|
| interpreter / io | 768.167 | 772.619 | 771.661 | +0.45% | -0.12% |
| interpreter / metadata | 159.924 | 160.727 | 161.603 | +1.05% | +0.55% |
| interpreter / pipe | 288.367 | 293.080 | 292.726 | +1.51% | -0.12% |
| hvf / io | 39.752 | 42.505 | 40.799 | +2.63% | -4.01% |
| hvf / metadata | 595.202 | 601.555 | 598.124 | +0.49% | -0.57% |
| hvf / pipe | 455.743 | 461.005 | 459.305 | +0.78% | -0.37% |


HVF IO improves **4.01% against the delivered cgroup version**, with all six paired blocks improving: −1.69%, −4.53%, −1.76%, −6.70%, −6.25%, −2.32%. Its median is **40.799 ms versus the pre-cgroup 39.752 ms (+2.63%)**. Paired differences against that older baseline have both signs (−1.65% to +11.45%); retain those observations rather than claim exact performance equivalence. Other workload medians are +0.45% to +1.51% against the pre-cgroup binary. This is a fixed synthetic workload, not a claim about all application latency.

## Evidence and delivery

Artifacts in the iPad repository: `target/validation-cgroup-closeout-20261127`; Linux test/Clippy records: `target/local-ci/io/cgroup-20261127/linux-closeout-*-v2*`. Source manifest `runtime-source-v2.json`, exact patch `candidate-v2.patch`, release runner SHA-256 manifests, `gvisor-audit-v2.json`, `combined-unit-audit.json` and `performance-v2/results.json` preserve identities and every sample. The first candidate and phase diagnostics remain alongside the final data. Each stage and exact unit test is bounded by a watchdog.

Runtime changes are limited to cache accounting/reuse and IO admission/completion. Delivery commits directly to main, then pairs both product Runtime pins; no unrelated allocator, debugger, storage, legal/security or Swift work is included.

Final independent phase diagnostic (same six orders, five samples per block): cold read 11.425 -> 9.733 ms (-14.81%) against 8bfc094; pre-cgroup read 8.514 ms. Write 19.081 / 19.395 / 19.218 ms and fsync 11.833 / 11.932 / 11.933 ms for pre-cgroup / 8bfc094 / closeout. These diagnostic runs are separate from the unchanged acceptance fixture above.
