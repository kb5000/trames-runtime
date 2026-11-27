# JIT affine regions and address reuse — 2026-11-28

The hardware-memory path now retains a connected admitted region and fixed host
bias in native registers, avoiding indexed page lookup on a direct hit. Cold
register-definition proofs reuse a checked effective address within the block;
verified invariant first/last operands can carry that proof through a same-block
backedge. Guest system, original instructions and guest-visible pointer values
are unchanged. [Architecture and safety contracts](../architecture/software-execution.md#register-held-affine-regions).

## Scope and validation

No new guest/host arena, allocation policy, mapping or physical copy is added.
Regions contain only already exported adjacent/overlapping pages with a common
bias, within 1 MiB. Read/write blocks require prepared RW admission; read-only
blocks can use immutable pages. Helpers clear address proofs, refresh register
borrows and retain/clear existing page/region loans according to the same frozen
View contract. Holes, COW/shared writable/provider pages, permissions and mixed
larger-host-page groups retain the existing page/helper path. Cross-guest-page
accesses stay checked; a wider operand cannot reuse a smaller proof.

ARM64 Linux passed **7 native/capability + 38 differential tests** (45 total) in
release, plus strict all-target Clippy. Debug passed all differential/native cases, with the added ABI canary also
verified separately in the final Debug build; release covers the complete final suite. Added checks cover base/index/SP definition changes,
width/cross-page boundaries, connected read-only pages, holes, real host write
protection on a reused post-index address, newer NZCV and exact writeback/fault
state. A native ABI canary checks all five new callee-saved registers on epoch,
budget and normal helper returns; LLVM-reserved x19 is saved/restored manually
inside that test asm. Existing tests retain exact budget, invalidation, fork,
independent RMW and host-extension behavior.

Apple scoped compilation/Clippy, iOS interpreter compilation/feature graph and
execution-boundary checks pass. The iPad graph still contains no JIT/native-code
feature. Shared memory implementation/platform code is unchanged (only the loan
contract's metadata-observation documentation is clarified), so preceding Linux
281+6 and Apple 278+6 memory-test results are reused. Apple does not execute the
optional JIT. Paired Android core JIT/interpreter tests pass on Linux; Mac core,
compile-time feature and dependency-notice checks pass. The strengthened existing
probe requires two actual direct accesses and at least one compiled address reuse
site, keeping schema 1 / 40-byte JNI and flag bit 6. No Android toolchain was
installed on Mac. Windows packaging and real app-UID/ART/16 KiB device execution
are separate acceptance lanes.

## Matched measurement

Baseline Runtime is the preceding hardware-alias implementation
`a96bacdc9f8ad3a49555108e6efa95817d87403b`; candidate is that base plus this commit's
implementation. Both use Linux transport source
`9db947eba448b871f31ca06511c46430bfb35387` in isolated measurement trees. Linux
product Runtime pin/code remain unchanged. The same release binary provides
candidate JIT/interpreter/KVM; the preceding JIT binary uses the same fixture and
setup. Candidate-only direct/reuse diagnostics use literal zero in the old
fixture because the fields did not exist there.

Environment: existing Lima/VZ nested ARM64 VM, kernel `7.0.0-44-generic`, actual
4096-byte pages, 6 vCPUs, pinned virtual CPU 2, real KVM API 12/SMCCC. Rust nightly
2026-10-16, release thin LTO/overflow checks, no incremental compilation. This is
nested KVM, not bare-metal Linux or Android device performance.

Both software backends use the existing resident/private worker admission with
all mm roots and the sole View held by the harness. Data is materialized before
View creation; no coordinator byte observation, fork, clone or mapping mutation
occurs until timing completes. KVM retains normal hardware admission/2 ms
assignments. Original code, canonical bytes, x0/x1/PC and all software retirement
counts are checked. KVM has no exact retirement counter and reports JSON null.
Short SVC cases simulate backend returns without real Linux syscall handlers.

Eight balanced four-lane orders give each lane each position twice and balance
predecessors. Each process has one warm-up and five timed samples for all seven
workloads: **32 processes, 1,120 timed + 224 warm-up samples**. Reported values are
the median of eight process medians. The new streaming case loads/increments/
stores every 8-byte element of a 512 KiB array, resets its guest base each sample,
and checks every canonical word plus a full-byte checksum after timing.

| Workload | Previous JIT | Affine JIT | Interpreter | Nested KVM |
|---|---:|---:|---:|---:|
| Integer loop, 262,144 × 33 instructions | 1.791 ms | 1.790 ms | 8.394 ms | 1.927 ms |
| Hot location, 65,536 iterations | 87.860 µs | 68.693 µs | 1.394 ms | 84.360 µs |
| Hot location, 1,048,576 iterations | 1.489 ms | 1.214 ms | 21.868 ms | 0.736 ms |
| Sequential 512 KiB / 65,536 elements | 100.216 µs | 92.465 µs | 1.365 ms | 51.545 µs |
| 10,000 SVC + backbranch/returns | 74.859 µs | 69.859 µs | 167.720 µs | 342.281 ms |
| 10,000 ADD/SVC + backbranch/returns | 74.213 µs | 70.922 µs | 175.845 µs | 342.363 ms |
| 10,000 16-ADD/SVC + backbranch/returns | 76.401 µs | 73.130 µs | 263.227 µs | 341.967 ms |

The 1M hot-loop elapsed time falls **18.49%** (1.227x speedup), and sequential
512 KiB falls **7.73%** (1.084x). The 65K hot loop falls **21.82%**. Integer timing
is effectively unchanged; short SVC medians do not regress in this cohort. Do not
splice prior cohorts into this comparison or infer general native/KVM equivalence.
The 1M candidate remains about 1.65x this nested KVM elapsed time; KVM process
medians span 0.513–0.866 ms, candidate 1.171–1.267 ms. Short-hot candidate ranges
also vary (55.004–87.256 µs), so one median beating KVM is not a general ranking.

Actual candidate direct counts per process are 786,420 / 786,432 memory operations
for hot-65K; 12,582,804 / 12,582,912 for hot-1M; and 784,896 / 786,432 for streaming
512 KiB. These are hardware accesses without indexed lookup, not estimates from
compiled site counts. Streaming performs checked first-write admission as each
page is reached. Address reuse-site counts are respectively 2, 4 (including budget
prefix variants) and 1; the stream changes its base and does not get the invariant
backedge proof. Staging and interpreter fallback are zero in every JIT sample.

## Reproduction and audit

[All raw records, summary, controller, fixture patches and source/binary hashes](jit-affine-memory-20261128/)
are frozen. Apply `benchmark-new.patch` / `benchmark-old.patch` to the existing
Linux `tools/cpu-backends` fixture, using the respective Runtime sources. Build
release with the recorded locks in two isolated Linux source trees, reusing an
existing target cache. `cohort.py` records exact source/binary paths under
`/mnt/trames-output`; adapt only those paths elsewhere. The 512 KiB case is added
to both fixtures, not inferred from the earlier single-location loop.

The offline audit checks all work/state/checksum identities and medians, balanced
positions, exact-vs-unavailable retirement, direct/total counters and six corrupted
negative cases. It optionally verifies every one of 970 owning Runtime inputs:

```sh
python3 docs/validation/jit-affine-memory-20261128/audit.py --runtime-source .
```

Task-owned source copies, measurement executables and the local Mac build cache
are cleaned after freezing evidence; shared dependency caches remain. This batch
uses one current affine region and static register definitions, not whole-program
pointer analysis. Noncontiguous regions continue through the page cache, wider/
cross-page accesses through canonical staging, and shared-memory/SIMD/atomic
boundaries retain their existing contracts. No whole-guest address reservation or
unrestricted `guest VA == host VA` assumption is introduced.
