# Inline JIT hardware memory — 2026-11-28

Scalar JIT accesses now use the existing host-MMU CPU aliases on eligible pages.
A cache hit computes the guest address, checks the full page tag/containment and
issues native LDR/STR while retaining host-register bindings. It does not enter
the Rust memory helper. The guest executable bytes remain unchanged. Slow paths,
canonical bytes and existing ownership/permissions remain shared with the
interpreter/native API. Architecture details and unsafe lifetime/fault contracts
are in [software execution](../architecture/software-execution.md#entry-scoped-hardware-aliases).

## Validated behavior

On the existing ARM64 Linux VM, release JIT tests passed **6 capability/native
unit tests + 36 differential tests**. New cases require actual inline hits and
cover scalar widths/sign extension, address forms/aliases, guest TBI, SP/base
writeback, live flags, private worker admission, immutable multi-View reads,
sparse high addresses, permissions, replacement and fork. A test embedding
revokes the real host alias protection after warm-up, exercising generated load
and store fault PCs and their local checked continuations without replay.
A regression assertion also verifies that the hardware-admission bit preserves
existing scalar/SVC tail cells.

Shared memory tests passed on Linux: **281 + 6 integration tests**, 3 existing
ignores; on Apple: **278 + 6 integration tests**, 3 existing ignores. Linux and
Apple scoped Clippy passed. Apple AArch64 iOS interpreter compilation and its
feature graph passed without JIT/native-code features. Execution-boundary checks
passed. Apple tests do not execute the optional JIT; native JIT runs here are
Linux/4 KiB. Android core interpreter/JIT probes passed on this Linux host.
The paired Android probe requires two real inline accesses through a complete
host protection group, preserving the existing JNI schema/flag ABI. Windows
packaging CI and real Android app-UID/ART/16 KiB execution are separate checks.

## Matched four-lane measurement

Environment: existing Lima/VZ ARM64 nested Linux/KVM VM, kernel
`7.0.0-44-generic`, actual host page size 4096, real `/dev/kvm` API 12 and SMCCC
forwarding; 6 vCPUs, workload pinned to virtual CPU 2. This is **nested KVM**,
not a bare-metal Linux host. Rust nightly 2026-10-16, release thin LTO, overflow
checks enabled, incremental disabled, existing build cache reused.

All four lanes use identical finite original guest bytes. Data is explicitly
made resident **before** View construction, then software uses existing unsafe
private-epoch admission with the sole actor/all mm roots owned by the harness.
No mapping, fork, clone or coordinator byte observation occurs until View drop.
KVM uses its normal hardware admission and 2 ms assignment behavior. Canonical
bytes are validated after all timed passes to avoid revoking KVM aliases between
samples. These results do not replace the earlier guarded/demand-populated
cohort or mix its samples into this cohort.

Eight balanced process-order rounds give each lane each position twice and
balance predecessor pairs. Each process has one warm-up and five timed samples
for each of six workloads: **32 processes, 960 timed + 192 warm-up samples**.
The table reports the median of eight process medians. Every software retirement
count, loop result/x0/PC, original instruction image and canonical final data is
checked. KVM exact retirement is unavailable and remains JSON null; known work
is not represented as an observed hardware counter.

| Workload | Old JIT | New JIT | Interpreter | Nested KVM |
|---|---:|---:|---:|---:|
| Integer loop, 262,144 × 33 instructions | 1.803 ms | 1.788 ms | 8.256 ms | 1.879 ms |
| Hot-page scalar loop, 65,536 iterations | 2.466 ms | 0.0888 ms | 1.388 ms | 0.0846 ms |
| Hot-page scalar loop, 1,048,576 iterations | 27.679 ms | 1.467 ms | 22.032 ms | 0.854 ms |
| 10,000 SVC-only + backbranch/returns | 0.0786 ms | 0.0720 ms | 0.1677 ms | 343.044 ms |
| 10,000 ADD/SVC + backbranch/returns | 0.0786 ms | 0.0721 ms | 0.1754 ms | 342.719 ms |
| 10,000 16-ADD/SVC + backbranch/returns | 0.0805 ms | 0.0742 ms | 0.2583 ms | 343.080 ms |

The large memory loop improves **18.87×** over old JIT and **15.02×** over this
interpreter cohort; its elapsed time is **1.72×** nested KVM. Inline counters are
12,582,804 / 12,582,912 accesses per process, **99.9991%**. The 65K loop has
786,420 / 786,432 hits, **99.9985%**, with time about 1.05× KVM. Integer timing
remains in the same range. Short SVC timing retains the previous fast path; it
simulates backend returns, excluding actual Linux syscall handlers/JNI/apps.

This is one repeatedly accessed, L1-hot data location. It establishes removal of
per-access helper cost, **not general application speed, streaming bandwidth or
native-equivalent performance**. The nested KVM large-loop process medians range
from 0.445 to 0.897 ms; new JIT ranges from 1.448 to 1.472 ms. Platform scheduling
and nested execution still limit comparisons.

A separate three-pair `worker` guarded control, with the same resident data but
no private admission, has zero inline hits and no fallback. Its 1M-loop medians
are old 30.190 ms and new 30.751 ms (~1.9% difference). Shared writable execution
retains the checked path and does not receive the private-page speedup. These
controls are separate from the four-lane table.

## Source and artifact audit

Old Runtime: `89c5abd57ce5cc8341f17fcea35a339b0f991595`. New Runtime: that base plus
the implementation in this commit. Linux transport source:
`9db947eba448b871f31ca06511c46430bfb35387`. Linux product pins/code are unchanged.
The isolated Linux measurement package is reused from the existing
`project-trames/trames-linux` `tools/cpu-backends` tool, with the complete
[benchmark patch](jit-hardware-memory-20261128/benchmark.patch). For the old lane,
replace the unavailable `memory.hardware` diagnostic with literal zero; all
measured guest code and setup are identical. No Android SDK or new VM was
installed on the Mac.

[Raw samples, summary, controller, source/binary hashes and audit](jit-hardware-memory-20261128/)
are frozen together. `receipt.json.gz` contains every compiled input hash, both
binary hashes and complete process orders. The offline audit rebuilds every
median, checks work/ordering/hits/retirement, rejects five corruptions and can
verify all 970 owning Runtime inputs:

```sh
python3 docs/validation/jit-hardware-memory-20261128/audit.py --runtime-source .
```

For reproduction, prepare two isolated Linux transport/tool source trees, use
Runtime base/new respectively, apply the benchmark patch, build release with the
recorded lockfiles and reuse a target cache. `cohort.py` records the binary/source
paths under `/mnt/trames-output`; adapt only those paths for another environment.
Do not install Android tools on the Mac. Temporary source trees and measurement
executables can be removed after preserving these artifacts.

## Remaining boundaries

Eligible protected aliases only: current shared writable/COW/provider/userfault
and async-memory cases retain their existing protocol. Larger host-page groups
must pass existing exact-permission/physical-contiguity eligibility; mixed 4 KiB
permissions and cross-page operands stay checked. Late pages without a published
CPU alias remain slow. SIMD/pairs/atomics keep existing lowering/fallback. Dynamic
fixup retirement is thread-affine and bounded. Actual Android non-debuggable
app-UID/ART signal-chain and 16 KiB device execution still require device tests;
Apple 16 KiB memory tests alone do not establish Android JIT acceptance.
