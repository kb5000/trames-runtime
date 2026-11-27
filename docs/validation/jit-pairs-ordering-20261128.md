# Native paired/ordered JIT memory — 2026-11-28

Integer LDP/STP W/X, LDPSW, LDNP/STNP, LDAR/STLR B/H/W/X and valid DMB/DSB
options / ISB SY now lower to their corresponding host instructions. They reuse
the protected alias, affine region and cold address-definition proofs. No guest
code patching, software extension state, new algorithm/global locks or ordinary
memory fences are introduced. There is no new software alignment preflight on
native hits; hardware retains its original behavior. Existing guest-page custody,
checked recovery, COW/provider and mapping boundaries stay in force.
[Detailed contracts](../architecture/software-execution.md#paired-and-ordered-native-memory).

## Verification

ARM64 Linux passes **8 unit/capability + 42 differential tests (50)** in Debug
and Release. The final expansion of the write-only provider case passes as a
scoped rerun. Tests cover W/X/sign-extending/non-temporal pairs, offset/pre/post,
SP/ZR and source/destination aliases, tagged and cross-page addresses, exact
slice retirement and writeback, permissions, live NZCV, native alias loops,
registered hardware protection faults and precise recovery without replay.
Generated-code checks verify a single pair/ordered host opcode and unchanged
barrier options. A concurrent guest STLR/LDAR data/flag/ack handshake passes
against the same canonical shared bytes; it adds no production synchronization.
Full-overwrite scalar/pair/release stores do not read old write-only provider
bytes. Unrepresentable provider pointers retain bounded aligned staging.

Strict scoped all-target Clippy passes on Linux and Apple. Memory tests with
`native-code`: Linux **282+6 pass / 3 ignored**, Apple **279+6 pass / 3 ignored**.
Apple fallback differential tests pass; Apple does not execute this JIT. iOS
memory/interpreter compilation passes and its feature graph excludes JIT and
`native-code`. Default interpreter builds keep all ordered hooks gated out.

Paired Android core interpreter/JIT probes pass on ARM64 Linux and Apple; the
strengthened memory probe requires scalar + paired + ordered + barrier execution,
eight memory instructions, six real hardware/direct hits, zero fallback/staging,
correct canonical bytes and unchanged guest code. Schema 1 / 40-byte JNI / flags
are unchanged. Compile-time dependency isolation passes. Android packaging runs
on the existing Windows CI; real Android app-UID/ART/16 KiB device execution is
a separate acceptance lane, not implied by these Linux/Mac checks.

## Matched measurement

Baseline: Runtime `1fa3f082b0760fae0a836a4b466cf5c15047febb`; candidate: that
base plus this implementation. The identical isolated CPU fixture runs both
release binaries in the existing ARM64 Lima VM: Linux `7.0.0-44-generic`, actual
4 KiB pages, 6 vCPUs, rustc `1.101.0-nightly (4ebd25825 2026-10-15)`, thin LTO /
overflow checks / no incremental compilation. No CPU affinity is imposed this
cohort. No KVM or native baseline is measured in this batch.

The harness uses a sole resident private worker View, materialized before timing.
Four pairs alternate old/new and new/old process order. Each process runs all ten
workloads, one warm-up and five timed samples each: **8 processes, 400 timed +
80 warm-up samples**. Values below are medians of four process medians. Guest
words/work/retirement, final registers/canonical bytes and code immutability are
checked; the pair's second element is also checked. Short SVC cases measure CPU
exit/resumption with simulated returns, not Linux syscall handlers.

| Workload | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| LDP/ADD/STP, 1,048,576 iterations | 90.365 ms | 1.511 ms | 59.82× |
| LDAR/ADD/STLR, 1,048,576 iterations | 140.182 ms | 1.498 ms | 93.59× |
| LDR/DMB ISH/ADD/STR, 65,536 iterations | 12.366 ms | 0.149 ms | 82.82× |
| Scalar LDR/ADD/STR control, 1,048,576 iterations | 1.263 ms | 1.222 ms | 1.03× |
| Sequential 512 KiB control | 93.167 µs | 93.146 µs | 1.00× |

Large gains remove per-instruction fallback crossings in these specific loops.
New samples have zero interpreter fallback/staging, with over 99% of memory
instructions on the actual hardware/direct path. They do not imply a whole
application speedup or equivalence with KVM/native performance. Integer/scalar/
SVC control medians move between −3.21% and +2.77%; this small cohort cannot
establish a general improvement or regression for those unchanged paths.

[All eight raw JSONLs, fixture, source/build hashes and summary](jit-pairs-ordering-20261128/)
are retained. Run `python3 jit-pairs-ordering-20261128/audit.py` from this directory
to check hashes, identical paired work, retirement, native/direct counters and
recompute every value. Passing the candidate Runtime directory also checks the
frozen Rust/Cargo source hashes. The artifact contains no VM disk or rootfs.
