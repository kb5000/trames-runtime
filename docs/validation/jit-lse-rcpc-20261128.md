# Native LSE / RCpc JIT — 2026-11-28

CAS/CASP, SWP, LDADD/LDCLR/LDEOR/LDSET, signed/unsigned min/max, their B/H/W/X
and ordering/store-alias forms now emit the original host LSE instruction.
LDAPR and unscaled LDAPUR/STLUR/signed loads use real RCpc instructions. HWCAP
admission stays in cold translation; absent extensions fault instead of gaining
software support. No guest code rewrite, software CAS loop, hot alignment
preflight, ordinary-memory fence, global lock or new extension state is added.
[Architecture and custody contracts](../architecture/software-execution.md#native-lse-and-rcpc).

Private alias hits retain existing hardware protection and address proofs.
Guarded shared workers reuse their existing object transaction over actual
canonical bytes. Exceptional backing providers retain their established staged
transaction, with ordering around the real read/publication. The shared memory
hook is enabled only by `native-code`. Failed CAS write intent may conservatively
invalidate a reservation/prepare COW; no extra software success preflight is used.

A cold allocator bug found by the new pressure matrix is fixed: empty register
slots must honor the same reserved-register exclusion as occupied slots. This
adds no execution check. CASP uses fixed even host pairs, remains one atomic
instruction and preserves host x18/TLS, callee state, NZCV and precise recovery.

## Validation

ARM64 Linux: **9 unit/capability + 48 differential tests (57)** pass in Debug and
Release, plus strict all-target scoped Clippy. Cases cover all LSE operations,
widths and four ordering variants, CAS/CASP success/failure and aliases, high
register pressure, signed/unscaled RCpc, tagged/misaligned/unmapped addresses,
write-before-read permission fault ordering, exact budgets, native alias loops,
code invalidation and guest exclusive-reservation invalidation. Generated-code
checks verify one original LSE/RCpc opcode and legal even CASP register pairs.
Forced hardware protection faults recover scalar/pair/ordered/LSE/CASP state
without prefix replay. Two concurrent guest LDADD workers produce all 8,192
increments with the expected aggregate returned-old-value sum, zero fallback and
zero staging, using the existing shared region mechanism.

Memory with `native-code`: Linux **282+6 pass / 3 ignored**, Apple **279+6 pass /
3 ignored**. Apple fallback differential tests pass (47 cases, including native
cases that return early); Apple does not execute the JIT. Apple/Linux scoped
Clippy, formatting, execution-boundary checks and iOS memory/interpreter builds
pass. The iOS interpreter graph contains neither JIT nor `native-code`.

Android core interpreter/JIT probes pass on Linux ARM64 and Apple; feature and
notice checks pass. The existing memory probe now tests only extensions present
in the process-host ABI. On this VM it requires 32 guest instructions / 17 memory
instructions / 15 hardware+direct accesses, zero fallback/staging, final canonical
value 49 and unchanged guest code. JNI schema 1, 40-byte layout and flags are
unchanged. SDK/NDK/JDK remain on Windows CI. Real Android app-UID/ART/16 KiB
device execution is a distinct lane, not established by these Linux/Mac tests.

## Matched measurement

Baseline Runtime: `d178606df13cef13b49e5ed5903eac8d2aed6d0c`; candidate: that base
plus this implementation. The same finite CPU fixture runs both release binaries
in the existing Lima ARM64 VM: Linux `7.0.0-44-generic`, 4 KiB pages, 6 vCPUs,
HWCAP `0xefb3ffff`, HWCAP2 `0x2000100326181`, rustc
`1.101.0-nightly (4ebd25825 2026-10-15)`. Thin LTO, overflow checks, no incremental
compilation and no imposed CPU affinity. No KVM/native comparison is made here.

A sole resident private View is materialized before timing. Four paired orders
alternate old/new and new/old. Eight processes each execute all 15 workloads,
one warm-up plus five timed samples: **600 timed + 120 warm-up samples**. Values
are medians of four process medians. Identical guest bytes/work/retirement,
registers, canonical bytes, the CASP second element and code immutability are
checked. Short SVC cases simulate returned values rather than real Linux syscall
handlers. New loops have zero interpreter fallback/staging and >99% of memory
operations counted as actual hardware/direct accesses.

| 1,048,576 iterations | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| LDADD + increment returned value | 73.716 ms | 1.546 ms | 47.69× |
| CAS update | 81.258 ms | 1.472 ms | 55.21× |
| LDP + CASP update | 163.755 ms | 3.660 ms | 44.74× |
| LDAPR/ADD/STLR | 136.312 ms | 1.484 ms | 91.83× |
| LDAPUR/ADD/STLUR | 134.998 ms | 1.491 ms | 90.51× |
| Existing scalar LDR/ADD/STR control | 1.262 ms | 1.257 ms | 1.00× |

Large improvements remove fallback crossings in these specific loops. They are
not whole-application speedups or equivalence to hardware virtualization. The
ten existing control medians move between −2.54% and +1.58%; this cohort does not
establish a general improvement/regression for those paths.

[All raw results, fixture/lockfile, source/build receipt, test logs and summary](jit-lse-rcpc-20261128/)
are retained. Run `python3 jit-lse-rcpc-20261128/audit.py` here to validate hashes,
matched work/retirement/native counters and recompute every result; optionally
pass the candidate Runtime directory to verify the source hashes. No VM image,
rootfs, SDK or temporary build cache is committed.

FP/NEON native register/context lowering and LDXR/STXR/LDXP/STXP reservation
execution remain future work. The latter cannot be replaced by independent
ordinary accesses or a reservation that silently expires at each helper call.
