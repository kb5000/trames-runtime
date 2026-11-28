# Complete system-register and control category — 2026-11-28

This completes the entire shared-CPU system category in the
[coverage plan](../roadmap/native-jit-coverage.md): guest TLS/TLS2, FPCR/FPSR and
existing NZCV, read-only TLS/cache geometry, timer frequency/four counter aliases,
RNDR/RNDRRS, cache zero/maintenance, architectural barriers/hints, BRK/HLT and
native-call exits. No instruction in this admitted list enters the interpreter.
Unrecognized registers/reserved instructions keep precise guest faults. The
remaining SIMD/FP arithmetic, exclusives and special/compatibility categories
are still active; this checkpoint does not complete all native ISA work.

TLS and FP system accesses use existing CPU fields, with compile-time offsets
and whole-CPU raw provenance. No host TLS/TPIDR2, extra architectural state,
per-instruction capability checks, global synchronization, full-state copies or
guest-code modifications are introduced. FPCR/FPSR writes update guest storage
and hardware together, preserving the existing masks. Clearing guest FPSR stays
cleared after native return and provider callbacks. Existing host FP suspension,
protected aliases and precise recovery are reused. The chain frame remains
120 bytes and the scalar native ABI/node layout is unchanged.
[Implementation contract](../architecture/software-execution.md#native-system-register-and-control-category).

AArch64 Linux/Android interpreter and JIT now share actual user CNTVCT/CNTFRQ.
The test VM frequency is **24 MHz**, replacing the previous artificial 1-GHz
software counter on these platforms. Ordinary guest counter reads are direct
MRS without an added barrier; the synchronized aliases use ISB + CNTVCT.
Apple/iPad keep their portable 1-GHz counter and no software clock sampler.
The ordered backend sampler enables the existing common Linux vDSO calibration;
there is no per-read conversion or timer helper in JIT code. Arm describes
[self-synchronized counter semantics](https://support.arm.com/documentation/111107/2026-03/AArch64-Registers/CNTVCTSS-EL0--Counter-timer-Self-Synchronized-Virtual-Count-Register);
Linux's [arm64 trap ABI](https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/traps.c)
handles trapped user CNTFRQ/CNTVCT reads without a new userspace probe/handler.

DC ZVA writes exactly the guest's 64-byte aligned block using four zero-pair
stores, each with recovery metadata, and retires once. Host DC ZVA is not used
because host geometry can differ. Other supported cache operations only check
translation and retain the existing runtime instruction-epoch coherency. DMB,
DSB, ISB and admitted SB use the real instruction on hardware-ordering memory;
other embeddings use their existing fence callback. Architectural hints retain
the existing profile and permitted spurious WFx wakeups; PAC/BTI hints do not
enable authenticated branches, MTE, SVE or SME. Reached BRK/HLT uses cached typed
metadata, with current native-call flags/x16/x17 and original retirement/faults.

## Verification

ARM64 Linux: **14 unit/capability + 82 differential tests (96)** pass in Debug
and Release, along with strict all-target JIT/interpreter Clippy. Interpreter
**48+2+1** passes. Apple: **79 JIT fallback tests** and interpreter **48+2+1** pass;
scoped strict Clippy, iOS interpreter compilation and execution boundaries pass.
Prior unaffected host-compute and memory package results are reused.

Whole architectural state and canonical bytes match the reference at every
slice in the system/maintenance/trap matrices. Coverage includes TLS source and
sink aliases, raw restored FP bits/masks, live GPR/vector pressure, FPSR clearing,
host TLS/FP canaries, callback success/fault restoration, exact budgets/PCs,
read/write-inaccessible but translated maintenance addresses, write-only backing
with zero reads, the exact 64-byte footprint, unaligned address-proof separation,
DC ZVA hardware-fault recovery, all barrier options and supported hints,
RNDR/RNDRRS result/flags on the RNG-positive host, cached native-call opt-in
changes and code replacement. A native code assertion verifies that relaxed
counter reads do not acquire implicit ISB instructions.

Counter tests check architectural reads against ordered brackets, frequency and
monotonicity across four workers. A frozen integration fixture installs the
**actual common Linux vDSO image**, calibrates it from each software backend and
executes its clock_gettime code for clock IDs 1/4/6. Both JIT and interpreter
return zero, write a timespec inside the enclosing host-counter bracket and
return to a sentinel SVC; there is no timer syscall fallback in that path.

Android default/JIT core probes pass on Linux ARM64 and Apple, and scoped strict
Clippy plus feature isolation pass. The native category probe checks TLS/FP,
cache/barriers/hints, all counter aliases and cached native-call/trap behavior,
including original guest bytes and zero interpreter entry. JNI schema/flags are
unchanged. One existing diagnostic chunk iterator follows the pinned Clippy
spelling. Android SDK/NDK/JDK/APK builds remain on Windows CI; real app-UID/ART
and 16-KiB Android device acceptance remain unverified by these Linux/Apple runs.

## Matched CPU-only measurements

Baseline `76c662beea2aaa93f074506a2b7fd8972f0d7c3a`; candidate is that commit plus
the hashed category sources. Same Lima ARM64 Linux VM, 6 vCPUs/8 GiB, 4-KiB pages,
kernel 7.0.0-44-generic, rustc 1.101.0-nightly (4ebd25825), thin LTO and overflow
checks. No imposed CPU affinity or concurrent build runs during measurement.

Four balanced old/new and new/old pairs run six finite programs, each with one
warm-up and five timed samples: **8 processes, 240 timed + 48 warm-up samples**.
Each program executes 65,536 trips of 28 body operations plus SUBS/B.NE, followed
by SVC. After every sample, both variants execute the same independent interpreter
untimed and compare complete architectural state plus the entire 4-KiB canonical
data page. Frozen rows retain guest words, register/vector/TLS/FP results and
the affected data. There are no nondeterministic timer/random reads in this
cohort; counter-domain behavior is tested separately above.

| Program | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| cache-zero | 97.901 ms | 1.072 ms | 91.35× |
| fp-control | 0.948 ms | 0.935 ms | 1.01× |
| fp-status | 91.280 ms | 7.806 ms | 11.69× |
| hints | 75.156 ms | 0.031 ms | 2419.42× |
| integer-control | 0.402 ms | 0.420 ms | 0.96× |
| tls | 77.052 ms | 0.180 ms | 427.37× |

The new-category samples have zero fallback/staging; cache-zero records the
expected 28 memory instructions per trip. Hints are elided using the existing
guest semantics, so their large speedup is dispatch removal, not equivalent
active CPU work. FP status writes retain real hardware synchronization cost.
The integer control median is about 4.4% slower and FP control about 1.4% faster;
individual ranges overlap. These short control loops do not establish an
application-wide regression/speedup or native/KVM equivalence. The data is
reported without discarding the slower control samples.

[Frozen fixture, lockfiles, raw logs, hashes and audit](jit-system-20261128/)
can be checked offline with `python3 jit-system-20261128/audit.py [Runtime-root]`.
For reproduction, place the two source checkouts at `jit-system-base` and
`jit-system-source`, recreate sibling `jit-system-old`/`jit-system-new` packages
using the frozen manifests/lockfiles and `benchmark.rs` as `main.rs`; run their
release binaries in the receipt's alternating order. The vDSO fixture is a
separate sibling package with its frozen manifest/lockfile/source and the same
Runtime vendor overrides. SDK provisioning is not needed for these CPU checks.
