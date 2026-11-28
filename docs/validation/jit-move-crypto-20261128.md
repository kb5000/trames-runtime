# Complete SIMD movement and crypto categories — 2026-11-28

This batch completes two categories from the [category plan](../roadmap/native-jit-coverage.md):

- SIMD copy/immediate/permute: scalar/vector DUP, INS from GPR/vector, UMOV/SMOV,
  MOV/MVN aliases, MOVI/MVNI/ORR/BIC modified immediates, vector FMOV immediates
  including host-admitted half, EXT, one-to-four-register TBL/TBX, ZIP/UZP/TRN,
  REV16/32/64 and the existing RBIT/NOT/scalar FMOV paths.
- Stateless crypto: AES rounds/mix/inverse, P8/P64 PMULL/PMULL2, SHA1/SHA256,
  SHA512, SHA3 EOR3/BCAX/RAX1/XAR, SM3 and SM4 round/schedule/indexed forms.

Cold forms preserve destructive destinations and immediate/index bits. TBL/TBX
use the existing consecutive-group allocator with wrapped guest lists, pinned
tables and index operands. TBX/INS/logical-immediate operations read the old
destination before writing it. Pin masks now distinguish actual vector operands
from unused fields and GPR XZR, preserving the usable host vector bank under
pressure. Execution uses original instructions and existing CPU banks; it adds
no software permutation, extension state, per-instruction capability branch,
full-state copy or guest-text rewrite. [Implementation](../architecture/software-execution.md#simd-movement-and-stateless-crypto-categories).

The shared interpreter now ignores low INS source-index bits as the architecture
specifies, removing its old rejection. This follows Arm's
[copy and permute definitions](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85),
including DUP general's ignored selector bits and insertion's preserved lanes.

Optional native crypto and half forms have cold ISA gates. Untranslated
JSCVT/BF16/FHM/FCMA/DotProd/I8MM/RDM/FP16/FRINT32/64 and SB also check the host
before interpreter entry; FCMA half requires both FCMA and AdvSIMD FP16. LS64
is rejected instead of being mistaken for LSE or reaching the software block
transaction: this profile does not own its HWCAP3/device-memory contract.
[Linux HWCAP definitions](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/hwcap.h)
and [LS64 memory requirements](https://www.kernel.org/doc/html/v7.0/arch/arm64/elf_hwcaps.html)
describe that distinction. These cold gates do not imply that all present-host
untranslated families already have native lowering, and do not change the
interpreter-only backend's compatibility policy.

## Verification

ARM64 Linux: **13 unit/capability + 74 differential tests (87)** pass in Debug
and Release; strict all-target JIT/interpreter Clippy passes. Apple: **71 JIT
fallback tests** and interpreter **48+2+1** pass; scoped strict Clippy, iOS
interpreter compilation, dependency feature isolation and execution boundaries
pass. Linux interpreter **48+2+1** passes. Host-compute and memory implementation
are unchanged; prior validation is reused for those packages.

Matrices exercise all copy sizes/lanes/ignored selector bits, immediate modes,
Q widths, source/destination/GPR aliases, real V31, reverse/zip/unzip/transpose,
all table lengths and wrapped starts, in/out-of-range indices, table/index/old
destination overlaps, exact budgets, dirty-register pressure, checked-memory
callback reloads and dynamic branch targets. Whole architectural state and
canonical memory match the reference at every slice. Crypto covers all forms,
rotation/lane immediates, destructive accumulators and aliases where admitted
by the real host; missing extensions fault at the reached PC with the exact
retired prefix, unchanged vectors and zero interpreter fallback.

The VM advertises AES/PMULL/SHA1/SHA2/SHA3/SHA512, so those run as real native
instructions. SM3/SM4 are absent: their native decoder/lowering is implemented,
and mock-capability admission plus actual-host negative paths are verified;
positive SM3/SM4 hardware execution remains unverified until suitable hardware
is available. This is distinct from completing their implementation coverage.

Android default/JIT core probes pass on Linux ARM64 and Apple. The added category
probe covers copy/permute/immediate/table operations and every crypto form admitted
by the process host, compares complete state to an independent interpreter and
requires exact retirement, zero fallback, one native entry and unchanged guest
code. JNI schema/flags remain unchanged. Android SDK/NDK/JDK/APK work stays on
Windows CI; real app-UID/ART/16-KiB-device acceptance remains outstanding.

## Matched CPU-only measurements

Baseline `f66050968f3433d89698e87bf7d3d477f28e38b7`; candidate is that base plus
the hashed sources. Same Lima ARM64 Linux VM, kernel `7.0.0-44-generic`, 4-KiB
pages, 6 vCPUs, rustc `1.101.0-nightly (4ebd25825 2026-10-15)`, thin LTO,
overflow checks and no incremental compilation or imposed affinity.

Four pairs alternate old/new and new/old. All six programs run in each process,
with one warm-up and five timed samples: **8 processes, 240 timed and 48 warm-up
samples**. Each program executes 65,536 iterations of 28 body operations and
SUBS/B.NE, then SVC. After every timed sample, a separate interpreter executes
the same program untimed and checks the entire architectural state. Both builds
perform identical reference work. Original instruction bytes remain unchanged.
The table gives medians of four process medians.

| Program | Previous JIT | New JIT | Speedup |
|---|---:|---:|---:|
| EXT / REV / ZIP / TBL / TBX | 159.032 ms | 0.856 ms | 185.70× |
| DUP / INS / UMOV / modified immediates | 146.035 ms | 0.213 ms | 685.19× |
| AES round / mix chain | 81.068 ms | 0.325 ms | 249.07× |
| SHA3 EOR3 / BCAX / RAX1 / XAR | 84.595 ms | 0.900 ms | 94.03× |
| Integer control | 0.407 ms | 0.414 ms | 0.98× |
| Scalar FP control | 0.935 ms | 0.939 ms | 1.00× |

New programs have zero interpreter fallback/staging and no guest memory
instructions, with two native entries per sample for the added categories.
The preceding interpreter crypto helpers could already use host arithmetic;
this optimization removes per-instruction dispatch/marshalling and retains
registers through whole native loops. These are specific CPU programs, not
application or KVM/native equivalence claims. Control variation is +1.84% and
+0.48%; it does not establish a general speedup in unchanged instructions.

[Frozen fixture/lockfiles, raw samples, source/binary hashes and test logs](jit-move-crypto-20261128/)
are retained. Run `python3 jit-move-crypto-20261128/audit.py` to verify evidence
and recompute the cohort; an optional Runtime path checks candidate source hashes.
Temporary VM sources/build artifacts are cleaned after publication. Remaining
categories stay active in the plan; this checkpoint does not finish all ISA work.
