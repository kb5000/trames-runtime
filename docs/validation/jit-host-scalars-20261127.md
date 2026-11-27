# Host-driven scalar JIT — 2026-11-27

The conditional countdown that previously spent about 7.6 times KVM's time now
has zero interpreter fallback and runs in the same range as KVM on this VM.
The implementation follows the owner's host-ISA requirement: supported optional
extensions emit host opcodes; absent extensions do not gain software replacements
or new emulated extension state. Full host-ISA native coverage is still open.

## Implemented scope

- Baseline ADD/SUB including SP, shifted/extended forms and flags; AND(S)/ORR/EOR,
  logical immediates; MOV/ADR; carry arithmetic; CSEL family and CCMP/CCMN;
  bitfield/EXTR; multiply/add, long/high multiply, divide; variable shifts and
  RBIT/REV/CLZ/CLS; direct B/BL, CBZ/CBNZ, TBZ/TBNZ, B.cond and BR/BLR/RET.
- CRC32/CRC32C, FlagM/FlagM2 and CSSC have direct host-opcode lowerings and cold
  host capability checks. The actual VM has CRC/FlagM/FlagM2, and lacks CSSC.
  CSSC negative execution is verified; positive hardware execution awaits a
  supporting host. No SWAR, software CRC or synthesized FlagM replacement ships.
- Immutable process-host capabilities are read once. Native guest capability
  advertisement is host capabilities intersected with the existing shared ABI,
  rather than the interpreter's complete virtual capability list. Raw host masks
  remain separately available. New extension-family gates run during translation.
- The 120-byte native ABI adds only link-PC metadata and temporary SP/NZCV values
  for existing task state. No additional persistent register bank or extension
  model is introduced. Host x18/TLS, SP, callee-saved registers and FP state remain
  untouched. No new guest memory policy, lock, barrier or coordinator is added.
- Dynamic native edges compare the selected guest PC with the checked cached
  target before following a host code pointer. Exact budgets, code epochs,
  permission checks, generations and RX revocation retain their original gates.

## Controlled performance cohort

Existing ARM64 Lima/VZ nested-KVM VM, real 4096-byte pages, vCPU 2, release thin
LTO, `nightly-2026-10-16`, incremental disabled. Each lane has one warm-up and
five measured samples, alternating lane order. Integer units are actual ADDs.
Each sample completes exactly 32,505,856 ADDs with SUB/CBNZ and a terminal SVC.
The only paired benchmark source change is its post-timing assertion: the new
JIT must have zero countdown fallback. The original guest work is identical.

Times are milliseconds per one million ADDs (median):

| Pair | Old JIT | New JIT | KVM before | KVM after | JIT improvement |
| --- | ---: | ---: | ---: | ---: | ---: |
| SMCCC | 1.691 | 0.215 | 0.224 | 0.224 | 7.88x |
| MMIO | 1.702 | 0.216 | 0.225 | 0.224 | 7.89x |

The small new-JIT/KVM difference is not a general performance ranking. New JIT
retains 6,291,208 native links across the six samples with zero fallback; the old
JIT executes 6,291,456 fallback CBNZs. Neither lane executes a Linux syscall
handler. These CPU-only nested-VM numbers do not establish full syscall,
application, bare-metal or Android-device performance.

Both controlled runners use Runtime base `eefc3b2`; only JIT differs. After this
frozen cohort, integration fast-forwards the independent published perf commit
`10dcf23`. The JIT source hashes are retained; integrated source has separate
functional/Clippy checks. Frozen samples are not relabelled as post-integration
measurements. KVM crate source is Linux `9db947e`, as in the earlier comparison.

[Raw before/after samples](jit-host-scalars-20261127/),
[derived medians](jit-host-scalars-20261127/summary.json),
[source/build receipt](jit-host-scalars-20261127/receipt.json) and the exact paired
benchmark source retain all 48 executions (40 measured), warm-ups, checksums,
counts and binary fingerprints. Raw normalized arithmetic and medians are audited.
The expanded `cpu-boundary` example also continuously measures both CBNZ and
SUBS/B.NE countdowns and requires zero fallback.

## Verification

- Actual ARM64 Linux: four ABI/cache/capability tests plus 22 differential tests
  pass. Corpus includes the existing 2,048 encodings, 4,096 extra alias/long-product
  encodings, all 16 NZCV values and conditions, SP/ZR aliases, overflow, zero
  divisors, precise budgets, link/restart/eviction and self-modifying-code guards.
- CRC/FlagM/FlagM2 execute real host opcodes. Missing CSSC produces exact reached-PC
  SIGILL with correct prior retirement and zero fallback. Host profile tests reject
  software-only capability advertisement and unowned stateful-extension promises.
- Strict JIT all-target/all-feature Clippy passes on ARM64 Linux and macOS.
  macOS runs the 22 non-native differential tests through the unchanged fallback.
- The integrated `10dcf23` source repeats these scoped checks, plus the Android
  core probe on actual ARM64. No full Linux/network/graphics suite is rerun.
- Android probe adds flag bit 5 for a linked SUBS/B.NE countdown, its exact 53
  retired instructions and final NZCV. The JNI schema/size remains 1/40 bytes;
  original initial-probe counters remain unchanged. Instrumentation requires bit 5.
  Default interpreter/JIT builds and compile-time feature isolation pass.

Real Android app-UID/device execution remains unverified locally; SDK/NDK/APK
builds run only in the existing Windows CI, not on the Mac.

## Remaining native coverage

Checked memory, atomics, FP/NEON, crypto/vector extensions and other untranslated
families still use the legacy interpreter path. Their replacement must preserve
Runtime memory/concurrency semantics while using host-supported instructions.
Stateful SVE/SME and pointer/tag protection require real state/ABI ownership before
advertisement; do not add a parallel software extension model. This batch does
not claim complete native coverage or remove the correctness fallback globally.

Primary interfaces: [Linux ARM64 HWCAP](https://www.kernel.org/doc/html/latest/arch/arm64/elf_hwcaps.html)
and [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).
