# Native special-memory category — 2026-11-28

Baseline Runtime `f595ae2a78e81a316fb842dd093c8c5c1eee005a`, paired Android
`cf631789e28e3f819ffdb23f57849d956ca2d232`. This closes the current shared-CPU
special-memory list under explicit host admission. It does not advertise an
unowned extension merely because the interpreter has a software implementation.

| Family | Native list and admission |
|---|---|
| MOPS | All 16 CPYF and 16 CPY option combinations, all 4 SET combinations, each P/M/E stage: 108 forms. Requires process HWCAP2 MOPS. |
| LSE128 | SWPP, LDCLRP, LDSETP, all four acquire/release combinations, independent in/out registers and SP/aliased bases. Requires HWCAP2 LSE128. |
| LOR | LDLAR/STLLR B/H/W/X retain their real opcodes; admission uses the system-wide safe CPUID ABI, never a physical-core assumption or LDAR/STLR substitution. Hidden/absent LO fields decline. |
| LS64 | Rejected: this CPU profile owns neither HWCAP3 nor the required Device-memory endpoint/ACCDATA contract. |
| MOPS SETG | Rejected: MTE allocation-tag ownership is not advertised. It is not changed into an untagged SET or tag-zero software fill. |

The independent LLVM 18 [assembly](jit-special-memory-20261128/category.S) and
[words](jit-special-memory-20261128/category.words) contain **548 encodings**:
432 MOPS, 72 LSE128, 32 LOR and 12 rejected LS64, including high/zero registers,
SP and legal address/data aliases. Reassemble with
`python3 scripts/audit-jit-special-memory.py --llvm-mc llvm-mc-18`.

## Native execution and memory

Capability, reserved-encoding, register allocation and stage-group decisions are
cold cache-compilation work. MOPS uses a single temporary operand frame, containing
the existing D/S/N/NZCV values and fault metadata. Only the actual CPU chooses its
algorithm and updates progress; compile-time size/offset assertions enforce the
native frame ABI without runtime checks. There is no second task extension state, software
copy/RMW algorithm, full CPU copy, guest-text rewrite or host TLS/x18 change.

Linux's [MOPS ABI](https://docs.kernel.org/arch/arm64/mops.html) requires adjacent
P/M/E opcodes so a kernel mismatch/migration handler can restart P. All emitted
entries share that consecutive sequence. A separately reached M/E entry skips
the preceding opcodes normally, while retaining them for the kernel. Cached
groups obey the exact instruction budget. Partial current-stage progress stays
in the original GPR/NZCV banks; cooperative returns do not retire an unfinished
instruction. Real migration between differing hardware implementations remains
an outstanding hardware acceptance item.

Complete resident private ranges up to 64 KiB use the original protected CPU
aliases directly, with no mmap, byte snapshot or provider call. Larger/private
operands clone admitted canonical aliases in bounded granule-rounded segments.
The slow operand arena reserves the whole remaining range plus guards; overlap
uses one common address bias, while disjoint operands can use independent biases.
It shares the original **32-GiB MMU VA ceiling** and fault-window registry rather
than adding a quota, service thread or polling loop. Capacity failure remains a
Memory limit error; a full-span reservation has a VA cost even when its pages
are inaccessible/nonresident. Chunking bounds active work near 64 KiB, rounded
to actual host granules, without synthesizing CPU progress or changing N.

Unknown embeddings explicitly decline multi-page loans. Shared/opaque/backed or
unrepresentable 4-KiB permission groups retain the original checked per-page byte
transport and publication, with the real MOPS opcode operating in protected
staging VA. Only the hardware-completed destination prefix is written back. A
failed publication restores the first unpublished instruction checkpoint. Read
and write fault paths retain the original Memory errors. Source-only reads keep
reservation tokens; writes join the original dirty/version/ABA domain. No global
or algorithm lock is added. Unsuitable CPYF overlap retains the original checked
page-snapshot transport; CPY is the overlap-safe move operation.

Reset replaces aliases with inaccessible anonymous mappings before any provider
call, slice exit or syscall, releasing physical owners as well as permissions.
The common Linux/Android/Apple alias primitive is reused. Signal recovery is
restricted to an exact registered PC and owned CPU VA, and can deliver FAR and
optional read/write ESR information through reserved caller-saved registers.
It uses no TLS, allocation, lock or unwinding in the handler. Linux's public
[signal-context ABI](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/sigcontext.h)
defines the optional ESR record; other contexts keep their original platform cfg.
The ARM64-only parser is omitted from amd64 production compilation.

LSE128 uses actual native pair RMW instructions through the original
`cpu_atomic_chunk` transaction, including alignment, COW, release/acquire and
reservation publication. Both input registers independently receive the old
values. Capability gates are process-wide OS data, read once. The Linux
[HWCAP ABI](https://docs.kernel.org/arch/arm64/elf_hwcaps.html) and
[safe CPUID ABI](https://docs.kernel.org/arch/arm64/cpu-feature-registers.html)
remain the authority; no software-only capability is added.

## Acceptance and limits

- Actual ARM64 Linux, 4-KiB host: **26 unit + 105 differential JIT tests (131)**
  pass in Debug and Release. This host exposes no MOPS, LSE128 or usable LOR;
  their missing-capability paths fault at the reached PC without emulation.
- Final memory suites: Linux **287 unit + 2 metadata + 4 translation** and
  Apple **283 + 2 + 4** pass, with 3 existing ignored units on each. The final
  signal change retains static-recovery priority: recognized original MMU sites
  do not scan the dynamic native-site table. The full memory suites and affected
  native MOPS fault paths are rerun for this change.
- Apple: **100 JIT fallback tests**, scoped all-target strict Clippy, default
  iOS interpreter compilation, and Android core default/JIT probes pass. Both
  the prototype interpreter and actual iPad dependency trees contain neither
  JIT nor `native-code`. No iPad source or Runtime pin was modified.
- Linux and Apple strict scoped Clippy passes. amd64 cross-checks cover both
  the native-code memory feature and the JIT crate's compile-time fallback path;
  they are compile/lint checks, not x86 native JIT execution.
- Independent MOPS-positive model: **QEMU 10.0.13**, Option A, runs the 6 MOPS
  unit/fragment tests, 7 MOPS integration tests and 2 optional-contract tests.
  Capability-dependent branches are explicit: LSE128-positive and MOPS-absent
  branches do not execute in this model. It provides no LSE128/LOR execution.
- The whole-state/data/retirement matrix includes 36 option combinations,
  serial/guarded/private epochs, low/high registers, three budgets, forward and
  backward overlap, zero fill, long cooperative progress, independent top-byte
  tags, zero length with unmapped pointers, missing/protected pages, original
  reservation invalidation, and real revoked-alias recovery. The opaque-memory
  tests separately exercise **4/16/64-KiB guard layouts** for 4-KiB guest pages
  and failed publication rollback. These layouts do not constitute a real
  16/64-KiB host or Android device test.
- Paired Android core default **1** and explicit-JIT **2** CPU tests pass on
  Linux/Apple; the new special-memory probe also passes under the MOPS-positive
  model. It exercises all 36 MOPS option combinations at budgets 1/64, exact
  exits, unchanged text, bounds and zero fallback, plus conditional LSE128.
  JNI schema/flags stay unchanged. SDK/NDK/JDK/APK work stays on Windows CI.

The system QEMU 8.2.2 fails internally on protected MOPS operands; it is not a
passing result. The newer independent Debian binary is extracted without package
installation and checked against the official package SHA256. Its provenance,
binary hashes, host/model capabilities and outstanding acceptance are frozen in
the [receipt](jit-special-memory-20261128/receipt.json). Upstream
[MOPS helpers](https://github.com/qemu/qemu/blob/master/target/arm/tcg/helper-a64.c)
retain helper return addresses around bulk host memory accesses. Model execution
is functional ISA evidence, not native MOPS throughput or Android app-UID/ART
acceptance. Real MOPS/LSE128/LOR, Option-B/migration and Android large-page device
acceptance still need appropriate hardware.

## Ordinary-path performance controls

Matched real-VM runs compare baseline `f595ae2` with this batch. Both use the same
control-harness logic: CPU affinity 0, four balanced before/after pairs, 8 warm +
40 timed samples per workload/run, 64 internal rounds/sample and 262,144 guest
trips/round. Complete state/data and unchanged guest bytes are checked outside
timing; every sample reports zero fallback. Old/new executable SHA256 and a new
MOPS code marker prevent reusing a stale shared-target example binary.

| Control | Geometric mean before/after speed ratio | Per-pair range |
|---|---:|---:|
| Integer | 1.0311 | 1.0005–1.0688 |
| Scalar memory | 0.9965 | 0.9787–1.0169 |

The controls are reused after final fault-only recovery-priority and compile-time
ABI checks; their ordinary timed paths did not change. These controls show no
consistent new ordinary-path regression; the VM variation
does not establish an integer improvement. They execute no MOPS and provide no
MOPS/KVM/native or Android application speed claim. Frozen
[raw samples](jit-special-memory-20261128/controls.jsonl),
[summary](jit-special-memory-20261128/controls-summary.json) and
[binary identities](jit-special-memory-20261128/controls-build.json) retain the
measurement scope. The existing exclusive-category harness now accepts optional
`TRAMES_BENCH_FILTER`, `TRAMES_BENCH_SAMPLES` and `TRAMES_BENCH_WARMUP`; defaults
preserve its original behavior. Reproduce controls with these set to `control-`,
`48` and `8` respectively.
