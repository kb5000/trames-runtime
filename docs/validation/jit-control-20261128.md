# Fixed-state native branch/call category — 2026-11-28

Baseline Runtime `bf8e801e09b43d9d04467cf2ca14711811da2d6a`, paired Android
`de69ef497bf84bb6db0e5ded4247a02a063a1bd9`. This batch closes the declared
fixed-state branch/call list, its cold encoding admission and original fault
boundaries. It does not claim every AArch64 or future host instruction.

## Native execution and process capabilities

B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET retain their native paths. HBC
`BC.cond` and CMPBR's W/X register/immediate and byte/halfword register forms
now use real branch instructions. Operand-swap and adjusted-immediate aliases
are independently assembled. CMPBR reuses existing GPRs and never reads/writes
NZCV. Dynamic targets are captured before an aliased LR write; guest text,
host x18/TLS and all architectural banks retain their original ownership.

Linux's [UAPI header](https://raw.githubusercontent.com/torvalds/linux/v6.17/arch/arm64/include/uapi/asm/hwcap.h)
assigns HWCAP_CMPBR bit 33 and HWCAP2_HBC bit 44. Admission intersects the
existing process-host `getauxval` result, in accordance with the
[Linux process capability contract](https://docs.kernel.org/next/arm64/elf_hwcaps.html).
No physical-core probe, hot capability check, guest-code rewrite, new CPU bank,
software native compare, extra memory fence or synchronization is added. Pure
interpreter capability advertisement remains unchanged. Both interpreter engines
understand the new semantics for reference and interpreter-only execution; native
JIT rejects absent host capabilities at the reached PC instead of using them.

Untranslated owned conditional/compare, D6/D7 register-branch and D4 exception
encodings now install the existing instruction-fault descriptor after the original
compatibility/system/memory classifiers. Cache identity/page validation and
exact retired-prefix accounting remain authoritative. Privileged, GCS and other
unowned extension forms remain instruction faults; successful shared-CPU forms
are not discarded to obtain zero fallback statistics.

## Independent encoding and semantic acceptance

The [audit script](../../scripts/audit-jit-control.py) uses the existing pinned
Rust toolchain's LLVM 23 assembler/disassembler, with no new tool installation.
`global_asm!` generates an ELF object; its `.text` is extracted independently.
The retained [assembly](jit-control-20261128/category.S), word list and semantic
case list contain **19,568 encodings**, including all conditions, displacement
boundaries, byte/half/W/X widths, six-bit immediates, high/zero registers and
link/target aliases. The separate **4,096-selector** CMPBR sweep has **1,536**
valid encodings. Native cold admission exactly matches that independent list,
and published code retains actual extension opcodes and immediate/condition
fields. No NZCV traffic is emitted for CMPBR.

Each interpreter path executes **119,648 programs** against an independent
assembly-semantic oracle and compares complete architectural state. Actual
ARM64 Linux executes **18,016** native programs and **101,632** exact reached-PC
host rejections in the same matrix, with unchanged executable bytes. A further
**324** actual-host programs combine dirty GPR/FP state, checked memory callbacks,
budgets 1/2/64 and serial/guarded/private execution. Extension loops, target-page
faults/permissions and SVC resumption are checked where process capabilities allow.

A selector audit confirms **822,635** untranslated owned selectors are original
interpreter instruction faults without a data-memory access. The retained
**12,854** sampled fault words use a traced provider: an extra decoder-page query
would detect interpreter entry even when zero instructions retire. Cold/warm
faults preserve state and PC; warmed descriptors do not fetch/recompile, exact
budget keys are retained for non-chaining embeddings, and permission/code changes
rejoin the original authority. Thus `fallback_instructions == 0` is not the sole
proof for fault paths. The sweep enumerates opcode selectors and declared operand
aliases/literals, not all 2^32 words or all future extensions.

Two old-source diagnostics each execute one test and fail for the intended
reason: HBC is rejected by the old decoder, and old control faults make an extra
interpreter decoder-page query. Neither result is a build failure or zero-test
execution. Baseline/current use distinct source roots and Cargo targets.

## Platforms and code generation

The full Linux JIT suite passes **34 unit + 131 integration** tests in Debug and
Release; two subsequently added category tests pass with all six category tests
in both profiles, bringing covered total to **167**. These additions are test-only;
unchanged earlier results are reused. Shared interpreter **52 unit + 3 integration**
checks pass. Scoped strict native Clippy and amd64 cross-Clippy pass; amd64 checks
compilation, not native x86 JIT execution.

Apple passes the full **126** JIT fallback tests, and all six final category tests
including the two added checks (**128** covered total), **55** interpreter tests,
scoped native/default strict lint, and a fresh current-interpreter iOS build.
JIT/executable allocation remain excluded from iPad at compile time. The prior
isolated current-manifest CPU graph is reused only after verifying owner
manifests/lock and every Runtime dependency manifest are unchanged; its provenance
and tree are retained. The owner working tree, Runtime pin and lock remain
untouched. This does not turn the earlier owner-root lock mismatch into a
successful `--locked` owner-root graph query.

Android core passes default **1** and explicit-JIT **7** Rust checks and strict
lint on Linux/Apple. Its new private probe includes **244** representative branch
encodings, each over all 16 NZCV values (**3,904** programs), full state and native
host rejection. Probe schema 1 / 40 bytes / flags stay unchanged. SDK/NDK/JDK,
APKs, ART/app-UID and real large-page Android acceptance remain Windows/device
work and are distinct from Linux native testing.

Before/after receipts compare **2,816** actual compiled existing branch programs
and **838** scalar programs. Their published machine-code streams are byte-for-
byte identical. Operation/Block/Node/Frame remain **192/152/264/120** bytes;
interpreter Op/Instruction/Entry/Cpu remain **24/32/40/992** bytes. The compact
new decoded branch operand does not grow existing cache/CPU layouts. Compressed
streams, comparison and source-bound accepted-log hashes are retained.

## Positive extension acceptance

The existing QEMU 10.0.13 `max` process model advertises HBC, without CMPBR.
All six category integration tests pass there, including **19,808** native matrix
programs and **99,840** absent-CMPBR rejections, plus **1,332** dirty-prefix/budget/
memory programs and HBC loops/target faults/resumption. The Android category probe
also passes in that model. This is positive HBC ISA-model acceptance, not host
hardware performance. Actual HBC-positive and CMPBR-positive hardware, and
CMPBR-positive model execution, remain unverified. CMPBR has complete independent
encoding/codegen and reference semantics plus actual absent-host rejection; that
is not reported as positive hardware execution.

## Remaining interpreter entry

Within completed shared-CPU categories there is no known ordinary valid
instruction requiring successful interpreter fallback. The generic one-instruction
entry still exists for unrecognized encodings outside the closed scalar and owned
control/exception spaces; some entries only return an instruction fault. Those
spaces still need their own full audit, so zero fallback over every possible
program/encoding is not claimed. SVC exits, checked Memory callbacks, cross-page
staging and original guest faults are not interpreter execution.

Full hardware PAC/BTI/MTE, stateful SVE/SME, LS64 Device-memory and SETG tag ownership
remain unadvertised pending real shared CPU/memory ABI ownership. They must not
acquire a software substitute through the interpreter. Interpreter-only products
and unsupported native hosts intentionally retain their compiled interpreter.

## Matched ordinary-path CPU controls

The identical existing harness sources run on independent before/current source
roots, Cargo targets and uniquely copied binary hashes, pinned to vCPU 0 of the
same 4-KiB ARM64 Linux VM. Four balanced pairs alternate before/after order. Each
process has 32 samples, eight warmups and 24 timed samples. Integer/memory controls
use 64 rounds of 65,536 guest trips per sample; SVC controls use 200,000 simulated
returns per sample. Complete state/data, exact retirement and unchanged executable
bytes are checked outside timing. Every row requires zero fallback.

Ratios are geometric means of four paired median before/current time ratios;
greater than one means current is faster. All **1,280** raw rows, including
warmups, are retained with exact harness and binary identities.

| CPU-only control | Before/current time ratio | Paired ratio range |
|---|---:|---:|
| Ordinary integer | 1.019x | 0.905–1.171x |
| Ordinary scalar memory | 0.995x | 0.990–1.005x |
| Cached SVC-only exit | 1.005x | 0.981–1.041x |
| ADD + SVC round trip | 1.008x | 0.996–1.026x |
| Branch continuation + ADD + SVC | 1.003x | 0.982–1.021x |

These measurements do not establish an ordinary-path speedup or a universal
regression bound. Published-code identity is separate evidence. They do not time
new extension throughput, Linux syscall handlers, KVM, JNI, graphics, ART or
Android lifecycle. Positive extension model acceptance is not hardware speed.
See the [source-bound receipt](jit-control-20261128/receipt.json) and retained
benchmark provenance/rows for the precise scope.
