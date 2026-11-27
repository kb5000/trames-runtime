# JIT syscall exits and register allocation — 2026-11-27

Baseline JIT sources: Runtime `393db29685ace8ed635c21f4f6a7f866f8bccdcb`.
The same `cpu-boundary` example was used with old/new JIT sources, same VM,
source path, target directory, release profile, toolchain and workloads.
Replaced source timestamps were refreshed before comparing versions, so Cargo
recompiled each JIT version rather than reusing a newer output after a source
mtime rollback. The table is the adjacent repeat; an initial repeat showed
host-load variation. It is not a confidence interval or device performance claim.

Host: existing Lima AArch64 Linux VM, Ubuntu kernel `7.0.0-44-generic`, 4096-byte
host pages. Rust `nightly-2026-10-16`, release/thin LTO, incremental disabled.
Each result is the median of five measured passes after one full warm-up pass.

| CPU workload | Old JIT median | New JIT median | Old / new |
| --- | ---: | ---: | ---: |
| integer-loop | 7.839 ms | 4.336 ms | 1.81x |
| svc-round-trip | 4.826 ms | 0.677 ms | 7.13x |
| svc-only | 3.222 ms | 0.633 ms | 5.09x |

Integer-loop pass: 16 × 1,048,576 guest instructions, using 31 adds plus a branch.
SVC-round-trip pass: 100,000 entries, each 16 adds + SVC, followed by a simulated
worker return value/PC re-entry. SVC-only pass: 100,000 one-SVC entries. These
measure CPU backend boundaries, **not** Linux handlers, host syscall cost,
filesystem/network, JNI, Android lifecycle or end-to-end application speed.

The new 16-add + SVC block emits 20 host words and accesses the integer frame
only once for reading and once for dirty writeback. Previously each add loaded
and stored its frame slot (32 frame accesses), and SVC entered the interpreter.
Cold compiler totals expose code size/load/store counts without adding checks
inside ordinary translated instructions. No original guest instruction changes.

Passed affected checks:

- Apple: ten JIT differential tests in the compile-time non-native configuration;
  scoped all-target/all-feature Clippy.
- Actual ARM64 Linux: one generated-code test (SVC-only emits BTI+RET, no host
  supervisor call), ten differential tests and scoped Clippy.
- Differential cases include 2,048 single encodings, 128 multi-instruction
  register-pressure/budget combinations, dirty evictions, aliased inputs,
  retained deferred flags, syscall arguments and simulated returns, boundary SVC
  immediates #0/#65535, reserved exceptions, exact budgets,
  page-end exits, mapping/code invalidation, exclusives and parallel views.
- Android core probe asserts exactly two native guest ALU instructions, one
  direct compiled syscall exit and zero fallback instructions. Probe flag bit 3
  carries this result without changing the 40-byte JNI report ABI.

JIT remains an explicit optional product feature. The interpreter, compute and
shared kernel/session implementations are unchanged; iPad's tested no-JIT
build graph and unaffected checks are reused. Android device execution and
full Session integration remain separate acceptance work.

Raw adjacent-repeat medians (nanoseconds):

```json
{
  "baseline": [
    {
      "workload": "integer-loop",
      "interpreter_ns": 15280629,
      "jit_ns": 7839482,
      "speedup": 1.949
    },
    {
      "workload": "svc-round-trip",
      "interpreter_ns": 4705639,
      "jit_ns": 4826389,
      "speedup": 0.975
    },
    {
      "workload": "svc-only",
      "interpreter_ns": 3085259,
      "jit_ns": 3221551,
      "speedup": 0.958
    }
  ],
  "optimized": [
    {
      "workload": "integer-loop",
      "interpreter_ns": 15439954,
      "jit_ns": 4335969,
      "speedup": 3.561
    },
    {
      "workload": "svc-round-trip",
      "interpreter_ns": 4636262,
      "jit_ns": 676543,
      "speedup": 6.853
    },
    {
      "workload": "svc-only",
      "interpreter_ns": 3146466,
      "jit_ns": 633335,
      "speedup": 4.968
    }
  ]
}
```
