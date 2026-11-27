# Shared software CPU / Android bootstrap — 2026-11-27

Source baseline: Runtime `87590639b4d8a340a3801ef6f3a7c7e2a1794605`.
Interpreter/compute source: iPad `a042d8d8ea5f6e94676682fe5a721f509f6a67da`.
No guest instruction rewriting; JIT is an opt-in separate crate.

Passed on Apple AArch64 with nightly-2026-10-16:

- Interpreter: 48 unit + 2 register-state + 1 small-stack tests.
- Host compute: 4 tests.
- JIT fallback differential tests and all-target/all-feature scoped Clippy.
- `cargo check -p trames-interpreter --target aarch64-apple-ios --locked`.
- Shared execution-boundary and reviewed-notice checks.

Passed on the existing ARM64 Linux VM, without KVM/SDK/toolchain changes:

- `cargo clippy -p trames-jit --all-targets --features native-aarch64 --locked -- -D warnings`.
- 55 interpreter/compute tests and 6 JIT integration tests.
- Differential corpus: 2,048 encodings; native execution is asserted, not
  inferred from successful compilation.
- Exact budgets, complete architectural state (TLS/FP/SIMD/deferred flags),
  B/BL, page-boundary faults/retirement, code/permission/unmap/remap/address-space
  invalidation, retained exclusives, pending native calls and parallel views.

Android non-debuggable app-UID execution, ART coexistence and 4/16 KiB device
acceptance remain separate required checks. The new Windows APK pipeline owns
Android cross-builds. No Android SDK, NDK, JDK or emulator was installed on Mac.
This batch does not claim complete JIT coverage or near-native performance.
