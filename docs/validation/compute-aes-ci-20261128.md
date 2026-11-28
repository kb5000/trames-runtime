# Compute AES architecture acceptance correction — 2026-11-28

The Runtime [Linux CI job](https://github.com/project-trames/trames-runtime/actions/runs/46125219883/job/140918217276)
at `be8bfedfe1450c060d2fc5e03ab051605a7b1432` failed in the newly merged compute
adapter's AES vector test. The product already declines compute functions 14–18
on non-AArch64 hosts before reading the guest frame: these functions own the
AArch64 guest AES key representation. The test nevertheless expected encryption
on amd64 and checked only a zero return value, which is also the fallback value.
The unchanged plaintext was consequently compared with the ciphertext vector.

The correction separates checksum/hash acceptance from AES acceptance. AArch64
tests require non-fallback key expansion, the expected round count, the known
AES vector and in-place decryption. Non-AArch64 acceptance requires all five
functions to decline with an unmapped frame and zero bytes read/written. The
existing architecture condition is expressed as target cfg; AArch64 compilation
contains no function-range preflight. There is no new production ABI or software
crypto replacement.

Actual Apple arm64 and ARM64 Linux both pass all **34 accelerator unit tests**
and scoped all-target strict Clippy. The prior ARM64 JIT job and Android's Apple,
ARM64 Linux and Windows APK jobs passed; they are separate from the failed amd64
compute test. Their source-unchanged CPU results remain valid. The amd64 negative
branch is exercised by the next main CI run; local ARM64 execution does not prove
that branch. This correction does not require another full CPU/Linux/network/
graphics acceptance round.
