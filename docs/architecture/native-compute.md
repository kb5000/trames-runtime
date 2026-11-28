# Native compression and crypto computation

Protocol 1/module 11 (`0x1000b`, auxv `0x5452000c`) extends the shared NativeCall
registry. It follows the existing `pure_accelerator` selection. The iPad
interpreter can use it; Mac HVF and Linux KVM retain their existing disabled
computation-thunk default and execute original library instructions on hardware.
There is no product UI or additional user setting.

At session creation, the runtime considers private-root AArch64 shared libraries
`libz.so.1`, `liblzma.so.5`, `libzstd.so.1` and `libcrypto.so.3` in the usual
`/lib`, `/usr/lib` and multiarch directories. Missing, read-only, busy, unsupported
or concurrently changed files retain original execution. Host mounts and other
mounted volumes are not rewritten. This is cold selection: package upgrades
inside a running session are reconsidered at the next session start.

Original SHA256 identities are pinned in `compute-catalog.tsv`. Unregistered,
modified or upgraded package images retain their complete original behavior;
matching an export name alone never opts a custom implementation into a thunk.

## Default adapters

- zlib: `crc32`, `adler32`, `compress2`, `uncompress`.
- liblzma: `lzma_crc32`, `lzma_crc64`, `lzma_easy_buffer_encode`,
  `lzma_stream_buffer_decode` with the default allocator.
- zstd: `ZSTD_compress`, `ZSTD_decompress`.
- libcrypto: SHA-1/256/512 `Init`, `Update`, `Final`, `Transform`, plus AArch64
  `AES_set_encrypt_key`, `AES_set_decrypt_key`, `AES_encrypt`, `AES_decrypt` and
  full-block `AES_cbc_encrypt`.

Compression stream contexts (`inflate`/`deflate`, `lzma_code`, zstd stream/context
APIs), custom allocator callbacks, dictionaries, static binaries and EVP/TLS
contexts retain original code. Public SHA contexts stay in guest memory; their
inline integer state and bounds are marshalled per call. The high-level SHA/EVP
provider-selection path remains guest-owned. Pure one-shot SHA operations are
also available in the protocol, but the ELF adapter does not replace the guest's
provider-selecting one-shot exports. This is not a claim that apt/apk/git/curl or
HTTPS are completely native, or that every installation becomes faster.

## ELF and fallback behavior

The cold adapter checks ELF64/AArch64 shared-image headers, dynamic symbols,
bounded program/section tables and relocatable entry instructions. Unsupported
entries remain original. It retains the original load segments, algorithms,
symbols, versions, TLS and dynamic loader. New RX wrappers and RW dynamic tables
are separate; the loader resolves `getauxval` and `__errno_location` through normal
guest relocations. Segment alignment respects the original maximum load alignment.

The library initializer selects a scalar guest capability once, preserves errno
and constructor arguments, then invokes the original initializer array in order.
Legacy `DT_INIT` stays intact; the new capability initializer uses `INIT_ARRAY`,
which both AArch64 musl and glibc execute. Calls made
before initialization retain original execution without requiring libc TLS.
Wrappers preserve BTI/PAC landing instructions, authenticate successful PAC
returns, retain sign-extended relative branch destinations and restore original
arguments before fallback. A missing/disabled capability selects original code.
The original bytes can be restored only after validating the embedded exact-original
SHA256 recovery recipe. Guest templates are assembled into the cold ELF derivative; no host JIT or
host executable-memory allocation is involved.

The call frame contains nine integer/pointer arguments; the ninth is read from
the caller stack only for the nine-argument liblzma decoder. Native authorization
uses the same five-word executable-page identity check as other pure calls.
Worker and source execution use the same `NativeMemory` transport and metrics.

## Memory and concurrency

Guest addresses are never host pointers. Checked reads gather call-owned bytes;
only call-owned host buffers and validated public SHA/AES integer contexts cross
the static FFI boundary. Output preflight uses the existing CPU permissions,
backing and resource admission. Ineligible ranges select original execution
before guest writes. Output scratch reserves capacity without zero-filling unused
bytes; only ranges the library reports initialized are published.

SHA `num`/digest-width and AES round counts are checked before native indexing.
SHA512 initialization preserves its originally untouched pending block. Host
hash operations use low-level arithmetic routines, not a host EVP provider or TLS
session. AES schedule marshalling is enabled on AArch64 hosts; other host
architectures retain the original AES implementation.

State remains guest-owned, including across fork. No persistent host stream
handle, host allocator callback, host TLS pointer, global algorithm lock, new
coordinator or polling bus is introduced. Reusing a non-thread-safe context
concurrently remains the guest caller's responsibility. Each native invocation
runs on its executing worker and uses private staging, so guest races cannot
turn into races over an opaque host C context.

Static dependencies are pinned by Cargo.lock and built from bundled zlib, xz,
zstd and OpenSSL sources for Apple and Linux. Product dependency catalogs include
their original notices. This module does not add networking or host filesystem
authority.
