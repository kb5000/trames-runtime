# Guest proc memory completion — November 23, 2026

This follows [guest ptrace mutation](guest-ptrace-mutation-20261123.md). On both the Mac hardware executor and the iPad product interpreter running locally on the Mac, **50 original gVisor cases pass and one skips**. The selection includes all 36 ptrace cases, twelve proc cases and three related exec cases. The eleven `ProcPidMem` cases all pass. The separate guest fixture and actual GDB smoke tests pass on both executors. This validation does not include physical iPad deployment.

## Remaining upstream ptrace skip

The only skipped ptrace case is `PtraceTest.SetYAMAPtraceScope`. The [pinned original source](https://github.com/google/gvisor/blob/89cacadae21eca4270a8f7c79281d0426d33ac5f/test/syscalls/linux/ptrace.cc#L2669) explicitly skips when `GvisorPlatform() == Platform::kNative` to avoid changing the host ptrace scope. The unchanged test binary classifies this execution environment as Native; the native Linux reference skips for the same reason. This skip does not indicate a missing ptrace request. The second upstream guard requires CAP_SYS_ADMIN; it is not the reason observed in these runs.

The original case and platform selection remain unchanged. The standalone fixture's `yama` mode runs only in the disposable guest: it verifies scope 0 allows an unprivileged child to attach its parent, scopes 1 and 2 deny that attach, and scope 3 cannot be reverted and rejects TRACEME. It checks sysctl readback and newline writes. The child drops effective CAP_SYS_PTRACE; the parent retains it to change the guest sysctl, following the runtime's Linux Yama capability policy. This is separate guest coverage, not a claim that the upstream case was unskipped or executed identically.

## Completed proc-memory behavior

* Read and write use the exact address space admitted when opening `/proc/PID/mem`. Later credential or dumpability changes cannot redirect an existing FD or redo its original admission. After that address space retires on exec or exit, old FDs return EOF and do not address the replacement image at the same virtual address.
* Forced reads now cover PROT_NONE and execute-only mappings, private file-backed memory and live shared file-backed memory. They no longer depend on the anonymous-page export used by cmdline/environ. Those other proc files retain their existing anonymous-only behavior.
* Forced writes retain private COW, original mapping permissions and executable-code invalidation. Protected shared mappings reject writes; writable shared mappings retain live file coherence. Ptrace word access shares the same page access implementation and retains its complete-word validation.
* Transfers continue across multiple 256 KiB windows until the staged operation completes or encounters a real short transfer. Unmapped memory produces EIO if no byte was transferred, or the exact successful prefix otherwise. Retirement returns EOF or the prefix already transferred. The existing bounded syscall staging limit remains 1 MiB per call.
* `SEEK_SET` accepts the complete unsigned address bit pattern; `SEEK_CUR` wraps as Linux proc mem does. Other seek origins return EINVAL. Positioned scalar and vector operations accept the same unsigned offsets and leave the OFD offset unchanged.
* Duplicated FDs retain one pending OFD position transaction across all windows, so simultaneous unpositioned operations cannot interleave chunks or commit the offset twice. A cancelled write retains the position lease until any accepted owner copy finishes, preserving actual write progress. Queued cancellation performs no copy and releases the lease.

The implementation follows the [Linux v6.12 proc mem implementation](https://github.com/torvalds/linux/blob/v6.12/fs/proc/base.c#L892) with its default forced-access policy. Waiting memory requests release the execution slot and use the existing original-mm owner and readiness mechanism. No new coordinator, polling loop or service thread is introduced.

## Regression evidence

| Selection | Mac hardware | Product interpreter |
| --- | ---: | ---: |
| ptrace, complete binary | 35 pass, 1 skip | 35 pass, 1 skip |
| proc, memory/access selection | 12 pass | 12 pass |
| related exec cases | 3 pass | 3 pass |

Requested identities, upstream executable hashes, original per-case Google Test XML and skip reasons were verified. There are no missing or unexpected cases, worker errors or regressions against the native results in this selection. Discovery errors carried from the older broad native inventory concern unrelated binaries and are not results for this selection.

The [standalone guest fixture](../../tests/fixtures/proc-mem.rs) covers protected and file-backed mappings, partial results and error/offset behavior, reads and writes larger than a transfer window, preadv/pwritev, concurrent reads through duplicated FDs, credential changes after open, exec/exit with the same address reused, and guest Yama modes. Its default mode also passes with one execution slot on the product interpreter. Build it with:

```sh
rustc --target aarch64-unknown-linux-musl -C linker=rust-lld -O --edition 2021 \
  tests/fixtures/proc-mem.rs -o /tmp/proc-mem
```

Run the default and `yama` modes in separate fresh guest runtimes. Mode 3 is deliberately irreversible for the current guest runtime.

Alpine GDB 15.2 passes a real software breakpoint, `stepi`, x19 mutation and normal continued exit on both executors. Existing hardware-breakpoint resource warnings are unchanged. All eight standalone runtime CI stages pass, including workspace tests, clippy with warnings denied and the release build. The ARM64 iOS FFI check passes. The earlier full interpreter kernel conformance results and their four reproduced pre-existing job-control failures are documented in the preceding ptrace report; unchanged tests outside this batch were not rerun.

## Ordinary workload performance

The previous committed ptrace runner is compared with this candidate on the same Mac. Each version has two warm-up samples and 32 measured samples, with version order alternated every pair. Median elapsed milliseconds; positive change means more time.

| Workload | Before | Candidate | Change |
| --- | ---: | ---: | ---: |
| `memory` | 179.114 | 180.259 | +0.64% |
| `mmap_fault_unmap` | 136.942 | 136.700 | -0.18% |
| `file_pread_pwrite` | 99.910 | 99.605 | -0.30% |
| `fork_wait` | 19.843 | 19.922 | +0.40% |

No slowdown above 1% is observed in these four ordinary workloads. This is a local comparison rather than a physical iPad performance result.

## Local artifacts

Evidence is retained under `target/proc-mem-completion` in the iPad checkout: requested plan, original XML and per-case logs, `verified.json`, both GDB logs, fixture logs including the single-slot run, the eight-stage `ci/summary.json`, `ios-check.log` and all raw performance samples in `performance-final.json`.

* Candidate Mac runner SHA-256: `bdde13022480d637c288800e7af8831c57b9b8fdf2c49f25d23e958a52b32a61`
* Previous committed runner SHA-256: `3e07afac0c900deb65f136e20b7be8076cc4f2831319da45e301607f7cd5871e`
* Guest fixture SHA-256: `79d8ab78f72c6be9593ae5561ba040a7c9f6e9f8c28a726d7c3abea8e8b632a5`
