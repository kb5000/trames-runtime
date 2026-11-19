# File cache advice, range writeback and vectored I/O on ARM64

The same six complete gVisor binaries ran on the Mac hardware executor before
and after this change. The baseline used runtime `8672eee`. Every passing case
was matched to its upstream XML. The ARM64 interpreter independently produced
the same per-case outcomes as the updated Mac build.

| Suite | Baseline pass / fail / skip | Updated pass / fail / skip |
| --- | ---: | ---: |
| fadvise64 | 2 / 2 / 0 | 4 / 0 / 0 |
| readahead | 5 / 1 / 2 | 6 / 0 / 2 |
| sync | 4 / 1 / 0 | 5 / 0 / 0 |
| sync_file_range | 1 / 3 / 0 | 4 / 0 / 0 |
| preadv2 | 9 / 1 / 0 | 10 / 0 / 0 |
| pwritev2 | 10 / 1 / 0 | 11 / 0 / 0 |

The two skips are upstream platform conditions for negative readahead operands.
The cumulative 3,163-case inventory now has 2,733 passes, 296 failures,
121 skips, ten timeouts, two missing results and one fixture failure. This
batch replaced 42 entries with newly audited results.

## Behavior

- Cache hints use the access mode and inode type from one accepted open file
  description. Path-only handles return EBADF, write-only handles reject
  readahead, and fadvise on a FIFO returns ESPIPE.
- ARM64 syscall 84 validates the signed range, flags and descriptor. The
  existing file worker submits writeback for mapped guest pages intersecting
  the requested byte range. A zero length extends to EOF. A private disk test
  checks the underlying bytes before unmapping, including wait-only flags,
  partial pages, an interval crossing a page boundary and an unchanged cursor.
  Linux hosts use native range writeback. Apple hosts use a file-wide data
  flush for the backing descriptor, which can wait longer on large files.
- Path-only handles also reject syncfs before queued filesystem writeback.
  Positioned vector reads and writes accept the HIPRI hint with the existing
  buffered I/O implementation. This introduces no busy-polling or service thread.

The error and range semantics follow the Linux [file advice](https://github.com/torvalds/linux/blob/master/mm/fadvise.c)
and [writeback](https://github.com/torvalds/linux/blob/master/fs/sync.c) implementations.

## Normal-path performance

Two independent alternating A/B runs used two warmups and 16 measured samples
per build each. Pooled medians use all 32 measured samples per build. A
positive change means longer elapsed time.

| Workload | Before (ms) | After (ms) | Pooled change | First run | Second run |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ordinary memory | 174.995 | 176.161 | +0.67% | +0.09% | +1.10% |
| Map, fault and unmap | 133.243 | 134.477 | +0.93% | +0.63% | +1.72% |
| Private file pread/pwrite | 95.522 | 95.993 | +0.49% | +1.70% | -0.83% |
| Fork and wait | 19.085 | 19.178 | +0.49% | +2.92% | +0.19% |

Runtime CI passed all eight steps. Interpreter kernel conformance passed 499
cases on the first run. Its historical O_PATH/FIFO expectation was updated and
the remaining case passed on rerun across all four worker configurations.
Three cases were ignored. The iOS FFI and ARM64 Linux musl session targets
compiled. Raw results and benchmark samples are in
`target/gvisor-file-cache-20261120` in the iPad checkout.
