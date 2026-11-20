# Large regular-file transfers on ARM64

Scalar read and pread accept the writable guest buffer prefix up to Linux MAX_RW_COUNT. Private storage, mapped files and shared-memory files shorten reads to the available bytes at EOF. The ABI and storage layers previously truncated a regular read to 1 MiB. Regular-file replies still stage the returned bytes in host memory before copying them to the guest. A multi-megabyte read can therefore temporarily require another buffer of the returned size.

Regular-file sendfile and copy_file_range process consecutive chunks of up to 1 MiB, with common transfer logic for joined and worker execution. A genuine short write or a later I/O error returns the transferred prefix. The operation retains progress and the already-read input across an output mapping-layout wait. A forward sendfile from the same inode can consume the bytes it just wrote. If the original read covers the tail up to the current output position at EOF, the writer expands that pattern within the current chunk under the destination inode and file-position locks. The normal write path enforces seals, file-size limits and storage quotas.

## Compatibility

The suites below used the original gVisor ARM64 binaries and two guest CPUs. Both executors ran on the Mac. The iOS device-target FFI compiled.

| Suite | Mac hardware execution | iPad interpreter | Recorded ARM64 Linux |
| --- | --- | --- | --- |
| copy_file_range | 25 passed | 25 passed | 25 passed |
| sendfile | 20 passed, 2 skipped | 20 passed, 2 skipped | 20 passed, 2 skipped |
| sendfile_socket | 5 passed, 1 failed | 5 passed, 1 failed | 6 passed |

Both 5 MiB socket-to-file client tests now read and compare the whole output file in one syscall. The same-file sendfile test now copies 10 MiB from a one-byte seed. The TCP shutdown test still fails on SOL_SOCKET/SO_LINGER setup. The two pipe skips come from the upstream platform guard. Updating only these 53 rows leaves the 3,240-case Mac inventory at 3,033 passed, 98 failed, 82 skipped, 25 timeouts, one fixture failure and one missing result.

Additional regressions check a multi-byte repeating pattern and file-size limits on ordinary and shared-memory files, positioned reads with partial guest buffers, and resuming a multi-chunk copy after its first chunk committed. The mapped-file test changes the committed destination byte and the original source tail during the wait, then verifies that both the existing destination prefix and the staged input survive.

## Performance

The signed Mac executors used the same private Alpine fixture and two guest CPUs. Each version had two warm-up runs and 16 measured runs per probe. The order alternated within each pair. Values are median elapsed milliseconds per probe. Positive changes mean longer elapsed time.

| Probe | d3fa0ae | Updated | Change |
| --- | ---: | ---: | ---: |
| Memory | 177.609 | 177.793 | +0.10% |
| mmap, fault and unmap | 133.187 | 133.068 | −0.09% |
| File pread and pwrite | 95.365 | 95.743 | +0.40% |
| Fork and wait | 19.278 | 19.254 | −0.12% |
| getuid | 103.788 | 103.153 | −0.61% |
| stat | 19.305 | 18.995 | −1.60% |
| open | 74.491 | 73.604 | −1.19% |

The 10 MiB same-file append from a one-byte seed took 32 ms on Mac hardware execution and 4 ms in the interpreter in the final suite runs. These single-case timings include other concurrent work. The original runtime returned one byte.
