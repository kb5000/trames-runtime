# Partial regular-file transfers

An ordinary file can transfer bytes up to the first inaccessible guest page. Scalar and vectored file calls use the prefix length from the existing memory permission walk when preparing the operation. The vector table, including entries following the fault, remains subject to ABI range validation. Current-position operations use the accepted byte count and positioned operations preserve the shared file position. The change covers synchronous regular-file calls on both execution backends. Record-oriented devices, sockets and asynchronous submission keep their existing import behavior.

## Original tests

The Mac hardware runner executed the same 141 named tests from nine suites on both builds. The baseline (5c53d12) passed 127 and failed 14. The updated build passed 139 and failed two. Every pass has an original gTest XML result. The 12 new passes comprise eight boundary-buffer read variants, readv and pwritev across a protected page, pwritev across the end of a mapped file, and rejecting an out-of-range zero-length iovec in a nonempty array.

The remaining two failures are the existing pread64 and pwrite64 maximum-offset cases. The large TruncatedAtMax fixture, which allocates over 2 GiB, was excluded from this focused run. Its earlier inventory result is retained. The merged 3,163-case inventory now has 2,769 passes, 242 failures, 28 timeouts, 121 skips, two cases without results and one fixture failure.

The native-hosted iPad interpreter ran 20 selected original cases, all of which passed. A shared-descriptor regression additionally checked the copied bytes, the untouched later vector, the offset seen through dup, the data written by a positioned short write and rejection of an invalid later vector descriptor. The shared runtime CI passed all eight steps. Interpreter kernel conformance passed 501 cases with three ignored. iOS FFI and ARM64 musl builds passed their compilation checks.

## Normal-path performance

Each comparison alternated old and new Mac executors on the same host and used 16 timed samples per build after two warmups. Each vector sample made 24,000 calls with four 1 KiB segments on a private file.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 178.146 | 177.893 | -0.14% |
| Map, fault and unmap | 131.601 | 131.954 | +0.27% |
| Private file pread/pwrite | 96.061 | 96.974 | +0.95% |
| Fork and wait | 19.541 | 19.529 | -0.06% |
| Four-segment preadv | 41.903 | 42.084 | +0.43% |
| Four-segment pwritev | 53.249 | 52.774 | -0.89% |

The local raw XML, combined inventory, benchmark inputs and timing samples are in the iPad checkout under `target/gvisor-partial-io-20261120`.
