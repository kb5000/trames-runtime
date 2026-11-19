# Pipe duplication and signed file transfer ranges

The Mac hardware executor ran all 105 tests in the pinned gVisor copy_file_range, pread64, pwrite64, sendfile, sendfile_socket and splice suites. Both builds used the same binaries, fresh guest stores, two vCPUs, and a nine-second deadline per case.

| Mac result | Previous (5715017) | Updated |
| --- | ---: | ---: |
| Passed | 84 | 97 |
| Failed | 16 | 6 |
| Timed out | 3 | 0 |
| Skipped by gTest | 2 | 2 |

All 84 previous passes remained green. Eight tee cases now pass, including blocked readers, blocked writers, nonblocking calls and partial duplication. The five other new passes cover maximum-offset pwrite and splice, negative and overflowing sendfile counts, and sendfile descriptor access versus append error ordering. Each pass was verified against its original gTest XML.

The shared runtime implements tee using the existing pipe wait queues. A successful tee copies a bounded prefix into the destination and leaves the source readable. This implementation copies bytes. The VFS regressions check the contents of both pipes across duplicate and broken-pipe calls, plus unchanged file contents, file position and pipe data after a rejected splice.

## Remaining failures

| Original case | Observed failure |
| --- | --- |
| Pread64Test.Overflow | The remaining failing assertion is truncating a memfd to the largest signed file offset. Exportable shared files currently have a 2 GiB length limit. |
| SendFileTest.SendFileToSelf | A same-descriptor copy returns one byte where the test expects 10 MiB. |
| SendMultiple, both socket address families | The final ordinary file read returns 1 MiB of the expected 5 MiB. |
| Shutdown, address family parameter 1 | Setting SO_LINGER returns ENOPROTOOPT. |
| ToPipeWithSmallCapacityDoesNotSpin | The guest fills 128 leftover bytes where a Linux pipe with no available buffer slots would block and then be interrupted. |

The cumulative 3,163-case inventory now contains 2,782 passes, 232 failures, 25 timeouts, 121 skips, two missing results and one fixture failure. Only the 105 cases above were replaced in that inventory. Raw XML, original classifications and the merged inventory are under `target/gvisor-transfer-range-20261120` in the iPad checkout.

## Execution backends and performance

The Mac-hosted iPad interpreter passed all 13 newly passing original cases. The shared runtime CI passed eight steps. The interpreter kernel suite passed 501 cases with three ignored. The iPad FFI and ARM64 Linux musl build checks passed. Physical iPad performance was not measured.

The old and new Mac binaries alternated on the same host. Each median uses 16 samples per build after two warmups. Percent changes are elapsed time.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| Memory | 173.319 | 173.328 | +0.01% |
| Map, fault and unmap | 129.517 | 128.907 | -0.47% |
| Private file pread/pwrite | 94.832 | 95.500 | +0.70% |
| Fork and wait | 19.118 | 19.033 | -0.45% |
