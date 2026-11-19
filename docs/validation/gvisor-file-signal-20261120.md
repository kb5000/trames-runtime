# File opening, seeking and signal compatibility

Eight original ARM64 gVisor suites ran on the Mac hardware executor against the same Alpine rootfs. Both builds used the same 169 named cases. Each passing case has an original gTest XML result.

| Result | Previous runtime (3256b08) | Updated runtime |
| --- | ---: | ---: |
| Passed | 141 | 154 |
| Failed | 24 | 11 |
| Timed out | 2 | 2 |
| Skipped | 2 | 2 |

Six cases cover opening directories with creation or truncation flags. Three cover end-relative seeks on regular directories and on generated proc statistics. One creates an unbound Unix socket inode and checks that connecting to it returns ECONNREFUSED. Two query the default SIGKILL and SIGSTOP actions and reject attempts to change them. One checks that sysinfo rounds a fractional uptime up to the next second.

The remaining failures comprise eight partial-buffer reads, the Linux access mode 3 case, and two concurrent mount traversal cases. Both rename race cases timed out on both builds. Tracer-dependent ELF cases from the preceding batch were outside this run.

The cumulative inventory now records 2,757 passes, 254 failures, 28 timeouts, 121 skips, two cases without results and one fixture failure across 3,163 cases. Two directory-entry copy cases already passed on the baseline replay and account for the difference between the 13 new passes and the 15 inventory corrections.

## Normal-path performance

The Mac alternated the previous and updated executors. Each median uses 16 guest timing samples per build after two warmups.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 175.266 | 176.891 | +0.93% |
| Map, fault and unmap | 132.188 | 132.047 | -0.11% |
| Private file pread/pwrite | 95.658 | 95.147 | -0.53% |
| Fork and wait | 19.263 | 19.382 | +0.62% |

Shared runtime CI passed all eight steps. The interpreter passed 501 kernel conformance tests with three ignored. The iOS FFI and ARM64 Linux musl session targets compiled. The raw suite XML, merged inventory and timing samples are in the iPad checkout under `target/gvisor-file-signal-20261120`.
