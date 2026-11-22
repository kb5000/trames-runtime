# Cross-process memory vector transfers, 2026-11-22

The previous shared runtime was `e4d7c1f`. The same original AArch64 binary ran in isolated Mac guest processes with the same seven-second deadline. On each Mac run the harness verified every original case individually. The interpreter ran the entire group in one guest process on Mac.

| Runner | Passed | Failed | Timed out |
| --- | ---: | ---: | ---: |
| Previous Trames, two CPUs | 41 | 5 | 5 |
| Updated Trames, two CPUs | 51 | 0 | 0 |
| Updated Trames, one CPU | 51 | 0 | 0 |
| Updated iPad interpreter on Mac, two CPUs | 51 | 0 | 0 |
| Native Linux ARM64 reference | 51 | 0 | 0 |

The ten gains cover nonempty child reads and writes, including mismatched vector lengths and the 32 MiB case in both directions. A separate original exec_binary case also changed from failure to pass on Mac. After exec an unprivileged parent could read eight bytes from the readable guest image and got EPERM for the execute-only image.

## Execution and lifetime

The caller imports both vector lists once and resolves the target in its guest PID namespace. For distinct address spaces, the original task credential binding selects the matching memory target under the real-credential and dumpability check. Per-image authority is separate from the public proc memory report. A guest PID, proc file, or subsequent exec cannot retarget a pending operation. Ordinary self copies run directly on the calling worker.

At most one 256 KiB piece is outstanding per syscall. The caller releases its execution slot. Existing memory-maintenance workers admit the target mm, apply its ordinary page permissions and COW rules, and notify the caller. There is no new thread. The caller and target check each page fragment for the correct partial byte count. Individual ranges, projected credentials, the original address space and completed byte counts survive worker handoff.

Last-owner retirement cancels queued windows. A call that already copied data returns the prefix, and a call that made no progress returns ESRCH. This differs in a concurrent exit or exec from Linux holding an mm reference until the syscall returns. [Linux process_vm_rw_core](https://github.com/torvalds/linux/blob/v6.12/mm/process_vm_access.c)

Additional runtime tests cover faults at either endpoint in both directions, original parent/child COW, permission changes before service, cancelled and retired requests, and credential and image changes. Another 113 vector-I/O and procfs cases retained their previous results (109 passed, three smaps failures, one skipped). All eight local CI stages and the iOS ARM64 build check passed. No physical iPad was used.

Cumulative measured inventory: 14,252 of 14,530 cases. There are 13,582 passes, 131 failures, 515 skips, 23 timeouts and one fixture failure. The remaining 278 cases have no current result.

## Main-path measurements

Two-CPU Mac runs alternated the previous and updated runners on the same Linux guest. Each timing is the elapsed median in milliseconds after two warm-up pairs. The ordinary memory, file, process and procfs probes used 32 pairs. The local vector probe used 48 pairs and checked the destination after each workload. The short 1 MiB probe used 64 copies per sample, and a second probe used 2,048 copies. Before the local cursor change, median time increased 4.29% for reads and 5.01% for writes in the short probe, and 3.66% and 3.63% in the sustained probe, respectively.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 175.708 | 175.636 | -0.04% |
| mmap_fault_unmap | 131.445 | 133.205 | +1.34% |
| file_pread_pwrite | 95.531 | 96.569 | +1.09% |
| fork_wait | 19.345 | 19.755 | +2.12% |
| proc_cpuinfo | 1.746 | 1.729 | -0.94% |
| ordinary_open | 75.583 | 75.162 | -0.56% |
| ordinary_stat | 19.244 | 19.354 | +0.57% |
| self_read_64 | 13.853 | 14.067 | +1.54% |
| self_write_64 | 13.902 | 14.011 | +0.79% |
| self_read_1MiB | 3.578 | 3.727 | +4.14% |
| self_write_1MiB | 3.543 | 3.661 | +3.34% |
| self_read_1MiB (2,048 copies) | 113.140 | 116.867 | +3.29% |
| self_write_1MiB (2,048 copies) | 114.839 | 118.335 | +3.04% |

Original test ELF SHA-256: `193ac48fb2afc4b9cd29dda80b1243237897907fad161567bfb40fa493d3bf3f`.

Updated Mac runner SHA-256: `d60fbc6500f46ba6d5454ac9e2aba851f168150a8134fe961f9d60ad0a3667fa`.
