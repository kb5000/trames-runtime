# Guest process memory vectors, 2026-11-22

Both Mac builds ran the same 51 ARM64 gVisor cases in individual processes with the same seven-second deadline and two guest CPUs. Native Linux passed all 51. The previous Trames runtime was `abad0d7`.

| Runtime | Passed | Failed | Timed out |
| --- | ---: | ---: | ---: |
| Previous | 20 | 23 | 8 |
| Updated | 41 | 5 | 5 |

All 20 previous passes held. Eighteen failures and three timeouts became passes. The iPad interpreter running on Mac passed all 21 improved cases, including the 32 MiB sibling-thread transfer. The iOS ARM64 build check and all eight local runtime CI stages passed. Physical iPad execution was not tested.

The syscall now imports the local vectors, handles empty transfers, imports the remote vector descriptors and then resolves the guest PID. The original address-space identity admits copies through the executing task’s own memory view, including a live sibling specified by TID. Missing or exited target tasks return ESRCH for nonempty transfers. Ordinary guest page permissions and partial-copy handling still apply. The ordering and vector limits follow [Linux process_vm_rw](https://github.com/torvalds/linux/blob/v6.12/mm/process_vm_access.c) and [Linux iovec import](https://github.com/torvalds/linux/blob/v6.12/lib/iov_iter.c).

All ten outstanding cases require nonempty transfers to a distinct child address space. In five reads the suite reports ENOSYS. In five writes it records the same error before its child-cleanup wait reaches the harness deadline. Implementing these operations requires retaining the admitted target mm across exec/exit and using its own memory access path.

Another 113 vector I/O and procfs cases kept their previous results (109 passed, three failed, one skipped). All three failures concern the pending per-mapping smaps accounting. The cumulative inventory now measures 14,252 of 14,530 cases: 13,571 passes, 137 failures, 515 skips, 28 timeouts and one fixture failure. The prior cumulative inventory did not include the 51 cases above.

## Performance

Elapsed medians from alternating old/new runs on the same guest. Memory, mapping, file and fork measurements pool two blocks of 32 pairs, procfs/open/stat use 32 pairs, and process-vector timings use 16 pairs. Each block excluded two warm-up pairs. The vector probe checked the full destination after 12,000 small transfers or 64 large transfers.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 174.212 | 175.981 | +1.02% |
| mmap_fault_unmap | 130.736 | 133.218 | +1.90% |
| file_pread_pwrite | 95.049 | 95.617 | +0.60% |
| fork_wait | 19.233 | 19.419 | +0.97% |
| proc_cpuinfo | 1.719 | 1.711 | -0.46% |
| ordinary_open | 74.879 | 74.293 | -0.78% |
| ordinary_stat | 19.330 | 19.326 | -0.02% |
| self_read_64 | 13.666 | 13.776 | +0.81% |
| self_write_64 | 13.677 | 13.708 | +0.23% |
| self_read_1MiB | 3.421 | 3.501 | +2.36% |
| self_write_1MiB | 3.406 | 3.414 | +0.22% |

Individual mmap/fault/unmap blocks changed by +3.03%, +0.09%.

Original Linux test SHA-256: `193ac48fb2afc4b9cd29dda80b1243237897907fad161567bfb40fa493d3bf3f`.

Updated Mac runner SHA-256: `a86db294c9017dedf80113c2033b08709de315abd7b647fce94ff060d8a5b949`.
