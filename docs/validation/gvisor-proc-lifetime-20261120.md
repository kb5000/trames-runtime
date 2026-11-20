# Process memory policy files and task directory lifetime

The guest exposes the process leader’s coredump_filter and the process and thread oom_score entries. The filter belongs to the address space. Threads sharing the address space see the same mask, fork copies it, and exec carries the mask into the new image. A retained descriptor follows the original process identity. Reads after address-space release return EOF and reads after reap return ESRCH. This change implements the policy file. Generating ELF core dumps is a separate feature.

The score uses resident guest pages, guest memory capacity and the existing group adjustment. Guest swap and Linux page-table pages contribute no charge in this runtime. The global init, zombies and tasks with the minimum adjustment report zero. The filter and score are independent of host process settings. A directory descriptor opened on a live process’s task directory now reports ENOENT once the process has been reaped. [Linux proc implementation](https://github.com/torvalds/linux/blob/v6.12/fs/proc/base.c)

## Validation

Four selected upstream cases failed on the previous signed Mac executor. The candidate ran all 160 original ARM64 proc cases, with 139 passes, 19 failures and two skips. GetdentsEnoent and SubprocessZombie changed from failure to pass. The other 158 classifications stayed the same. In SubprocessRunning and SubprocessExited, the new memory-policy entries passed their assertions. The missing io entry still fails both cases. Per-task and per-process I/O accounting remain open.

The iPad interpreter on the Mac ran the two newly passing upstream cases. A separate guest shell on each executor checked the default mask, fork and exec inheritance, isolated child writes, octal input, rejection of overflow, and a positive score adjustment. The score moved from 666 to 1000 on the Mac hardware executor and from 667 to 1000 on the interpreter. Both were isolated guest environments. The iOS device target also compiled.

Updating the 160 rows of the cumulative 3,240-case inventory gives 3,039 passes, 93 failures, 82 skips, 24 timeouts, one fixture failure and one missing result.

## Main-path timings

The old and new signed Mac executors alternated on the same two-CPU Alpine store with two warmup pairs and 16 measured pairs per run. The path probe was repeated after stat took 2.47% longer in the first run. The repeat measured +0.52%. The table pools both path runs and reports the median of each workload in milliseconds.

| Workload | Before | After | Change |
| --- | ---: | ---: | ---: |
| memory | 174.740 | 173.876 | -0.49% |
| mmap_fault_unmap | 134.647 | 134.201 | -0.33% |
| file_pread_pwrite | 93.796 | 94.845 | +1.12% |
| fork_wait | 19.492 | 19.459 | -0.17% |
| getuid | 102.709 | 103.506 | +0.78% |
| ordinary_stat | 19.357 | 19.632 | +1.42% |
| ordinary_open | 73.177 | 73.160 | -0.02% |

Raw samples, normalized upstream results and the cumulative inventory are under `target/gvisor-proc-lifetime-20261120` in the iPad checkout.
