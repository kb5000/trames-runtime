# POSIX message queues on ARM64

Runtime baseline `72b2b03` failed all 19 cases in gVisor's `mq_test` at
revision `89cacadae21eca4270a8f7c79281d0426d33ac5f`. The updated Mac
hardware runner passed all 19 in disposable two-CPU guests. The iPad CPU
interpreter running on the Mac also passed all 19. The original Google Test
XML identifies every passing case.

| Suite | Cases | Previous passes | Current passes | Failures | Timeouts | Skips |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| POSIX mqueue | 19 | 0 | 19 | 0 | 0 | 0 |
| System V messages and semaphores | 66 | 66 | 66 | 0 | 0 | 0 |
| System V shared memory | 27 | 26 | 26 | 0 | 0 | 1 |
| epoll | 24 | 24 | 24 | 0 | 0 | 0 |
| poll | 25 | 15 | 15 | 8 | 2 | 0 |
| unshare | 5 | 3 | 3 | 2 | 0 | 0 |
| Total | 166 | 134 | 153 | 10 | 2 | 1 |

Across the [rolling inventory](gvisor-shm-20261120.md), 2,460 of 2,998
cases now pass. There are 391 failures, 120 skips, 24 timeouts and three
missing results. The 2,832 cases outside this batch retain their previous
observations.

## Queue operations

Named queues share the IPC namespace's mqueue filesystem. Multiple mounts
resolve the same queue. An open description retains its queue across unlink,
recreation of the same name and namespace changes. Waiting senders and receivers
subscribe to the original queue on the existing I/O wait path. Actual payload
storage is allocated on demand. The real UID's capacity reservation follows
the queue to its last reference. Its size follows the AArch64 message and
priority-node accounting in [Linux mqueue.c](https://codebrowser.dev/linux/linux/ipc/mqueue.c.html#365).

The [additional guest test](../../tests/fixtures/posix-mq.c) ran on both CPU
backends. It covers priority order, FIFO ties, attribute changes through dup,
cross-process delivery, deadline expiry, nonblocking errors, poll and edge-triggered
epoll, reuse of an unlinked name and RLIMIT_MSGQUEUE exhaustion and recovery.
The upstream suite does not send messages. Remaining gaps include mq_notify,
writable mqueue sysctls and hierarchical quota accounting for nested user
namespaces. Native Linux CI and physical iPad execution were outside this run.

## Main-path timing

Both Mac builds used the same guest binary with external Vulkan linkage,
graphics disabled and two CPUs. Two warmups preceded 16 measured pairs in
alternating order. The table gives median guest times in milliseconds.

| Workload | Before | After | Time change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 170.87 | 168.76 | -1.23% |
| Map, fault and unmap | 127.88 | 127.50 | -0.30% |
| 20,000 private-file 4 KiB pwrite/pread pairs | 93.32 | 93.14 | -0.19% |
| 150 fork/wait pairs | 19.11 | 19.21 | +0.55% |

The raw XML, merged inventory and individual timings are in
`target/gvisor-mq-20261120` in the iPad checkout.
