# Pipe readiness and descriptor-set bounds on ARM64

The Mac hardware runner executed 275 original gVisor cases at revision
`89cacadae21eca4270a8f7c79281d0426d33ac5f`. Every passing case was matched
to its original Google Test XML. The baseline runtime was `5caeca8`.

| Group | Cases | Previous passes | Current passes | Failures | Skips |
| --- | ---: | ---: | ---: | ---: | ---: |
| poll | 25 | 15 | 25 | 0 | 0 |
| ppoll and pselect | 20 | 18 | 20 | 0 | 0 |
| select and epoll | 33 | 33 | 33 | 0 | 0 |
| pipe and fifo | 167 | 162 | 162 | 1 | 4 |
| eventfd and POSIX queues | 30 | 27 | 27 | 0 | 3 |
| Total | 275 | 255 | 267 | 1 | 7 |

Ten original poll cases gained passes from the runtime changes. Two further
cases intentionally block SIGALRM and wait 30 seconds. Both passed on the
previous runner when given sufficient time (30.47 and 30.23 seconds). The
harness now gives those individual waits 45 seconds by default. Other cases
keep their configured timeout. FifoTest.OpenBlockedAndInterrupted still fails
while setting up its POSIX timer, before it can exercise the FIFO wait.

The [rolling inventory](gvisor-posix-mq-20261120.md) now has 2,472 passes,
383 failures, 120 skips, 20 timeouts and three missing results across 2,998
cases. Results for the other 2,723 cases were carried forward.

## Runtime coverage

Both retained worker waits and VFS queries use the same pipe readiness
calculation, including bidirectional FIFOs, normal read/write masks and
writability concurrent with a disconnected-reader error. Epoll and io_uring
share the directional edge calculation. The queue's existing lock and
notification generation supply the observed state.
[Linux pipe readiness](https://codebrowser.dev/linux/linux/fs/pipe.c.html#695)

Poll uses the calling process's current soft FD limit. Select uses the bitmap
extent of the FD table even after the process lowers its soft limit. Select
keeps read, write and exceptional conditions separate.
[Linux select masks](https://codebrowser.dev/linux/linux/fs/select.c.html#459)

The iPad interpreter on Mac passed all 25 original poll cases.
Both CPU backends passed a [guest ABI test](../../tests/fixtures/poll-masks.c)
covering normal-only epoll edges on a bidirectional FIFO, FD 511 after a
limit reduction, and rejection after close. Native Linux CI and physical
iPad execution were outside this batch.

## Main-path timing

Both builds used external Vulkan linkage and the same guest binaries with
two CPUs and graphics disabled. Two warmup pairs preceded 16 measured pairs
with alternating order. Values are median guest times in milliseconds. The
poll workloads selected the same writable pipe in every array position.

| Workload | Previous | Current | Time change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 171.18 | 170.87 | -0.18% |
| Map, fault and unmap | 128.30 | 131.33 | +2.37% |
| 20,000 private-file 4 KiB pwrite/pread pairs | 93.60 | 94.97 | +1.47% |
| 150 fork/wait pairs | 19.24 | 19.41 | +0.90% |
| 50,000 ready polls with one pipe entry | 62.83 | 62.83 | +0.00% |
| 6,000 ready polls with 64 entries | 38.16 | 37.92 | -0.62% |
| 1,500 ready polls with 256 entries | 32.06 | 31.74 | -0.99% |

Original XML, samples and the merged inventory are under
`target/gvisor-poll-20261120` in the iPad checkout.
