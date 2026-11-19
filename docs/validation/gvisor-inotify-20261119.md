# File notification compatibility

The Mac ARM64 runner executed all 80 original gVisor inotify cases against a
fresh private store. The upstream revision was
`89cacadae21eca4270a8f7c79281d0426d33ac5f`, and the baseline runtime was
`3c32cc20469c9ae4a23ecf9d91625cd197453a66`.

| Selection | Previous pass | Final pass | Failed | Skipped | Timed out |
| --- | ---: | ---: | ---: | ---: | ---: |
| inotify (80 cases) | 48 | 79 | 0 | 1 | 0 |
| 15 related file, metadata and execution suites (449 cases) | 344 | 344 | 78 | 26 | 1 |
| Total | 392 | 423 | 78 | 27 | 1 |

Each of the 423 passes has a matching original XML testcase. The inotify
improvement covers 29 assertion failures and two waits. The original
`IllegalSeek` case skips itself on this platform. The remaining timeout is an
existing exec/ptrace case. Updating the [previous inventory](gvisor-memory-locks-semaphores-20261119.md)
with these 529 results gives 2,397 passes, 453 failures, 120 skips, 24 timeouts
and four missing results. The other 2,469 observations carry forward.

## Delivery and lifetime

An accepted read or write consults the original open file description and its
live inode and parent watches. Registering a watch after open, replacing a
one-shot watch, moving a file, or unlinking it while open affects the next
operation. Prepared file capabilities retain a weak notification lease. In the
ordinary unwatched case, the inode and original parent's interest bits avoid
locking the queue or looking up the pathname.

Directory reads, proc file reads, executable opens and reads, timestamp changes
and link-count changes issue the events checked by the upstream suite. A
pathname truncate retains the resolved file without generating user-visible
open/close events. Directory removal publishes the parent's delete event and
the child's final removal according to the lifetime of the open directory.
The tests also cover exclusion of events after unlink and event order when
the same instance watches both a file and its parent.

## Waits and elapsed time

The blocking read case finished in 0.084 s. The thousand-directory epoll case
timed out on the baseline both with the standard deadline and with a dedicated
60 s allowance. The intermediate build finished it in 21.746 s in isolation.
The final build finished in 26.971 s in the four-worker suite run, with a 60 s
allowance for inotify. The native Linux reference measured 5.081 s. This stress
test remains appreciably slower on the private store.

The paired benchmark used the same ARM64 guest fixture as the previous report,
with two warmups and 16 measured runs per runner in alternating order. Values
below are median guest milliseconds.

| Workload | Baseline | Final | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 171.39 | 171.02 | −0.21% |
| Map, fault and unmap | 130.11 | 128.34 | −1.36% |
| 20,000 unwatched 4 KiB pwrite/pread pairs | 100.52 | 94.24 | −6.24% |
| 150 fork/wait pairs | 19.62 | 19.91 | +1.48% |

One measured pair was visibly slower on both runners and is included in the
medians. These figures cover ordinary guest I/O and do not measure throughput
with many active listeners. The local evidence directory is
`target/gvisor-inotify-20261119` in the iPad checkout. The final runner
SHA-256 is `e15cb5cc96d0e13be5d5febbaaa9cf41b9dac77e7ac2d3d9bdc3dd44ab6d57e2`.
