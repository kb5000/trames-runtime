# FUSE daemon transport and mount metadata on ARM64

The Mac runner reran all 83 original cases in the gVisor `fuse`, `dev` and `ioctl` suites at upstream revision `89cacadae21eca4270a8f7c79281d0426d33ac5f`. The runtime baseline was `e9a731840ffdeb25ab3e64c698e231edfcfdd12e`. Each case used a fresh guest store. The 77 passes have matching original GoogleTest XML.

| Suite | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| dev | 17 | 0 | 0 |
| ioctl | 42 | 0 | 0 |
| fuse | 18 | 4 | 2 |

The preceding inventory recorded 56 passes, 26 failures and one skip for the same selection. Twenty-one failures now pass. One former failure now reaches its upstream skip condition. There were no timeouts. The cumulative 3,265-case inventory has 3,103 passes, 53 failures, 87 skips, 20 timeouts, one fixture failure and one missing result. Entries outside the selection retain their previous evidence.

## Exercised paths

- The guest opens character device 10:229. A mount publishes its original daemon endpoint and negotiates FUSE 7.31. Cloned daemon descriptions share its request queue. Its final close aborts pending work.
- The guest daemon handles root `GETATTR`, `STATFS` and `ACCESS`. Requests carry the caller's filesystem IDs. Mount access checks the mount owner's IDs. Ordinary permission denials and a daemon declining future access requests with `ENOSYS` are distinct.
- Signals before and after daemon receipt, interrupt priority, `EAGAIN` retry, `ENOSYS`, ignored interrupts, stale replies and fatal cancellation all have original upstream coverage. The three checkpoint-named cases ran in their ordinary Linux mode. They did not exercise VM snapshot restoration.
- An additional transport regression subscribes before mounting and observes three successive notifications. This caught a wakeup that was coalesced indefinitely after the first event. Guest waits use existing task and descriptor subscriptions. There is no additional polling or service thread. The connection lifetime and interrupt protocol follow the [Linux FUSE documentation](https://docs.kernel.org/filesystems/fuse/fuse.html).

The 21 newly passing original cases also passed on the iPad interpreter executed locally on the Mac. Interpreter kernel conformance passed 502 tests with three ignored. The iOS ARM64 FFI compiled.

## Remaining coverage

Guest file data I/O through a FUSE mount is incomplete. Access to a child name still fails in `AccessUnsupported`. `AioRead`, `Fallocate` and `FlushUnsupported` stop at opening the child file. An `O_PATH` descriptor to the mounted root works. Opening it for ordinary directory I/O and unsupported child operations return an error.

`EpollAfterAbort` skips because the guest has no mounted `fusectl` control filesystem. Daemon close and mount teardown exercise connection abort separately. `LookupUpdatesInode` also skips under this fixture. Neither skip contributes to the 21 new passes.

## Performance

On the same Mac, two warm-up pairs preceded 16 measured pairs, alternating old and new release runners in both orders. Median elapsed-time changes were getuid +0.24%, stat +2.09%, open +1.92%, memory +1.49%, mmap/fault/unmap −1.73%, pread/pwrite −1.08% and fork/wait −4.02%. These measure the established ordinary workloads. FUSE file throughput has no result yet.
