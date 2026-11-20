# UTS sysctl files and change notifications

The seven gVisor cases for kernel hostname and domainname passed on the native ARM64 Linux reference. At runtime revision `214492d`, both files existed and matched `uname`, but all three change-notification cases failed with `EPERM` on `epoll_ctl(ADD)`.

## Behavior

Reads and writes through a retained file descriptor use the caller's current UTS namespace. Each guest has separate notification counters for hostname and domainname. Independent opens observe changes separately, while duplicated descriptors share one observation cursor. Setting a name through its system call or writing the proc file wakes subscribers. The shared runtime uses the existing resource wait mechanism. [Linux UTS sysctl implementation](https://github.com/torvalds/linux/blob/v7.0/kernel/utsname_sysctl.c) · [Linux proc sysctl poll implementation](https://github.com/torvalds/linux/blob/v7.0/fs/proc/proc_sysctl.c)

The proc text interface accepts up to 64 name bytes and stops at a newline or NUL. Tests cover partial writes, explicit offsets, writes beyond the current string, a shared file position and permission changes after opening the file. [Linux string sysctl handler](https://github.com/torvalds/linux/blob/v7.0/kernel/sysctl.c)

## Verification

| Check | Result |
| --- | --- |
| Mac hardware executor, original gVisor tests | 60 passed across epoll, poll, uname and the two UTS proc test groups, each in a fresh store |
| Shared interpreter, original gVisor tests | All seven hostname and domainname cases passed |
| Resource ownership regressions | Independent opens, duplicates, repeated edge-triggered notifications with an empty interest mask, inherited descriptors after unshare, and isolation across guest instances |
| Blocked waiters | Two guest threads opened the same sysctl independently and blocked in epoll. One proc write woke both, each reported its own event data and each queue drained |
| iPad build coverage | The device-target FFI crate passed compilation. The interpreter tests ran on the Mac |

Applying these 60 results to the previous 3,163-case inventory changes three failures to passes. The cumulative totals are 2,896 passes, 121 failures, 119 skips, 25 timeouts, one fixture failure and one missing result. Each pass in this batch was checked against its original test XML.

## Performance

Before and after builds used the same Mac hardware executor, guest fixture and two-CPU configuration. Each table entry is median elapsed guest workload time from 16 paired samples per build after two warmups. The execution order alternated between pairs.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| poll on a readable eventfd, 8,000 | 10.24 | 10.26 | +0.20% |
| Level-triggered epoll wait, 8,000 | 10.60 | 10.53 | -0.63% |
| Eventfd read/write and edge-triggered epoll wait, 4,000 | 14.72 | 14.77 | +0.39% |
| Memory access | 177.39 | 174.44 | -1.66% |
| Map, fault and unmap | 134.30 | 131.02 | -2.44% |
| Private pread/pwrite | 96.58 | 95.38 | -1.24% |
| Fork and wait | 19.53 | 19.50 | -0.14% |

Raw XML, inventory, guest probes and all timing samples are in `target/gvisor-uts-watch-20261120` in the iPad checkout.
