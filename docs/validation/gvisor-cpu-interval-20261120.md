# Process CPU interval timers on ARM64

The runtime implements ITIMER_VIRTUAL and ITIMER_PROF on the process CPU clock. Threads share both timers. A fork starts with disarmed timers and exec preserves the process timers. Each existing execution worker checks for expirations at the same boundaries used for CPU limits. An expiration places a standard signal in the shared process queue and prefers the sampling thread for wakeup when its mask permits. A late periodic sample advances to the next deadline on the original schedule. Disarmed timers require no clock sample or timer lock on the worker path. [Linux interval timers](https://man7.org/linux/man-pages/man2/setitimer.2.html)

Trames currently charges guest execution assignments as user CPU time and does not report a separate system CPU time. The virtual and profiling timers therefore advance on the same clock. Parked guest tasks accrue no time. Host preemption during an active assignment can still affect the measurement.

## Upstream validation

With two guest CPUs on the Mac hardware executor, all four upstream itimer cases passed. The previous runtime failed both SIGPROF cases at timer setup. The same two cases passed on the Mac-hosted iPad interpreter. The iPad FFI also built for the device target. No physical device was used.

| Executor and workload | Worker 1 samples | Worker 2 samples | Main thread samples |
| --- | ---: | ---: | ---: |
| Mac active | 796 | 805 | 0 |
| Mac with sleep | 799 | 801 | 0 |
| Interpreter active | 808 | 800 | 0 |
| Interpreter with sleep | 802 | 806 | 0 |

The four existing CPU-limit cases passed on Mac. A deterministic kernel test covers independent one-shot and periodic state, simultaneous expirations, aliasing of old and new values, shared thread accounting, exec, periodic phase and disarm.

ReadvTestNoFixture.TruncatedAtMax now gets past disarming ITIMER_PROF. Its actual readv on /dev/zero still transfers 1,048,576 bytes of the expected 2,147,479,552. The guest vector import and memory-device transport apply an internal chunk limit to the whole syscall. This case remains a failure.

The nine Mac cases above replace their previous inventory entries. Across all 3,240 historical and updated entries, 3,015 passed, 115 failed, 83 skipped, 25 timed out, one fixture failed and one had no result. In the earlier 84-case clock/timer/FIFO set, three previously observed failures remain in process CPU sleep, boottime sleep and POSIX process CPU timer creation.

## Paired performance samples

The two Mac executors alternated against one private guest store per probe. Each workload had two warmup pairs and 16 measured pairs. Times below are median guest elapsed milliseconds. Positive changes mean longer elapsed time.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| memory | 176.25 | 175.74 | -0.29% |
| mmap_fault_unmap | 137.22 | 135.36 | -1.36% |
| file_pread_pwrite | 96.36 | 96.77 | +0.42% |
| fork_wait | 19.32 | 19.23 | -0.44% |
| getuid | 103.44 | 103.51 | +0.06% |
| ordinary_stat | 19.13 | 19.16 | +0.11% |
| ordinary_open | 74.00 | 73.99 | -0.01% |

Original XML, normalized results and per-run timings are under `target/gvisor-cpu-interval-20261120` in the iPad checkout.
