# Process CPU limits, POSIX timer signals and poll deadlines on ARM64

## Behavior

Process CPU limits use the existing guest process CPU clock, including charged execution from sibling and retired threads. The soft threshold sends SIGXCPU and advances by one CPU second. The hard threshold sends SIGKILL. Fork copies the current limits into the child, whose CPU accounting starts independently. Threads share the limit pair and threshold. The process resource-limit interface and procfs expose the same values. Concurrent executors claim a soft expiration under the limit object's existing lock. Unlimited processes skip group CPU sampling. Long-running assignments check limits at guest quantum boundaries and periodically during repeated kernel entries. No timer thread was added. Trames measures time assigned to guest execution, which can include host preemption. [Linux process CPU timer accounting](https://codebrowser.dev/linux/linux/kernel/time/posix-cpu-timers.c.html#986)

The raw AArch64 timer_create entry copies the Linux sigevent and accepts SIGEV_THREAD for process-directed notification. Guest libc owns callback creation. Each POSIX timer has a distinct pending signal record, including when a regular signal of the same number is already pending. Subsequent expirations of the same timer update its overrun count. This keeps the original sender and each timer's payload in delivery order. [Linux timer creation](https://codebrowser.dev/linux/linux/kernel/time/posix-timers.c.html#398) and [Linux signal queuing](https://codebrowser.dev/linux/linux/kernel/signal.c.html#2061)

A retained poll can find no ready file descriptors just before its deadline expires. The wait now reaches its final readiness and output check in this case. An ARM64 upstream test exercising repeated one-microsecond pipe polls in a grandchild exposed the internal EAGAIN escaping to the caller.

## Original test results

The baseline was runtime `16ed6f4`. The same binaries and rootfs ran on the Mac hardware executor with two guest CPUs and a fresh disposable store per focused case. Of the 84 clock, timer and FIFO cases, 69 passed on the baseline, 11 failed and four skipped. A 25-second preliminary deadline interrupted the 30-second AlarmTest.Restart on the baseline. It passed when rerun with the final 110-second deadline. The candidate passed 75, failed five and skipped four. Every changed case went from a failure to an original XML-confirmed pass.

- All seven FIFO cases passed, including interruption of both a blocked reader and a blocked writer.
- All four upstream CPU limit cases passed, covering soft, repeated soft, hard and inherited limits.
- IntervalTimerTest.AlreadyPendingSignal passed, including its signal sender, timer ID, payload and overrun assertions.

A separate run of 100 epoll, poll, ppoll, signal, resource-limit and accounting cases matched every prior classification, with 99 XML-confirmed passes and one skip. The Mac-hosted iPad interpreter also passed all six newly passing cases. The iPad FFI compiled for the physical device target. No physical iPad was used.

Five cases in this expanded clock/timer coverage remain open. The process CPU sleep and boottime sleep each fail one case. The two statistical SIGPROF interval timer cases still lack CPU-time-based ITIMER_PROF delivery. The negative interval case cannot create its process CPU clock POSIX timer to reach its input assertion.

Of these 84 cases, 77 had not been included in the previous 3,163-case inventory. On the previous scope, one additional case passed and failures fell from 113 to 112. Including the additional clock and timer coverage brings the cumulative results to 3,013 passes, 117 failures, 83 skips, 25 timeouts, one fixture failure and one missing result in 3,240 cases. This total combines historical and newly measured results.

## Paired main-path timings

The two Mac runners alternated on the same hardware and guest store, with two warmup pairs followed by 16 measured pairs per workload. Medians are in guest elapsed milliseconds. Positive changes mean longer elapsed time.

| Workload | Baseline | Updated | Change |
| --- | ---: | ---: | ---: |
| memory | 177.70 | 176.44 | -0.71% |
| mmap fault unmap | 134.18 | 133.77 | -0.30% |
| file pread pwrite | 95.36 | 95.76 | +0.42% |
| fork wait | 19.20 | 19.14 | -0.27% |
| getuid | 103.28 | 103.47 | +0.19% |
| ordinary stat | 18.80 | 19.07 | +1.46% |
| ordinary open | 73.58 | 72.70 | -1.19% |

Raw runs, passing XML audits and paired performance samples are under `target/gvisor-time-abi-20261120` in the iPad worktree.
