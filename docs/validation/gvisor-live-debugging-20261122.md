# Live ARM64 debugging in a Trames guest

GNU GDB 15.2 from Alpine 3.22 ran an AArch64 Linux executable on the Mac hardware backend and the Mac-hosted iPad interpreter. In both runs GDB launched its own inferior, stopped on SIGUSR1, read the signal record and register sets, printed a source-level stack with the argument value, continued the program and saw a normal exit. The iPad result was obtained on the interpreter used by the app. A physical iPad was not exercised.

The test program called a non-inlined function named `retained_frame` with the value 41. It raised SIGUSR1 and returned its argument plus one. Main checked for 42 before printing `debuggee finished`. It was compiled with debug info and frame pointers. The debugger session used these commands:

```gdb
set disable-randomization off
set startup-with-shell off
file /opt/demo
handle SIGUSR1 stop print nopass
run
p $_siginfo.si_signo
info registers pc sp fpsr fpcr
bt 8
continue
```

On both paths the signal number was 10, the program counter was in musl's signal-mask restoration after `raise`, and the stack included `demo::retained_frame (value=41)` and `demo::main`. The demo printed its completion message exactly once. GDB also reported that hardware breakpoint and watchpoint capacity could not be determined. No software breakpoint insertion, instruction stepping or live attach is claimed here. GDB's independent `starti` check on the previous Mac binary already reached the first instruction in the musl loader and read the general registers.

## Runtime changes

* A voluntarily traced child's stop retains its ARM64 CPU state and the original queued signal identity. GDB can read the general and FP/SIMD register sets, signal information and the event message. The worker takes the snapshot at the stop, with no per-instruction tracing or additional coordinator.
* Eligible signals reach the trace stop before the ordinary fatal disposition. SIGKILL stays deliverable. The tracer can discard the stopped signal on continue, adjust the stopped child's signal mask, terminate the child or deliver its original pending signal on detach. Changing a signal into an unrelated signal is outside this implementation.
* On ARM64, a successful PEEKTEXT or PEEKDATA copies exactly eight bytes to the tracer's output word. Remote data uses the existing original-address-space transfer machinery with current access checks. A short read on the remote side returns EIO before touching the output. Ordinary guest page read permissions apply.
* A non-dumpable image carries its inspection user namespace across exec publication and fork. For an unreadable executable or ELF interpreter, the namespace walks up until the file owner and group are mapped. The proc-memory open, process-memory transfer and trace admission checks now require capability in that image namespace when dumpability is disabled.

## Upstream results

The two Mac runs used the same signed candidate and 95 distinct upstream cases. They produced 75 passes, seven failures, one timeout and 12 skips. Six prior gaps acquired a passing result: all three execute-only script/readable interpreter variants, the user-namespace attach-denial test for an execute-only binary, the signal-mask test and the tracer termination test. The attach-denial test exercises the rejection path.

Against native ARM64 Linux, the remaining gap count in this category changed from 38 to 32. The rolling count across the reference inventory changed from 164 to 158. The 32 comprise 25 ptrace, two ELF, two syscall-return, one exec, one proc-memory and one signal-restart case. The latest evidence for these 32 consists of 11 failures, two timeouts, 11 conditional skips and eight unmeasured cases. The full reference inventory was not rerun.

External attach/seize, descendant and nonleader tracing, syscall stops, changing another task's registers or code and signal substitution remain open. Several upstream policy tests select a specific Yama configuration and skip on this guest.

The interpreter passed 17 selected upstream cases individually. All eight local runtime CI stages passed, including the namespace authority and cross-page short-read regressions. The ARM64 iOS FFI target compiled successfully.

## Ordinary workload cost

Two alternating runs with reversed order each excluded two warm-up pairs. Each median combines 64 measurements per version on the two-CPU Mac guest. Positive values mean more elapsed time.

| Workload | Previous (ms) | Candidate (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 169.616 | 169.042 | -0.34% |
| mmap fault unmap | 124.393 | 124.782 | +0.31% |
| file pread pwrite | 96.371 | 96.117 | -0.26% |
| fork wait | 18.323 | 18.300 | -0.12% |
| map unmap file | 14.331 | 14.457 | +0.88% |
| map read unmap file | 79.353 | 79.301 | -0.07% |
| fork shared file | 15.134 | 15.201 | +0.44% |

Previous Mac executable SHA-256 `3bc2308c23ffc9271cb08afe997cfdc21e391a8015c3fbca4988ce818df18e32`. Candidate `dd94c92d7a203435ce4ab8828ae572a46578b64a1624d2e19e36e7717332f8f1`.

Interface references are the [Linux ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html) and [GNU GDB program startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html).
