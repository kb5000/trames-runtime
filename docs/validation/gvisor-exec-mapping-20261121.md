# Guest exec image mapping and vfork timing

The Mac hardware executor ran all 140 original ARM64 cases from exec_binary, exec, vfork and close_range against the same Bash-capable root filesystem. Runtime 5e9ec5e passed 102 cases, failed 12, timed out on 22 and skipped four with the short watchdog. The candidate passed 107, failed 10, timed out on 19 and skipped four. Each pass has original GoogleTest XML.

| Suite | Passed | Failed | Timed out | Skipped |
| --- | ---: | ---: | ---: | ---: |
| exec_binary | 19 | 8 | 18 | 4 |
| exec | 70 | 2 | 1 | 0 |
| vfork | 4 | 0 | 0 | 0 |
| close_range | 14 | 0 | 0 | 0 |

Two historical runtime failures, ElfTest.UnalignedOffset and ElfTest.PIEOverflow, now pass on hardware and on the iPad interpreter running on the Mac. The three vfork watchdog changes recover timeouts in this run's short baseline. All four already had passing evidence in the cumulative ledger. The ledger now has 7,162 passes, 44 failures, 20 timeouts, 213 skips and one fixture failure across 7,440 distinct cases.

## Behavior

- The loader reads the main program and interpreter headers and resolves PT_INTERP before mapping either image. A missing interpreter returns ENOENT and a malformed interpreter header returns ELIBBAD, including when the main image also has an invalid segment.
- A segment page-offset mismatch, a file extent larger than its memory extent, and an unrepresentable guest mapping address are reported to an executing guest as fatal image failures. The existing task-group exit path carries SIGSEGV to the parent. Host launch requests without an admitted guest PID receive a launch error. This models the guest-visible ordering of [Linux ELF loading](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c) and [fatal exec failures](https://github.com/torvalds/linux/blob/v6.12/fs/exec.c).
- For interpreted executables the loader receives the main program's AT_ENTRY and starts at its own entry point. A static executable can start in the mapped file-page prefix. Unit tests cover both cases and interpreter error precedence.
- Upstream vfork cases deliberately sleep for 10 to 20 seconds. Per-case watchdogs allow those waits and retain the explicit per-suite override. A separate 48-second standalone replay passed all four original cases.

A two-thread guest probe ran with both CPU backends. A normal replacement exited 42, the missing-interpreter case returned ENOENT, and three late segment failures each terminated the child group with SIGSEGV. Six interpreter exec lifecycle regressions passed, including nonleader replacement and the multi-CPU and private-store variants. The targeted original interpreter replay passed 19 cases and retained four upstream skips. The iOS device-target FFI compiled.

The remaining exec_binary timeouts include ELF and script tests whose child calls PTRACE_TRACEME and stops itself. Their parent expects waitpid without WUNTRACED to report the traced stop. The shared runtime still lacks this tracing lifecycle. Passing those tests will require a separate traced-stop implementation and verification of the operations performed after the stop.

## Local performance

Both builds used two guest CPUs, the same fixture and the same benchmark binary. Each of two runs discarded two warmup pairs and alternated build order. The second run reversed the starting order. Values are pooled median elapsed milliseconds across 32 measured pairs.

| Probe | Baseline | Candidate | Elapsed change |
| --- | ---: | ---: | ---: |
| 120 /bin/true child launches | 131.42 | 134.58 | +2.40% |
| 120 shell launches followed by exec /bin/true | 265.27 | 265.60 | +0.12% |
| 10,000 private 4 KiB pwrite/pread pairs | 39.20 | 39.30 | +0.25% |
