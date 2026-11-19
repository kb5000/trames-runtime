# ARM64 executable images and interpreter scripts

Two complete upstream suites used identical binaries and runfiles on the Mac
hardware executor. The baseline was runtime `e1d8e6a`. The candidate ran each
case in isolation. All 79 passes were matched to original XML.

| Suite | Before (pass / fail / timeout / skip) | Updated |
| --- | ---: | ---: |
| exec | 57 / 15 / 1 / 0 | 62 / 10 / 1 / 0 |
| exec_binary | 13 / 32 / 0 / 4 | 17 / 10 / 18 / 4 |

Nine former failures passed. All 70 previous passes stayed green. Another 18
former failures timed out after the loader changes. They remain unresolved.
Across the historical inventory of 3,163 cases, 2,742 passed, 269 failed,
28 timed out, 121 skipped, two lacked results and one had a fixture failure.
Only these 122 cases were re-run.

## Executable behavior

- Linux reads the ELF64 program table using its offset, count and entry width.
  The loader now accepts a zero e_ehsize. It maps the prefix of a file page,
  handles the zero-filled tail at EOF, and gives later overlapping PT_LOAD
  segments their own bytes and permissions. File-backed pages carry the
  accepted image inode, file offset and path into proc maps. Entire anonymous
  BSS pages keep their own identity. Full missing file pages remain unsupported.
- Relative PT_INTERP names resolve in the caller’s working directory. Static
  interpreters may occupy a fixed address. A wrong-architecture interpreter
  returns ELIBBAD. Interpreter lookup runs under the original credentials.
  Its read access also contributes to the resulting process dumpability.
  The guest exposes the current fixed fs.suid_dumpable policy (zero).
- Script parsing handles space, tab, NUL termination, bounded partial optional
  arguments and five interpreter-script levels. Argv and envp share one
  allowance of a quarter of Trames’ fixed 1 MiB stack. A string including its
  NUL is limited to 32 guest pages. Tests cover pointer charges and exact limits.

See the Linux [ELF loader](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_elf.c)
and [script loader](https://github.com/torvalds/linux/blob/v6.12/fs/binfmt_script.c).

## Separating image execution from debugger support

Independent programs returned their expected exit codes on both the Mac
hardware executor and the iPad interpreter backend for a fixed executable,
PIE, overlapping load segments, dynamic and fixed interpreters, a relative
interpreter name with bytes following the NUL, and a five-level script.
The probes also checked a NUL-terminated script argument and proc maps.
The interpreter passed a further 19 selected original gVisor tests.

A syscall trace of upstream ElfTest.Execute shows the child entering its new
image, receiving -ENOSYS from PTRACE_TRACEME and sending itself SIGSTOP.
The parent is waiting without WUNTRACED. A successful exec is insufficient
to pass this debugger-dependent case. The unchanged Alpine test root also
lacks the /bin/bash requested by the original exit_script fixture.

## Normal-path performance

The same Mac alternated old and updated runners. The first four measurements
pool 32 timed samples per build across two runs, excluding warmups. The last
row measures host elapsed time for launching a shell and executing BusyBox
60 times, with 16 timed samples per build.

| Workload | Baseline ms | Updated ms | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 175.395 | 176.065 | +0.38% |
| Map, fault and unmap | 129.408 | 132.555 | +2.43% |
| Private file pread/pwrite | 95.206 | 96.250 | +1.10% |
| Fork and wait | 18.857 | 19.043 | +0.99% |
| 60 BusyBox executions | 143.145 | 143.056 | -0.06% |

The runtime CI passed eight checks. All 500 enabled interpreter kernel
conformance tests passed, with three ignored. The additional argument-boundary
test passed separately. iOS FFI and ARM64 Linux musl session targets compiled.
Local evidence is under `target/gvisor-exec-image-20261120` in the iPad checkout.
