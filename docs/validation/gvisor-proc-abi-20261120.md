# Process-entry ABI and procfs observations

The ARM64 entry stack now includes an AT_PLATFORM pointer to the guest string `aarch64`. The stack and `/proc/self/auxv` describe the same image. Both executors map the common ELF vDSO. When the CPU has no calibrated counter, its zero frequency selects the Linux syscall path before the counter instruction. Only the immutable image template is shared across launches. Code, calibration and permissions remain guest mappings in each image.

The status file reports VmData and VmStk, and statm counts both in its data column. Sizes come from published virtual ranges, their sharing mode, and the provenance of the initial stack. A cached query walks mapping metadata without reading guest pages. Ordinary memory access maintains no additional counters. A memory regression checks a private writable region next to the stack, shared anonymous pages, protection changes, replacement, unmap and fork isolation.

Proc stat sets PF_EXITING for zombies. Namespace symlinks whose target depended on the exited task's nsproxy no longer resolve, while the active PID and credential-owned user namespace remain available through their existing paths. Ordinary file and PTY opens discard creation-only flags after opening, so fdinfo exposes the actual status flags and the descriptor's close-on-exec bit.

## Original test results

The same 23 original proc tests ran on the previous Mac binary (runtime 7aff430) and the updated one, using a fresh store per case. The previous build passed 16, failed six and skipped one. The updated build passed 22 and retained the same upstream skip. All 97 original fcntl cases also passed. Published inventory counts combine 120 refreshed entries with the previous evidence for the remaining cases.

| Cumulative status | Cases |
| --- | ---: |
| Passed | 2,788 |
| Failed | 226 |
| Timed out | 25 |
| Skipped | 121 |
| Missing result | 2 |
| Fixture failed | 1 |

The Mac-hosted iPad interpreter passed the six repaired proc cases plus five related controls. On the first interpreter build, the platform test succeeded while the entry-presence test still failed on AT_SYSINFO_EHDR. The final interpreter run used a fresh store and verified both the ELF platform pointer and the vDSO entry. Physical iPad execution was not measured. Raw XML, the merged inventory and timing samples reside under `target/gvisor-proc-abi-20261120` in the iPad checkout.

The interpreter also passed both upstream monotonic vDSO comparisons (CLOCK_MONOTONIC and CLOCK_BOOTTIME), alternating libc reads and explicit Linux syscalls for ten seconds per clock. Shared runtime CI passed eight steps, the interpreter kernel suite passed 501 cases (three ignored), and the iOS FFI and ARM64 Linux musl build checks passed.

## Timings

Each Mac hardware comparison alternated 16 measured samples per build after two warmups. For the interpreter clock comparison, each timed sample made 50,000 libc CLOCK_MONOTONIC calls. Ten samples per build followed two warmups. The interpreter baseline uses the same proc changes with the vDSO disabled. The probe verified AT_SYSINFO_EHDR absence or presence on every sample. All values are median elapsed times on the same Mac.

| Workload | Previous (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| Mac memory | 177.854 | 175.800 | -1.15% |
| Mac map, fault and unmap | 133.775 | 130.775 | -2.24% |
| Mac private file pread/pwrite | 94.175 | 94.937 | +0.81% |
| Mac fork and wait | 19.189 | 19.374 | +0.96% |
| Interpreter clock_gettime | 14.658 | 12.395 | -15.44% |
