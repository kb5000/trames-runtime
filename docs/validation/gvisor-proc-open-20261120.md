# Global proc text files and ARM64 CPU reporting

The original native ARM64 Linux reference passed all five `ProcCpuinfo` cases and `Proc.RegressionTestB236035339`. In a fresh retest of the previous Mac runtime (`0a58588`), four failed. The CPU report lacked the ARM64 identification and BogoMIPS fields, both write-mode open tests returned the wrong result, and opening an eventfd through procfs with `O_DIRECTORY` returned `ENXIO`.

## File and CPU semantics

For global proc sequence files, the mounted filesystem and the inode's access permissions govern open. A privileged caller can obtain a read/write descriptor on a writable proc mount. The file rejects writes with `EIO` and preserves generated content across `O_TRUNC`. An unprivileged write-mode open of cpuinfo returns `EACCES`. Directory-only opens check the type of a proc descriptor link's target before trying its data operations. The kernel command line also reads from global metadata, independently of any process's argument memory. [Linux proc file operations](https://github.com/torvalds/linux/blob/v7.0/fs/proc/inode.c)

Each virtual CPU reports its feature list and a delay calibration derived from the guest architectural timer. The generic profile reports zero vendor and part identifiers. A guest probe compared the text to a direct `CNTFRQ_EL0` read on each backend. The Mac hardware executor reported 24 MHz and the iPad interpreter reported 1 GHz. [Linux ARM64 CPU reporting](https://github.com/torvalds/linux/blob/v7.0/arch/arm64/kernel/cpuinfo.c)

The interpreter had advertised FCMA at HWCAP bit 16, which Linux assigns to DCPOP. It now sets FCMA at bit 14. One compile-time declaration produces both interpreter HWCAP words and the proc feature names. The instruction audit reassembled its samples and verified the same decode outcomes on all 893 representative encodings. [Linux ARM64 HWCAP definitions](https://github.com/torvalds/linux/blob/v7.0/arch/arm64/include/uapi/asm/hwcap.h)

## Validation

| Coverage | Result |
| --- | --- |
| Six original gVisor cases on the Mac hardware executor and shared interpreter | 6/6 on each |
| Mac related suites | 106 passes with matching XML, three previous failures and three previous skips across 112 cases |
| Direct guest file test | On both backends, all 14 global proc text files preserved read access after read/write open with truncation and rejected positioned writes. Ordinary private files remained writable |
| iPad | CPU crate tests and lint passed and the device FFI target compiled. The interpreter ran on the Mac |

The remaining related failures concern access mode 3, the overflow ID sysctl and seeking an open process-memory file. Refreshing the cumulative 3,163-case inventory with this batch gives 2,900 passes, 117 failures, 119 skips, 25 timeouts, one fixture failure and one missing result.

## Paired performance

The previous and candidate Mac builds alternated order in each pair. Each series used two warmups and 16 measured pairs. The four memory, I/O and process workloads ran a second series because the first mmap median was 2.51% slower. The repeat was 1.72% faster. Their table entries pool all 32 measured samples per build. Results are median guest elapsed times.

| Workload | Pairs | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: | ---: |
| Read cpuinfo at offset zero, 1,000 | 16 | 1.95 | 1.69 | -13.23% |
| Ordinary file open/close, 4,000 | 16 | 74.32 | 74.28 | -0.06% |
| Ordinary file stat, 4,000 | 16 | 19.51 | 19.12 | -2.00% |
| Memory access | 32 | 176.63 | 177.02 | +0.22% |
| Map, fault and unmap | 32 | 131.69 | 132.42 | +0.55% |
| Private pread/pwrite | 32 | 96.00 | 95.17 | -0.87% |
| Fork and wait | 32 | 19.24 | 19.51 | +1.42% |

Raw results, original XML, guest probes and timing samples are in `target/gvisor-proc-open-20261120` in the iPad checkout.
