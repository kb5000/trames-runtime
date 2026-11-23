# gVisor cgroup v2 controllers and BPF revision

The fixed November 23 selection contains 16 cgroup2 cases and one cgroup
device BPF revision case. The baseline is Runtime `002bd1e`. Each original
case ran separately in an isolated Alpine guest with two virtual CPUs.
The binaries and hashes match the November 17 native ARM64 inventory.

| Selection | Baseline Mac HVF | Baseline interpreter | Candidate Mac HVF | Candidate interpreter |
| --- | ---: | ---: | ---: | ---: |
| CPU accounting and controls | 6 skipped | 6 skipped | 6 passed | 6 passed |
| Cpuset | 1 skipped | 1 skipped | 1 passed | 1 passed |
| Memory and domain lifecycle | 2 failed, 6 skipped | 2 failed, 6 skipped | 8 passed | 8 passed |
| v1/v2 controller ownership | 1 failed | 1 failed | 1 passed | 1 passed |
| BPF revision | 1 failed | 1 failed | 1 passed | 1 passed |

The BPF revision row uses the original test's userspace-kernel mode on both
revisions. The default mode skips it at the Linux 6.17 version check. The
guest release string remains `6.0.0-trames`. Across all 126 Mac regression
cases, the default mode produced 121 passes and five skips with no failures.
Four skips select platform-specific paths. The fifth skip is the separately
verified revision assertion.

The guest applies subtree controller changes atomically. New controller
files retain the original cgroup inode and delegated file ownership.
A failed clone or migration cannot place a member inside a non-root domain
that has delegated controllers. A cgroup v1 mount requesting a controller
owned by v2 reports `EBUSY`. The device BPF revision begins at one for
local queries and changes with successful attach and detach operations.

CPU statistics use the original task clocks and settle at migration or exit.
The guest releases a worker slot when its cgroup exhausts its CPU bandwidth.
The run queue applies CPU weights while eligible groups contend for a slot.
The effective cpuset constrains task selection and affinity queries.

Resident anonymous pages keep the memory controller that charged them.
Charges count toward active ancestors, including when a task runs in a
descendant that has no controller of its own. A hard limit rejects the
charge and rolls back the ancestor reservations. Configured OOM-group
policy can terminate the processes in the affected memory domain.
Allocations above the high watermark add a bounded scheduling delay.
Shared page-cache and private COW ownership need dedicated accounting and
acceptance. Linux-style reclaim and Android memory-pressure behavior remain
separate implementation work.

Both executors placed a constrained task on guest CPU 1. With a 20 ms
budget per 100 ms, a 45 ms CPU workload took 219 ms on Mac HVF and 215 ms
on the interpreter. Two groups with weights 50 and 200 sharing one guest
CPU recorded 162,328 and 607,120 microseconds on Mac HVF, and 150,718 and
600,901 microseconds on the interpreter. A 1 MiB hard limit killed both
members of an OOM group on each executor and the remaining charge was zero.
An 8 MiB fault workload above a 1 MiB high watermark completed on both
executors, recorded high events and waited for a scheduling delay.

Local macOS Runtime CI passed all eight steps with 1,932 passed and
31 ignored tests. The iOS ARM64 FFI compiled.

The performance fixture alternated both release runners for 32 measured
samples after two warmups per runner. Values are median elapsed milliseconds.

| Workload | Previous | Current | Change |
| --- | ---: | ---: | ---: |
| Memory access | 178.860 | 179.137 | +0.16% |
| mmap, fault and unmap | 138.706 | 139.829 | +0.81% |
| File pread and pwrite | 98.841 | 98.711 | -0.13% |
| Fork and wait | 20.100 | 20.216 | +0.58% |

Tested runner SHA-256 fingerprints are
`7be8ec36591dc9501236d7ae3fa68a023ebdb9fb1a7ba3101b79041d6714bb42` for Mac HVF and
`66d9cc63d44a010706bd17a9ef466d20b8df8b329cc354616fa7be9776441474` for the interpreter.

ABI references are the [Linux cgroup v2 interface](https://docs.kernel.org/6.17/admin-guide/cgroup-v2.html)
and [Linux cgroup BPF revision logic](https://raw.githubusercontent.com/torvalds/linux/v6.17/kernel/bpf/cgroup.c).
