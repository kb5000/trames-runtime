# Memory locking, System V semaphores, process limits and overlay ACLs

The Mac ARM64 runner executed 400 upstream gVisor cases from 11 complete suites
against disposable guest stores. The comparison uses the same case names and
upstream binaries at revision `89cacadae21eca4270a8f7c79281d0426d33ac5f`.
The baseline runtime is `5f750931671f68996eb7c01b7bba4d9a4f643ab5`.

| Suite | Cases | Previously passed | Now passed |
| --- | ---: | ---: | ---: |
| System V semaphores | 30 | 0 | 30 |
| Memory locking | 20 | 0 | 20 |
| POSIX ACLs | 111 | 95 | 97 |
| Memory residency queries | 5 | 4 | 5 |
| Resource limits | 7 | 5 | 6 |
| Fork, madvise, mremap, msync, message queues and unshare | 227 | 216 | 216 |
| Total | 400 | 320 | 374 |

All 374 passes have matching original XML records. The other results were 11
failures, 14 skips and one missing result. Every previous pass remained a pass.
Updating the [previous inventory](gvisor-core-apis-20261119.md) with these 400
records and retaining 2,598 earlier observations gives 2,366 passes, 482 failures,
120 skips, 26 timeouts and four missing results.

## Runtime behavior

- Memory locking tracks ranges and quotas on the original address space.
  Ordinary guest loads and stores keep their existing access path. Fork starts
  with fresh lock state. Shared address spaces retain their range state across
  mapping changes. Eager and on-fault modes describe guest residency. The host
  retains its normal physical memory and compression policies.
- System V semaphore sets live in the IPC namespace. Each atomic operation
  array commits under its set lock. Waiting uses the existing retained syscall
  path and releases the execution slot. Undo records follow task membership
  through fork, shared creation, exec, unshare and exit. A separate guest
  lifecycle probe exercised those transitions, including last-member undo.
- The proc limits table reports all 16 entries using the same underlying limit
  values as the resource-limit syscalls. Stacked lower overlays now support the
  two tested ACL copy-up paths.

Eight mremap failures remain around zero-length source aliases and shrinking
across mappings. One ACL case creates a lower device *after* the overlay has
mounted and the merged lookup misses it. Two unshare cases still fail for
`mbind(MPOL_MF_MOVE_ALL)` and `PR_SET_MM`. The shared-anonymous mremap death
test returned no case result.

## Cost on the ordinary paths

A single guest thread ran the same ARM64 executable in a two-CPU environment.
The two runners alternated order. Each had two warmups and 16 measured runs.
Values are median guest elapsed milliseconds, so a positive change is slower.

| Workload | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Read and modify a 16 MiB working set, 1,024 passes at 64-byte strides | 168.85 | 169.31 | +0.27% |
| 8,000 map/fault/unmap cycles | 126.37 | 126.88 | +0.41% |
| 20,000 pairs of 4 KiB writes and reads | 100.90 | 101.07 | +0.16% |
| 150 fork/wait cycles | 18.88 | 19.56 | +3.60% |

The initial eight-pair run used a 64-pass memory loop taking about 11 ms and
measured +6.46% on that loop. Extending the loop sixteenfold gave −1.13% on
the intermediate build and +0.27% on the final build. Fork/wait was slower
in all three comparisons (+2.35%, +1.27%, +3.60%). Its final difference is
about 4.5 microseconds per fork/wait pair.

The shared runtime passed both native ARM64 workflows, including the reclaim
checks. An initial interpreter run under build load ended a file-control test
at its 10 ms host checkpoint before guest completion. The fixture now waits
for the existing single cohort to become idle and retains every syscall,
marker and dispatch assertion. It passed 32 consecutive runs. The full
interpreter regression then passed 500 cases with three existing ignores.

Raw results, XML audit, the combined inventory and paired timings are under
`target/gvisor-locks-semaphores-20261119` in the iPad checkout. The final
runner SHA-256 is `bd92505e08165ddc37f697d203c6ca7ed01b6ce41f97c3b29e2634eaab427c9d`.
