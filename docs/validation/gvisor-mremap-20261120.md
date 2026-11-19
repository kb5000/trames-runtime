# Linux mremap compatibility, 2026-11-20

On the Mac ARM64 hardware executor, 25 of 34 upstream mremap cases passed
before the change. Eight failed and one produced no result. All 34 now pass
in both grouped and case-isolated runs. The ARM64 interpreter also passed
all 34 in a single run. The three proc_pid_smaps failures and one upstream
skip were reproduced unchanged on Mac. The iPad app was not installed or run.

## Guest-visible behavior

- In-place shrink removes the tail across VMA boundaries and preserves
  the surviving mappings and their permissions. A fixed shrink follows the
  guest's Linux 6.12 ordering: reject invalid address overlap, unmap the
  destination, shrink the source, then validate and move the surviving VMA.
  A failure at that last step can leave both the destination and tail unmapped.
- An old size of zero can create a second mapping of a shared object,
  starting at the original page offset. Both addresses refer to the same
  bytes. A focused runtime test also checks access after unmapping the
  original, inheritance of on-fault locking, and rejection of a private source.
- Shared anonymous mmap now retains the original object's page extent.
  Shrinking and re-expanding recovers previously written pages. Expanding
  beyond that extent reserves the virtual address and delivers SIGBUS on
  access. In the baseline, the death test produced no XML and the Mac worker
  reported a page-publication bookkeeping panic. The final death test
  delivered the expected guest signal on both executors.

The syscall ordering follows the [Linux 6.12 implementation](https://github.com/torvalds/linux/blob/v6.12/mm/mremap.c).
The scoped change covers the existing MAYMOVE and FIXED interface.

## Verification and timing

The same 38 original cases ran before and after, on freshly created Mac
stores, grouped and isolated. Passing outcomes were checked against the
original GoogleTest XML. Replacing those rows in the 3,003-case rolling
inventory gives 2,604 passes, 267 failures, 119 skips, ten timeouts, two
without results and one fixture failure. The other 2,965 rows retain
their previous evidence.

Mac before/after used the same guest binary and two CPUs. Each column is
a median of 16 samples, alternating build order after two warmup pairs.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 175.071 | 174.521 | -0.31% |
| Map, fault and unmap | 133.365 | 130.132 | -2.42% |
| Private file pread/pwrite | 98.501 | 96.195 | -2.34% |
| Fork and wait | 19.776 | 19.538 | -1.20% |

Runtime CI passed all eight steps. The product kernel suite passed 500
tests with three ignored. The iOS FFI and Linux ARM64 musl session targets
compiled. The raw runs and timing samples are in
`target/gvisor-remap-smaps-20261120` in the iPad workspace.

## Remaining procfs work

The guest still returns ENOENT for /proc/self/smaps. Its three failing cases
cover private anonymous memory, shared anonymous memory, and a read-only
shared file. The current maps report coalesces by permissions and publishes
resident memory at address-space granularity. Accurate smaps output needs
mapping boundaries and per-mapping accounting. The whole-process resident
count cannot be reused for each VMA.
