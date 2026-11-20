# AArch64 tagged addresses in Linux mapping operations

An ARM64 application can retain a top-byte tag in a pointer to an existing mapping. The Linux ABI accepts that pointer for address-space management, including when the calling thread has not enabled tagged user buffers. Mapping placement has different rules. The fixed target for mremap and fixed mmap must not alias an existing low address through tag removal. [Linux AArch64 tagged address ABI](https://docs.kernel.org/arch/arm64/tagged-address-abi.html)

The shared Linux runtime normalizes an existing mapping address before validation and lookup for munmap, mprotect, mincore, madvise, msync and the source of mremap. Locking and NUMA range operations reuse the same conversion. An in-place remap compares its result to the normalized source before deciding whether to move the allocation cursor. The change is in the syscall implementations and adds no synchronization or per-page work.

## Compatibility

The Mac hardware executor ran all 319 original ARM64 cases in fault, madvise, mempolicy, mincore, mlock, mmap, mremap, msync and munmap. All 319 passed. Runtime 612e3c8 reproduced the tagged munmap failure in a fresh Mac environment. Both fault cases also passed in the iPad interpreter on the Mac, and the iOS device target compiled.

A separate freestanding guest program wrote through a tagged pointer, checked residency, changed protection, synchronized and locked the mapping, and moved its contents. It checked that tagged fixed destinations fail without changing the existing destination byte and that a tagged brk request preserves the break. It then discarded and unmapped another page and checked its residency error. Both candidate executors passed. The old Mac executor failed at the tagged residency query.

Updating the 319 rows gives 3,037 passed, 95 failed, 82 skipped, 24 timeouts, one fixture failure and one missing result across the 3,240-case inventory.

## Main-path timings

The signed Mac binaries alternated on the same two-CPU Alpine environment. Each round had two warm-up pairs and 16 measured pairs. The path probes were repeated after stat increased by 2.44% in the first round. Their table entries use the pooled median from 32 measured pairs. Positive differences indicate longer elapsed time.

| Guest workload | Old median (ms) | New median (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 175.076 | 173.333 | -1.00% |
| mmap_fault_unmap | 138.353 | 136.222 | -1.54% |
| file_pread_pwrite | 95.577 | 95.324 | -0.27% |
| fork_wait | 19.911 | 20.063 | +0.77% |
| getuid | 102.847 | 103.073 | +0.22% |
| ordinary_stat | 19.466 | 19.727 | +1.34% |
| ordinary_open | 73.174 | 73.174 | +0.00% |

The stat repeat measured +1.09%. These runs measure whole guest workloads and do not establish a cause for the difference. Raw samples, upstream XML and the cumulative inventory are under `target/gvisor-tagged-vm-20261120` in the iPad checkout.
