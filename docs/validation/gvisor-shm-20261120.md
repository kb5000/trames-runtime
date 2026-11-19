# System V shared memory on ARM64

The Mac hardware runner executed 253 original gVisor cases from revision
`89cacadae21eca4270a8f7c79281d0426d33ac5f` in disposable two-CPU guests.
The baseline is runtime `bf01f2a`. Every new pass was verified against its
original Google Test XML.

| Suite | Cases | Previous passes | Current passes | Failures | Skipped | No result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shm | 27 | 0 | 26 | 0 | 1 | 0 |
| mmap / munmap | 121 | 121 | 121 | 0 | 0 | 0 |
| mremap | 34 | 25 | 25 | 8 | 0 | 1 |
| semaphore / msgqueue | 66 | 66 | 66 | 0 | 0 | 0 |
| unshare | 5 | 3 | 3 | 2 | 0 | 0 |
| Total | 253 | 215 | 241 | 10 | 1 | 1 |

The single skipped shm case assumes its new segment occupies slot 1. Upstream
skips that assumption on the native platform. The runner retained the original
platform selection and test assertions.

The [previous inventory](gvisor-tmpfs-20261119.md) plus these observations gives
2,441 passes, 410 failures, 120 skips, 24 timeouts and three missing results
across 2,998 cases. Results for the 2,745 cases outside this batch were carried
forward.

## Coverage

The IPC namespace owns segment IDs, keys and metadata. Removing a live segment
immediately releases its key. Existing attachments keep its bytes and ID until
the last detach. The address space owns attachment lifetimes across fork, shared
VM clones, exec, exit, fixed replacements and partial unmaps. Shared anonymous
page providers supply the same bytes through guest CPU and native paths.
Metadata changes use the original IPC resources and mapping operations use the
existing address-space execution path. Ordinary guest loads and stores do not
consult the segment registry.

An additional static ARM64 program ran inside a two-CPU guest. A child saw its
inherited attachment, changed a byte visible in the parent and executed a new
image that verified the attachment count had fallen. The program also exercised
reattachment after removal, a read-only alias, a private replacement in a hole,
and final destruction. Focused library tests cover a new IPC namespace, reused
keys, DONTFORK, moved mappings and regrowth within the segment.

Remaining scope includes SHM_LOCK/SHM_UNLOCK, explicit huge pages and the
procfs/sysctl administration interface. Extending an attachment beyond the
original segment via mremap is currently rejected. This batch did not exercise
iPad hardware or a native Linux CI boot.

## Main-path timing

Both runners used external Vulkan linkage and ran the same guest program in an
isolated, graphics-disabled environment. Two warmups per build preceded 16
paired measurements with alternating execution order. Values are median guest
times in milliseconds.

| Workload | Previous | Current | Time change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 172.31 | 169.87 | −1.42% |
| Map, fault and unmap | 128.07 | 127.25 | −0.64% |
| 20,000 private-store 4 KiB pwrite/pread pairs | 93.61 | 94.34 | +0.78% |
| 150 fork/wait pairs | 19.53 | 19.85 | +1.62% |

Local XML, normalized inventory, timing samples and the extra guest program
are under `target/gvisor-shm-20261120` in the iPad checkout.
