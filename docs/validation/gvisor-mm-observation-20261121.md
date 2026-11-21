# Guest memory observation on Apple Silicon

The shared runtime reports the guest's fixed address layout through the read-only
`kernel/randomize_va_space` and `vm/mmap_min_addr` entries in proc sysctl.
Both read zero. A regression checks fixed mapping at guest address zero and
repeatable anonymous mapping placement across independent address spaces.

Both original-memory and worker-view `mincore` readers now sample native
anonymous extents from their physical owner. The HVF implementation queries
macOS once per covered extent and translates host granules into the requested
4 KiB guest-page flags. Queries create no guest pages. Hardware residency,
quota ownership and pages whose contents must survive fork are distinct.
The regression queries a native write before a guest wrapper exists and checks
the same guest page after eviction and conversion to an explicit frame.

## Verification

The Mac hardware runner repeated 83 original gVisor cases across madvise,
mincore, mremap and proc. 82 passed with original XML. The remaining failure
is `ProcSysVmMaxmapCount.HasNumericValue`. The two sysctl cases changed from
failed to passed. Across the existing 3,265-case inventory, 3,109 passed,
47 failed, 87 skipped, 20 timed out, one fixture failed and one had no result.
The Mac-hosted iPad interpreter passed both repaired cases and all five mincore
cases. Shared runtime CI passed all eight steps. The signed Mac hardware tests
passed 26 session and 56 HVF cases. The session suite needed updated fcntl
expectations for ignored flags, O_LARGEFILE and the allocated future-write seal.

Per-VMA smaps and smaps_rollup are still absent. The physical-residency
query alone does not establish physical sharing, dirty state or proportional
ownership across fork, COW and file-backed aliases.

## Mac timings

The same two-core private guest alternated the previous and candidate runners
for two warmups and sixteen measured samples per build. Times are medians in
milliseconds. Raw XML, the merged inventory and per-run samples are under
`target/gvisor-mm-observation-20261121` in the iPad checkout.

| Workload | Previous | Candidate | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 176.752 | 176.657 | -0.05% |
| Map, fault and unmap | 133.128 | 133.810 | +0.51% |
| Private file pread/pwrite | 94.641 | 95.055 | +0.44% |
| Fork and wait | 19.297 | 19.578 | +1.46% |
