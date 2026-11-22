# Guest session keyrings, 2026-11-22

The shared Linux runtime implements session keyring lookup, join, describe and permission changes through AArch64 keyctl. Each environment owns its serial registry and separate root and ordinary-user count limits. Each task selects its own session ring. Fork copies the selection, exec preserves it and exit releases it. Threads holding the same ring observe the same permissions. The executing worker checks the caller's current filesystem credentials and supplementary groups. The description maps IDs into the reader's user namespace. Named lookup is scoped to the caller's user namespace. [Linux process keyrings](https://codebrowser.dev/linux/linux/security/keys/process_keys.c.html) · [Linux keyctl](https://codebrowser.dev/linux/linux/security/keys/keyctl.c.html)

The guest can read and change the enabled count limits under `/proc/sys/kernel/keys/{maxkeys,root_maxkeys}`. Both proc files use the same counters and limits as ring creation. This batch covers session ring metadata. Key payloads, request helpers, arbitrary links, byte quotas and other key types remain outside its scope.

## Compatibility results

The previous runner used runtime `5f4f01be03df3d27b7b215d93561060353634980`. Both Mac builds used the same original gVisor test binaries, fresh guest stores, two virtual CPUs and one case per invocation. Each pass was checked against the test's XML result.

| Suite | Cases | Previous runner | Updated runner |
| --- | ---: | --- | --- |
| keys | 31 | 31 failures | 31 passes |
| proc_keys | 3 | 3 failures | 3 passes |
| personality and uname | 14 | 13 passes, 1 skip | 13 passes, 1 skip |

All 34 keyring cases also passed in the native Linux reference and in the iPad CPU interpreter on the Mac. The personality skip is conditional on running under gVisor. Two local regressions additionally verify quota release after the last holder exits and that a child retains its inherited default ring when its parent requests a private session. The iOS arm64 FFI check and all eight stages of local runtime CI passed, with two unchanged setup stages reused.

This batch measured 34 cases that were absent from the previous inventory. After adding their old-runner results, the comparable baseline is 12,964 passes and 171 failures. The updated inventory has 12,998 passes, 137 failures, 508 skips, 25 timeouts and one fixture failure over 13,669 of 14,530 discovered cases.

## Main-path performance

The same Mac alternated previous and current release-mode runners for 32 measured pairs after two warm-up pairs. Both used identical guest fixtures, two CPUs and networking disabled. Median elapsed times include only guest workload execution.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 167.046 | 167.241 | +0.12% |
| mmap fault unmap | 123.953 | 123.093 | -0.69% |
| file pread pwrite | 92.062 | 91.449 | -0.67% |
| fork wait | 18.296 | 18.317 | +0.11% |
| proc cpuinfo | 1.639 | 1.643 | +0.26% |
| ordinary open | 70.717 | 70.672 | -0.06% |
| ordinary stat | 18.350 | 18.211 | -0.76% |
