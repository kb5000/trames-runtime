# Unmapped identities and file ownership on ARM64

## Linux behavior

Each environment owns `/proc/sys/kernel/overflowuid` and `overflowgid`. The default for each is 65534. The initial guest user namespace can configure values between 0 and 65535. Child user namespaces observe changes on the next conversion of an unmapped identity. Mapping-file extents use the unmapped sentinel. Credential and capability decisions continue to use actual mappings even when the display value is set to zero. [Linux sysctls](https://codebrowser.dev/linux/linux/kernel/sys.c.html#184) and [user namespace conversions](https://codebrowser.dev/linux/linux/kernel/user_namespace.c.html#613).

Retained proc status files render UID and GID for the opener's namespace. Unix socket messages queued without credentials use the unmapped sentinel internally, so enabling credential delivery after a send respects the receiving namespace's configured values.

Ordinary-file `fstat` reads the metadata of the inode retained by the accepted operation, including ownership and link count after chown, hard link, unlink or descriptor reuse. The capture now records only the effective device and a weak inode reference in place of a 128-byte stat template. A shared file description already retains the inode. Changing the owner of a regular file clears set-user-ID and only clears set-group-ID when group execute is set.

## Original test results

The upstream setgid fixture supports an explicit pair of usable GIDs. The isolated native and Trames runners now pass groups 0 and 1 to this binary. Production guest group lists are unaffected. Previously all 21 cases skipped before the assertions. With the fixture enabled, 19 passed initially. The two chown cases exposed stale ownership from a prepared descriptor and unconditional clearing of set-group-ID on a non-group-executable file.

| Check | Result |
| --- | --- |
| Original ARM64 Linux `setgid` binary | 21/21 on native Linux, Mac HVF and the interpreter |
| Mac in batched test mode | 21/21 using the same group pair |
| Original `ProcFilesystems.OverflowID` | Previously failed with ENOENT, passed on Mac HVF and the interpreter |
| Mac targeted rerun | 115 passed with matching original XML, 20 skipped, 0 failed across 135 cases |
| Additional guest checks | Both backends covered live ID changes, retained proc status, late maps and six Unix socket credential combinations. Mac also checked retained fstat after unlink and replacement |
| Product coverage | Shared runtime CI on macOS and the iPad FFI device-target compile passed. Interpreter checks ran on the Mac host |

Replacing these 135 rows in the existing 3,163-case Mac inventory gives **2,924 passed, 114 failed, 98 skipped, 25 timed out, one fixture failure and one case without a result**. One previously failing case and 21 previously skipped cases now pass.

## Paired performance

Release builds of the previous Mac runtime (`b7fff31`) and the candidate alternated first position. Each median is from 16 measured samples after two warmup pairs, in guest workload milliseconds.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| fstat open file | 27.99 | 28.00 | +0.03% |
| getuid | 103.98 | 103.59 | -0.37% |
| ordinary stat | 19.15 | 19.04 | -0.59% |
| ordinary open | 74.66 | 74.28 | -0.52% |
| memory | 176.48 | 177.30 | +0.46% |
| mmap fault unmap | 133.44 | 132.97 | -0.35% |
| file pread pwrite | 95.90 | 96.84 | +0.98% |
| fork wait | 19.39 | 19.44 | +0.25% |

These measurements cover syscall and memory probes. Raw results and benchmark samples are in the iPad checkout under `target/gvisor-overflow-20261120`. The native reference for the setgid suite is in `target/local-ci/io/gvisor-overflow-setgid-20261120`.
