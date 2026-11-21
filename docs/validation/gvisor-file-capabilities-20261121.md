# Guest executable file capabilities

Seven original gVisor failures on runtime `cc0c2c6` passed on the Mac ARM64 hardware backend and on the ARM64 interpreter running locally. Four cover exec with ambient capabilities and no-new-privileges. Two cover overlay CAP_SETFCAP enforcement and revision-3 root ID translation. The seventh verifies that an unprivileged write removes a private file's capability. The targeted interpreter run also passed both controls and retained the upstream platform skip.

The hardware backend replayed 198 distinct cases across capabilities, exec, overlay and xattr. The final results were 197 passes with original GoogleTest XML and one upstream skip. InterpreterScript requires Bash. Its first run on minimal Alpine returned ENOENT. Its passing replay used the previously validated Bash fixture with archive SHA-256 `26ed979f3f706d31bc443756d2ab019cdc54ae9c5f76e3508dd2d3ce8568fcb3`. Combining these results with the preceding inventory gives 6,800 passed, 46 failed, 213 skipped, 20 timed out and one fixture failure across 7,080 unique cases.

## Storage and exec

- Revision 2 and 3 records carry guest capability masks and a namespace-relative root ID. Exec consumes the final executable's record under the accepted image lease. The interpreter named in a shebang supplies the executable credentials. Ambient, inheritable, permitted, effective and bounding sets, nosuid, no-new-privileges, dumpability and AT_SECURE are evaluated together. The implementation follows the [Linux common capability logic](https://github.com/torvalds/linux/blob/master/security/commoncap.c).
- Regular tmpfs files keep the record alongside sparse bytes. The private store keeps a small `.cap` record beside the corresponding `.dat` object only for a granted inode. The grant syncs the backing bytes before publishing the record. The first modification durably removes the record before changing data. Store recovery reads capability records during its existing object scan. An ordinary write uses the existing byte lock. No coordinator or per-write host metadata lookup is involved.
- The storage regression exercises hard links, restart, private mapping, a writable shared mapping, a zero-length write and an overwrite. The Mac CLI backup and restore round trip retained the grant. Modifying the restored copy removed its grant and left the original environment's grant intact. Readers predating this change reject stores or archives containing the new object suffix.
- A potentially writable shared mapping revokes the grant at admission. Installing a new grant with a live mapping writer returns EBUSY. Direct metadata operations on an unmaterialized overlay lower file, arbitrary non-root revision-3 IDs supplied from a child namespace, plain vector-backed RAM files and host-directory passthrough are outside this implementation.

## Local performance

Two warm-up pairs preceded 16 measured pairs, alternating baseline and candidate order on the same Mac. Each value is median elapsed time in milliseconds.

| Probe | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Memory | 176.43 | 178.51 | +1.18% |
| mmap, fault, unmap | 132.70 | 134.38 | +1.27% |
| Private pread, pwrite | 96.31 | 96.76 | +0.46% |
| Fork and wait | 19.81 | 19.45 | −1.84% |

The measurements exercise ordinary operations. The first write to a capability-bearing private inode incurs the separate directory synchronization described above. This run did not measure its latency or simulate power loss. The iOS ARM64 FFI compiled. Physical-device performance was not sampled.
