# Executable files, shared filesystem contexts and sysfs

The Mac ARM64 runner reran 381 distinct upstream cases across exec, exec_binary, fork, memfd, open, truncate, mount and rename. The reference was runtime `3e8f6e2bc6d69810fe037bf0d1ae413ed718faec` with gVisor `89cacadae21eca4270a8f7c79281d0426d33ac5f`. Repeated cases use the last verified result. The 342 passes have matching original GoogleTest XML. The other results were 16 failures, 19 timeouts and four skips.

| Original case | Previously | Current | Change |
| --- | --- | --- | --- |
| ExecTest.RunningBinaryIsNotWritable | Failed | Passed | Per-inode writer and execution lifetimes |
| ExecTest.SUIDExecDoesntGainUIDWithSharedFSContext | Failed | Passed | Group-external filesystem sharing suppresses privilege gain |
| ExecTest.InterpreterScript | Failed | Passed | Real Bash and its loader in the test rootfs |
| RenameTest.SysfsFileToSelf | Failed | Passed | Writable sysfs mount in the guest, matching the native fixture |
| RenameTest.SysfsDirectoryToSelf | Failed | Passed | Same mount behavior for a directory |

- A writable open retains its claim in the open file description. A running image retains its claim through fork. Temporary truncate work retains its claim while deferred. The VFS regression exercises hard links, unlink, duplicate descriptors, read-only opens, truncate and release of the final image.
- Exec checks filesystem sharing before publishing potentially elevated credentials. The check uses admitted group members and live filesystem owners. A separate test run on the previous binary with the new Bash fixture still failed the running-binary case. The script passed on both versions with Bash present.
- The initial sysfs mount is read-only. Explicit mounts, detached mounts and remounts honor requested flags. The guest VFS continues to enforce individual pseudo-file permissions and inherited mount restrictions. Both mount and rename fixtures remount the disposable guest sysfs to match the native reference. All 161 original cases across these two suites passed together.
- The local Bash fixture used the pinned Alpine archive with ARM64 Bash, glibc loader, libc and libtinfo from the Debian test root. Its SHA-256 was `26ed979f3f706d31bc443756d2ab019cdc54ae9c5f76e3508dd2d3ce8568fcb3`. The same five original cases also passed on the iPad interpreter executed locally. The iOS ARM64 FFI compiled.

The cumulative inventory is 3,057 passed, 77 failed, 82 skipped, 22 timed out, one fixture failure and one missing result across 3,240 cases. The 2,859 cases outside this selection retain their preceding evidence. Remaining exec failures include file capabilities and tracing. No timeout was reclassified as a pass.

## Performance

On the same Mac, each probe alternated baseline and candidate in both orders, with two warm-up pairs and 16 measured pairs. Median elapsed-time changes were getuid −0.37%, stat −0.21%, open +0.98%, memory +0.16%, mmap/fault/unmap +1.94%, pread/pwrite +0.03% and fork/wait +1.30%. These are local microbenchmarks.
