# gVisor cgroup hierarchy and control files, 2026-11-22

The previous runtime was `dbc300aab2c5850f705a0fae033e4c36c5d6bbfa`. Both Mac runners used the same ARM64 gVisor binaries and Alpine rootfs with two guest CPUs, a fresh store per worker and a 12-second timeout per case. Each case ran in a separate test process. The Linux ARM64 reference is the existing original run of the same suite. Passing results were checked against the individual GoogleTest XML entries.

## Behavior

- Creating a group checks the depth and descendant limits of every ancestor. A successful removal releases its ancestor quota immediately, including when an open descriptor still pins the deleted object. Lowering a limit preserves existing groups. Live and dying descendants have distinct counts. The separate runtime storage caps remain 128 live or retained groups and 32 levels. The controls follow the Linux signed, base-zero integer syntax and its `max` sentinel. [Linux implementation](https://codebrowser.dev/linux/linux/kernel/cgroup/cgroup.c.html#3731)
- Removing a populated group or one with children reports busy. Mounting the same cgroup root over itself reports busy. Control files expose empty controller lists, validate process IDs and distinguish malformed input from out-of-range freezer and kill values.
- Cgroup inodes accept user and trusted extended attributes through the existing file permission, capability and read-only mount checks. Tree counters change only when the hierarchy changes. Ordinary opens, file I/O, fork and page faults take no additional hierarchy lock.

## Results

| Same 146 cases | Passed | Failed | Skipped | Timed out |
| --- | ---: | ---: | ---: | ---: |
| Previous Mac runtime | 33 | 39 | 73 | 1 |
| Updated Mac runtime | 49 | 23 | 73 | 1 |
| Native Linux ARM64 | 85 | 0 | 61 | 0 |

The gains include hierarchy limits, creation and removal, PID limits, task migration, population events, invalid freezer and kill writes, mount collision handling and xattrs. All 16 newly passing original cases also passed on the iPad interpreter running on the Mac. The iOS arm64 FFI compiled and all eight local runtime CI stages passed.

The remaining failures include clone placement, delegation and open-time credentials, mount reporting across cgroup namespaces, memory charging, zombie membership and cgroup v1/v2 controller ownership. A frozen process receiving a default fatal signal still times out. Thirteen more v2 cases skip because the guest does not expose their required controllers. The reference and Trames each skip two v2 platform-specific cases.

A further 244 original cases covered ordinary mounts (117), mount file descriptors (41), xattrs (47) and cgroup device-program controls (39). Every outcome matched its baseline. The device-program suite contributed 21 passes, 15 failures and three skips on both versions. Its remaining gaps include attachment flags, program queries and argument validation.

This adds 185 previously unmeasured cases to the cumulative inventory. At equal coverage of 13,635 of the 14,530 discovered cases, passes increased from 12,933 to 12,949 and failures decreased from 168 to 152. There are also 508 skips, 25 timeouts and one fixture failure. The 114 failures in the preceding report covered 13,450 cases.

## Performance

The Mac ran the same guest binaries on the previous and updated hardware runners with two CPUs and networking disabled. Each workload alternated runner order for 32 measured pairs after two warm-up pairs. The table gives median elapsed milliseconds. The hierarchy workload used 32 child groups, 5,000 stat reads and 500 create/remove pairs.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| memory | 167.247 | 166.960 | -0.17% |
| mmap fault unmap | 124.773 | 122.961 | -1.45% |
| file pread pwrite | 92.553 | 92.609 | +0.06% |
| fork wait | 18.415 | 18.422 | +0.04% |
| proc cpuinfo | 1.654 | 1.650 | -0.24% |
| ordinary open | 70.940 | 70.653 | -0.40% |
| ordinary stat | 18.029 | 18.157 | +0.71% |
| subtree stat 32 children | 6.521 | 5.969 | -8.47% |
| cgroup create remove | 11.055 | 10.616 | -3.97% |

The first implementation increased group creation/removal time by 6.60%. The final implementation constructs the control-file index while creating each group and uses the ordered path index to limit removal to that group’s entries.
