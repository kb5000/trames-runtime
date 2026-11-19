# User namespaces and Unix compatibility — 2026-11-19

This batch adds real guest user namespaces to the shared runtime. It closes the
72 Unix receive-buffer privilege tests that previously stopped at
`unshare(CLONE_NEWUSER)`, without weakening their assertions. Both products use
the same identity and resource-ownership implementation; no coordinator or
resource service thread is added.

## Identity and authority

- `clone` / `unshare` create a user namespace before other requested namespaces.
  Creation rejects unmapped creator identities, chrooted roots, depth above 32,
  incompatible shared-FS/thread flags and multithreaded `unshare` / `setns`.
- Internal credentials, inode owners and queued socket identities remain global.
  UID/GID conversion occurs at syscall, proc, metadata and ancillary-message ABI
  boundaries. An unmapped identity reads as overflow UID/GID 65534; absent peer
  credentials retain Linux's separate `-1` sentinel.
- `/proc/PID/{uid_map,gid_map,setgroups}` and task aliases have live controls.
  Maps are write-once, validate ranges and parent authority, support the narrow
  own-ID mapping exception and require permanent setgroups denial before an
  unprivileged GID map. Mapping parent root observes `CAP_SETFCAP` requirements.
  A retained OFD keeps its original target and opener; a fresh proc-FD reopen
  captures the new opener. Parent writes are visible without scanning tasks.
- Child-local capability masks do not grant initial-user-namespace authority.
  Ancestor capability and namespace-owner rules follow the parent hierarchy;
  capabilities never extend into ancestors or siblings.
- UTS, PID, mount, IPC, cgroup and network spaces retain their owning user
  namespace. Inherited sockets and TUN controls keep their original network
  authority across later `unshare`. Moving a link between network spaces checks
  both source and destination ownership. Global resource and force-buffer
  operations still require initial-namespace capability.
- `/proc/PID/ns/user`, user-namespace parent/owner queries and `setns` retain
  original namespace resources, not a reusable numeric descriptor or task ID.
  Source workers publish successful identity changes through the existing
  objective credential record and replace only their retained resources.

The implementation follows the relevant [Linux user namespace code](https://github.com/torvalds/linux/blob/v6.12/kernel/user_namespace.c)
and [capability hierarchy](https://github.com/torvalds/linux/blob/v6.12/security/commoncap.c).

## Original upstream comparison

The exact pinned gVisor static ARM64 ELFs and native Linux oracle are reused.
The full prior **17 Unix groups / 6093 cases** are rerun, plus seven complete
credential, mapping, capability and network-namespace groups: **24 groups / 6194
cases** total. No upstream assertion or test source is changed. Every reported
pass is audited against its exact original XML identity.

| Selection | Passed | Skipped | Failed | Timeout |
|---|---:|---:|---:|---:|
| Unix before | 5773 | 248 | 72 | 0 |
| Unix after | 5845 | 248 | 0 | 0 |
| Expanded Trames selection | 5920 | 271 | 3 | 0 |
| Same expanded native selection | 5903 | 270 | 2 | 0 |

The native oracle also has **19 no-result cases**, excluded from successful
comparisons. All **5826/5826 native-passing Unix cases** now pass (previously
5754). There are **zero regressions** among the previous passing Unix cases.
In the expanded selection, **5901/5903 native-passing cases** pass (99.966%).
The other two are an existing netlink link-flag behavior mismatch and an
upstream UID test skipped because Trames reports Linux 5.15, while that test
requires Linux 6.3 or newer. Unexpected skips are not counted as passes.

The three expanded failures are explicitly retained:

- `NetworkNamespaceTest.LinkChangeFlagsLikeLinux`: original Linux passes;
  Trames does not yet implement the full `ifi_change` flag-update semantics.
- `NetworkNamespaceTest.LoopbackAddressesAddedOnUp`: fails in both runs; Trames
  retains an IPv4/IPv6 loopback down/up semantics gap.
- `NetworkNamespaceTest.IPv6FlushedOnDown`: fails in both runs; arbitrary IPv6
  address/route lifecycle support is not completed by user namespace support.

## Scope limits

This is not a full Linux namespace or security conformance claim. Existing
filesystem limitations remain: file capability xattrs, idmapped mounts and
complete set-ID-bit retention for mapped files are not supplied by this batch.
Some global VFS operations deliberately remain initial-namespace privileged.
`NS_GET_PARENT` here covers user namespaces; full PID-namespace-parent ioctl
semantics are not claimed. Other gVisor groups and disabled upstream cases are
not silently included in the pass count.

The initial namespace has no map allocation or map lock. Child maps are
published once and then read without a map mutex; only cold configuration
mutations serialize within the namespace. Packet read/write/poll resources
retain their original direct path. See the paired measurements below for the
actual normal-path cost rather than assuming zero overhead.

## Local validation and evidence

Both complete shared-runtime workflows pass 8/8 steps on macOS and ARM64 Linux.
Linux uses the previously established 8 MiB **test-harness** stack, without a
production stack change. Additional tests exercise retained map OFDs, late
mapping, namespace escape rejection, descendant ownership, mapped metadata,
inherited socket/TUN authority, setgroups policy and clone credential publication.
The iOS target and FFI checks run locally; the physical iPad is not contacted.
Installed apps and existing environments are not replaced or restarted.

[Machine-readable evidence](gvisor-user-namespaces-20261119.json) records exact
case identities, source/binary hashes and performance samples. Ignored raw
logs are under `target/gvisor-userns-20261119`, with Linux workflow evidence in
`target/local-ci/io/gvisor-userns-20261119`.


## Interpreter fixture limitation

The final uninstrumented complete interpreter suite timed out in three bounded
runs. The unchanged 4e14d22 baseline independently reproduces this problem:
2/8 isolated raw-IP runs time out, and 1/2 full runs times out. Captured stacks
show a bounded epoch handoff waiting for worker return; additional diagnostic
output changes the timing. Temporary diagnostics were removed.

The two affected tests are
`raw_ip_scalar_vector_pairs_run_without_owner_on_native_and_packet_stack_transports`
and `complete_socket_controls_use_workers_and_one_filter_decision`. They remain
unchanged and enabled in source. An explicit verification command excluding
these two yields **489 passed / 3 ignored / 2 filtered out**; **24 FFI tests**
and the iOS compile pass. This is **not a fully green interpreter claim**. The
existing bounded-handoff race needs its own follow-up; no production polling,
coordinator fallback or relaxed assertion is added here.

## Normal-path performance

The frozen 4e14d22 binary and candidate use identical nine-scenario source,
compiler, dependency lock, overflow checks and thin LTO. Fifteen alternating
process pairs each run 300,000 iterations after warmups. No conformance workers,
CI/build jobs or disposable Linux VM run during measurement. Existing installed
Dev/Stable environments continue running for both sides.

| Operation | Baseline ns | Candidate ns | Median change |
|---|---:|---:|---:|
| stream-64 | 51.98 | 52.09 | +0.21% |
| stream-4096 | 113.88 | 115.43 | +1.36% |
| dgram-64 | 48.44 | 47.18 | -2.60% |
| dgram-4096 | 109.58 | 110.01 | +0.39% |
| seqpacket-64 | 47.69 | 47.18 | -1.06% |
| recvmsg-stream-64 | 62.11 | 62.82 | +1.15% |
| addressed-dgram-64 | 116.88 | 114.59 | -1.95% |
| addressed-dgram-4096 | 176.34 | 179.58 | +1.84% |
| poll-empty | 5.47 | 5.47 | +0.07% |

Positive changes mean more time. Medians range from -2.60% to +1.84%; paired p10/p90 intervals include zero in every scenario. These samples show no clear systematic I/O slowdown, but do not establish zero overhead or a tight performance bound. Exact samples, ranges and identities are in the JSON.
