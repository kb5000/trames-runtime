# gVisor miscellaneous and PIDFD_THREAD batch

This batch selects the 27 miscellaneous cases and six `PIDFD_THREAD` cases
from the November 23 Trames gap ledger. The test binaries and their hashes
come from the November 17 ARM64 inventory. The native reference used Linux
7.0.0-43-generic. Both Trames executors use isolated Alpine stores, two guest
CPUs and internal guest networking.

The original binaries run in two modes. Twenty cases use the upstream
`TEST_ON_GVISOR=trames` switch, passed by `--test-on-gvisor`, to exercise
the userspace-kernel ABI paths. The other 13 use the ordinary harness settings.
`--mount-fusectl` mounts the guest control filesystem in the FUSE case's
test directory. The Mac harness allows 90 seconds for
`MmapEternalTest.PageTableLeak`. The interpreter run uses a 120-second case
timeout. Neither mode changes the guest's reported kernel release.

| Executor | Baseline pass | Baseline skip | Baseline fail | Baseline timeout | Candidate pass |
| --- | ---: | ---: | ---: | ---: | ---: |
| Mac hardware virtualization | 1 | 24 | 7 | 1 | 33 |
| Interpreter | 2 | 24 | 7 | 0 | 33 |

Both candidates passed all six PIDFD_THREAD cases and all 27 miscellaneous
cases. The page-table pressure case took 54.75 seconds on the Mac candidate
and 60.29 seconds on the interpreter during the final run. All eight steps
of the local Runtime CI passed, with 1,924 tests passed and 31 ignored.
The iOS ARM64 FFI build check and 18 harness unit tests passed. The Mac
runner also passed 176 previously passing original gVisor cases in the
affected suites.

The Mac performance fixture ran 32 measured samples per runner, alternating
the baseline and candidate after two warmup samples for each. Values are
median guest elapsed times in milliseconds.

| Workload | Baseline | Candidate | Change |
| --- | ---: | ---: | ---: |
| Memory access | 177.930 | 177.872 | −0.03% |
| mmap, fault and unmap | 139.684 | 139.040 | −0.46% |
| File pread and pwrite | 99.387 | 98.770 | −0.62% |
| Fork and wait | 20.014 | 20.010 | −0.02% |

The final candidate SHA-256 fingerprints were
`a16d81e3d5255cd42f5ebcd3b3784894a5e363fe5e98ed40ac9e3ddb9daa2cdb`
for the Mac runner and
`9c17de4090c30f89e4b1ada870996943a4c6663c220e6d5b4a6d2f666f46ef1b`
for the interpreter. This is a selected-case rerun of the November 23
ledger.

## Runtime behavior

- A thread pidfd retains the original TID. The process wait record supplies
  delayed readiness for a leader. For a traced nonleader, the observer keeps
  the PID descriptor through wait consumption, including after execution
  resources are released. A nonleader exec retires the original TID and
  retains the existing leader PID and its descriptors.
- Empty-path `linkat` checks the descriptor's open credentials or
  `CAP_DAC_READ_SEARCH` in the opener's user namespace. A path walk through
  a removed directory retains the original parent chain. Overlay lookup
  projects a newly encountered lower inode under an existing visible
  directory, including its mode and ACL. A zero-length POSIX ACL clears it.
- `FALLOC_FL_KEEP_SIZE` preserves logical EOF and file position while
  reserving storage. Ordinary file data/hole seeking uses the generic
  data-to-EOF model. Global expedited membarrier targets registered memory
  domains through their existing execution leases. The vDSO calibration
  page appears as `[vvar]` and rejects writable guest protection.
- A mounted `fusectl` exposes a write-only abort endpoint for each active
  FUSE connection. An additional mount using the same daemon file retains
  that connection and its readiness state.
- The procfs network knobs are namespace-local. The guest IP stack uses
  the IPv6 defaults for socket binding, automatic flow labels and
  reassembly timeouts. `tcp_recovery` retains its configurable ABI value.
  TCP retransmission continues to use the existing transport implementation.
  `vm.max_map_count` exposes the runtime's fixed mapping-descriptor limit.
  nftables table and chain destruction is idempotent. IPv6 route requests
  retain their installed route type.

The detached-overlay and refused-peer veth assertions also exercise existing
behavior. The baseline `chown` capability case already passed on both
executors. The page-table pressure case already passed on the interpreter.

The Linux references for PID readiness, link authorization, eventfd writes,
and IPv6 route types are the [v6.15 pidfs implementation](https://raw.githubusercontent.com/torvalds/linux/v6.15/fs/pidfs.c),
[linkat credential change](https://github.com/torvalds/linux/commit/42bd2af5950456d),
[v6.9 eventfd implementation](https://raw.githubusercontent.com/torvalds/linux/v6.9/fs/eventfd.c),
and [v7.0 IPv6 route implementation](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv6/route.c).
