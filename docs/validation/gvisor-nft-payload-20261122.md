# nftables payload reads, writes and checksums

The reference runtime is `e5e03cc`. The guest packet backend can write register bytes into the IPv4/IPv6 network header or transport packet in place. Later expressions see the edit immediately. Checksum handling covers Internet checksums and transport pseudo-header adjustments. The implementation validates the register range at rule installation and updates only fields that exist in the packet. The namespace backed by native host sockets rejects write rules with `EOPNOTSUPP` because its filter sees a synthetic packet. Link-layer/inner-header writes and SCTP CRC32c remain unsupported. See [Linux nftables payload expressions](https://github.com/torvalds/linux/blob/master/net/netfilter/nft_payload.c).

## Compatibility

| Original gVisor cases | Previous | Current |
| --- | ---: | ---: |
| Payload expressions (9) | 2 passed, 7 failed | 9 passed |
| All Netlink Netfilter (268) | 253 passed, 8 failed, 7 skipped | 260 passed, 1 failed, 7 skipped |
| IPv4/IPv6 UDP interface regressions (46) | 46 passed | 46 passed |

The reference and current runs used the same original test binaries. Runner and fixture hashes, the individual GoogleTest XML and all 268 classifications were checked. Only the seven payload results changed. The remaining Netfilter failure is the packet mark read (`GetMarkValid`). The inventory now covers 14,372 of 14,530 cases, with 13,733 passed, 99 failed, 23 timed out, 516 skipped and one fixture failure. This is cumulative coverage.

All eight local runtime CI stages passed (1,896 tests). The iOS ARM64 FFI compiled and all nine original payload cases passed on the iPad interpreter running on Mac. No physical iPad run was performed.

Runtime tests verify a checksum-adjusted odd-offset UDP payload edit between two virtual nodes, IPv4 and IPv6 destination rewrites with subsequent load/compare in the same rule, zero checksum handling and register bounds. A separate signed Mac runner test installs a Netlink rule, sends 5,000 UDP datagrams, checks the new application bytes at the receiver on every iteration and verifies exactly 5,000 counter hits.

## Performance

Both signed Mac runners used the same two-CPU environment, guest binary and workloads. Each series has two warmup pairs and 32 alternating measured pairs. Values are median guest milliseconds. Positive changes are slower. The payload match test requires its counter to advance exactly 5,000 times.

| Workload | Before (ms) | After (ms) | Change |
| --- | ---: | ---: | ---: |
| udp_payload_match_counter | 150.58 | 150.81 | +0.15% |
| udp_active_output_counter | 153.22 | 153.23 | +0.01% |
| udp_64B | 45.90 | 45.71 | -0.42% |
| udp_1400B | 46.80 | 46.81 | +0.01% |
| udp_8KiB | 36.58 | 36.67 | +0.25% |
| tcp_16KiB | 71.24 | 71.59 | +0.49% |
| memory | 175.96 | 175.48 | -0.27% |
| mmap_fault_unmap | 136.23 | 135.08 | -0.84% |
| file_pread_pwrite | 98.92 | 99.25 | +0.34% |
| fork_wait | 20.13 | 20.02 | -0.52% |
