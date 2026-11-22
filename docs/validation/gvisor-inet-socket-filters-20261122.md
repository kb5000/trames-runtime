# TCP and UDP socket receive filters

The isolated guest network now runs classic BPF on IPv4 and IPv6 TCP and UDP sockets. Filters inspect the original transport header and payload after socket selection. A zero return drops the packet before queuing or TCP state changes. A positive return keeps at least the transport header. UDP multicast and broadcast use the same receive policy as unicast. TCP listener changes apply to half-open slots while established children retain their own policy, including children waiting for acceptance. Attaching to a TCP socket requires CAP_NET_ADMIN in its owning user namespace.

The guest stack reuses the existing verified classic BPF interpreter. An installed program is shared by reference. Ordinary unfiltered ingress has one optional-filter branch, with no extra allocation, packet copy or lock. Coverage applies to guest packet-stack transports. Native macOS and hybrid sockets do not support attachment. Ancillary BPF metadata offsets remain outside the supported instruction set.

Linux reference implementations: [TCP ingress](https://github.com/torvalds/linux/blob/master/include/net/tcp.h) and [UDP ingress](https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c).

## Compatibility

| Original gVisor tests | Previous Mac | Updated Mac | Interpreter on Mac |
| --- | ---: | ---: | ---: |
| TCP and UDP socket filter options | 4/14 | 14/14 | 14/14 |
| Neighboring TCP, UDP, packet and netlink assertions | 114 previously passed | 114/114 | — |

The same binaries and GoogleTest cases were checked against their XML results. Additional tests exercise data-dependent return values, full drop, header-only datagrams, replacement after enqueue, rejection of an invalid replacement, detachment, listener inheritance before accept and multicast truncation. The iOS ARM64 FFI compiled. Validation used the interpreter on the Mac. A physical iPad run was outside this batch.

The cumulative inventory covers 14,372 of 14,530 discovered cases. It now has 13,719 passes, 113 failures, 23 timeouts, 516 skips and one fixture failure. Ten previously recorded failures now pass. All eight local runtime CI stages passed.

## Performance

Both signed Mac release runners used the same two-CPU guest configuration. Each workload had two warmup pairs and 32 measured pairs with alternating order. The entries below are median guest times in milliseconds.

| Workload | Previous | Updated | Change |
| --- | ---: | ---: | ---: |
| udp_64B | 45.51 | 45.79 | +0.62% |
| udp_1400B | 46.59 | 46.67 | +0.18% |
| udp_8KiB | 36.28 | 36.25 | -0.08% |
| tcp_16KiB | 72.15 | 72.14 | -0.01% |
| memory | 174.46 | 175.89 | +0.82% |
| mmap_fault_unmap | 130.75 | 132.12 | +1.05% |
| file_pread_pwrite | 100.54 | 99.47 | -1.06% |
| fork_wait | 19.60 | 19.72 | +0.62% |
