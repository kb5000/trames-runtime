# Guest raw IP header inclusion

The reference is runtime `e8d4736`. IPv4 and IPv6 raw sockets on the virtual packet backend now accept protocol 255 and expose their header-inclusion option. Protocol 255 defaults to this send mode. A raw UDP socket can select it independently. Receive matching still uses the actual IP protocol. The virtual interface completes the IPv4 length and checksum, fills an unspecified source address and allocates a nonzero packet ID when one was omitted. Unfragmented IPv4 raw reception preserves header options, the ID and other original bytes. IPv6 senders supply the complete header. These operations use the existing guest routing, filtering, multicast and virtual link paths. Group delivery of caller-built packets uses the existing UDP multicast and broadcast path. Other group protocols are outside this implementation. The native host socket backend is outside this change. See the [Linux raw socket manual](https://man7.org/linux/man-pages/man7/raw.7.html) and the [IPv6 raw send implementation](https://github.com/torvalds/linux/blob/master/net/ipv6/raw.c).

## Compatibility

| Original gVisor cases | Previous | Current |
| --- | ---: | ---: |
| IPv4 IP_HDRINCL (15) | 15 failed | 15 passed |
| Raw IPv4/IPv6 socket suite (155) | 154 passed, 1 failed | 155 passed |
| ICMP datagram suite (37) | 36 passed, 1 failed | 36 passed, 1 failed |
| Broadcast and multicast regression selection (282) | 242 passed, 40 skipped | 242 passed, 40 skipped |

All 16 recovered cases pass on the native ARM64 Linux reference. They also passed on the iPad interpreter on the Mac, and the iOS ARM64 FFI compiled. The 489-case Mac rerun matched case names, original binary and runner digests, and individual GoogleTest XML. The remaining ICMP failure is `PingSocket.ICMPPortExhaustion`, which reaches the guest file descriptor ceiling. The native reference skipped that suite. No physical iPad or external-host traffic was used.

The eight local runtime CI stages passed (1,899 tests). Additional tests verify byte-exact IPv4 options, a supplied and an assigned IP ID, distinct send-route and wire destinations, MTU and short-header errors, multicast TTL and valid IPv6 delivery. The UDP receiver and independent raw receiver observe the same application payload.

The cumulative inventory covers 14,372 of 14,530 discovered cases, with 13,749 passes, 83 failures, 23 timeouts, 516 skips and one fixture failure. Cases outside this selection retain their previous measurements.

## Performance

Two signed Mac runners used the same guest programs and two-CPU internal environment. Each series alternated runner order and used two warmup pairs followed by 32 measured pairs. The raw receive probe checks 4,000 UDP payloads through both the ordinary socket and an independent IPv4 raw socket. Positive change means longer elapsed time.

| Workload | Before (median ms) | After (median ms) | Change |
| --- | ---: | ---: | ---: |
| udp_with_raw_receiver | 280.04 | 279.62 | -0.15% |
| udp_64B | 45.97 | 46.01 | +0.11% |
| udp_1400B | 46.67 | 46.62 | -0.12% |
| udp_8KiB | 36.12 | 36.28 | +0.44% |
| tcp_16KiB | 71.94 | 71.60 | -0.47% |
| memory | 174.87 | 174.18 | -0.40% |
| mmap_fault_unmap | 140.44 | 136.33 | -2.93% |
| file_pread_pwrite | 99.12 | 99.04 | -0.08% |
| fork_wait | 19.99 | 19.97 | -0.13% |
