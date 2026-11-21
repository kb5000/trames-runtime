# UDP error delivery and extended error queues

The comparison uses shared runtime `09d1ead` as its baseline. The guest-owned UDP stack now attributes incoming ICMP destination-unreachable messages to the original local binding using the quoted IP addresses and UDP ports. The existing readiness source wakes the socket's reader. A connected socket can consume a hard error once through normal I/O or SO_ERROR. An application that enables IP_RECVERR or IPV6_RECVERR can also read the corresponding record through MSG_ERRQUEUE.

Error records retain the destination, reporter and available bytes from the quoted payload. The queue shares one receive budget across a socket's address handles and charges empty records as well. SO_ERROR consumes the pending code independently of queued records. Reading the queue never waits for a normal datagram. An oversized IPv6 send reports a local EMSGSIZE with the outgoing interface MTU. An oversized IPv4 datagram fails synchronously.

The normal UDP payload path checks a socket-local pending-error word. Payload copying into the error queue and the error-queue lock are confined to error handling and configuration. No worker or coordinator is added. Path-MTU discovery and router Packet Too Big handling remain separate work. The host-native BSD socket backend retains its existing capabilities.

The Linux reference for destination-unreachable code translation is the IPv4 and IPv6 ICMP implementation. The socket's family determines the ancillary message format, including mapped addresses. [IPv4 ICMP](https://github.com/torvalds/linux/blob/master/net/ipv4/icmp.c) · [IPv6 ICMP](https://github.com/torvalds/linux/blob/master/net/ipv6/icmp.c) · [IPv6 error delivery](https://github.com/torvalds/linux/blob/master/net/ipv6/datagram.c)

## Original syscall tests

| Mac hardware execution | Previous passes | Updated passes | Remaining failures | Upstream skips |
| --- | ---: | ---: | ---: | ---: |
| UDP socket | 149 | 158 | 6 | 0 |
| UDP loopback pairs | 524 | 530 | 6 | 16 |
| Generic TCP and UDP loopback pairs | 24 | 24 | 0 | 0 |
| Total | 697 | 712 | 12 | 16 |

All 712 passes have original GoogleTest XML. The 15 newly passing cases agree with the native ARM64 Linux reference. The iPad interpreter on the Mac passed all 16 focused cases, including the previously passing wrong-family option check. The iOS ARM64 build check and all eight steps in local runtime CI passed. This run used no physical iPad.

The runtime regression tests additionally exercise truncated ICMP quotations across two namespaces, SO_ERROR alongside unread error and data queues, bounded admission of empty records, per-family queue cleanup, and reuse-port selection for 32 distinct peer ports. The standalone transport suite has 610 passes and the same five baseline failures in IPv4 and 6LoWPAN.

Twelve failures in the three replayed suites concern forced receive buffers (6), socket filters (4) and path-MTU discovery options (2). Across 12,766 measured cases of 14,530 discovered, the updated inventory has 12,185 passes, 153 failures, 20 timeouts, 407 skips and one fixture failure. Only the 740 cases above were rerun in this batch.

## Performance

Both Mac executors ran the same verified Linux guest workload with two guest CPUs. Each series alternated versions and discarded two warm-up pairs. The table gives medians across 16 measured pairs per series. Positive changes are longer elapsed times.

| Workload | Previous (ms) | Updated (ms) | Change | Reverse-order change |
| --- | ---: | ---: | ---: | ---: |
| UDP bind and close | 90.57 | 90.93 | +0.39% | -0.74% |
| Connected UDP delivery | 143.56 | 142.84 | -0.50% | -0.68% |
| TCP connect, accept and send | 19.28 | 19.15 | -0.65% | -0.36% |
| Unix socketpair | 11.86 | 11.91 | +0.39% | -0.30% |
| Unix stream send and receive | 19.40 | 19.42 | +0.10% | -0.04% |
| Unix datagram send and receive | 20.84 | 20.78 | -0.30% | -0.12% |
| sendmsg and recvmsg | 54.11 | 54.02 | -0.16% | — |
