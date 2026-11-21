# UDP disconnect, rebinding and receive queues

The Mac hardware executor ran the same 1,133 upstream ARM64 GoogleTest cases from 16 suites on baseline `38944ff` and the updated runtime. Both runs used the same root filesystem, two guest CPUs and 20-second timeout.

| Outcome | Baseline | Updated |
| --- | ---: | ---: |
| Passed | 954 | 974 |
| Failed | 122 | 102 |
| Skipped | 57 | 57 |
| Timed out | 0 | 0 |

All 20 changes were failures becoming passes. They cover eight disconnect and rebind cases, sending to a different destination on a connected socket, and receiving one oversized datagram on an empty queue, each for IPv4 and IPv6. All 20 also pass on the native Linux reference and on the iPad interpreter running on the Mac. The 974 Mac passes have original passing GoogleTest XML. The iOS ARM64 FFI check and all eight local shared-runtime CI steps passed. Physical iPad execution was outside this run.

## Socket behavior

On the guest-owned UDP stack, AF_UNSPEC disconnect releases an automatically allocated port and retains a port explicitly requested by bind. The runtime tracks an explicitly requested local address independently of the port. Detaching the peer clears its ingress filter. Packets already in the socket retain their queue storage, source and original destination port through another bind or connect. An explicit send to the unspecified destination address resolves to loopback. The underlying macOS BSD socket has separate disconnect semantics and was outside this batch.

A direct two-family test delivers a packet, disconnects, checks FIONREAD, binds a second socket to the released port, and verifies that it receives subsequent traffic to that port. It reconnects the first socket and checks both the old and new destination ports on peek and consume. It also exercises a specific address bound with port zero.

An empty Linux UDP receive queue can admit one datagram larger than SO_RCVBUF. Backing storage grows when that record arrives. The configured limit still applies to subsequent arrivals while the queue is occupied. Ordinary binds avoid reading live socket statistics when neither privileged-port policy nor the legacy AF_UNSPEC bind form needs socket identification.

## Inventory

All selected cases were already in the cumulative inventory. Coverage remains 10,392 of 14,530 discovered cases. It now contains 9,860 passes, 140 failures, 20 timeouts, 371 skips and one fixture failure. The 64 outstanding failures at raw socket creation still stop before their multicast assertions.

## Common-path timings

The socket workloads ran in two series of 16 measured pairs with opposite starting orders. Each series included two warm-ups. The separate sendmsg/recvmsg workload ran for 16 measured pairs after warm-up. The values are medians on one Mac.

| Workload | Baseline (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 97.08 | 97.09 | +0.01% |
| udp_connected_delivery | 152.67 | 152.88 | +0.14% |
| tcp_connect_accept_send | 21.61 | 21.62 | +0.05% |
| unix_socketpair | 12.40 | 12.34 | -0.45% |
| unix_stream_send_recv | 19.94 | 19.82 | -0.56% |
| unix_datagram_send_recv | 21.64 | 21.54 | -0.51% |
| sendmsg_recvmsg | 56.84 | 56.87 | +0.06% |
