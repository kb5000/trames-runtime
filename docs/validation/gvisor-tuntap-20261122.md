# TUN and TAP compatibility, 2026-11-22

The Mac executor passed 19 of the 25 original gVisor TUN/TAP cases. The previous runtime passed seven under the same network setup. Eleven failures and one timeout became passes. All 19 also passed with the iPad interpreter running on the Mac, using the original AArch64 binary and a separate network namespace per case. The ARM64 iOS FFI check and all eight stages of local runtime CI passed.

| TUN/TAP environment | Passed | Failed | Timed out |
| --- | ---: | ---: | ---: |
| Previous runtime on the default internal test bridge | 6 | 14 | 5 |
| Previous runtime in a fresh network namespace | 7 | 16 | 2 |
| Updated runtime in a fresh network namespace | 19 | 5 | 1 |
| Native Linux in a fresh network namespace | 22 | 2 | 1 |

The fixture uses 10.0.0.1/24 for TAP and .2 for its remote peer. The default internal bridge already uses those addresses. The guest harness now starts each TUN/TAP case in an empty network namespace, like the native reference. The old runtime already passed the UDP address-resolution test with this correction. The runtime improvement accounts for the other twelve gains.

## Changes verified

- Persistent interfaces survive the last close. A newly attached file starts with an empty queue. Carrier, packet information and persistence remain visible through ioctl and rtnetlink as appropriate. Explicit link deletion invalidates persistence operations on the old descriptor.
- Link setup accepts the Linux TUN and TAP MTU ranges. A regression lowers a live TUN MTU, sends UDP traffic and checks fragment lengths, offsets, IPv4 checksums and reassembled data. The same test checks exclusive and concurrent opens, retained address configuration and queue disposal.
- Raw packet sockets receive TUN ingress before IP validation and can transmit to a TUN queue. The queue carries the protocol separately from the payload. TAP accepts the Ethernet header supplied by the guest, including frames larger than the local transmit MTU. Pending ARP traffic, bidirectional ICMP, zero-length writes and writes to down links have original-test coverage.

The rtnetlink and ioctl changes follow the [Linux TUN driver](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c). The final exclusive-open errno adjustment was also checked separately against the native result.

## Remaining differences

Three cases pass on the Linux reference and still fail in Trames. Two exercise failed ARP resolution during blocking and nonblocking TCP connects to port zero. The isolated Trames namespace returns EINVAL before the expected EHOSTUNREACH notification. The third moves an open TUN interface to another network namespace. That move remains unsupported.

The other three cases have the same outcome on the Linux reference. The exclusive-open test expects retained IFF_TUN_EXCL and EEXIST on a second descriptor. Linux omits the flag and returns EBUSY. The large-write test expects EMSGSIZE, while both Linux and Trames accept the 4,206-byte TAP write. The no-packet-info test leaves the link down and times out waiting for a reply.

Six bridge cases, ten network-namespace cases and 55 packet-socket cases kept their previous outcomes. The full inventory uses the latest result of each measured test.

Across 14,293 measured cases there are 13,616 passes, 136 failures, 24 timeouts, 516 skips and 1 fixture failure. 237 discovered cases remain unmeasured.

## Performance

Both signed Mac runners used the same two-CPU guest and workload executable. Each row shows median elapsed time across 32 alternating pairs after two warmup pairs.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 99.880 | 97.594 | -2.29% |
| udp_connected_delivery | 150.732 | 149.663 | -0.71% |
| tcp_connect_accept_send | 20.182 | 20.236 | +0.27% |
| unix_socketpair | 12.520 | 12.496 | -0.20% |
| unix_stream_send_recv | 19.925 | 20.054 | +0.65% |
| unix_datagram_send_recv | 21.586 | 21.887 | +1.39% |
| sendmsg_recvmsg | 56.551 | 56.376 | -0.31% |
| udp_64B | 45.571 | 45.625 | +0.12% |
| udp_1400B | 46.735 | 46.914 | +0.38% |
| udp_8KiB | 36.152 | 36.164 | +0.03% |
| tcp_16KiB | 77.071 | 76.941 | -0.17% |

Updated Mac runner SHA-256 `069eb56463c4c70ccf9c0d993c3ef6d3de067b03ebbdd445e21ba90f7b327c4a`. Measurements cover socket setup, transport and message passing on this Mac.
