# IPv4 path MTU socket policy on the internal network, 2026-11-22

Against the previous runtime `c7baea5`, all six original gVisor IPv4 PMTU failures changed to passes. Four cases cover TCP and two cover UDP. They exercise SOL_IP on IPv4 and dual-stack descriptors. The same original AArch64 binaries passed on the Mac hardware executor and on the iPad interpreter running on Mac. The native Linux reference passes all six. Another 171 original cases in six socket suites passed on Mac, preserving every previous outcome. All eight runtime CI stages and the iOS ARM64 FFI build check passed.

## Socket and packet behavior

The bridge's guest TCP and UDP sockets retain all six Linux IP_MTU_DISCOVER values. On TCP, changing policy updates the transport handles, including listener slots, and accept inherits the listener policy. UDP applies the socket policy at send time to the selected IPv4 route, including IPv4-mapped destinations. Strict modes report EMSGSIZE and the interface MTU to the socket's existing error queue when enabled. IP_MTU reads the current route MTU for a connected endpoint. Small SOL_IP arguments use the existing Linux byte-or-int ABI.

A runtime regression uses the guest Ethernet interface to capture TCP and UDP headers. It checks DF and the IPv4 header checksum, the 1,472/1,473-byte UDP payload boundary on a 1,500-byte link, valid fragmentation and delivery, local error details, TCP inheritance and delivery of a 4 KiB IPv4-mapped loopback datagram and strict-size enforcement on a connected multicast socket. The route MTU lookup shares the existing route validation and reads the device field directly. Sending on a loopback or jumbo route can now carry a whole IPv4 datagram through the software IP port.

The current route model supplies the interface MTU. Learning a lower destination MTU from remote ICMP and locked route MTU metrics remain separate compatibility gaps. The IPv6-level IPV6_MTU_DISCOVER option and the host-native socket backend were outside this measurement. Hybrid wildcard endpoints reject an unsupported policy before changing either transport. [Linux socket options](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/ip_sockglue.c) and [Linux packet output](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/ip_output.c).

## Inventory

At equal coverage of the original 14,252 cases, failures fell from 131 to 125. Running 41 additional original cases brought measured coverage to 14,293 of 14,530, with 13,603 passes, 145 failures, 28 timeouts, 516 skips and one fixture failure. There are 237 unmeasured cases.

| Newly measured suite | Passed | Failed | Timed out | Skipped |
| --- | ---: | ---: | ---: | ---: |
| bridge | 3 | 3 | 0 | 0 |
| network_namespace | 6 | 3 | 0 | 1 |
| tuntap | 6 | 14 | 5 | 0 |

Every newly measured case had the same outcome on the two Trames revisions.

The native Linux reference passes 16 of the newly observed failures and four of the timeouts. It also fails four cases and times out on one case, so those five need separate interpretation before attributing a difference to Trames. The largest cluster is TUN/TAP attachment, link controls and packet I/O.

## Performance

Each Mac runner used the same two-CPU guest registration and executable for each comparison. The order reversed after every pair. Medians exclude the first two warm-up pairs. The payload workloads compare all returned bytes and include endpoint setup outside the timed transfer loop.

| Workload | Previous (ms) | Updated (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 97.511 | 97.727 | +0.22% |
| udp_connected_delivery | 150.397 | 150.743 | +0.23% |
| tcp_connect_accept_send | 20.186 | 20.222 | +0.18% |
| unix_socketpair | 12.322 | 12.308 | -0.11% |
| unix_stream_send_recv | 19.804 | 19.766 | -0.19% |
| unix_datagram_send_recv | 21.566 | 21.343 | -1.04% |
| sendmsg_recvmsg | 56.371 | 56.341 | -0.05% |
| udp_64B | 45.783 | 46.073 | +0.63% |
| udp_1400B | 46.745 | 46.914 | +0.36% |
| udp_8KiB | 39.334 | 36.323 | -7.65% |
| tcp_16KiB | 80.841 | 76.995 | -4.76% |

32 measured pairs per workload. Mac runner SHA-256 `c418321d5522ad30f61787b8ef5e933a3d00001c612e0dff24c5f8d0d4f3f017`.
