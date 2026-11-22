# TCP active opens, TIME_WAIT and UDP ephemeral binds

The previous Mac runtime was `f1797cd`. Three original gVisor stress tests exhausted the TCP source port range after the client shut down first. The IPv4, IPv6 and IPv4-mapped cases returned `EADDRINUSE`. All three now succeed with the original timeout and retry logic. A separate before/after replay confirmed and fixed a UDP automatic-bind failure on the same baseline. The cumulative inventory already recorded a pass for that UDP case, so it contributes no additional gain to the inventory.

## Changes

- TCP active opens choose a source port for the selected local address and peer. Two connections can share a source port when their four-tuples differ. Explicit binds and listeners continue to reserve their ports. An exhausted active open returns `EADDRNOTAVAIL` and leaves its descriptor unbound. TCP bind with port zero still returns `EADDRINUSE` when it cannot reserve a port.
- Loopback TCP negotiates timestamps. When an old four-tuple has spent one quiet second in TIME_WAIT, a new active open can reuse it under the fabric lock and advance its initial send sequence beyond the prior connection. Timestamp negotiation, the close timer and the loopback endpoints are checked before recycling. Link traffic retains its existing TIME_WAIT protection. This implements the default loopback behavior; the reuse-policy sysctls are not implemented here. See [Linux IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html#tcp-tw-reuse-integer).
- Timestamped data segments account for the 12-byte padded option in both send readiness and payload sizing. Before this adjustment, two of the three 31 MiB TCP echo tests timed out on the timestamp-enabled candidate. All three complete on the final candidate, with the contents checked by the original tests.
- UDP automatically allocated ports honor the bind’s existing address, device, owner and reuse options. The UDP reuse-address case now succeeds when the guest restricts its port range and binds more sockets than the range can hold.

A two-family runtime regression constrains the client to one source port. It exchanges distinct payloads over two peers, checks that an early retry fails and an explicit bind cannot take the port, then advances the guest transport clock and exchanges data on the recycled connection.

## Original test results

The Mac runner used the original AArch64 binaries, the internal virtual network and a two-CPU guest. The two stress suites and 56 bind/UDP cases ran on the final candidate. The other 160 cases exercise the same TCP implementation before the final UDP-only adjustment. The table counts each suite/case pair once.

| Suite | Cases | Passed | Failed | Skipped | Linux passed |
| --- | ---: | ---: | ---: | ---: | ---: |
| socket_bind_to_device_sequence | 42 | 41 | 1 | 0 | 42 |
| socket_data_transfer_stress | 3 | 3 | 0 | 0 | 3 |
| socket_inet_loopback_isolated | 166 | 164 | 2 | 0 | 166 |
| socket_inet_loopback_nogotsan | 4 | 2 | 0 | 2 | 2 |
| socket_ipv4_udp_unbound_loopback_nogotsan | 4 | 4 | 0 | 0 | 4 |
| socket_stress | 30 | 30 | 0 | 0 | 30 |
| Total | 249 | 244 | 3 | 2 | 247 |

Remaining failures include the mixed TCP REUSEADDR/REUSEPORT bind sequence and both device-bound REUSEPORT cases. The latter stop in the raw-socket capability probe. The physical iPad did not run these tests. Its interpreter running on Mac passed eight upstream cases, covering the active-close sequence and TCP/UDP automatic-bind rules. The ARM64 iOS FFI target compiled and all eight stages of local runtime CI passed.

The cumulative inventory covers 14,326 of 14,530 discovered cases, with 13,655 passes, 130 failures, 24 timeouts, 516 skips and 1 fixture failure.

## Socket performance

The same two-CPU Mac guest ran each workload on the previous and final executors in alternating order. Times are medians in milliseconds over 32 paired samples after two warmup pairs.

| Workload | Previous | Final | Change |
| --- | ---: | ---: | ---: |
| `udp_bind_close` | 96.60 | 97.77 | +1.21% |
| `udp_connected_delivery` | 151.84 | 152.48 | +0.42% |
| `tcp_connect_accept_send` | 20.24 | 20.38 | +0.68% |
| `unix_socketpair` | 12.33 | 12.44 | +0.88% |
| `unix_stream_send_recv` | 19.79 | 19.87 | +0.38% |
| `unix_datagram_send_recv` | 21.63 | 21.65 | +0.07% |
| `sendmsg_recvmsg` | 56.27 | 56.57 | +0.54% |
| `udp_64B` | 45.90 | 45.52 | -0.85% |
| `udp_1400B` | 46.89 | 47.25 | +0.77% |
| `udp_8KiB` | 36.25 | 36.41 | +0.44% |
| `tcp_16KiB` | 73.63 | 71.78 | -2.51% |

The upstream 31 MiB echo workload ran separately with no concurrent build or test. The table uses the GoogleTest XML duration inside the guest, with five alternating pairs after one warmup pair. Each run verifies the echoed bytes and EOF.

| TCP variant | Previous (s) | Final (s) | Change |
| --- | ---: | ---: | ---: |
| IPv6 | 3.981 | 3.983 | +0.05% |
| IPv4 | 3.976 | 3.996 | +0.50% |
| dual stack | 3.982 | 3.960 | -0.55% |
