# Internal network binding and TCP listener selection

## Changes

An internal TCP or UDP bind now checks overlapping address families, device scope and Linux reuse options. A dual-stack IPv6 wildcard can overlap IPv4. A concrete IPv6 address and a v6-only wildcard keep their family boundaries. Dual-stack UDP accepts IPv4 destinations in sendto and connect. The bind operation checks the address family separately.

An application can read back its bound guest device, including the terminating NUL and the Linux option length. Changing or clearing an existing binding requires CAP_NET_RAW in the socket's owning user namespace. TCP and UDP unicast receive use the guest ingress interface. IP fragment reassembly keeps different ingress devices separate. A network regression test binds sockets on lo and eth0 to the same port, checks that traffic reaches only the loopback endpoint, and exercises the permission check for rebinding. [Linux socket controls](https://github.com/torvalds/linux/blob/master/net/core/sock.c)

For TCP, SO_REUSEADDR allows sharing before listen. Distinct connections sharing a local port must have different remote endpoints. Compatible SO_REUSEPORT listeners distribute incoming connections by their four-tuples. A listener's backlog slots share a selection key and are replenished independently of sibling listeners. The connection-setup conflict lookup is limited to explicitly bound sockets that could share a port. A two-sided shutdown reports hangup during protocol close and the detached endpoint retains its reuse policy while it owns the port.

UDP port allocation respects the order in which sockets bound. For an explicit reusable port, the newest overlapping binding not already admitted by SO_REUSEADDR decides whether the reuse-port owner matches. [Linux UDP bind lookup](https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c)

## Test isolation

The pinned gVisor isolated-loopback suite uses fixed ports in multiple cases. On baseline runtime `8fb9a73`, three of four repeated-bind cases failed when sharing a guest network namespace. All four passed in fresh namespaces. The harness now runs the isolated suite one case at a time. Both sides of this comparison used isolated reruns for all 78 affected cases. Performance measurements used separate guest workloads.

## Results

Against runtime `8fb9a73`, 105 failures became passes across 2,306 matched original cases. Every changed case also passed on the native Linux reference. The full comparison went from 2,135 passes, 136 failures and 35 skips to 2,240 passes, 31 failures and 35 skips. The validation runner resumed 734 cases deferred by its disk-space guard. Each result counts once.

| Focus suite | Cases | Previous passes | Current passes | Current failures | Skips |
| --- | ---: | ---: | ---: | ---: | ---: |
| Device binding sequences | 42 | 6 | 41 | 1 | 0 |
| Internet loopback | 65 | 39 | 62 | 0 | 3 |
| Isolated Internet loopback | 78 | 29 | 76 | 2 | 0 |

All five TCP listener distribution tests passed with 10,000 real connections apiece. The three residual failures in the focused suites are one TCP mixed reuse-option sequence and two bind-to-device cases whose raw-IP socket probe fails before the bind under test. The interpreter ran 100 of the original cases on Mac, with 97 passes and three skips matching hardware-backed execution. The iOS FFI target compiled. Local CI passed all eight stages, and all 18 harness tests passed. Physical iPad performance was not measured.

This batch adds 161 cases to the cumulative inventory. It now covers 12,993 of 14,530 original cases, with 12,426 passes, 136 failures, 410 skips, 20 timeouts and one fixture failure.

## Timing

The 22 active-close bind cases went from a median of 11.005 seconds and a wrong bind result to 1.001 seconds and the expected result. Reconnecting the same TCP endpoints after a passive close still takes about 11.5 seconds on Trames, compared with about 1.05 seconds on native Linux. This remains a latency gap.

The table gives median elapsed time for each guest workload in the final 32 paired observations per version, following two warm-ups. Ordering alternated within the pairs.

| Workload | Previous ms | Current ms | Change |
| --- | ---: | ---: | ---: |
| UDP bind and close | 90.89 | 90.83 | −0.07% |
| Connected UDP delivery | 143.56 | 143.86 | +0.21% |
| TCP connect, accept and send | 19.26 | 19.21 | −0.26% |
| Unix socket pair | 11.89 | 11.94 | +0.41% |
| Unix stream send and receive | 19.38 | 19.41 | +0.17% |
| Unix datagram send and receive | 20.74 | 20.72 | −0.10% |

Connected UDP delivery varied by +0.42% and +2.36% in the two earlier 16-pair runs. A separate 128 MiB TCP bulk transfer changed by +0.13% in one order and −0.56% in reverse order.
