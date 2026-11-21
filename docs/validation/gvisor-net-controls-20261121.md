# Guest port allocation, UDP delivery and TCP SACK

The virtual Linux network namespace owns its ephemeral port range.
Writes to `ip_local_port_range` affect the next automatic bind, including
connect-time port allocation. The cursor wraps within the configured range.
Live sockets keep their bindings. Range changes and writes to
`ip_unprivileged_port_start` preserve the privileged-port boundary.
The default range is 49152–65535. Host-backed sockets still allocate their
ports through the host.

UDP sockets can share a local binding when each conflicting owner opts into
`SO_REUSEADDR`. Unicast delivery checks the connected peer, specific local
binding and bind order to choose one receiver. An ordinary exclusive match
can finish immediately. TCP checks live bindings and closing protocol
endpoints before reusing a port. The mixed IPv4 and IPv6 send cases check
the selected source family.

The virtual interface applies `tcp_sack` during handshakes. Retransmitted
active SYNs retain their original offer. Established endpoints expose the
negotiation result in `TCP_INFO.tcpi_options`. Tests exercise all four
combinations of active and passive offers and change the setting again
while the endpoints are connected. Additional tests cover namespace
isolation, range boundaries, duplicate UDP delivery and close.

## Compatibility

Both Mac hardware builds ran the same 59 upstream cases on an internal network
with two guest CPUs. Each passing case has matching original gTest XML.

| Suite | Previous passes | Current passes | Cases |
| --- | ---: | ---: | ---: |
| proc_net | 8 | 13 | 26 |
| proc_net_tcp | 10 | 10 | 10 |
| proc_net_udp | 7 | 7 | 7 |
| socket_inet_loopback_nogotsan | 0 | 2 | 4 |
| udp_bind | 9 | 12 | 12 |

Failures fell from 22 to 12 with three upstream skips on both builds. Seven
remaining failures cover SNMP/netstat counters, two cover TCP recovery and
three cover IPv6 configuration. The Mac-hosted iPad interpreter exercised
38 cases across the same five suites, with 36 passes and two upstream
protocol-parameter skips. The iOS device target passed its compile check.

The cumulative inventory now contains 3,369 cases, including 16 newly
covered cases. It records 3,197 passes, 60 failures, 91 skips, 20 timeouts
and one fixture failure. This batch reused prior evidence for 3,310 cases.

## Internal network performance

Two release builds alternated on the same Mac and internal bridge with
two guest CPUs. Each ran two warmups and 16 measured samples of the same
ARM64 Linux binary. Values are median milliseconds per batch of operations.

| Guest operation | Iterations | Previous | Current | Change |
| --- | ---: | ---: | ---: | ---: |
| Bind an ephemeral UDP port and close | 2,000 | 95.926 | 95.489 | −0.46% |
| Connected UDP send and receive, 6 bytes | 5,000 | 151.703 | 151.807 | +0.07% |
| TCP connect, accept and transfer 2 bytes | 100 | 21.513 | 21.646 | +0.62% |

These measurements cover guest loopback on the internal network. WAN
throughput, multicast fan-out and physical iPad timing were outside the run.
