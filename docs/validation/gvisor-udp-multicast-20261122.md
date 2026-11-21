# IPv4 multicast and limited broadcast on guest networks

The Mac hardware executor ran 307 original ARM64 gVisor cases from 12 suites on both baseline `f2b25d9` and the updated runtime. Both runs used the same binaries, two guest CPUs and a 20-second timeout.

| Result | Baseline | Updated |
| --- | ---: | ---: |
| Passed | 180 | 290 |
| Failed | 122 | 12 |
| Skipped | 5 | 5 |
| Timed out | 0 | 0 |

All 110 changed cases went from failure to pass. The native Linux reference passes the same 110 cases. Original GoogleTest XML confirms all 290 Mac passes. Running the iPad interpreter on the Mac independently produced passing XML for all 110 changed cases. The ARM64 iOS FFI check and all eight local shared-runtime CI steps passed. Physical iPad execution was outside this run.

## Delivery and scope

The guest UDP stack selects an IPv4 multicast interface, tracks per-socket group memberships, and implements multicast TTL, local loopback and IP_MULTICAST_ALL. Limited broadcast sends require SO_BROADCAST. Group packets reach eligible sockets on the selected guest link through their existing receive queues. A waiting reader uses the same readiness notification as unicast. Group packets carry the incoming interface, the interface address and the packet destination separately for IP_PKTINFO.

The two-namespace regression sends a 6,113-byte payload over a guest Ethernet link and checks reassembly, TTL and packet metadata. It also checks membership isolation, local delivery with zero TTL, suppression of the Ethernet sender's local copy and filtering by namespace input and output rules. This validation covers guest links and limited broadcast (255.255.255.255). IPv6 multicast, subnet-directed broadcast, host LAN membership and IGMP are outside these results. The group path rejects TUN egress and drops packets when the firewall rewrites their destination to another IP address.

## Ordinary socket performance

Elapsed times are medians from 16 paired samples on one Mac after two warm-ups, alternating which build ran first.

| Guest workload | Baseline (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| UDP bind and close | 95.17 | 95.64 | +0.49% |
| Connected UDP delivery | 151.58 | 151.32 | −0.17% |
| TCP connect, accept and send | 21.64 | 21.65 | +0.07% |
| Unix socketpair | 12.36 | 12.36 | +0.00% |
| Unix stream send and receive | 19.98 | 20.06 | +0.39% |
| Unix datagram send and receive | 21.48 | 21.39 | −0.42% |
| sendmsg and recvmsg | 56.75 | 56.58 | −0.31% |

## Inventory

Of the 110 fixes, 50 clear previously counted failures and 60 cover newly counted cases. The cumulative inventory covers 9,723 of 14,530 discovered cases, with 9,329 passes, 50 failures, 20 timeouts, 323 skips and one fixture failure. The 12 failures still present in this selection involve seven port-binding sequences, three procfs cases, one ethtool timestamp query and one isolated network fixture.
