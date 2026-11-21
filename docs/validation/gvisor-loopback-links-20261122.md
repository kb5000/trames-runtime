# Loopback addresses, connected routes and Netlink notifications

The baseline is runtime `9246f9e`. The comparison uses the six original Netlink suites measured in that revision, with each case in a fresh hardware-backed Mac guest and an internal virtual network. Native Linux results come from the same pinned gVisor binaries.

## Changes

- Packet-backed namespaces now use the same loopback state for topology queries and actual packet delivery. IPv4 aliases on loopback own their configured prefix. IPv6 binds require an assigned address. Removing the last matching loopback address also changes TCP and UDP connect results. Host-managed loopback addresses remain owned by the host.
- IPv4 UDP directed broadcasts use the selected guest network and reach wildcard and broadcast-address receivers sharing a port. The path uses the existing socket broadcast permission, guest packet hooks, and per-socket receive queues. IPv4 destinations that cannot be directed broadcasts skip the subnet lookup.
- Address and link changes publish address and connected-prefix events from the before/after interface state. Aliases sharing a prefix keep a single connected route until the last alias is removed. Guest ioctl and route Netlink changes use the same comparison. Loopback down/up applies the IPv6 address retention setting and restores the default IPv6 loopback address when enabled.
- Route updates can install separate next hops for one destination. Delete operates on the selected entry. Gateway resolution accepts connected prefixes, direct routes and explicit on-link next hops. Route notifications carry the sender and sequence for explicit requests and kernel identifiers for derived prefixes.
- The interface address budget accounts for loopback aliases across the namespace, including the slot needed to restore IPv6 loopback. A focused regression fills that budget, exercises removal of an alias while another shares its route, and cycles the interface down/up.

## Original test results

| Test group | Cases | Previous passes | Current passes |
| --- | ---: | ---: | ---: |
| TCP/UDP connect after removing the loopback address | 4 | 0 | 4 |
| IPv4 UDP aliases and subnet broadcast | 4 | 0 | 4 |
| IPv6 UDP subnet binding | 2 | 0 | 2 |
| Route Netlink | 120 | 76 | 101 |
| Other Netlink socket and uevent cases | 15 | 9 | 9 |

The 16 remaining failures in these suites concern automatic Netlink port IDs, policy rules, link updates including MTU and multicast reporting, a route-type case, veth IPv6 link-local configuration, and uevent socket filters.

The six suites moved from 85 passes, 51 failures and 9 skips to 120 passes, 16 failures and 9 skips. Eight additional socket suites retained all 680 prior outcomes (657 passes, 7 failures and 16 skips). Every one of the 35 newly passing cases also passed on native Linux and on the iPad interpreter running on the Mac. The iOS arm64 FFI check passed. The eight-stage runtime workflow passed with three unchanged stages reused.

Across the full tracked inventory, 13,138 of 14,530 cases have recorded outcomes. There are 12,546 passes, 152 failures, 419 skips, 20 timeouts and one fixture failure. This batch remeasured 825 cases. Other case results carry forward.

## Performance

Both revisions ran the same guest binaries on the hardware-backed Mac runner with an isolated internal bridge. Each pair ran both versions in alternating order. The table gives the median guest workload time over 32 pairs after two warm-up pairs. Negative values mean less time.

| Workload | Previous (ms) | Current (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 91.006 | 90.543 | -0.51% |
| udp connected delivery | 142.638 | 141.843 | -0.56% |
| tcp connect accept send | 19.138 | 18.806 | -1.73% |
| unix socketpair | 11.850 | 11.882 | +0.27% |
| unix stream send recv | 19.321 | 19.327 | +0.03% |
| unix datagram send recv | 20.746 | 20.705 | -0.20% |
| get link | 2.242 | 2.241 | -0.06% |
| dump addr | 6.534 | 6.538 | +0.05% |
| dump route | 8.432 | 8.404 | -0.33% |
