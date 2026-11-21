# Netlink link and route control

The comparison covers all 145 original cases in six previously unmeasured gVisor suites. Both the baseline (runtime `f5ea446`) and candidate ran each case in a fresh Mac hardware-backed guest on an internal network. Grouping six tests per process had changed one baseline result. All numbers below use the isolated runs.

| Suite | Cases | Baseline passes | Current passes | Current failures | Skips |
| --- | ---: | ---: | ---: | ---: | ---: |
| Netlink socket | 12 | 6 | 8 | 4 | 0 |
| Route Netlink | 120 | 43 | 76 | 35 | 9 |
| Kernel uevents | 3 | 1 | 1 | 2 | 0 |
| Unbound IP sockets with Netlink | 4 | 0 | 0 | 4 | 0 |
| IPv4 UDP with Netlink | 4 | 0 | 0 | 4 | 0 |
| IPv6 UDP with Netlink | 2 | 0 | 0 | 2 | 0 |
| **Total** | **145** | **50** | **85** | **51** | **9** |

All 35 cases that changed also passed on native Linux. Each previously passing case passed again. With the new suites the inventory covers 13,138 of 14,530 cases. Across that inventory 12,511 passed, 187 failed, 419 skipped, 20 timed out, and one failed during fixture setup.

## Implementation

- Route datagrams process complete request headers in order and ignore a trailing incomplete record. Control messages honor the ACK flag. A peer query before connect reports the default kernel endpoint. Membership listing reports the allocated bitmap length and copies only whole 32-bit words.
- A route or address dump accepts a ROOT-only request. Address dumps group IPv4 before IPv6. Route dumps omit the destination attribute on default routes and order entries within their address family. Single-route lookup accepts a longer destination attribute and returns an address with the correct width.
- Route installation interprets prefix-sized IPv6 destinations, validates route types and next-hop attributes, and resolves a missing output device for an on-link gateway. Deletion can omit device or gateway. The selected configured route supplies the data for the resulting change notification.
- The topology chooses unused names for unnamed bridges and either end of a veth pair. Selection accounts for a peer in the same namespace and publishes the complete pair under the existing topology lock.

The framing and membership behavior follows the Linux Netlink implementation. [Linux Netlink source](https://github.com/torvalds/linux/blob/master/net/netlink/af_netlink.c)

## Verification and remaining gaps

All eight local runtime CI stages passed. The iOS FFI target compiled. The iPad interpreter on Mac replayed all 35 newly passing originals on a private virtual network. Restricting that fixture to loopback denied the two workloads that actually send IPv6 UDP over a veth pair. They passed with virtual interface traffic enabled. No physical iPad run was performed.

Remaining failures include automatic Netlink port IDs, loopback address changes used by UDP and multicast tests, route policy rules, multicast notifications for link and route changes, and socket filters on the uevent channel.

## Performance

Elapsed times are medians of 32 paired guest observations per version, after two warm-up pairs. Each pair alternated which build ran first. Each Netlink observation performed 800 complete queries and received their replies.

| Guest workload | Previous ms | Current ms | Change |
| --- | ---: | ---: | ---: |
| UDP bind and close | 90.091 | 90.959 | +0.96% |
| Connected UDP delivery | 143.518 | 143.508 | -0.01% |
| TCP connect, accept and send | 19.217 | 19.187 | -0.15% |
| Unix socket pair | 11.896 | 11.862 | -0.29% |
| Unix stream transfer | 19.423 | 19.307 | -0.60% |
| Unix datagram transfer | 20.737 | 20.703 | -0.16% |
| Netlink interface lookup | 2.253 | 2.237 | -0.72% |
| Netlink address dump | 6.487 | 6.527 | +0.62% |
| Netlink route dump | 8.504 | 8.445 | -0.69% |
