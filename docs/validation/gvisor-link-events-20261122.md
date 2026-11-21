# Netlink socket identity, receive filters and interface updates

The baseline is runtime `23cd1b8`. Both builds used the same upstream gVisor binaries and the internal virtual network on the hardware-backed Mac runner.

## Behavior

- Binding without a port, connecting, and sending the first request use the calling process's namespace-visible PID when that port is available. Additional sockets use the high port-ID range. The registry is scoped to the network namespace and protocol. Closing a socket releases its port.
- Multicast retains the sender's port and kernel-global process, user and group IDs. The receiving syscall maps credentials into the reader's namespaces. Kernel notifications retain kernel credentials. Matching the Netlink protocol as well as the group prevents route notifications from entering the uevent group with the same numeric ID.
- Classic socket filters use the existing BPF validator and interpreter for multicast data and unicast replies. Filtering precedes delivery and supports both drops and truncation. Queued data survives filter replacement. The filter storage is allocated on first attachment. Multicast overrun observes the listener's receive buffer independently of its send buffer.
- Route Netlink and interface ioctls update the same guest loopback name and MTU. Interface lookups and the existing UDP path-MTU check read that state. A repeated rename or MTU setting generates no link event. The MTU of a host-backed interface remains constrained by its transport.
- A focused socket regression exercises process/port reuse, distinct protocol groups, filter replacement, short packets and sender credentials. A separate regression exercises rename, MTU readback, invalid values and unprivileged writes through both ioctl dispatch paths.

## Original cases and remaining failures

| Group | Cases | Baseline passes | Current passes |
| --- | ---: | ---: | ---: |
| Netlink socket creation, binding and connection | 12 | 8 | 12 |
| Route Netlink | 120 | 101 | 107 |
| Uevent sockets | 3 | 1 | 3 |
| IPv4/IPv6 loopback binding and delivery | 10 | 10 | 10 |

The four outstanding route failures cover adding and removing IPv4 and IPv6 policy rules, special route types, and automatic IPv6 link-local addressing on veth. The special-route case exercises several types in a single test.

The six target suites moved from 120 passes, 16 failures and 9 skips to 132 passes, 4 failures and 9 skips. Another 680 socket cases retained their prior results (657 passes, 7 failures and 16 skips). Every newly passing case also passed on native Linux and with the iPad interpreter executing on the Mac. The iOS arm64 FFI target compiled. The eight-stage local runtime workflow passed, with three unchanged stages reused.

The cumulative inventory covers 13,138 of 14,530 cases with 12,558 passes, 140 failures, 419 skips, 20 timeouts and one fixture failure. This comparison updates only the 825 cases rerun on the final hardware-backed build.

## Performance

The same guest binaries ran against both revisions on an isolated internal network. The table reports median elapsed time in milliseconds over 32 paired samples after two warm-up pairs. Execution order alternated by pair.

| Guest workload | Previous (ms) | Current (ms) | Elapsed time change |
| --- | ---: | ---: | ---: |
| udp bind close | 93.182 | 93.440 | +0.28% |
| udp connected delivery | 145.040 | 145.022 | -0.01% |
| tcp connect accept send | 18.979 | 19.058 | +0.42% |
| unix socketpair | 12.066 | 12.132 | +0.55% |
| unix stream send recv | 19.446 | 19.655 | +1.07% |
| unix datagram send recv | 20.935 | 21.271 | +1.61% |
| get link | 2.314 | 2.342 | +1.22% |
| dump addr | 6.695 | 6.659 | -0.54% |
| dump route | 8.494 | 8.533 | +0.46% |
