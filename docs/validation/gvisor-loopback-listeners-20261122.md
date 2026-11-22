# Loopback listeners, address selection and TCP close, 2026-11-22

The previous Mac runner used shared runtime `c6a694d`. The signed Mac runners executed the same original Linux ARM64 gVisor binaries in fresh two-CPU guest stores on the internal network. The 264 newly covered cases all passed on the native Linux reference. Six TCP distribution tests exceeded the previous 12-second watchdog. The updated distribution tests had a 60-second watchdog. Each TCP case creates 10,000 connections. The updated runner completed all eight below the original 12-second watchdog.

| Original test group | Before | After |
| --- | --- | --- |
| socket_bind_to_device_distribution / Tcp | 6 timeout | 6 passed |
| socket_bind_to_device_distribution / Udp | 2 failed | 2 passed |
| socket_inet_loopback / LoopbackAddressRangeConnect | 1 timeout | 1 passed |
| socket_inet_loopback / TCPAcceptAfterReset | 22 timeout | 22 passed |
| socket_inet_loopback / V4ListenerV6Connect | 2 failed | 2 passed |
| socket_inet_loopback / V6ListenerV4Connect | 2 failed | 2 passed |
| socket_inet_loopback / ValidateErrForBadCallsToSocketPair | 1 failed | 1 passed |
| socket_inet_loopback_isolated / TCPLinger2TimeoutAfterClose | 22 failed | 22 passed |

The other 206 newly covered cases passed on both runners. We also replayed 701 previously measured cases with the updated binary. All 701 matched their previous status. Across nine suites, 959 of the 965 cases passed, three failed and three skipped. The three failures concern mixed address/port reuse during device binding and the raw-socket capability probe in the TCP and UDP device-binding fixtures. The cumulative inventory covers 13,933 of 14,530 cases, with 13,284 passes, 117 failures, 508 skips, 23 timeouts and one fixture failure. Another 597 have no Trames result.

## Implementation

- Established TCP children retain their endpoint pair and pending reset until accept. The accepted socket reports the reset once. A listener waiting for connections subscribes to its own slots, including slots added while it sleeps. An accepted socket no longer uses the listener subscription.
- Final close wakes the existing protocol driver. Closes within the next four milliseconds share a scheduled wake, and normal packet I/O can send a pending FIN earlier. An idle guest still advances the FIN exchange and releases the port at the orphan deadline. A wildcard listener handling a loopback alias replenishes the slot with the original listen address. Device-specific TCP listeners retain priority at backlog capacity. UDP reuse-port distribution selects from peers of the same priority.
- Dual-stack clients with an explicit local address report the Linux address-family error for incompatible destinations. Internet socket-pair creation preserves the validation order for the socket type and protocol.

All eight local runtime CI stages passed. The standalone network stack returned 600 passes and the same five failures as the previous runtime. The iPad interpreter executed 34 original cases on the Mac, and the ARM64 iOS FFI passed its build check. Physical iPad behavior was not measured.

## Main-path performance

Both signed runners alternated order on the same guest fixtures. The table reports median workload time after two warm-up pairs, using 16 pairs for sockets and messages and 32 for memory, files and processes. A negative change indicates less elapsed time.

| Workload | Previous (ms) | Updated (ms) | Change |
| --- | ---: | ---: | ---: |
| udp bind close | 91.512 | 91.262 | -0.27% |
| udp connected delivery | 143.215 | 143.822 | +0.42% |
| tcp connect accept send | 18.730 | 19.132 | +2.15% |
| unix socketpair | 11.802 | 11.926 | +1.04% |
| unix stream send recv | 19.380 | 19.300 | -0.42% |
| unix datagram send recv | 20.840 | 20.892 | +0.25% |
| sendmsg recvmsg | 55.425 | 55.380 | -0.08% |
| memory | 167.552 | 167.399 | -0.09% |
| mmap fault unmap | 122.959 | 123.410 | +0.37% |
| file pread pwrite | 92.417 | 92.733 | +0.34% |
| fork wait | 18.338 | 18.551 | +1.16% |
| proc cpuinfo | 1.650 | 1.660 | +0.61% |
| ordinary open | 70.407 | 70.877 | +0.67% |
| ordinary stat | 18.301 | 18.413 | +0.61% |

Performing protocol work on each final close cost 22.6% on the 100-connection TCP workload. Coalescing close notifications reduced this overhead. In the final compatibility replay, the eight distribution tests took 2.27–5.39 seconds per 10,000 connections.
