# Network protocol counters and TCP reset delivery

The guest transport exports TCP and IPv4 UDP counters through
`/proc/net/snmp` and four TCP extended counters through `/proc/net/netstat`.
These files follow the network namespace of the task identified by the proc
path. They cover the implemented fields. Native host traffic has no
per-environment protocol counters.

The interface accumulates events under its existing ownership. Reading the
established TCP gauge scans live protocol endpoints, including CLOSE_WAIT.
TCP tracks opens, failed handshakes, resets, input/output segments and
retransmissions. Output classification uses the existing sequence watermark.
IPv4 UDP tracks transmitted datagrams, datagrams consumed by a reader,
unbound destination ports, invalid input and receive-buffer drops. Peeking at
a datagram leaves the consumed count unchanged. A two-namespace test checks
source and destination independently.

Closing the final descriptor of a virtual TCP stream with unread data sends a
reset. The peer can drain already received data before its pending reset is
returned. TCP FIONREAD queries the socket's receive queue and preserves the
data. A guest probe on the Mac host-network backend checked EINVAL on a
listener and queue sizes of 5, 3 and 0 across partial reads.

## Compatibility

Both hardware runners used the pinned upstream gVisor tests and two guest
CPUs. The 59 cases from the transport-controls round reuse its verified
baseline. The 36 additional TCP cases were run on both revisions.

| Cases | Before | After |
| --- | --- | --- |
| 59 existing network cases | 44 passed, 12 failed, 3 skipped | 51 passed, 5 failed, 3 skipped |
| 36 additional reset cases | 24 failed, 12 timed out | 36 passed |
| Total | 44 passed, 36 failed, 12 timed out, 3 skipped | 87 passed, 5 failed, 3 skipped |

All 87 candidate passes have matching gTest XML. The additional suite covers
12 parameter combinations each for RSTSentOnCloseWithUnreadData,
RSTSentOnCloseWithUnreadDataAllowsReadBuffered and RSTCausesPollHUP. The
old runner had a 25-second watchdog for these cases. The candidate ran the
combined set with a 35-second watchdog. All 36 candidate reset cases also
completed on the Mac-hosted iPad interpreter, which passed 79 of 81 selected
cases with two upstream parameter skips. The physical iPad target passed its
compile check.

The cumulative inventory contains 3,405 cases with 3,240 passes, 53 failures,
91 skips, 20 timeouts and one fixture failure. Evidence for the other 3,310
cases comes from earlier runs. The five outstanding failures in this selection
cover TCP recovery policy and IPv6 configuration.

## Timing

Both release builds ran the same ARM64 guest benchmark on Mac hardware inside
an internal bridge. Each build had two warmups and 16 measured samples,
with the order reversed on alternate pairs. Values are median milliseconds.

| Operation | Iterations | Before | After | Change |
| --- | ---: | ---: | ---: | ---: |
| Bind an ephemeral UDP port and close | 2,000 | 97.224 | 96.758 | −0.48% |
| Connected UDP send and receive | 5,000 | 153.985 | 152.511 | −0.96% |
| TCP connect, accept and transfer two bytes | 100 | 21.594 | 21.602 | +0.04% |

The measurements cover internal loopback. They do not measure external
network throughput or physical iPad timing.
