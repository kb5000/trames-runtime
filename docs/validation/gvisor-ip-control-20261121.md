# UDP IP control messages on the internal network

The shared guest stack carries traffic class and hop limit in the queued UDP
record. Socket defaults apply by wire family. A sendmsg override applies to
one datagram. IPv4 fragments retain their traffic class and checksum. The
receiver reads the wire header and selects the enabled control messages when
consuming or peeking at the datagram. A dual-stack receiver can request both
IPv4 and IPv4-mapped IPv6 packet info for the same incoming IPv4 datagram.

Linux recvmsg now accounts for short control buffers. A missing payload byte
sets MSG_CTRUNC, a partial payload reports its copied length, and a buffer
that fits the last payload can omit trailing alignment padding. The Mac host
socket path still lacks per-message traffic-class and hop-limit overrides.
The measurements below used the internal network.

## gVisor validation

The comparison used the same ARM64 upstream binary, two guest CPUs and the
same 23 cases on both Mac hardware runner builds. The selection contains
every case in UdpSocketControlMessagesTest (five behaviors across IPv4, IPv6
and dual-stack), plus eight connected UDP, record boundary and FIONREAD
controls. The previous runtime passed 9 and failed 14. The updated runtime
passed 23. Each pass was checked against its original gTest XML. The shared
iPad interpreter also passed 23 on a Mac. The iOS device target compiled.

Fourteen cases overlapped the previous cumulative inventory, including six
previous failures. Nine cases gained their first inventory entry. The
cumulative inventory now covers 3,472 cases with 3,307 passes, 53 failures,
91 skips, 20 timeouts and one fixture failure. Other cases retain their
previously verified outcomes.

## Cost on ordinary sockets

Identical guest code alternated between two release hardware runners.
Medians exclude two warmups and use 16 samples per build.

| Internal loopback operation | Iterations | Previous (ms) | Current (ms) | Change |
| --- | ---: | ---: | ---: | ---: |
| UDP bind and close | 2,000 | 96.673 | 98.891 | +2.29% |
| Connected UDP send and receive | 5,000 | 155.405 | 156.107 | +0.45% |
| TCP connect, accept and transfer two bytes | 100 | 22.110 | 21.778 | −1.50% |
