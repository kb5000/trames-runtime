# TCP urgent data on ARM64, 2026-11-22

The guest TCP transport carries the urgent pointer on the wire and tracks its position in TCP sequence space across retransmission, partial reads and FIN. A new urgent indication supersedes the old one. Applications can use MSG_OOB, MSG_PEEK, SO_OOBINLINE, SIOCATMARK and priority readiness. Accepted sockets inherit the listener's inline setting. The native TCP gateway preserves the position in both directions. Signal-driven delivery to an F_SETOWN owner was outside this validation.

The Darwin endpoint uses a lazily created kqueue exception filter for Linux POLLPRI. In a local native reproduction, Darwin poll did not return POLLPRI for an available urgent byte. MSG_OOB combined with MSG_PEEK at the urgent mark also consumed the byte. The endpoint retains that byte for repeated peeks and a subsequent consuming read. The ordinary receive path on a socket that has never received through MSG_OOB does not acquire this cursor's mutex.

A full suite rerun also exposed a separate MSS regression. Changing TCP_MAXSEG on an established socket now preserves the value negotiated at the handshake. With timestamps and TCP_CORK enabled, the preceding build could deliver 1,012 of a 1,024-byte write in the first read. The same gVisor case now receives all 1,024 bytes.

## Original tests and transport checks

| Original ARM64 gVisor suite | Mac passed | Native Linux reference passed |
| --- | ---: | ---: |
| socket_ip_tcp_generic_loopback | 805 | 805 |
| tcp_socket | 190 | 190 |
| socket_stream_blocking_tcp | 60 | 60 |
| socket_blocking_ip | 12 | 12 |
| Total | 1,067 | 1,067 |

The selected ELF hashes, case names and individual GoogleTest XML outcomes were checked. On the preceding Mac binary, all 12 SetOOBInline and all 12 WaitTillMSSWithCorkOption cases failed in a fresh run. The rolling inventory already counted the 12 MSS cases as passes on an older build. This batch therefore recovers 24 cases against the previous binary and adds 12 passes to the historical inventory.

On a Mac, the iPad interpreter passed the 24 affected original cases. A separate ARM64 Linux program passed on both executors using real system calls for IPv4 and IPv6 with inline mode enabled and disabled. It checked poll, SIOCATMARK, two consecutive peeks, a consuming read and the surrounding normal bytes. The network regressions also cover replacement of a pending urgent byte, inherited options, FIN and bidirectional forwarding through a real host TCP connection.

Runtime CI passed all eight stages, reusing three unchanged stages. The ARM64 iOS FFI check passed. A previous UDP firewall test now waits for the allowed datagram with a bounded timeout after it verifies the denied datagram on a nonblocking descriptor. No physical iPad or installed application was used.

The cumulative inventory covers 14,437 of 14,530 cases across revisions. Outcomes comprise 13,804 passed, 48 failed, 23 timed out, 561 skipped and one fixture failed. Another 93 cases have no recorded result.

## Paired performance

The same Mac ran both signed binaries with two guest CPUs. Each workload ran in 34 alternating pairs. The table gives median elapsed time after discarding the first two pairs. TCP bulk and burst exercise the internal guest network.

| Workload | Before (ms) | After (ms) | Elapsed time change |
| --- | ---: | ---: | ---: |
| TCP bulk | 31.593 | 31.778 | +0.59% |
| TCP burst | 35.569 | 35.436 | -0.37% |
| udp bind close | 94.566 | 94.407 | -0.17% |
| udp connected delivery | 146.009 | 146.679 | +0.46% |
| tcp connect accept send | 19.587 | 19.650 | +0.32% |
| unix socketpair | 12.188 | 12.213 | +0.20% |
| unix stream send recv | 19.502 | 19.444 | -0.30% |
| unix datagram send recv | 21.163 | 21.220 | +0.27% |
| memory | 173.879 | 173.827 | -0.03% |
| mmap fault unmap | 128.372 | 127.168 | -0.94% |
| file pread pwrite | 97.256 | 97.617 | +0.37% |
| fork wait | 18.675 | 18.816 | +0.75% |

Mac executable SHA-256 before and after the change was `f6bca7d8f67fd7ef190613a87980973424592c4a4d799e7460df7009d6098972` and `bd866e282c4e977398a038a5482bc90e7deca9f880059caef9159a2c26683054`, respectively.
