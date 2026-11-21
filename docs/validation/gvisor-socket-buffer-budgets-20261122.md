# TCP and UDP queue budgets and implicit TCP listen

## Behavior

The guest TCP and UDP stack implements SO_SNDBUFFORCE and SO_RCVBUFFORCE. The existing Linux syscall entry checks CAP_NET_ADMIN. A privileged setting can exceed the ordinary socket buffer limit, and applications read it back through SO_SNDBUF or SO_RCVBUF. These changes apply to guest-owned sockets. The policy for binding a host TCP listener still applies to host-backed sockets. [Linux socket options implementation](https://github.com/torvalds/linux/blob/master/net/core/sock.c)

New queues with a large budget start with 64 KiB of payload backing per direction. A TCP write grows its send ring as needed. Receive credit grows as incoming data fills the ring. Growth preserves already acknowledged sequence offsets and out-of-order data. A listener passes its settings to accepted connections. Increasing the send budget of a full TCP queue wakes an already registered writer. UDP retains record boundaries, including empty datagrams, across growth and shrinkage.

A TCP listener in an internal guest network can now acquire an ephemeral port on its first listen without an explicit bind. It uses the same namespace allocator as bind and connect. A previously bound listener retains its port. The pinned gVisor TCP test exercises the implicit bind, while its TCPListenUnbound companion explicitly calls bind. [Pinned test source](https://github.com/google/gvisor/blob/89cacadae21eca4270a8f7c79281d0426d33ac5f/test/syscalls/linux/socket_inet_loopback.cc#L369-L428)

## Verification

The baseline is shared runtime `d580d2b`. Both Mac executors used an isolated internal network. All reported gVisor passes were checked against the original GoogleTest XML.

| Comparison | Cases | Before pass | After pass | After fail | Skip |
| --- | ---: | ---: | ---: | ---: | ---: |
| Six previously measured TCP and UDP suites | 2,121 | 2,049 | 2,061 | 28 | 32 |
| Newly measured internal TCP listen, connect and state cases | 66 | 44 | 66 | 0 | 0 |
| Total | 2,187 | 2,093 | 2,127 | 28 | 32 |

All 34 corrected results agree with native ARM64 Linux. The previously measured inventory gained 12 passes from privileged receive buffers. The coverage extension found and fixed 22 additional implicit-listen failures. The remaining 28 failures in this replay concern TCP inline urgent data (12), socket filters (10) and path MTU discovery (6).

Of 14,530 discovered cases, the cumulative inventory now contains 12,832 measured cases, including 12,263 passes, 141 failures, 20 timeouts, 407 skips and one fixture failure. The iPad interpreter running on the Mac passed all 90 focused original tests. The iOS ARM64 build check passed. No physical iPad was used for this batch.

All eight macOS runtime CI steps passed. A direct TCP test requested a near-2-GiB socket budget and observed 64 KiB of initial ring capacity, then transferred and verified 512 KiB. A UDP test queued 384 KiB before shrinking the receive budget to 8 KiB and reading back every record. Ring capacity is a storage measurement, not process RSS. Standalone transport tests had 612 passes and the same five baseline failures (four IPv4 cases and one 6LoWPAN fragmentation case).

## Performance

Both Mac executors ran the same two-vCPU guest workload. Runs alternated between baseline and candidate. Each series discarded two warm-up pairs. Durations are medians over 16 measured pairs for the socket and message workloads and 24 pairs for the byte-checked 128 MiB TCP transfer. Positive percentages indicate longer elapsed time.

| Workload | Before (ms) | After (ms) | Change | Reverse-order change |
| --- | ---: | ---: | ---: | ---: |
| UDP bind and close | 90.67 | 90.77 | +0.11% | +0.90% |
| Connected UDP delivery | 142.63 | 143.83 | +0.85% | -0.03% |
| TCP connect, accept and send | 19.34 | 19.32 | -0.07% | +0.30% |
| Unix socketpair | 11.85 | 11.85 | +0.02% | +0.33% |
| Unix stream send and receive | 19.41 | 19.41 | -0.02% | +0.24% |
| Unix datagram send and receive | 20.76 | 20.86 | +0.48% | +0.20% |
| sendmsg and recvmsg | 54.09 | 54.24 | +0.28% | — |
| TCP bulk transfer, 128 MiB | 309.48 | 310.49 | +0.33% | +0.27% |
