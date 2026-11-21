# Unix socket binding and sender addresses

The Mac ARM64 hardware backend ran the original gVisor accept_bind, accept_bind_stream, bind, socket and socket_capability suites with two guest CPUs. Runtime 31b44c3 passed 320 of 360 cases, failed 39 and timed out on one. The candidate passed all 360. The iPad interpreter on the same Mac separately passed the 40 previously failing or timed-out cases. The iOS ARM64 FFI compiled. These results cover local execution on the Mac.

| Previously failing behavior | Cases recovered |
| --- | ---: |
| Bound, unbound and late-bound sender addresses across connect and accept | 28 |
| Sender address after coalescing stream writes | 4 |
| Connecting to an abstract name with a different socket type | 4 |
| Socket inode permissions and permissions inherited at pathname bind | 2 |
| Receiving with MSG_NOSIGNAL on an IP socket | 1 |
| Blocking stream sendmsg with 1 MiB of data and one passed descriptor | 1 |

Peers share the socket's address cell. A later bind updates the address visible to a connected peer, and a peer can read the address after the sender closes. Datagram messages carry their sender's address snapshot. Abstract bindings are scoped by socket type and network namespace. Pathname binding applies the process umask to the socket inode's current permission bits.

A blocking stream sendmsg retains its byte offset with the accepted syscall when the sender's queue fills. A receiver draining the queue wakes the sender. Only the first successful transfer carries the descriptor rights. Nonblocking sends can return a short count, and interruption after partial delivery returns the number of committed bytes. A regression with two bytes of space checks both paths. The batch-send regression separately checks short-item completion.

## Regression coverage

The final Mac replay covered 2,387 distinct cases across 15 suites, with 2,327 passes verified against the original GoogleTest XML and 60 upstream skips. All 2,027 previously recorded cases retained their outcome. The cumulative ledger now contains 7,440 unique cases with 7,160 passes, 213 skips, 46 failures, 20 timeouts and one fixture failure. The 360 newly recorded cases increase the ledger's coverage. Earlier results outside this replay are carried forward.

## Local performance

The baseline and candidate used the same guest binary and two CPUs. Each run alternated build order and discarded two warmup pairs. The six network probes used two runs with reversed starting order and 32 measured pairs in total. The separate stream message probe used 16 measured pairs. Values are median guest elapsed times in milliseconds.

| Workload | Baseline | Candidate | Elapsed change |
| --- | ---: | ---: | ---: |
| 2,000 UDP binds and closes | 97.18 | 97.81 | +0.65% |
| 5,000 connected UDP deliveries | 152.81 | 155.22 | +1.58% |
| 100 TCP connect, accept and transfer sequences | 21.51 | 22.06 | +2.56% |
| 3,000 Unix stream socketpairs | 12.50 | 12.76 | +2.12% |
| 8,000 Unix stream write/read pairs | 20.07 | 20.27 | +0.96% |
| 8,000 Unix datagram send/recv pairs | 21.72 | 21.95 | +1.08% |
| 20,000 Unix stream sendmsg/recvmsg pairs | 56.47 | 56.29 | -0.33% |
