# Blocking Unix stream writes and tracing request admission

Nine complete upstream ARM64 Unix socket suites and two ptrace cases ran on the Mac hardware executor with two guest CPUs per environment. The baseline was runtime 374b767. Both builds used the same executables, rootfs and GoogleTest filters.

| Status | Baseline | Candidate |
| --- | ---: | ---: |
| Passed | 2,288 | 2,296 |
| Failed | 8 | 0 |
| Skipped by the original test | 106 | 106 |
| Timed out | 0 | 0 |

All candidate passes have a matching passing case in the original GoogleTest XML. Six BlockPartialWriteClosed variants returned a second successful 1 MiB write on the baseline. The first blocking write had returned as soon as its staging buffer was consumed, while the peer was still open. The candidate retains the original socket, iovec layout, sender identity and accepted byte count across backpressure. Guest copying stays bounded at 1 MiB per chunk. A ready scalar write can complete without allocating a retained request. The immediate dispatch path checks queue space and enqueues under the same socket lock so that a retry cannot duplicate a prefix.

Direct runtime tests cross the staging boundary with write, writev and connected sendto, consume the stream in uneven pieces, overwrite the guest iovec table after acceptance, and compare every received byte. They also exercise peer close, an inaccessible suffix, interruption accounting, send timeout and a change to nonblocking mode.

PtraceTest.AttachSelf and PtraceTest.AttachSameThreadGroup now observe EPERM. Tracing requests resolve targets in the caller's guest PID namespace. Attach and seize validate their prerequisites. An authorized attach and TRACEME still return ENOSYS. Trace stops, register access and the 18 previously recorded exec_binary timeouts remain open.

All eight changed upstream cases also passed under the iPad interpreter running on the Mac. The iOS ARM64 FFI compiled and the shared runtime completed its eight-step local CI on macOS.

## Cumulative coverage

This batch adds 2,018 distinct results to the previous 7,440-case inventory. The combined 9,458 cases contain 9,075 passes, 43 failures, 20 timeouts, 319 skips and one fixture failure. The eight corrected baseline failures were outside the previous inventory. The native reference lists 14,530 cases, of which 5,072 still lack an entry in the cumulative inventory.

## Performance

Two builds took turns running each guest workload on the same Mac, reversing their order on successive pairs. The table shows median elapsed time from 16 measured pairs after two warm-up pairs.

| Workload | Baseline (ms) | Candidate (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| udp_bind_close | 98.36 | 97.51 | -0.86% |
| udp_connected_delivery | 155.36 | 154.53 | -0.54% |
| tcp_connect_accept_send | 22.02 | 21.87 | -0.69% |
| unix_socketpair | 12.39 | 12.39 | -0.01% |
| unix_stream_send_recv | 20.07 | 20.00 | -0.34% |
| unix_datagram_send_recv | 21.39 | 21.60 | +0.97% |
| sendmsg_recvmsg | 56.53 | 56.36 | -0.31% |
