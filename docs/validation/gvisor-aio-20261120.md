# Legacy AIO compatibility on ARM64

The baseline was runtime `e5920f5`. Both HVF builds used the same Alpine
rootfs, two virtual CPUs and the same unmodified gVisor AIO binary.
The 14 tests ran first as one process and then individually in fresh stores.

| AIO execution | Before | After |
| --- | ---: | ---: |
| Mac HVF, one process | 2/14 | 14/14 |
| Mac HVF, separate processes | 9/14 | 14/14 |
| ARM64 interpreter, one process | — | 14/14 |

Previously, moving or protecting the header page changed the only page used
for subsequent contexts. Seven timeout and argument-validation cases failed
as a consequence. Five other failures reproduced independently. Each context
now owns a mapped ring. A move retains the backing, removing read access
invalidates lookup, and expanding the ring fails with EFAULT. Teardown
preserves unrelated replacement pages and a pending submitter keeps its
original context until copyout finishes.

A separate guest fixture consumed an event using the ring ABI, advanced
the head, and then checked that a syscall could not return the same event.
This passed on HVF and the interpreter. The Rust AIO tests also exercise a
blocked pipe during destruction, late disk completion, eventfd ordering,
staged request limits and numeric handle reuse. The ring protocol follows
the [Linux AIO implementation](https://github.com/torvalds/linux/blob/v6.12/fs/aio.c).

The nine single-node memory policy cases retained their baseline four passes
and five failures. Replacing the 23 verified rows produces 2,590 passes,
280 failures, 119 skips, 10 timeouts, three without results and one fixture
failure across the rolling 3,003-case inventory. Only these two suites were
rerun in this round. Raw output, XML, inventory and performance samples are
in `target/gvisor-aio-numa-20261120` in the iPad workspace.

## Main-path timing

Guest wall-time medians on Mac HVF, 16 measured samples per build after two
warmup pairs, with alternating run order. These figures characterize this Mac.

| Workload | Before ms | After ms | Change |
| --- | ---: | ---: | ---: |
| Ordinary memory | 172.589 | 172.383 | −0.12% |
| Map, fault and unmap | 130.780 | 131.587 | +0.62% |
| Private file pread/pwrite | 95.022 | 93.593 | −1.50% |
| Fork and wait | 19.737 | 19.209 | −2.67% |

The shared workflow passed all eight checks. Kernel conformance passed
500 cases with three ignored after correcting a test that waited for stop
notifications from worker slots which the already-completed epoch had
never admitted. The iOS FFI and ARM64 Linux session compiled. The iPad
execution check used the local interpreter.
