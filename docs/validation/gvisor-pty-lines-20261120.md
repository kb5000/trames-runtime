# PTY line discipline and job control

On 2026-11-20 the same two original ARM64 gVisor binaries ran against
runtime baseline `8b26aac` and the candidate on macOS HVF. Each case used a
fresh isolated guest with two CPUs. Passing cases were checked against their
individual GoogleTest XML and process exit status.

| Fixture and runtime | Passed | Failed | Timed out | Skipped |
| --- | ---: | ---: | ---: | ---: |
| Baseline, previous fixture | 95 | 23 | 8 | 2 |
| Baseline, inherited PTY for host_pty | 96 | 22 | 8 | 2 |
| Candidate, inherited PTY for host_pty | 126 | 0 | 0 | 2 |

The harness now gives `host_pty` a reference to the runner's interactive
terminal on FD 3. The resize signal already worked on the baseline once the
fixture supplied a terminal. The candidate adds two more passes on that
terminal, extended termios and chmod preserving the character device type.
The native reference runner supplies an inherited slave from `openpty`.
Host-side descriptor inheritance was tested locally. The native Linux
reference suite was not rerun in this iteration.

The guest PTY suite gained 28 passes. Canonical editing handles UTF-8 erase,
word erase, line length, alternate delimiters and transitions between raw
and canonical mode with unread input. Input/output CR and LF transformations,
directional queue flush, packet notifications, normal poll readiness, window
size and the extended speed fields exercise both ends of the PTY.
A PTY reports ESPIPE for positioned I/O. Process stat obtains the
mount-local terminal number and live foreground group from the controlling
terminal. A missing group returns ESRCH when setting the foreground group.
The original terminal object owns the state. No new service thread is needed.

The two skips are upstream gates. `DevPtmxMode` requires gVisor identification.
`SetTTYDifferentSession` requires an unprivileged caller. Nonzero VTIME
remains unsupported. This run covers the published suites under these
conditions, not every Linux line-discipline mode. See the [Linux N_TTY
implementation](https://github.com/torvalds/linux/blob/v6.12/drivers/tty/n_tty.c)
and [Linux speed encoding](https://github.com/torvalds/linux/blob/v6.12/drivers/tty/tty_baudrate.c).

All 28 newly passing guest-PTY cases also passed on the shared ARM64
interpreter. The iOS FFI target and Linux ARM64 session target compiled.
The runtime workflow passed all eight steps. Kernel conformance passed
500 cases with three ignored.

## Performance

Identical guest binaries alternated between the old and new HVF runners.
Each median uses 16 measured pairs after two warmup pairs. Each PTY mode
writes and drains 512 blocks of 4 KiB. The translated output inserts a
carriage return before every newline (one newline per 64 input bytes).
The guest clock measures the loop, excluding guest startup.

| Workload | Before (ms) | After (ms) | Change in time |
| --- | ---: | ---: | ---: |
| Raw PTY output | 30.180 | 2.531 | -91.62% |
| PTY output with newline translation | 32.243 | 8.731 | -72.92% |
| Raw PTY input | 8.408 | 6.084 | -27.64% |
| Ordinary memory | 171.329 | 172.521 | +0.70% |
| Map, fault and unmap | 129.690 | 129.847 | +0.12% |
| Private file pread/pwrite | 94.869 | 94.757 | -0.12% |
| Fork and wait | 19.728 | 19.643 | -0.43% |

Raw output now copies a whole contiguous slice into the bounded queue.
Translated output uses stack storage per character and commits a column
change only when the translated character fits. Application-level terminal
latency and physical iPad throughput were not measured.

The rolling inventory contains 3,003 cases. After replacing these 128 rows
it has 2,558 passes, 312 failures, 10 timeouts, 119 skips, one fixture
failure and three without results. Local plans, original XML, per-sample
timings and the inventory are in `target/gvisor-pty-lines-20261120` in the
iPad checkout.
