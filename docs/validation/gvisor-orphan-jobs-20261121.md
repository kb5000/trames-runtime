# Process groups on exit and adoption

The Mac hardware executor replayed all 90 original ARM64 cases in the processes, wait, kill and sigstop suites. Runtime 6bcee80 passed 86. The candidate passed 87, failed one, skipped one and recorded one child-fixture failure. All 87 passes have matching original GoogleTest XML. The one changed result was Processes.ExitThatOrphansGroupSignalsStoppedMembers. The 7,440-case cumulative inventory now records 7,163 passes, 43 failures, 20 timeouts, 213 skips and one fixture failure. Results outside these four suites carry forward.

When a process exits, a parent in a different process group in the same session may cease to link its group, or the group of an adopted child, to the session. The family graph examines the affected groups after adoption. If a group has lost its last such link and has a fully acknowledged stopped job, the runtime queues SIGHUP for each remaining process and then sends SIGCONT. Original task references survive concurrent changes in numeric IDs. The family lock is released before signal delivery. Ordinary same-group exit does not scan the process table. If several groups lose links during the same exit, they share a single membership scan. See the [Linux exit implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c#L309-L375).

The original positive case observes EOF on the stopped descendant's pipe after hangup. The existing negative case verifies that an already orphaned group receives no extra signal. Shared-kernel regression coverage also checks both exit and adoption, retained links through a subreaper, groups without stopped jobs and notification of running peers. The iPad interpreter ran the entire eight-case processes suite on the Mac. The iOS ARM64 FFI compiled. The shared runtime completed its eight-step local CI on macOS.

## Discovery and remaining tracing dependencies

Inventory generation now verifies ELF hashes, records failed listings, and checks duplicate names while retaining upstream disabled cases. Native batch discovery records missing, modified and unlistable binaries. A replay carries forward reference discovery errors separately from its own worker errors. Duplicate requests, duplicate results and unexpected cases cannot contribute to the batch aggregate. All 17 harness regression tests passed.

The remaining assertion failure in these four suites is KillTest.RestartArgumentNotExecutedTwice. WaitTest.TraceeWALL still records the child fixture failing PTRACE_TRACEME. The earlier exec_binary replay contains 18 timeouts. All 18 upstream test bodies call WaitStopped, which uses waitpid with zero options on a child whose test stub requests tracing and stops itself. Six of those tests also require GETREGSET after the wait. BrkAfterBinary additionally requires SETREGSET and syscall stops. These source dependencies explain why a job-control stop alone cannot establish compatibility. The individual points of timeout have not been traced in all 18 executions.

## Local hot-path check

Two runs alternated versions and reversed their starting order. Both used two guest CPUs and the same static benchmark and fixture. After two warmup pairs per run the pooled results contain 32 measured pairs. Elapsed times are medians.

| Workload | Baseline (ms) | Candidate (ms) | Elapsed change |
| --- | ---: | ---: | ---: |
| 120 /bin/true launches | 134.63 | 136.62 | +1.48% |
| 120 shell launches followed by exec | 270.93 | 268.40 | -0.93% |
| 10,000 private 4 KiB pwrite/pread pairs | 39.82 | 39.70 | -0.30% |
