# Unix ancillary-message completion — 2026-11-17

Follow-up: the [multi-area compatibility batch](gvisor-multi-area-20261117.md)
repairs large Unix packets and send-buffer flow control, retaining all ancillary
passes and bringing the sequenced-packet local group to 336/336.

This closes all 84 remaining native-confirmed Unix ancillary failures from the
[network ABI checkpoint](gvisor-network-abi-fixes-20261117.md). The complete
upstream `UnixSocketPairCmsgTest` matrix now has **1,914 passes, 30 upstream skips
and no failures**, across abstract, filesystem and socketpair targets. All
**1,895 cases that pass on native Linux pass on Trames**; the other 19 passing
Trames cases have no successful native reference and are excluded from that claim.

## Repairs

| Gap | Original cases repaired | Behavior |
|---|---:|---|
| Null receive control buffer | 36 | A null `msg_control` disables ancillary copyout even when `msg_controllen` is nonzero. Payload is received, descriptors are discarded and `MSG_CTRUNC` is reported. |
| Nonexistent SCM_CREDENTIALS PID | 36 | Permission checks precede PID existence checks. A privileged nonexistent PID returns `ESRCH`; an unauthorized claim returns `EPERM`. Invalid UID/GID values return `EINVAL`. |
| Zero-length descriptor receive | 12 | A stream `recvmsg(0)` receives pending SCM_RIGHTS once without consuming payload. Packet transports retain their existing consume-and-truncate behavior. |

Credentials consult the existing indexed process provider and PID namespace;
they do not enumerate process metadata, request CPU custody or return to a
coordinator. Normal self credentials bypass the foreign-PID lookup. Generic PID
translation remains distinct from verifying a PID for SCM_CREDENTIALS.
The ordering follows [Linux SCM_CREDENTIALS validation](https://github.com/torvalds/linux/blob/v6.12/net/core/scm.c#L169-L198).

Zero-length message receive and plain zero-length byte read have distinct
entry points into the same queue algorithm. Rights are moved out of the original
queue while payload stays queued. `MSG_PEEK` clones references to the same OFDs
without detaching rights. File-table installation and final-close work still
occur outside the queue lock, using the existing portable rights graph.
The metadata-only receive follows [Linux stream descriptor detachment](https://github.com/torvalds/linux/blob/v6.12/net/unix/af_unix.c#L2736-L2757).

Owner/embedding and worker message decoders share these rules, including batch
messages. No new resource thread, global algorithm lock, polling loop or
coordinator fallback was added.

## Concentrated validation

The expanded selection runs every upstream sendmsg, recvmsg, sendmmsg and
recvmmsg case plus the complete ancillary matrix: **24 groups / 3,232 cases**.
It uses the original static ARM64 ELF binaries pinned at gVisor
`89cacadae21eca4270a8f7c79281d0426d33ac5f`, the same native Linux reference,
fresh disposable stores, an internal network, two CPUs and a lazy 8 GiB budget.
No upstream assertion, test source or skip policy was changed.

| Result | Count |
|---|---:|
| Trames passes, independently checked against original XML | 2,955 |
| Assertion failures | 169 |
| Timeouts | 30 |
| Upstream skips | 78 |
| Native-passing cases | 3,131 |
| Trames passes on those native-passing cases | 2,932 (93.64%) |

All **84 repaired cases now pass**. There are **zero regressions against previously
passing records**: the preceding repair run is used where it covered the same
case, with the original full sweep used elsewhere. This is an affected-message
selection, not a replacement overall pass rate for the 14,530-case inventory.
The [machine-readable summary](gvisor-unix-ancillary-20261117.json) records the
exact selection totals, groups, source hashes and evidence locations.

Batch receive remains 132 passes / 48 upstream skips; batch send passes all
96 selected cases. The 169 failures and 30 timeouts in other message tests were
already nonpassing; fragmented receives and other non-ancillary semantics remain
outside this completed control-message class. nftables and the broader inventory
are unchanged by this checkpoint.

Additional validation:

- Common-runtime local workflow: **8/8 macOS and 8/8 ARM64 Linux**, including
  formatting, clippy, all-feature tests, release build and physical reclaim.
- Linux/VFS unit regressions: **335 and 638 passes**, plus a subsequently added
  zero-length peek regression. Its test-only addition does not repeat unrelated
  CPU/network/graphics acceptance.
- iPad interpreter conformance: **490 passes, three existing ignores**, run
  serially after Linux CI to avoid contention between test instruction budgets.
- iPad ARM64 core compile check passes with the iPhoneOS SDK.
- Added tests cover closed/reused source FDs, real OFD aliases, one-time rights
  delivery, CLOEXEC, preserved stream payload, null control truncation, permission
  ordering, foreign-PID liveness and nested PID translation without metadata scans.

Raw logs, reference plans and original XML are retained under ignored
`target/gvisor-ancillary-completion-20261117`; native CI evidence is under
`target/local-ci/io/gvisor-ancillary-completion-20261117`. Validation uses
`tests/gvisor/batch.py`, `normalize.py` and `compare.py` as described in the
[test guide](../../tests/gvisor/README.md). The existing Linux CI instance is
stopped after validation. Installed applications and guest environments are not
replaced or restarted. Incremental compilation remains disabled for these builds;
free space stayed around 130 GiB.
