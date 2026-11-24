# FUSE filesystem implementation checkpoint, 2026-11-23

This is an in-progress record for item 02 of the implementation follow-up
queue. The complete FUSE batch is not yet delivered. The candidate starts from
Runtime `47b743501f73122716d5a737b0bbca983d86803e`.

## Performance timing correction, 2026-11-24

The archived `path-walk-performance-long.c` used `tv_sec * 10000000000`
instead of `tv_sec * 1000000000`. Any interval crossing a whole-second boundary
therefore has corrupted elapsed nanoseconds. The earlier long-probe percentages
below are preserved as historical reports, **not valid quantitative performance
evidence**. `performance-clock-correction.json` under the artifact directory
identifies the bad ELF checksum and affected result references. The earlier
short `path-walk-performance.c` has the correct factor and is not affected.
Functional regression results are unaffected.

The corrected probe uses the proper conversion, extends getcwd to one million
iterations, and bounds the measured interval sum against an independent host
monotonic process timer. Current results are recorded in the daemon leaf-inode
checkpoint below. Historical runner/source/raw result artifacts remain intact.

## Implemented candidate

- Directory OPEN/READDIR/RELEASEDIR and FSYNCDIR use the existing accepted
  FileWork path. Directory cookies commit per successfully copied guest entry;
  partial EFAULT, insufficient buffers, dup, seek, cancellation, final close and
  FD reuse have targeted coverage.
- INIT negotiates data requests above the previous 4 KiB ceiling. The daemon's
  `max_write` is bounded to 4–128 KiB; the guest fixture verifies 16 KiB requests
  and short replies with correct original OFD offsets.
- mkdir, mknod, symlink, unlink/rmdir and rename capture the original mount and
  directory operands through the VFS walker, then park on daemon requests.
  Lookup references and accepted mount uses survive waits and numeric FD reuse.
  Mount write admission uses the existing per-mount writer protocol, including
  pending namespace and data operations.
- `open(O_CREAT)` uses CREATE and remembers an ENOSYS fallback to MKNOD+OPEN.
  Cancellation balances both the granted inode reference and open handle.
  Rename supports normal, NOREPLACE and EXCHANGE operations; an unsupported
  RENAME2 maps to EINVAL and is remembered by that connection. These protocol
  choices follow the [Linux FUSE directory implementation](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/fuse/dir.c).
- Failure coverage includes sticky ownership, directory/file mismatches,
  existing create targets, trailing slashes, malformed created-inode replies,
  and releasing write admission after failure. mknod of a directory now returns
  EPERM before mutation, matching the native comparison.

## Evidence

The standalone [`fuse-filesystem.c`](../../tests/fixtures/fuse-filesystem.c)
forks a real guest daemon. It verifies directory copy faults and cookies,
negotiated byte I/O, nested directory creation/removal, symlink creation and
readlink/lstat, atomic file creation, cached CREATE fallback, NOREPLACE,
EXCHANGE, cross-directory rename, removal and daemon/unmount cleanup.

At that namespace checkpoint, the exact same ELF passed on native Linux and on the product interpreter
with **1, 2 and 4 CPUs**. Its SHA-256 is
`795255b8f872df9d95deabbf801d140653b6bf049ef8ba9892adb1b07b5cdabc`.
The native run used private mount/PID/IPC/UTS/network namespaces in the existing
test VM; that VM was stopped after verification.

- All **27 FUSE unit tests** and **18 Linux file-path tests** pass.
- The complete VFS suite passed **762 tests, with one ignored**, at the preceding
  namespace checkpoint. Subsequent error-path changes have the targeted tests
  and guest/native checks above; unchanged ordinary VFS results are reused.
- The original 24-case gVisor FUSE group has **22 passes and two existing fixture
  skips**. A second audit checks original XML identities and process exit status.
- VFS/Linux clippy with all targets/features, formatting and production
  execution-boundary checks pass.

Artifacts are under `target/fuse-complete-20261123`. The immutable
`namespace-negative-interpreter-runner`, `fuse-filesystem-namespace-negative`
and `namespace-negative-source` retain this tested checkpoint separately from
later worktree changes. `namespace-progress.json` records source/binary hashes
and outcomes. Native output is under
`target/local-ci/io/fuse-namespace-negative-20261123-native`.

## Directory identity and fs_struct checkpoint

The subsequent local candidate gives daemon-backed directories canonical VFS
inode identities keyed by node ID and generation. The weak identity table
retains no unused directory. Directory OFDs, cwd and accepted path operations
share the actual lookup lease and retain their parent ancestry; fresh pathname
components still issue daemon LOOKUP requests. Ordinary inodes carry only the
optional pointer to this FUSE resource.

This enables relative directory-FD lookup, opening `.`, chdir/fchdir, cwd path
rendering across rename, and climbing from a removed cwd. Chdir publishes into
the original fs_struct only after daemon search permission succeeds; ACCESS
ENOSYS uses the existing connection fallback. A pending call keeps its accepted
directory when the FD slot or shared cwd changes. Successful rename/rmdir
updates the retained directory topology after the daemon reply.

The extended ELF initially exposed a shutdown failure: every file/path check
completed and unmount succeeded, but a cold fs_struct projection retained the
old mount, preventing the daemon connection from aborting. The client waited
for daemon exit and the interpreter reported no event source. Cwd/root
projection caches now hold weak handles; existing namespace ownership and real
OFD/fs_struct pins retain live topology. A regression keeps a cold observer
alive and verifies that unmount still wakes the daemon.

No coordinator or resource-service thread was added. Requests park through
the existing FileWork/readiness path; the single-CPU fixture verifies that
daemon waits release the execution slot. Identity-table and directory-location
locks cover object changes and are not held while waiting for daemon replies.

Evidence for this checkpoint:

- **33 FUSE tests**, **7 fs_struct tests**, and **133 related path/mount/proc
  tests** pass (these selections overlap). The earlier complete VFS run had
  756 passing tests and 14 host-permission failures; only those 14 were rerun
  outside the sandbox and all passed. Subsequent cache changes use the affected
  selections above, rather than repeating unaffected network tests. The final
  **18 Linux file-path tests** also pass after the cache fix.
- The exact same extended ELF passes on native Linux and on the interpreter
  with **1, 2 and 4 CPUs**, including final daemon exit after cwd/rename/rmdir.
  ELF SHA-256: `fdb7d822cfbd0d24b92733686ad04af9c14e7535bc1a0c3de6416074753633ff`.
- The original gVisor FUSE group again has **22 passes and two existing fixture
  skips**, audited against completed original XML and exact case identities.
- VFS/Linux clippy with all targets/features, formatting and production
  execution-boundary checks pass.

`target/fuse-complete-20261123/directory-identity-progress.json` records the
source/binary hashes and results. `directory-identity-fixed-source` and
`directory-identity-fixed-runner` preserve the final tested candidate. The
unfixed candidate and its original shutdown failure/trace remain separately
under the `directory-identity-source` and `directory-identity-trace-*` names.
Native results are in `target/local-ci/io/fuse-directory-identity-20261123-native`;
the VM was stopped after verification. This remains an uncommitted candidate
within the incomplete item 02 batch.

## Resumable pathname-walk checkpoint

The latest local candidate retains the ordinary VFS walk's root, current
directory, remaining components, scope boundary and link count across each
FUSE request. Metadata/open/access/chdir lookups resume that walk after daemon
LOOKUP/READLINK replies. Relative targets retain their original parent; a
numeric FD or shared cwd changed during the wait does not restart the lookup.
The accepted credentials survive the wait, including access(2)'s real-ID mode.

The same walk now handles `.`/`..`, relative and absolute followed links,
ordinary filesystem targets, crossing between FUSE connections, and the tested
openat2 NO_SYMLINKS/BENEATH/IN_ROOT constraints. A crossing open keeps its
original reserved FD and rejoins the existing FileWork/layout path when an
ordinary target needs truncation. Cancellation and interrupts follow the new
current daemon request; lookup references on the completed source are released.
Pending pathname requests retain real mount use independently of metadata Arcs.

Non-root FUSE directories cloned through open_tree(AT_EMPTY_PATH) and attached
with move_mount use their retained node IDs as bind roots. Root stat identifies
that mount root, and `..` exits through its mountpoint instead of following the
underlying FUSE directory's parent. Empty READLINK replies and link-loop bounds
were also checked with the same ELF on Linux. The implementation follows the
[Linux pathname-walk rules](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/namei.c)
and the FUSE directory operations linked above.

Evidence:

- **42 FUSE tests** and **18 Linux file-path tests** pass on the latest source.
  The preceding walk checkpoint passed **753 VFS tests, one ignored**; 26
  unaffected network/clock cases were filtered, reusing their earlier evidence.
  Ordinary-path results are reused after the FUSE-only bind-root changes.
- The exact final ELF passes on native Linux and interpreter **1/2/4 CPUs**,
  including followed links, scoped opens, an ordinary target's truncation,
  open_tree/move_mount of a FUSE subdirectory, cwd and mount-boundary `..`, and
  final daemon/unmount cleanup. ELF SHA-256:
  `560c1183883975ada615bc805847e711cb70f57d92870a23b91d4dc1651b5ae8`.
- The original gVisor FUSE group remains **22 passing, two existing fixture
  skips**, audited against completed original XML and exact testcase names.
- Clippy with all targets/features, formatting and production execution-boundary
  checks pass. No coordinator/service thread or polling mechanism was added.

The immutable source, runner and results are
`target/fuse-complete-20261123/path-walk-bind-source`, `path-walk-bind-runner`
and `path-walk-bind-progress.json`. Native output is under
`target/local-ci/io/fuse-path-walk-bind-20261123-native`; the VM was stopped.
The earlier pre-bind walk candidate and its timing samples remain separately
under the `path-walk-source`/`path-performance.json` names. This checkpoint is
still part of the uncommitted, incomplete FUSE batch.

The final bind-root candidate also ran the same ordinary private-volume probe
against `directory-identity-fixed-runner`, using copied seed stores and five
alternating measured pairs after one warmup pair. Guest timing excludes rootfs
import and runner startup:

| Probe | Before (ms) | After (ms) | Median change |
| --- | ---: | ---: | ---: |
| 10,000 ordinary stat calls | 29.177 | 29.344 | +0.57% |
| 5,000 ordinary open/close pairs | 53.716 | 53.706 | −0.02% |
| 10,000 getcwd calls | 5.083 | 5.116 | +0.67% |

`path-performance-bind.json` retains every sample and the runner/fixture
hashes. This is an incremental interpreter probe on the development Mac;
full-batch workload acceptance and FUSE transfer throughput remain pending.

## Namespace parent walk checkpoint

The mkdir/mknod/symlink/unlink/rmdir/rename prelude now retains both original
parent operands and resolves them through the common resumable PathWalk. The
old FUSE-private parent pathname loop was removed; the mutation driver only
performs the resolved parent's final LOOKUP and mutation protocol. A parent
symlink may leave FUSE for ordinary storage or enter a covering mount. Mount
classification, readonly admission and rename's EXDEV check use the resolved
parents, after pathname errors. An ordinary parent retained while the other
operand waits follows that directory's identity through rename and replacement.

When the final filesystem needs host storage work, the continuation makes one
ready transition into the existing native executor. Daemon requests still park
on readiness and release the guest CPU slot. No coordinator, resource-service
thread or polling bus was added; this is a requirement for the entire queue.

At this earlier checkpoint, mkdir and mknod retained the shared fs_struct umask
capability and sampled it after the final negative LOOKUP. A native Linux
comparison used a guest CLONE_FS helper, signaled by the daemon before replying
ENOENT, to change the caller's umask from 0027 to 0077. The resulting mkdir mode
was 0700 on both Linux and the candidate, including one guest CPU. The subsequent
open/create checkpoint below corrected an extra preparation-time mask and
checked relaxed masks and ENOSYS fallback; this tightening-only probe did not
establish all umask stages.

Evidence for this immutable candidate:

- **760 VFS tests pass, one ignored**; 26 unaffected network/clock cases remain
  filtered, with their previous evidence reused. This includes **48 FUSE tests**.
  **18 Linux file-path tests** also pass. New tests cover original FD reuse,
  relative parent links, retained ordinary rename parents, readonly-prefix
  escape, pathname-error ordering and live mkdir/mknod umask sampling.
- The exact same expanded ELF passes on native Linux and interpreter **1/2/4
  CPUs**, including namespace mutations through parent links, dotdot, a tmpfs
  covering a FUSE directory, ordinary private-storage targets, live shared
  umask and final daemon/release/unmount cleanup. ELF SHA-256:
  `f38cd539d99c8daa36971531ea13ea33f9c0d522fc1d411b57be920e60b8feb9`.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**;
  original passing XML and exact testcase identities were audited.
- Clippy with all targets/features, formatting and production execution-boundary
  checks pass. The native VM was stopped after the comparison.

The immutable source and runner are
`target/fuse-complete-20261123/namespace-parent-source` and
`namespace-parent-runner`; `namespace-parent-progress.json` stores hashes and
results. Native output is under
`target/local-ci/io/fuse-namespace-parent-20261123-native`. The earlier bind-root
checkpoint remains intact. This is still an uncommitted part of item 02, with
no changes to the delivered Runtime or either product's paired pin.

The same ordinary private-volume probe also ran against the immediately prior
`path-walk-bind-runner`, with copied seed stores and five alternating measured
pairs after one warmup pair. Guest timing excludes runner startup/rootfs import:

| Probe | Before (ms) | After (ms) | Median change |
| --- | ---: | ---: | ---: |
| 10,000 ordinary stat calls | 29.688 | 30.128 | +1.48% |
| 5,000 ordinary open/close pairs | 54.327 | 54.174 | -0.28% |
| 10,000 getcwd calls | 5.035 | 4.963 | -1.42% |

`namespace-parent-performance.json` retains all samples and binary hashes. This
is incremental ordinary-path evidence, not FUSE throughput or final workload
acceptance.

## Open/create state checkpoint

Exclusive creation now reports EEXIST for an existing final inode before
symlink, access or readonly errors, including a final symlink with O_NOFOLLOW
or openat2 NO_SYMLINKS. Lookup retains the shared mount flags instead of copying
them before a daemon wait; access tests change readonly/noexec during that wait
and verify the final EROFS/EACCES checks against current state.

Open reservations retain the unmasked requested mode and original shared umask
capability. Each CREATE or fallback MKNOD callback samples live umask for the
wire mode, then reads it again for the wire umask. ENOSYS retains the raw mode
and actual parent directory through the fallback request. This also fixes a
premature FORGET of the creation parent discovered by the new fallback test.

The initial experiment incorrectly applied a VFS umask before final LOOKUP and
expected mode 0604 after changing 0002 to 0070. Native Linux instead sent mode
0606 with umask 0070. Linux FUSE sets SB_POSIXACL internally specifically to defer
VFS umask stripping, even without negotiating userspace ACL support; mode is
masked inside the FUSE callback. The candidate and assertions now follow that
behavior. The earlier failed native fixture and diagnostic run remain under
`target/local-ci/io/fuse-open-state-20261123-native` and
`fuse-open-state-probe-20261123-native`; both timed out after the daemon's failed
assertion, and their VMs were stopped. They are not counted as passing runs.
The final assertion was restored to the Linux-observed value, and the native
fixture also verifies a later 0027-to-0077 change between CREATE ENOSYS and its
MKNOD fallback, producing mode 0600.

Source references: Linux v6.12
[FUSE superblock initialization](https://raw.githubusercontent.com/torvalds/linux/refs/tags/v6.12/fs/fuse/inode.c),
[FUSE CREATE/MKNOD callbacks](https://raw.githubusercontent.com/torvalds/linux/refs/tags/v6.12/fs/fuse/dir.c)
and [namei open ordering](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/namei.c).

Evidence for the corrected immutable candidate:

- **51 FUSE tests pass**. Reuse the preceding **760 passing VFS tests, one
  ignored**, with 26 unaffected network/clock cases filtered, **18 Linux file-path
  tests**, and ordinary-path performance above: later edits only affect FUSE
  state, FUSE reservation arguments and the guest fixture.
- The final identical ELF passes on native Linux and interpreter **1/2/4 CPUs**.
  ELF SHA-256:
  `40e38f014fcd8375c9030cf5fe77b3ccc5e252a7de6761e4feeaac90b1ed6522`.
  The single-CPU run includes the CLONE_FS/daemon handshake and ENOSYS fallback;
  this is guest test machinery, with no new production host thread.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**,
  audited against original XML and all 24 exact planned testcase identities.
- Clippy, format and execution-boundary checks pass; the native VM was stopped.

`target/fuse-complete-20261123/open-state-fixed-source`,
`open-state-fixed-runner` and `open-state-fixed-progress.json` retain source,
runner, binary hashes and result provenance. Native output is under
`target/local-ci/io/fuse-open-state-fixed-20261123-native`. Both preceding
checkpoints and the failed native experiments remain intact. Item 02 remains
incomplete and uncommitted; the delivered Runtime/pins are unchanged.

## Native pathname continuation checkpoint

A resumed FUSE walk now yields before entering an ordinary path stage that may
perform hostfs, private-volume or overlay I/O. It retains the same current/root
paths, remaining components, link count, credentials and original open
reservation. A ready continuation runs through the existing native executor;
it does not block a guest CPU slot in the daemon-reply path. Native traversal
can return to FUSE, at which point the work parks on the new daemon request.
No coordinator/service thread or polling bus was added.

The native stage has no FUSE request to interrupt or subscribe to. Old completed
requests and lookup references are retired when that stage is accepted. A
cancelled native stage releases its reserved FD without opening/creating the
host target. Namespace parent work forwards the same scheduling state, and a
host mutation reuses its current native walk job. Chdir publishes the original
shared fs_struct cwd only after native completion.

Evidence:

- **56 FUSE tests pass with hostfs enabled**, including five new hostfs tests
  covering the scheduling boundary, original FD reservation, cancellation,
  host symlink returning to FUSE and the new interrupt identity, host namespace
  mutation before effects, and shared-cwd publication.
- The ordinary affected VFS set passes **763 tests, one ignored**, with 26
  unaffected network/clock cases filtered and their previous evidence reused.
  **18 Linux file-path tests** pass. Clippy with all targets/features, formatting
  and production execution-boundary checks pass.
- The same guest daemon/client ELF passes on the product interpreter at
  **1/2/4 CPUs**, including ordinary private-volume targets, namespace mutations
  and the CLONE_FS handshake/ENOSYS fallback. Its source and ELF are unchanged
  from the preceding checkpoint, so that exact ELF's passing native Linux
  result is reused. ELF SHA-256 remains
  `40e38f014fcd8375c9030cf5fe77b3ccc5e252a7de6761e4feeaac90b1ed6522`.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**,
  audited against original XML and all 24 exact planned testcase identities.

Artifacts are `target/fuse-complete-20261123/native-walk-source`,
`native-walk-runner` and `native-walk-progress.json`. This closes the native
scheduling gap demonstrated above; typed proc original/owner fallback after a
deferred walk remains separate work. In particular, an unavailable proc
provider or final owner-only open must retain its continuation and accepted
resources rather than replay the original FUSE pathname or expose internal
EOPNOTSUPP. Item 02 is still incomplete and uncommitted, with delivered Runtime
and paired product pins unchanged.

The ordinary private-volume probe also ran against `open-state-fixed-runner`,
with copied seed stores and five alternating measured pairs after one warmup
pair. Guest timing excludes rootfs import and runner startup:

| Probe | Before (ms) | After (ms) | Median change |
| --- | ---: | ---: | ---: |
| 10,000 ordinary stat calls | 29.366 | 29.030 | -1.14% |
| 5,000 ordinary open/close pairs | 53.946 | 54.354 | +0.76% |
| 10,000 getcwd calls | 4.960 | 4.935 | -0.51% |

`native-walk-performance.json` preserves all samples and runner/fixture hashes.
This is incremental ordinary-path evidence; FUSE transfer throughput and final
workload acceptance are still pending.

## Proc/original-resource continuation checkpoint

A resumed walk now stops before unavailable proc metadata or an original legacy
TTY resource needs its existing owner checkpoint. It retains the same current
and root directories, unconsumed components, policy/link count, credentials and
open reservation. `resume_owner` returns that same FileWork to normal scheduling;
it can subsequently wait on another daemon, enter native work or finish. Both
source dispatch and the serial interpreter path handle that resumable outcome.
The original FUSE pathname is never replayed after the handoff.

Cold final opens reuse the existing io_uring original-resource scope over the
accepted Files, credentials, filesystem/namespace and byte providers. Its private
caches/admission are restored on exit or unwind. A joined metadata view can use
its original published proc/legacy devpts resources; this adds no second guest
permission policy and no coordinator/service thread. Available production proc
providers continue through the ordinary source path.

A proc-fd link to an ordinary FUSE file previously lacked a guest NodeRef and
could lose its FUSE control when reopened. That path now retains the original
inode lookup lease and source handle for GETATTR, then issues a fresh OPEN and
publishes a new OFD/handle with an independent position. Closing/reusing the
source FD cannot retarget it. Ordinary pathname opens and these inode reopens
share their final open checks, including exclusive-existing ordering and current
readonly flags. The new OFD and final lookup reference release independently.

Evidence for this immutable candidate:

- **63 FUSE tests pass with hostfs enabled**, including unavailable/no-provider
  stat without path replay, memfd/proc-fd open with its original reserved slot,
  a proc directory returning to FUSE after owner join and surviving FD reuse,
  parent creation, legacy PTY open, owner-stage cancellation, and a reopened
  FUSE file's new handle, source-FD reuse, FLUSH/RELEASE and final FORGET.
- **770 VFS tests pass, one ignored**, with 26 unaffected network/clock cases
  filtered. **18 Linux file-path tests** and **four interpreter file-scheduling
  conformance tests** pass. A new conformance case actually crosses the owner
  checkpoint, returns a retained FileWork and completes the open, asserting
  exactly one FUSE LOOKUP and READLINK. The existing layout/native-result tests
  also pass. Clippy with all targets/features, formatting and production
  execution-boundary/host-execution checks pass.
- The expanded identical ELF passes on **native Linux and interpreter 1/2/4
  CPUs**, including proc directories returning to FUSE, proc-fd opens of ordinary
  storage and FUSE files, independent file positions, and final daemon/handle/
  unmount cleanup. ELF SHA-256:
  `9933c2cb704937fc0580ef67d445740c6375454d337c6a55155ee1dca7ed5c5a`.
  The native VM was stopped after its run.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**,
  audited against original XML and all 24 exact planned testcase identities.

Use `cargo test -p trames-core --test kernel-conformance process::file_io::tests`
for these interpreter cases. The exploratory direct-runtime `--cfg` invocation
failed because runtime/session intentionally has no CPU dependency; an earlier
wrong module filter selected zero tests. Neither attempt is counted as passing
coverage. Their logs and the corrected four-test run are retained.

Artifacts are `target/fuse-complete-20261123/proc-walk-source`, `proc-walk-runner`
and `proc-walk-progress.json`. Native output is under
`target/local-ci/io/fuse-proc-walk-20261123-native`. This verifies the described
metadata/open/parent continuation and cold resource handoff, not every proc magic
link consumer. Item 02 remains incomplete and uncommitted; delivered Runtime and
paired product pins remain unchanged.

The same ordinary private-volume probe ran against `native-walk-runner`, with
copied seed stores and five alternating measured pairs after one warmup pair.
Guest timing excludes rootfs import and runner startup:

| Probe | Before (ms) | After (ms) | Median change |
| --- | ---: | ---: | ---: |
| 10,000 ordinary stat calls | 29.197 | 29.186 | -0.04% |
| 5,000 ordinary open/close pairs | 55.491 | 54.110 | -2.49% |
| 10,000 getcwd calls | 5.006 | 5.033 | +0.53% |

`proc-walk-performance.json` preserves all samples and runner/fixture hashes.
This remains incremental ordinary-path evidence; real FUSE transfer throughput
and final workload acceptance are pending.

## Final-inode access checkpoint

Access after a proc magic jump now uses the retained descriptor/inode rather
than discarding that target or sending ACCESS to FUSE node 1. A FUSE file or
directory retains its original lookup lease and actual mount until the ACCESS
reply or cancellation. Closing/reusing the numeric source FD cannot retarget
the operation; FLUSH/RELEASE and the final FORGET remain independent. ENOSYS
caching starts only after the actual inode request.

The resumed operation keeps the access(2) real-ID or faccessat2 effective-ID
authority across the existing owner checkpoint. It retains the live mount
flags, while special device/pipe/socket inode writes keep their Linux readonly
exception. The exact readonly-check stage is corrected in the follow-up below.
Anonymous inodes and memfd targets use their
actual ownership/mode with the shared DAC/capability decision. The retained
directory shortcut now performs the same allow_other check before walking out
of a removed FUSE bind root.

`F_OK` also delegates an ACCESS request with a zero wire mask. This corrects an
older local shortcut; Linux supplies MAY_ACCESS even when the user mask is zero
([Linux v6.12 FUSE permission/access implementation](https://github.com/torvalds/linux/blob/v6.12/fs/fuse/dir.c#L1468-L1585)).
Both the protocol regression and the native Linux fixture reject F_OK when the
daemon rejects the final inode, making this difference observable.

A final proc-fd jump to hostfs now retains the already resolved entry before
entering the existing native executor. Its current permissions are refreshed
through the original host fd, including after rename, path replacement and
numeric guest-fd reuse. It does not replay the proc pathname. This adds no
coordinator, resource-service thread or polling bus; production waits use the
existing FileWork/readiness protocol and release the execution slot.

Evidence for the immutable `access-target` candidate:

- **72 FUSE tests pass with hostfs enabled**, including nine new final-inode,
  authority, readonly/noexec, unsupported-ACCESS, cancellation, removed-directory
  and native-target regressions. The native fixture now answers ACCESS and
  rejects selected actual nodeids instead of globally returning ENOSYS.
- **778 VFS tests pass, one ignored**, with 26 unaffected network/clock cases
  filtered. **18 Linux file-path tests** and **four interpreter file-scheduling
  conformance tests** pass. All-target/all-feature clippy for VFS/Linux/session,
  formatting, execution boundaries and host-execution checks pass.
- The same expanded ELF passes on **native Linux and interpreter 1/2/4 CPUs**,
  including FUSE regular/directory proc-fd access, zero-mask daemon rejection,
  memfd/eventfd permissions, readonly special inodes, noexec, and ENOSYS caching.
  ELF SHA-256:
  `0e71f86002390dafccc548b90caea07a66057958d7fc2195bbab3e6a13c77379`.
  The native VM stopped successfully after the run.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**.
  Original passing XML and all 24 exact planned testcase identities are audited.

The initial real-ID fixture reached a root-owned proc fd directory and correctly
failed before ACCESS. It now observes a target process owned by the real UID/GID
so the test actually reaches the final FUSE request under both authorities.
The memfd fixture explicitly sets mode 0600 because Linux memfd defaults to 0777.
A test-only atomic suffix prevents concurrent hostfs fixture directory collisions.
Failed exploratory logs are retained and excluded from passing evidence.

Artifacts are `target/fuse-complete-20261123/access-target-source` (44 hashed
source files), `access-target-runner`, `fuse-filesystem-access-target`, and
`access-target-progress.json`. Native output is under
`target/local-ci/io/fuse-access-target-20261123-native`. This closes the described
access consumer and native final-entry handoff; it does not establish all other
pathname consumers or the complete FUSE item. Delivered runtime/product pins
remain unchanged.

The first short ordinary-path probe against `proc-walk-runner` reported median
changes of +8.91% stat, +7.15% open/close and +2.11% getcwd. All samples are saved
in `access-target-performance.json`; this run is not treated as a performance
pass. A longer probe, with 100,000 stat calls, 50,000 open/close pairs and 100,000
getcwd calls per sample, then ran eight alternating measured pairs after one
warmup pair. Its changes were -0.65%, -1.26%, and -0.66%, respectively, preserved
in `access-target-long-performance.json`. The longer run did not reproduce the
short-run regression. These are development-Mac incremental measurements, not
real FUSE transfer throughput or final workload acceptance.

The `access-target` snapshot is superseded by the permission-order follow-up:
its readonly error precedence was still incorrect when the daemon denied ACCESS.
Its successful checks above remain evidence only for that exact intermediate
source, not full Linux permission-order parity.

## ACCESS permission-order follow-up

For a bind readonly mount, the final noexec check precedes inode permission,
then the daemon's ACCESS result precedes the mount readonly result. A successful
ACCESS (including cached ENOSYS) samples the live readonly flag when finishing;
it does not reserve a mount writer. This follows
[Linux do_faccessat](https://github.com/torvalds/linux/blob/v6.12/fs/open.c#L467-L525).
The earlier eager EROFS could hide EACCES/EPERM and sample flags before a daemon
wait. The new retained ACCESS state holds the actual mount flags and inode kind
until reply, preserving malformed reply/error handling and the special-inode
exception. No new thread, queue, timer or polling route is introduced.

The `access-order` candidate supersedes the earlier access snapshot:

- **73 FUSE tests with hostfs** and **779 related VFS tests, one ignored** pass;
  26 unaffected network/clock cases remain filtered. New cases verify daemon
  EACCES/EPERM before EROFS, RW-to-RO and RO-to-RW changes during ACCESS, ENOSYS
  with readonly completion, and noexec before ACCESS on a readonly mount.
- The identical expanded ELF passes on **native Linux and interpreter 1/2/4
  CPUs**. The daemon changes the actual shared mount to RO/RW while ACCESS is
  pending; both kernels observe the completion-time flag, and a denied inode
  still returns EACCES on a readonly mount. SHA-256:
  `4ceedfe20cf2167fb8c294f207beaeaeee60314499ecdb64cb8b7442fb29d3eb`.
  The native VM is stopped.
- Original gVisor FUSE is again **22 passing, two existing fixture skips**;
  original XML and all 24 exact planned identities are audited. Updated clippy
  and formatting checks pass. The unchanged 18 Linux file tests, four interpreter
  scheduling cases and production boundary checks reuse the prior checkpoint's
  evidence; this follow-up only changes FUSE ACCESS completion and its tests.

Artifacts: `access-order-source` (44 source hashes), `access-order-runner`,
`fuse-filesystem-access-order` and `access-order-progress.json` under
`target/fuse-complete-20261123`. Native output is
`target/local-ci/io/fuse-access-order-20261123-native`. The uncompiled exploratory
snapshot/log are retained separately; they are not passing evidence. Item 02
remains uncommitted and incomplete, with delivered runtime/product pins unchanged.

The final `access-order-runner` repeats the longer ordinary-path comparison
against `proc-walk-runner`, with eight alternating measured pairs after a
warmup pair and independent copied seed stores. Median changes are **-0.29%
stat, +0.14% open/close and +1.20% getcwd**. All rows and binary/fixture hashes
are in `access-order-long-performance.json` and the progress JSON. The earlier
short-probe increase was not reproduced by either longer run. These measurements
do not replace real FUSE throughput or complete-workload acceptance.

## Chdir final-magic-target checkpoint

The previous hostfs regression reproduced a wrong cwd: after a FUSE link jumped
to a proc directory fd, the walk converted that inode into a pathname before
native dispatch. Closing/reusing the fd and replacing that pathname while the
job waited made chdir enter the replacement directory. The failing assertion
and original source remain in `chdir-proc-host-before2.log` and the prior
`access-order-source` snapshot.

Chdir now retains the complete final ResolvedEntry through the existing
NativeEntry handoff. The final operation uses the accepted descriptor/inode and
mount, without resolving its display label again. Fchdir uses the same final
directory checks with one accepted descriptor. Native search permissions are
refreshed through the original host capability before publishing fs_struct.
Proc-cwd observations also retain that capability, so a target changing its cwd
and a subsequent process-view refresh cannot drop or redirect the accepted
directory. Constructing a host proc-cwd target uses a cached name hint; native
path rendering is not needed to identify the final inode before dispatch.

The FUSE directory path keeps its original GETATTR/ACCESS nodeid and lookup
lease. Closing/reusing the source fd and renaming the directory during ACCESS
cannot redirect publication; denial or cancellation leaves cwd unchanged and
releases the final lookup. A FUSE regular-file or anonymous-inode proc fd now
reports ENOTDIR for chdir, rather than failing through missing guest NodeRef
metadata. No coordinator/service thread, queue or polling route was introduced.

Evidence:

- **79 FUSE tests pass with hostfs enabled**. Six new regressions cover retained
  host fd identity, proc-cwd capability lifetime, live chdir/fchdir search
  permission, FUSE rename/fd reuse during ACCESS, denial/cancellation cleanup,
  and non-directory errors.
- **782 related VFS tests pass** in the default configuration and **826 pass
  with hostfs**; each has one ignored case and 26 unaffected network/clock
  cases filtered. **18 Linux file-path tests** and **four interpreter file
  scheduling conformance tests** pass. Formatting and production execution/host
  boundary checks pass; current all-target/all-feature VFS/Linux/session clippy
  passes after the equivalent Option::map expression cleanup noted below.
- The identical expanded ELF passes on **native Linux and interpreter 1/2/4
  CPUs**. It exercises proc-fd/proc-cwd chdir, daemon denial, ENOTDIR for ordinary
  FUSE files and memfd/eventfd, and entering an already removed FUSE directory
  before getting ENOENT from getcwd and climbing to its actual parent.
  SHA-256: `0d5d7547e1648c9cc8e5f496770bd3722b98630453e01f80b7b8ab73d106a708`.
  The native VM stopped successfully.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**,
  audited against original XML and all 24 planned testcase identities.
- The longer ordinary private-volume probe compares `access-order-runner` with
  `chdir-proc-runner`, using eight alternating measured pairs after a warmup
  pair. Median changes are **-0.01% stat, +1.40% open/close, -0.24% getcwd**;
  all rows/hashes are preserved in `chdir-proc-long-performance.json`. This is
  incremental evidence, not real FUSE throughput or final workload acceptance.

Artifacts are under `target/fuse-complete-20261123`: `chdir-proc-source` (46
hashed validation sources), `chdir-proc-runner`, `fuse-filesystem-chdir-proc` and
`chdir-proc-progress.json`. Native output is under
`target/local-ci/io/fuse-chdir-proc-20261123-native`. After behavioral validation,
clippy requested replacing one if-let/Some/None expression with Option::map;
`chdir-proc-clippy-style.patch` and `chdir-proc-current-sources.json` identify
that sole equivalent source change. Unchanged behavior evidence is reused,
without repeating the CPU/backend checks solely for the expression cleanup.
The early host permission fixture tried opening a mode-0 host directory on
macOS; it now opens first and changes permissions via the guest syscall. Owned
temporary-directory cleanup handles permission-revocation tests on unwind.
Exploratory failures are preserved and excluded from passing evidence.

This proves final magic targets, not every proc jump with remaining components.
The non-final host directory branch still converts the target via location
before continuing; its capability, trailing-dot/child/dotdot behavior and deleted
host directory parent traversal require further audit. The ordinary FUSE inode
and removed-directory cases above do not close that separate common-walk gap.
Item 02 remains incomplete and uncommitted; runtime/product pins are unchanged.

## Proc directory continuation checkpoint

The non-final proc magic jump now retains its accepted directory through the
existing PathWalk/native/owner handoffs. A hostfs regression first reproduced
stat/open/chdir resolving a replacement inode after the original directory fd
was closed/reused, its directory moved, and its old pathname recreated.
`directory-anchor-before.log` preserves that failure. The fixed regression
covers a child, `.`, `..` and a trailing slash, and checks the actual dev/inode.

Host paths retain an operation-owned native directory capability and resolve
children relative to it. Remaining components, parent namespace operations,
relative symlinks and mount attachment checks use that identity. They do not
replay a display key after a native wait. Directory capabilities use Darwin's
search-only descriptor where available: O_EVTONLY alone loses fstat access
after rmdir. Deleted-directory chdir/getcwd/parent traversal is tested. Native
getcwd also checks whether a still-rendered F_GETPATH spelling names the same
inode, without adding an ancestor DAC requirement when that check gets EACCES.

Memory and private-volume directories likewise retain their accepted inode.
Child lookup obtains the parent's current key within the existing namespace
index guard; overlay materialization retries only if that parent changed while
its guard was released. Mutations rebase accepted parents inside the existing
namespace mutex. A further hard-link regression demonstrated insertion under
the replacement parent; rebasing both ordinary hard-link operands fixes it.
The failing and passing runs are `directory-anchor-link-before2.log` and
`directory-anchor-link-after.log`.

Positive lookup results and original proc/mount resources are retained only
for their accepted operation; failed lookups are not cached across CREATE.
Normal unanchored native paths keep their existing fast route. No coordinator,
resource-service thread, polling bus, whole-call lock or ordinary-memory fence
was added. The namespace locks and native executor are existing resources.

Evidence:

- **84 FUSE tests pass with hostfs enabled**, including retained host parent
  mutations, covering mounts after parent rename, deleted host directories and
  private-volume continuation. Separate accepted-walk tests close/reuse the fd
  and replace its old pathname for both memory and private-volume roots.
- **785 default and 833 hostfs related VFS tests pass**; each configuration has
  one ignored case and 26 unaffected network/clock cases filtered. **18 Linux
  file-path tests** and **four interpreter file scheduling tests** pass.
  All-target/all-feature VFS/Linux/session clippy, formatting and execution/host
  boundary checks pass against the current source snapshot.
- The identical expanded ELF passes on **native Linux and interpreter 1/2/4
  CPUs**. Added guest checks include proc directory children, relative
  symlinks, creation/deletion/rename and a covering mount after parent rename.
  ELF SHA-256 is
  `76ea69c6287ae520335b216e7257af1a6f16505779f1bc760be85e3c5894dc1f`.
  Native output is in
  `target/local-ci/io/fuse-directory-anchor-20261123-native`; its result is zero
  and `directory-anchor-native.log` records VM shutdown.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**,
  with original passing XML and all **24 planned testcase identities** audited.
- The ordinary private-volume long probe compares `chdir-proc-runner` with
  `directory-anchor-runner`: eight alternating measured pairs after a warmup
  pair, with 100,000 stat, 50,000 open/close and 100,000 getcwd calls per row.
  Median changes are **-0.47%, -0.16%, +0.11%**, respectively. Every sample and
  binary hash is retained in `directory-anchor-long-performance.json`.
  This is incremental pathname performance evidence, not FUSE throughput.

Artifacts are under `target/fuse-complete-20261123`:
`directory-anchor-source` contains 48 hashed Rust/C sources and the base/patch;
`directory-anchor-runner` has SHA-256
`3297362467af3ca711fbb9e8d5a60762115757a7ed54b8e312bbbb89a2fbde52`;
`directory-anchor-progress.json` ties the source, test logs, ELF, native result,
interpreter results and gVisor audit together. Sources were unchanged after
validation. Failed experiments and fixture corrections are preserved separately
and excluded from passing evidence. In particular, the private-volume fixture
originally closed the fd before the proc target had been accepted; it now keeps
it live until that checkpoint, while the separate accepted-walk regressions
test close/reuse after acceptance.

This closes the identified remaining-component directory identity gap, not the
entire pathname audit. The guest covering-mount fixture mounts at the ordinary
pathname and looks up through the FUSE/proc alias; mounting with a target that
itself traverses a FUSE symlink is still a separate consumer to join. Async mmap,
the full permission/writer audit, a real FUSE program, throughput and final
paired backend acceptance remain open. Item 02 is incomplete and uncommitted;
runtime/product pins are unchanged.

## Legacy topology pathname checkpoint

Legacy mount, umount and pivot_root now resume daemon-backed pathname walks
through their existing NamespaceWork. The original synchronous mount-through-
FUSE-link regression returned EOPNOTSUPP; `topology-path-before2.log` records
that failure against the preceding directory-anchor sources with the new test.

Each operation retains accepted ResolvedEntry values while another operand
waits. Keys include the operand's position and resolution parameters, so equal
source/target strings remain separate lookups. Re-entering the unchanged
topology algorithm consumes those original results. Bind now derives namespace
and inode information from one accepted source, including recursive binds,
instead of resolving that source again. Cloned original proc-directory leases
share the same MountUse through Arc; accepted aliases do not add new users.

The existing mount-admin lease is released on daemon/native/owner waits, then
reacquired when the topology algorithm runs. The path-change guard covers the
actual topology mutation. No new coordinator/service thread, bus, polling loop
or synchronization policy was introduced. An additional hostfs regression
found that after accepting a native operand, a later FUSE reply could run the
final algorithm on its receiving worker. NamespaceWork now explicitly returns
that phase to the existing native executor. The regression verifies the yield
before any mount effect, and retains the original host target after rename and
same-name replacement.

Evidence:

- **94 FUSE tests pass with hostfs enabled**. Nine new topology tests cover
  escaped links, covering/unmounting FUSE directories, bind/move target identity,
  independent equal-spelling operands, ordinary-file binds, pivot_root,
  capability ordering, NOFOLLOW and cancellation. One new hostfs test checks
  the final native dispatch and original directory capability.
- **794 default and 843 hostfs related VFS tests pass**, each with one ignored
  case and 26 unaffected network/clock cases filtered. **Four interpreter file
  scheduling conformance tests** pass. All-target/all-feature VFS/Linux/session
  clippy, formatting and execution/host boundary checks pass. The initial
  topology checkpoint's **18 passing Linux direct-file tests** are reused:
  the subsequent refinements affect legacy topology operand capture/dispatch,
  while those direct-file paths are unchanged. Final VFS/session checks reran.
- The identical expanded ELF passes on **native Linux and interpreter 1/2/4
  CPUs**, adding mount/remount/bind/move/umount through FUSE links, NOFOLLOW,
  and covering a real FUSE directory. ELF SHA-256 is
  `519aea7ed44d1d59846f567b281f43d2a79e6fab38117703072214b4a665b6fe`.
  Native result is zero in
  `target/local-ci/io/fuse-topology-path-20261123-native`; the VM stopped.
- Original gVisor FUSE remains **22 passing, two existing fixture skips**, with
  all 24 planned testcase identities and original passing XML audited.
- The ordinary private-volume long probe compares `directory-anchor-runner`
  with `topology-path-runner`: eight alternating measured pairs after a warmup
  pair. Median changes are **-0.09% stat, -0.87% open/close, -0.83% getcwd**.
  All samples and hashes are in `topology-path-long-performance.json`. This
  does not measure real FUSE transfer throughput.

Final artifacts are under `target/fuse-complete-20261123`:
`topology-path-accepted-source` contains 49 hashed Rust/C sources;
`topology-path-runner` has SHA-256
`5cd1c0cdf0e020ad21328cb4d3d90a37c0ddf05e30c766808e842a2792622ec0`;
`topology-path-progress.json` links those sources, checks and runtime evidence.
Sources were unchanged after validation. The earlier `topology-path-source`
and `topology-path-final-source` snapshots are exploratory, superseded by
`topology-path-accepted-source`. Native-dispatch and operand-aliasing failures
are retained in `topology-path-native-dispatch-before.log` and
`topology-path-operands-before2.log`. An early pivot_root postcondition tried
using the synchronous embedding stat API on a FUSE root; the final test checks
the new root and an ordinary original-root marker without requiring daemon I/O
from that synchronous API.

This joins the tested legacy topology calls for FUSE directories and links
that reach supported targets. It does not complete FUSE regular-file bind
capabilities or modern mount-FD pathname consumers; the direct daemon regular
leaf still returns EOPNOTSUPP on the new resolution route. Other pathname
consumers and the permission/writer audit remain open, along with async mmap,
real application/throughput and final paired backend acceptance. Item 02 is
still incomplete and uncommitted; runtime/product pins are unchanged.

## Regular-file bind and connection lifetime checkpoint

Legacy bind can now retain a daemon regular inode as its source or covered
mountpoint. Canonical `(nodeid, generation)` identity is shared by LOOKUP,
CREATE and MKNOD-open; reported inode numbers alone do not merge objects.
The inode has explicit daemon content, with no synthetic local file bytes.
A bound root issues GETATTR/ACCESS/OPEN against the original nodeid. Fresh
opens acquire independent daemon handles; proc-fd bind keeps inode authority
after the source FD closes without keeping that old handle alive. An invalid
CREATE type collision releases its granted handle and lookup reference.

The expanded guest fixture exposed three integration failures that the first
unit checks missed:

- O_PATH fstat parked two requests and stalled. Typed FileWork now consumes the
  pending GETATTR directly, preserving the accepted original FD through close
  and reuse. Linux direct-file regression records one original request and no
  pathname or numeric-FD replay. The file view keeps the original PID namespace
  for O_PATH daemon mounts too.
- After path bind/umount, proc-fd bind returned ENOENT because a local-index scan
  cleared the inode's path hint. The accepted OFD label plus actual inode now
  provide the mount operand. Canonical daemon files do not populate that local
  pathname cache. Regression entry replies use real nonzero link counts and
  include the preceding path bind/umount that triggers cache invalidation.
- Final umount succeeded but daemon read remained blocked. A proc namespace
  metadata projection retained the superblock after its real users departed.
  Mount owners, real MountUse/OFD leases, daemon file handles and mount binding
  publication now share a ConnectionUse. Metadata projections retain physical
  objects without retaining this active connection lease. Its last drop aborts
  the connection; a weak back-reference prevents cold metadata from reviving it.
  Reused daemon mounts and lazy-unmounted open files/implicit FLUSH have explicit
  regressions. This changes lifetime ownership, not the scheduler's idle test.

Standalone topology continuations also preserve an initial owner/native phase
without creating a daemon request. The accepted first mount operand survives
rename/replacement while another operand joins the owner checkpoint. Disconnect
now advances the existing poll epoch as well as notifying readiness; a separate
negative regression covers that missing transition. Poll epoch advancement
alone did not fix the retained-connection failure.

All paths reuse existing workers, native execution, owner checkpoints and
readiness. No coordinator/service thread, polling bus or new global call lock
was introduced.

Final evidence, all under `target/fuse-complete-20261123` unless stated:

- **104 hostfs FUSE tests**, **804 default / 853 hostfs related VFS tests**
  pass. The broad VFS runs each have one ignored and 26 unaffected network/clock
  filters. **19 Linux direct-file tests and four interpreter file scheduling
  conformance tests** pass. All-target/all-feature VFS/Linux/session clippy,
  formatting and execution/host boundary checks pass.
- The identical ELF passes on **native Linux and interpreter 1/2/4 CPUs**.
  It checks path and proc-fd file binds, O_PATH fstat, fresh open/read/write after
  source unlink, live readonly bind remount and an ordinary file covering a
  daemon file. It waits for all 14 RELEASE messages before final umount.
  ELF SHA-256 is
  `22aee21ae6359ed7e470007709102f2525d65730719349bad3e1cf4ea087fa08`.
  Native result is zero in
  `target/local-ci/io/fuse-file-bind-active-20261123-native`; the VM stopped.
  An earlier native launch lacked the copied ELF's execute bit (exit 126);
  that fixture launch failure is preserved separately from the successful run.
- Original gVisor FUSE remains **22 passing and two existing fixture skips**;
  all 24 exact planned identities and the 22 original passing XML cases are
  audited in `gvisor-file-bind-active-audited`.
- The ordinary private-volume long probe compares `topology-path-runner` with
  `file-bind-active-runner`, eight alternating measured pairs after one warmup
  pair: median changes **-0.53% stat, +2.16% open/close, +0.19% getcwd**.
  Samples/hashes are in `file-bind-active-long-performance.json`. These are
  local ordinary-workload measurements, not FUSE transfer throughput.

`file-bind-active-source` contains 52 hashed Rust/C sources;
`file-bind-active-runner` SHA-256 is
`6f3e721ee22fc4631fe1603fa0bfe0001d285f263a2fb6d94d42c3c4265ee936`.
`file-bind-active-progress.json` links the final sources and evidence. Source
hashes were unchanged after validation. Earlier file-bind source/final/capability
and disconnect snapshots/runners are exploratory, not accepted integration
results. Failed dispatch, linked-inode cache, metadata lifetime and poll epoch
regressions remain in `file-bind-path-stat-dispatch-before.log`,
`file-bind-fd-after-path-linked-before.log`, `file-bind-metadata-before.log` and
`file-bind-disconnect-before.log`; the blocked guest traces are also retained.

This closes the tested legacy regular-file bind gap from the preceding
checkpoint. It does not establish modern mount-FD consumers, every remaining
pathname/permission/writer path, async mmap, real applications or final paired
backend acceptance. Item 02 remains incomplete and uncommitted; product/runtime
pins are unchanged.

## Modern mount-FD directory and regular-file continuation checkpoint

`open_tree`, `move_mount` and nonempty `mount_setattr` now retain accepted
pathname operands in the existing NamespaceWork continuation, alongside the
legacy topology calls. The first directory regression returned EOPNOTSUPP
before this change (`mount-fd-before.log`). An empty-path FD operand also uses
the accepted inode/OFD capability, including daemon regular files whose data
handle has no local Node field. It does not reopen that handle or search its
old pathname. The proc inode helper now accepts a fallback label slice; ordinary
proc callers keep their existing behavior.

The existing admin lease is released across daemon, owner and native waits.
Seven new common VFS tests cover directory clone/attach, source identity while
another FUSE operand waits, empty-path file/tree FD close and reuse, attributes
through a followed link, an unprivileged non-cloning O_PATH tree, validation/noop
ordering and cancellation cleanup. A hostfs test verifies that a FUSE link's
native tree target returns to the existing executor before publishing its FD.
No new coordination thread, service, polling bus or whole-call lock was added.

**A separate native-verified gap remains:** Linux `open_tree` with
AT_SYMLINK_NOFOLLOW can retain a symbolic link, with or without CLONE. Native
Linux also permits moving the resulting cloned link tree. The daemon-specific
companion fixture checks NOFOLLOW clone, fstat and `readlinkat(fd, "", ...)`;
the identical ELF passes on native Linux but the current interpreter exits one
at the initial open_tree with EINVAL. This is not classified as a fixture skip
or a passing mount-FD case. Canonical daemon symlink capability, empty-path
readlink and bound-link traversal still need implementation and validation.

Verified directory/regular-file stage evidence:

- **112 hostfs FUSE tests** and **811 default / 861 hostfs related VFS tests**
  pass, with one ignored and 26 unaffected network/clock filters per broad run.
  All-target/all-feature VFS/Linux/session clippy, formatting and execution/host
  boundary checks pass. The preceding checkpoint's **19 direct-file and four
  file scheduling conformance** results are reused: their sources/paths were
  not changed by this mount-FD continuation work. The product guest below
  exercises the affected syscall decoding, scheduling and daemon waits.
- The same expanded directory/regular-file ELF passes on **native Linux and
  interpreter 1/2/4 CPUs**. Added checks include cloning a live daemon file FD,
  directory clones and non-cloning tree views, readonly attributes through a
  tree FD and FUSE link, and moving an attached mount through a FUSE source link
  onto a FUSE directory. Its SHA-256 is
  `c06efb83d2d88bc79f6ca163ca7fc57d461d2a2aba852c466f0e4131cc2cab21`.
  Native evidence is `target/local-ci/io/fuse-mount-fd-20261123-native`.
- All **158 original mount/mount_fd testcase identities** ran. Initial result:
  **153 passed, five skipped**. Two native-passing overlay cases selected
  upstream version guards from the guest release; both pass when rerun alone
  in the same original userspace-kernel ABI mode used by the full validation.
  Verified result is **155 passed, three skipped**, covering every native-passing
  case. Original passing XML is audited for the initial 153 and both followups;
  raw first results and profile distinction remain preserved. The original
  FUSE group remains **22 passed, two existing fixture skips**, with all 24
  identities and original XML audited separately.
- Against `file-bind-active-runner`, the ordinary private-volume long probe has
  eight alternating measured pairs after a warmup pair: medians change
  **-1.03% stat, -1.04% open/close, -0.83% getcwd**. Samples and hashes are in
  `mount-fd-long-performance.json`; these do not measure FUSE throughput.

Artifacts under `target/fuse-complete-20261123`: `mount-fd-source` has 54 hashed
Rust/C sources, unchanged after validation. `mount-fd-runner` SHA-256 is
`27eff7ddbeb71ae1f78372f8ee2f542c4eaa9103a659c4d1d8209f085aa50ea7`.
`mount-fd-progress.json` links the sources, checks, native comparison, gVisor
profile followups, performance and known negative probe. Two initial expanded
unit assertions accidentally retained an inspecting Descriptor and assumed a
FORGET order; the final tests release that observer and accept both FORGET
orders while checking the exact two node IDs.

The negative `mount-fd-symlink-probe` ELF SHA-256 is
`67ee1f610ea75d9be76874b6c53a134806e9b4c66a8a093d47acc08c8327078f`;
native evidence is
`target/local-ci/io/fuse-mount-fd-symlink-probe-20261123-native`, and interpreter
failure is `mount-fd-symlink-probe-guest-1.stderr`. Its source is retained beside
the ELF. The simpler ordinary-filesystem `mount-fd-link-probe` records Linux's
four follow/NOFOLLOW and clone/non-clone combinations. The VM stopped after
each native run.

This stage does not complete modern mount-FD handling of daemon symbolic
links or all FUSE consumers. The remaining permission/writer audit, async mmap,
real application/throughput and final paired backend gates stay open. Item 02
is incomplete and uncommitted; runtime pin remains `47b7435`. The product
snapshot base is `497ef71`, recorded with the runtime base in the source manifest.

## Daemon leaf inodes and symlink capabilities checkpoint, 2026-11-24

Canonical daemon non-directory identity is now represented by Leaf rather than
Regular. It retains `(nodeid, generation)`, the lookup lease and wire attributes;
its content stays explicitly daemon-backed. Symlink text is fetched by READLINK,
not stored as synthetic local bytes or a guessed pathname. GETATTR rejects an
immutable inode-type change, as in the preceding regular-file implementation.

This closes the prior native-verified `open_tree(AT_SYMLINK_NOFOLLOW)` gap for
daemon symlinks. Cloning and non-cloning tree FDs retain the original symlink;
fstat and `readlinkat(fd, "", ...)` use that inode after source unlink, same-name
replacement, close/reuse and cancellation. An O_PATH|O_NOFOLLOW daemon open also
exposes its retained leaf through the same metadata path without obtaining a
daemon fh. Pending READLINK keeps its own accepted inode, rather than looking up
the numeric FD again. Ordinary final-inode access derives the actual leaf kind.

A followed bound symlink goes through the original PathWalk. Relative text is
resolved against the mountpoint's parent, matching the standalone Linux probe;
absolute text restarts at the accepted root. The existing link count,
NO_SYMLINKS/scope/credential handling, native dispatch and FD reservation continue
through this route. Namespace parent mutations capture the accepted symlink and
parent before waiting instead of re-running their original spelling. Readonly
attributes on the symlink mount do not become write restrictions on a distinct
writable target.

The first parent implementation still retained only its textual spelling for
an ordinary parent. A new regression (`leaf-parent-before.log`) renamed that
parent and installed a same-name replacement during READLINK; mkdir went to the
replacement. The final walker retains the original parent inode too, and the
existing indexed/host directory capability handles the relative continuation.
The final guest daemon performs the same rename/replacement in its READLINK
callback, and both Linux and Trames create under the original moved parent.
No source path is replayed and no coordinator/service/polling thread or new
whole-call lock was added.

Final evidence:

- **120 hostfs FUSE tests**, **818 default / 869 hostfs related VFS tests**
  pass. Each broad run retains one ignored and 26 unaffected network/clock
  filters. Seven new common symlink tests cover the retained capabilities,
  relative parent identity, lazy unmount/replacement, cancellation and link-loop
  policy. One hostfs test checks the accepted open reservation across native
  dispatch. All-target/all-feature VFS/Linux/session clippy, formatting and
  execution/host boundary checks pass. **19 direct-file and four file scheduling
  tests** passed on the preceding leaf revision; those byte/layout paths were
  unaffected by the final bound-link parent pin and fixture callback changes.
- The identical final expanded ELF passes on **native Linux and interpreter
  1/2/4 CPUs**. It includes NOFOLLOW tree/view FDs, empty-path readlink after
  source unlink/replacement, bound relative/absolute links, lstat/stat, O_PATH,
  ELOOP ordering, directory opens/chdir, mutations through the link, readonly
  link mounts with writable targets, and parent rename/replacement during the
  daemon callback. Tree FDs close before UMOUNT_NOFOLLOW cleanup. Test-only
  daemon node capacity increases from 64 to 128; no execution thread is added.
  ELF SHA-256 is
  `4a552eac209fcebf91cb8d736d2a087eedb170bf9d1e352cf6fbc503d32c1f47`.
  Native evidence is `target/local-ci/io/fuse-leaf-parent-20261124-native`;
  the VM stopped. The **unchanged original negative ELF**, SHA-256
  `67ee1f610ea75d9be76874b6c53a134806e9b4c66a8a093d47acc08c8327078f`,
  also passes on the final interpreter (`leaf-final-original-guest-results.json`).
- All **182 original FUSE/mount/mount_fd identities** ran. Raw result:
  **175 passed, seven skipped**. The established userspace ABI profile passes
  the two version-gated overlay cases; the fusectl fixture now actually runs and
  passes `FuseTest.EpollAfterAbort`. Verified result: **178 upstream passes,
  four original skips**, with every passing XML audited. This covers **all 177
  native-passing cases** in that selection. The additional upstream pass is
  `CloneFromUnconnectedDeviceFails`: the pinned native kernel returned EPERM
  where upstream/current Trames expect EINVAL. That native failure remains
  separate from the passing oracle and belongs to the remaining error audit.
  The FUSE portion is now **23 passed, one original GVISOR_FUSE_TEST mode skip**;
  mount/mount_fd remains **155 passed, three original skips**. Default and
  followup profiles/raw results remain separate in the artifacts.
- The corrected ordinary private-volume probe compares `mount-fd-runner` with
  `leaf-final-runner`, eight alternating measured pairs after one warmup pair.
  It runs **100,000 stat, 50,000 open/close and 1,000,000 getcwd** iterations.
  Correct elapsed-time medians change **-1.16%, +1.23%, +1.39%**, respectively.
  All 18 guest interval sums fit within the independent host monotonic process
  elapsed time (plus the stated 50ms tolerance). Samples, source/binary hashes
  and the guard are in `leaf-corrected-performance.json` and its script. This is
  incremental ordinary-workload evidence, not FUSE transfer throughput. Earlier
  long-probe percentages are invalidated by the timing correction at this
  record's beginning; their raw artifacts are preserved.

`target/fuse-complete-20261123/leaf-final-source` contains 55 hashed Rust/C
sources, unchanged after validation. `leaf-final-runner` SHA-256 is
`a47eb80541d059b43cd08bdccedb0e2fe0d2eb3b74a7940c1426f47a5d354817`.
`leaf-final-progress.json` and the executable `leaf-final-audit.py` link the
sources, checks, profile-aware testcase comparison, native fixtures and timing
correction. The earlier `leaf-source`/`leaf-runner` checkpoint predates the
parent-capability fix and is exploratory. Its long-probe timing is invalidated
as above. The `leaf-bound-before.log` and `leaf-parent-before.log` failures are
retained. A cancellation test initially expected FORGET before the transport's
normal INTERRUPT; the final test verifies the original request ID in INTERRUPT,
the single FORGET and ignored late reply.

This completes these tested daemon-symlink capability and traversal paths,
not all FUSE consumers or non-regular data operations. Item 02 stays incomplete
and uncommitted. Runtime/product pins remain the source snapshot's `47b7435` /
`497ef71`; modern mount administration's broader item 03 is also still open.

## Still required for item 02

- Join/audit the other pathname consumers, including link/chroot/statfs and
  attribute/xattr paths. The topology and symlink checkpoints do not establish
  every inode type or every consumer's support.
- Audit remaining non-regular data operations such as daemon FIFO/device nodes;
  retaining a leaf's metadata does not implement its Linux data behavior.
- Complete the remaining error/permission audit and live mount writer/flag
  lifetimes, including the native EPERM vs current EINVAL discrepancy for an
  unconnected FUSE clone source. The upstream native case fails its EINVAL
  assertion, so this needs an isolated/version-aware errno check rather than
  being counted as a native-passing result. The open/create checkpoint covers
  exclusive-existing ordering,
  shared CREATE/MKNOD umask callbacks and access's post-LOOKUP mount flags; it
  does not establish every concurrent remount or permission lifetime. The
  final-inode access checkpoint additionally covers allow_other on a removed
  bind root and live flags on proc-fd access; the overall audit remains open.
- File-backed mmap with asynchronous page faults, shared/private coherence,
  writeback, cancellation and page lifetimes. A daemon wait must release the
  execution slot, including with a single guest CPU.
- An original FUSE application, actual transfer throughput and ordinary-workload
  performance; the custom daemon fixture alone does not satisfy that gate.
- Mac HVF and final paired Runtime validation/delivery for the complete batch.

This checkpoint does not establish SSHFS, rclone mount, Android storage,
snapshot restoration or physical iPad support.

## Statfs, chroot and retired-wait checkpoint, 2026-11-24

This remains an uncommitted part of follow-up item 02. It does not complete the
FUSE subsystem or the complete follow-up queue. No coordinator, resource service
thread or polling bus was added.

### Accepted operations and exit cleanup

- Pathname `statfs` now uses the common retained walk, including daemon links,
  proc targets and native handoff. `fstatfs` accepts the original OFD once;
  closing/reusing its numeric FD and lazily detaching its mount do not redirect
  the request. STATFS uses the accepted target nodeid, including regular files
  and directories, rather than always nodeid 1. It retains the lookup and real
  mount use through completion/cancellation.
- STATFS decodes the daemon's 80-byte payload into the ARM64 120-byte ABI. The
  native probe confirmed zero fsid and target-specific nodeids. `f_flags`
  includes ST_VALID and reads the accepted mount's current flags after the
  reply. A daemon callback that changes readonly status is covered in both
  directions. Ordinary statfs shares the same mount-flag encoding.
- `chroot` joins the existing chdir directory/ACCESS continuation. It retains
  the original fs_struct and publishes only its root after successful search
  permission; cwd and prior directory FDs remain unchanged. Tests cover mount
  covering during ACCESS, unshare while pending, ENOTDIR, capability/access
  denial, ENOSYS and cancellation. Native host roots retain their original
  directory handle, including through proc-FD reuse, rename and replacement;
  proc root projections carry that same capability.
- The first 203-case gVisor run exposed
  `FuseInterruptTest.FatalSignalDequeuesUnsentRequest`: daemon poll still saw
  readiness after the killed client had been waited for. Three isolated runs
  on each pre-fix runner passed, so those reruns alone did not establish a fix.
  A deterministic scheduling regression then reproduced the actual lifetime
  defect: a retired job's `Done.io` retained its accepted FUSE wait while the
  CPU return remained alive. `Job::finish_retired` now drops that I/O before
  publishing the retired return/vfork release. Normal stopped or checkpointed
  calls still retain their results. The old-source regression reads a queued
  STATFS packet where EAGAIN is required; the fixed regression passes.
- A default-feature clippy check also found an equivalent cfg label fallback
  expressed as `None.unwrap_or_else`. That branch was refactored without
  changing pathname behavior.

### Evidence and validation

All local artifacts below are under `target/fuse-complete-20261123` in the
product repository unless a native output path is given.

- Final source snapshot: `fs-complete-source`, 57 hashed Rust/C files. Base
  Runtime remains `47b743501f73122716d5a737b0bbca983d86803e`; product remains
  `497ef71ef49958fcd85599c6eeca19e31d5ba508`.
- Final runner `fs-complete-runner`: `a2b4b1e869c8fe8281027bc36c1e1db707efde8d60636b2037b3b88d11e2cd6b`.
- Same static guest ELF on Linux and interpreter:
  `fuse-filesystem-fs-context`, SHA-256 `85c70fa940844f5dee1da2523a4c1c56eccf20e9f7032180db5c3e4a7040ff20`.
  `target/local-ci/io/fuse-fs-context-20261124-native` exited 0 and its VM was
  stopped. Final interpreter 1/2/4 CPU runs all exited 0
  (`fs-complete-guest-results.json`). Besides statfs/chroot, the fixture retains
  the prior namespace, symlink, mount-FD, file-bind, data-I/O and lifecycle work.
- 127 hostfs-enabled FUSE tests passed. Relevant VFS checks: default 824 and
  hostfs 876 passed, each with one existing ignored test and 26 unrelated
  network/clock filters. The 19 direct Linux file tests passed; four session
  file-scheduling tests passed on the final sources. Unaffected VFS/direct-file
  results precede only the returned-wait fix and equivalent cfg fallback and
  are reused rather than repeated.
- Scheduling checks: 29 passed, one existing ignored. The sandboxed run had
  four loopback-bind EPERM failures; only those four were rerun outside the
  sandbox, and all passed (`retired-fuse-loopback-retry.log`). The deterministic
  old-source failure is preserved in `retired-fuse-before-compiled.log`.
- Original gVisor FUSE/mount/mount_fd/chroot/statfs/exit/fork/vfork/wait:
  301 exact identities, 296 passes and five original skips after the existing
  userspace-ABI and fusectl fixture profiles. All 294 native-passing identities
  are covered. The other two upstream passes were not native passes: the
  unconnected clone errno assertion and a reference `ForkBlock/0` timing
  assertion. Raw results, exact passing XML audits and merged identities are
  preserved in `gvisor-fs-complete*` and `fs-complete-verified-results.json`.
  Additional original FUSE groups at 1 and 4 CPUs each passed 23 with one
  original mode skip, including the fatal-signal cases.
- Final default-feature and all-target/all-feature VFS/Linux/session clippy,
  formatting, execution boundaries and host-execution checks passed. No full
  unrelated CPU/network/graphics acceptance was rerun for this checkpoint.
- Correct-clock ordinary-path probe: eight alternating measured pairs after a
  warmup pair, comparing `leaf-final-runner` with `fs-complete-runner` on copied
  storage. Median changes: stat +2.06%, open/close +5.03%, getcwd +3.64%.
  `fs-complete-corrected-performance.json` records all samples and hashes;
  every guest interval sum is bounded by independent host monotonic process
  elapsed time plus 50 ms. This is incremental interpreter pathname evidence,
  not FUSE transfer throughput or Mac HVF/physical iPad validation. A second
  independent round used 12 measured pairs after warmup with reversed starting
  order, and the same runner/fixture hashes and external-clock bounds:
  stat +5.99%, open/close +2.26%, getcwd +1.51%
  (`fs-complete-confirmed-performance.json`, all 26 samples retained). Both
  rounds show slowdowns with variable magnitude. **Ordinary-path performance
  remains an open gate; profile the cost before full-batch delivery.** Neither
  round is discarded or replaced by the better number. Historical long-probe
  percentages remain invalid as recorded in the timing correction.
- `fs-complete-audit.py` verifies the final source/runner/ELF/result/XML/perf
  associations and writes `fs-complete-progress.json`. The first failing
  gVisor run remains untouched in `gvisor-fs-context` and its XML audit.

### Unconnected clone errno isolation

`fuse-clone-isolated` separately opened devices in a private Linux fixture on
`7.0.0-43-generic`, uid/euid 0. Two unconnected FUSE devices still produced
EPERM; an invalid source FD and `/dev/null` source each produced EINVAL. The
observational program exited 0; this is an errno observation, not an upstream
case pass. Evidence is in
`target/local-ci/io/fuse-clone-isolated-20261124-native` and
`clone-isolated-native.log`; its VM was stopped. The discrepancy therefore
reproduces outside the original GoogleTest case, but its kernel/version/security
cause is not established. Runtime EINVAL was not changed speculatively. This
remains in the error audit and outside the native-passing oracle.

### Still required for item 02

- Remaining pathname consumers, notably hardlink, attribute and xattr operations;
  these statfs/chroot paths do not establish every operation/inode type.
- Remaining non-regular data operations, permission/writer/remount lifetimes and
  the version-aware clone errno audit.
- Asynchronous file-backed mmap faults, shared/private coherence, writeback,
  cancellation and page lifetimes without occupying an execution slot.
- Locate the ordinary pathname slowdown observed in both valid probe rounds;
  this checkpoint does not pass the ordinary-workload performance gate.
- An original FUSE application, actual transfer throughput, final Mac HVF and
  paired Runtime validation/delivery. SSHFS, rclone mount, Android storage,
  snapshot restoration and physical iPad support are not established here.


## Ordinary pathname controls and continuation-state size checkpoint, 2026-11-24

This continues item 02; it does not complete FUSE, its real-application and
throughput gates, or the full follow-up queue. No coordinator/resource-service
thread, polling bus, extra access policy or ordinary-memory synchronization was
introduced.

### Evidence and implementation

The prior two short, correctly timed rounds are retained. Their phases lasted
roughly 0.3–0.6 seconds and reported variable positive deltas; they were not
silently discarded as noise. Additional controls now distinguish those numbers
from longer steady-work evidence:

- A/A control used the same `leaf-final-runner` hash on both copied stores.
  Eight measured pairs after warmup gave stat -1.54%, open/close +0.17%, getcwd
  +1.49% (`path-aa-control-performance.json`). This alone does not explain every
  difference from the earlier short rounds.
- Runtime metrics on both checkpoint runners were identical: 48,403,803 guest
  instructions, 1,200,014 syscalls, 1,150,005 direct calls, 1,150,004 file calls,
  50,001 FD calls and three I/O waits. Service requests, serviced syscalls and
  global VM checkpoints were all zero. Final-runner metrics reproduce those
  same counts (`path-profile-metrics.json`, `path-state-metrics.json`). Metrics
  runs are diagnostic and are not substituted for the uninstrumented timings.
- The new `path-performance-steady` ELF performs ten times the corrected
  probe's work: 1,000,000 stat, 500,000 open/close and 10,000,000 getcwd calls.
  CLOCK_MONOTONIC uses seconds × 1,000,000,000 + nanoseconds; every measured
  guest phase sum remains bounded by independent host process elapsed time
  plus 50 ms. An initial six-pair comparison of the previous runner against
  `leaf-final-runner` gave +0.71%, +1.55%, +0.65%
  (`path-steady-performance.json`), smaller than the earlier short deltas.
- Code inspection found a redundant root/cwd selector inside `directory::Change`
  while `Lookup.operation` already represented that state. The selector now
  comes from the accepted operation and is retained with the final ACCESS
  continuation, preserving the same original fs_struct publication. This
  shrinks Lookup's temporary representation. The generated ARM64
  `resolve_walk` local stack reservation changes from 0xa80 back to the
  baseline 0xa70, with the common 0x60 saved-register prologue unchanged.
  `path-state-prologue.py/json` verify the actual instructions and runner hashes.

Only `fuse/mount.rs` and `fuse/mount/directory.rs` changed from the previous
accepted source snapshot. The final runner is `path-state-runner`, SHA-256
`a37b5f266cbad8eca4030e9134dc21005a25742c270f7ba23fd9ba894cfff635`; `path-state-source`
retains all 57 source hashes and the candidate patch. Base commit identities
and paired product pins remain unchanged; this is not a commit or delivery.

### Controlled three-version measurement

`path-state-steady-performance.json` compares the leaf baseline, the previous
statfs/chroot runner and the current runner using the same copied seed and
longer ELF. After one warmup triplet, all six execution-order permutations are
measured: each version appears first, middle and last twice. No other agent
build, test or VM job overlaps these measurements. All 21 observations and
external-clock bounds are retained.

| Comparison, current minus reference | stat | open/close | getcwd |
| --- | ---: | ---: | ---: |
| Leaf baseline | +0.61% | -1.27% | -2.03% |
| Previous statfs/chroot runner | -0.96% | -2.54% | -0.12% |

These longer measurements do not reproduce the previous 2–6% magnitude, and
remove the redundant stack growth. They do **not** establish that the 16-byte
change caused every timing difference, prove exact performance equivalence, or
replace the remaining actual FUSE application, transfer-throughput, Mac HVF and
physical iPad acceptance. Historical invalid-clock percentages remain invalid;
all valid short and long rounds remain available.

### Scoped verification and next work

- 127 hostfs-enabled FUSE tests pass. Original FUSE and chroot groups: 36 exact
  identities, 35 passes with exact original passing XML verified and one
  original mode skip (`gvisor-path-state-audited`).
- The unchanged `fuse-filesystem-fs-context` ELF passes the current interpreter
  with 1/2/4 CPUs. Its existing native Linux pass is reused because the guest
  source and ELF are unchanged.
- All-target/all-feature VFS/Linux/session clippy, formatting, execution-boundary
  and host-execution checks pass. Unaffected VFS, direct-file, scheduling and
  other gVisor results are reused. The combined ledger remains 301 identities,
  296 passes and five original skips, covering all 294 native-passing identities;
  **36 were rerun on this runner and 265 reuse the prior unaffected results**.
- `path-state-audit.py` verifies source and runner hashes, the exact changed-file
  scope, guest runs, passing XML, generated stack instructions, identical
  diagnostic counters and all performance controls. It writes
  `path-state-progress.json` and `path-state-verified-results.json`.

The next implementation remains hardlink, followed by attribute/xattr and the
other outstanding item-02 gates. Source inspection confirmed that Link does not
yet retain async pathname operands; empty-source data OFDs need their canonical
FUSE inode rather than `open.node` alone. When adding FUSE_LINK (opcode 13), its
successful entry reply must also join lookup-reference cleanup for cancelled or
late replies. These are implementation dependencies, not newly completed
features. Detailed source pointers and planned regressions are preserved in
`hardlink-next-notes.md` under the same artifact directory.

## Hardlink original-source and protocol checkpoint, 2026-11-24

Item 02 remains in progress. The entire follow-up queue still has item 01 done,
item 02 incomplete and items 03–12 outstanding. No coordinator/resource-service
thread, polling message bus, extra ordinary-memory barrier or global algorithm
lock was introduced. These are local candidate results, not a completed batch,
product pin update or publication.

### Implemented source and daemon lifetime

- Link now retains its accepted source operand through another operand's daemon
  or native wait. The capability holds the actual inode, original mount usage
  and descriptor as needed, rather than resolving the old name or numeric FD
  again. Empty-path links include data FUSE OFDs whose `open.node` is absent;
  their canonical inode comes from the existing FUSE control resource.
- FUSE_LINK (opcode 13) sends the original oldnodeid to the accepted destination
  parent. Destination lookup, symlink nofollow/follow, cross-mount, protected
  hardlink, directory, last-unlinked and existing-destination checks use that
  original source. Native source capability rebasing stays inside the existing
  filesystem namespace transaction and native executor.
- Open-time link identity is initialized before descriptor observers receive the
  resource, including reopen/adoption; closing/reusing the numeric descriptor
  during a later wait cannot substitute a replacement source.
- A successful LINK reply owns an entry lookup grant. Normal, cancelled and late
  successful replies release their grants exactly once via the existing
  transport resource cleanup. ENOSYS becomes EPERM and disables future LINK
  callbacks on that connection. This follows the Linux
  [FUSE LINK implementation](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/dir.c#L1245).
- Unlink updates a known canonical leaf's local positive link count and shared
  stat attribute. A held FD cannot resurrect an ordinary or FUSE inode whose
  last link has gone. This basic correction does **not** implement or establish
  all Linux attr_version/GETATTR/unlink concurrency ordering.

### Native evidence and preserved corrections

The real daemon/client fixture now supports hardlinks with canonical shared
inode IDs and link counts. The same immutable `fuse-filesystem-hardlink-permitted`
ELF passes native Linux and the product interpreter with 1/2/4 CPUs. Native output
is `target/local-ci/io/fuse-hardlink-permitted-20261124-native`; the isolated VM is
stopped before performance runs. This fixture also checks ordinary source
rename/replacement while the destination's FUSE symlink READLINK is pending,
O_PATH and data-FD empty paths, symlink follow/nofollow, link counts, last-unlinked
FDs, cross-mount and directory errors, and unsupported-operation caching.

Two tentative expectations were corrected using actual native results:

- Linux accepts a same-kind LINK entry reply with a different nodeid. The
  runtime now accepts it and releases both original and returned lookup grants;
  it refreshes the original inode only when the returned nodeid matches.
- With this FUSE default permission delegation, a non-owner may hardlink a
  root-owned regular 0600 file, while a setuid source is denied. The native
  diagnostic records `protected_hardlinks=1`, successful ordinary foreign link,
  and EPERM for the setuid link. Runtime tests retain the ordinary filesystem's
  existing permission check and follow the FUSE delegation for daemon leaves.

The first client failure placed the rename callback during initial symlink
creation, before source acceptance; it was corrected to the destination's actual
READLINK wait. A subsequent native retry found files left by that failed fixture;
the race fixture now uses its own tmpfs. Those failed artifacts remain intact.
A temporary hostfs edit accidentally applied capability rebasing to rename,
causing an existing cache-lock recursion. Its stack sample and failed run are
retained; rename was restored, the change limited to link, and existing rename
and FUSE tests passed afterward. No failure was silently promoted to success.

### Audited functional checkpoint before final error-order follow-up

`hardlink-final-runner` SHA-256 is
`72294cb832ede6425180275a4ce23972b66d5de232dbd8bc92fe5d0f6fa66892`.
`hardlink-final-source` archives all 60 source hashes, base identities and the
candidate patch. `hardlink-audit.py` verifies that archived source rather than
claiming later edits share these results; it writes `hardlink-progress.json`
and `hardlink-verified-results.json`.

- Relevant VFS: default 835 passes, hostfs 888 passes, including 139 FUSE tests.
  Direct Linux file tests: 19 passes; interpreter file scheduling: four passes.
  All-target/all-feature VFS/Linux/session clippy, default-dependency session
  clippy, formatting and both execution-boundary checks pass.
- Original gVisor FUSE/link/symlink/unlink: 103 exact identities. The ordinary
  profile has 99 passes and four skips; three version-guarded empty-path link
  cases pass in the existing userspace ABI profile. Merged: 102 passes and one
  original FUSE mode skip, covering all 101 native-passing identities. Passing
  identities are checked against their exact original XML.
- Combined with prior unaffected results: 380 identities, 375 passes and five
  original skips, covering all 373 native-passing identities. **103 were rerun
  on this runner; 277 reuse previous unaffected evidence.** The native clone
  errno discrepancy remains outside the native-passing oracle; the ledger does
  not turn it into a successful native comparison.

### Ordinary-path controls

The corrected tenfold steady probe, six alternating measured pairs after
warmup, reports stat -2.94%, open/close +1.06%, getcwd +3.83% against the previous
`path-state-runner` (`hardlink-steady-performance.json`). An isolated probe of
20,000,000 getcwd calls, four measured pairs, gives +0.91%
(`hardlink-cwd-control.json`). Both rounds use seconds × 1,000,000,000 plus
nanoseconds and independent external elapsed-time bounds; all observations are
preserved. Neither round alone establishes exact equivalence or causation.

Source and generated ARM64 instructions show that Cwd returns before the new
Link `retains_paths` match, and both checkpoint runners use the same 0xa20 local
stack reservation in `namespace_attempt`. Thus a claim that Link's accepted-path
allocation caused getcwd's difference would be incorrect. A separate outlining
experiment and its balanced three-version measurements are retained under
`hardlink-cwd-outline-*` and `hardlink-outline-steady-*`; its final disposition
is recorded below.

Remaining work includes actual SETATTR/xattr operations and original identity
through their waits, metadata version ordering, other inode data operations,
permissions/writer/remount lifetimes, asynchronous mmap, notifications, real FUSE
applications and throughput, and final Mac HVF/paired validation and delivery.
Source pointers for the next attribute group are in `attribute-next-notes.md`.

### Final cached-error correction and experiment disposition

The new regression first reproduced EPERM (1) instead of EXDEV (18), with the
correct comparison retained in `hardlink-cached-order-before-corrected.log`.
The first test attempt incorrectly used a helper that always expects another
pending daemon request; its failure remains in `hardlink-cached-order-before.log`
and is not substituted for that explicit errno comparison. Cached LINK support
is now checked after the accepted source's mount, kind, permission and link-count
checks. This follows the VFS ordering before calling a filesystem's link method
([Linux filename_linkat](https://github.com/torvalds/linux/blob/v7.0/fs/namei.c#L5470)).
The corrected regression passes and no extra LINK request is sent.

The same assertion is included in `fuse-filesystem-hardlink-cached`: after
ENOSYS has disabled LINK, an ordinary source on another mount still returns
EXDEV. This final ELF passes isolated native Linux and the interpreter with
1/2/4 CPUs (21.71/14.34/10.97 seconds). Native evidence is
`target/local-ci/io/fuse-hardlink-cached-20261124-native`; its VM exited normally
and was stopped by the launch script.

The outlining experiment reduces the fast Cwd frame's local reservation from
0xa20 to 0x1c0, but adds a separate caller frame to general namespace operations.
All 21 longer observations use one warmup triplet followed by all six version
orders. Relative differences of the experimental runner are:

| Reference | stat | open/close | getcwd |
| --- | ---: | ---: | ---: |
| Previous path-state runner | -2.25% | -0.66% | +0.75% |
| Unoutlined hardlink runner | +0.05% | -2.36% | -1.01% |

These numbers do not establish a stable getcwd benefit or prove a cause for
unrelated operation timings. The outlining change was **reverted**; the complete
experimental source, runner, generated instructions and observations remain
available. No ordinary-path performance improvement is claimed for the final
LINK check-order correction. The performance gate remains open alongside the
actual application and throughput gates.

The final local candidate is `hardlink-cached-runner`, SHA-256
`438f180b856a97b48fe4173795a575888b30a56d354cc28982d03cb7eaae28a9`.
`hardlink-cached-source` archives 60 source hashes; exactly three files changed
from the preceding functional checkpoint: the FUSE namespace driver, its LINK
regression file and the C fixture. `namespace_work.rs` matches the unoutlined
checkpoint exactly. `hardlink-cached-audit.py` verifies current and archived
source hashes, exact original passing XML, same-ELF native/interpreter outcomes,
the explicit failed/passed errno regression and the preserved experiment. It
writes `hardlink-cached-progress.json` and `hardlink-cached-verified-results.json`.

Final scoped checks: 139 hostfs-enabled FUSE tests, the default-feature cached
LINK regression, all-target/all-feature VFS clippy, formatting, execution and
host-boundary checks pass. Earlier 835 default VFS, 888 hostfs VFS, 19 direct
Linux file and four file-scheduling passes are reused outside this final narrow
change. The same 103 original gVisor identities were rerun on the final runner;
after the existing three-case ABI profile, there are 102 passes and one original
skip with every passing XML identity verified. Combined evidence remains 380
identities / 375 passes / five skips, covering all 373 native-passing identities;
103 current reruns and 277 unaffected prior results remain distinguished.

No commit, runtime product pin or push was made for this incomplete FUSE batch.
The next group is attribute/xattr protocol and original-inode continuations;
all remaining item-02 gates and items 03–12 remain on the implementation queue.

## Chmod, chown and timestamp SETATTR checkpoint, 2026-11-24

This continues item 02 and the existing 12-item queue; it does not complete
SETATTR size/truncation, xattrs, FUSE, the platform/performance gates or delivery.
No coordinator/resource-service thread, polling bus or new global algorithm
lock was added. Blocking daemon operations use existing FileWork/readiness and
release their execution slot. The mount writer reference is an actual object
lifetime, not an inode lock held across the daemon wait.

### Implemented behavior and native counterexamples

Path and descriptor chmod/chown/utimens now send SETATTR (opcode 4) to the
accepted canonical inode. O_PATH empty-path variants and data OFDs use the same
inode and original mount; the latter recover it from their FUSE control resource
rather than assuming `open.node` is populated. Live requests retain the actual
mount's writer admission and original open where needed. Cancellation releases
that writer and sends INTERRUPT only for a sent request. A daemon rejection or
malformed reply does not publish the requested permissions in local metadata.

Chown refreshes a non-directory inode before computing suid/sgid removal, using
mapped IDs in the daemon's namespace. Timestamp requests preserve explicit
nanoseconds and the distinction between UTIME_NOW and UTIME_OMIT; two OMIT values
still return without resolving a path. Symlink lchown operates on the symlink
inode, while chmod with NOFOLLOW rejects it. The implementation follows the
[Linux SETATTR conversion and validation](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/dir.c#L1872)
and the observed native request flags, including the absence of FATTR_FH for
these chmod/chown/utimens operations.

The immutable `fuse-filesystem-attributes` ELF passed isolated native Linux, but
`hardlink-cached-runner` failed its first chmod with ENOTSUP (95). The same ELF
then passed the initial implementation with interpreter 1/2/4 CPUs. That initial
functional checkpoint archives 62 source hashes as `attributes-source`, with
841 default VFS and 894 hostfs VFS passes, six new attribute tests, and 87 passes /
one original skip from 88 original chmod/chown/utimes/FUSE identities. Exact
original passing XML is audited; the full upstream attribute assertions were
not weakened.

An additional same-ELF/native comparison exposed directory cache inconsistency:
chmod succeeded, but an already-open directory's AT_STATX_DONT_SYNC stat still
reported 0755 instead of 0700. `fuse-filesystem-attributes-directory` passed native
Linux and failed `attributes-runner` at that assertion. The deterministic
regression retained in `attributes-directory-before-final.log` reproduces the
same stale mode. Two earlier regression attempts mishandled separate LOOKUP
FORGET grants; their failed logs remain and are not substituted for the explicit
mode counterexample.

Directory attributes now share a canonical snapshot across OFDs, as daemon leaf
inodes already do. SETATTR, pathname GETATTR and FD GETATTR update that snapshot
and canonical node. The regression checks two existing O_PATH descriptions after
SETATTR and again after GETATTR. This fixes the observed cache inconsistency;
it does not establish all concurrent attr_version or bad-inode lifetime rules.
The directory-inclusive ELF has an independent native pass at
`target/local-ci/io/fuse-attributes-directory-20261124-native`; native test VMs
were stopped by their launch scripts.

### Ordinary-call regression found and corrected during this batch

The first accepted functional implementation eagerly allocated and populated an
accepted-path map for every chmod/chown/utimens call. Four paired measurements on
the CLI's existing ephemeral memory backend found +56.58%, +59.02%, +56.73%
respectively against the hardlink baseline (`attribute-memory-performance.json`).
That regression and its immutable `attributes-final-runner`/source are retained.
It was not accepted merely because the gVisor and daemon tests passed.

The first cost correction used the existing prepared-work storage for a **single**
accepted metadata operand only after a real suspension. Ordinary calls allocate
no operand map and do not pin/rebase an already-resolved ordinary inode a second
time. Suspended calls retain the exact final entry, original namespace resources
and native-executor boundary. This also prepares the continuation mechanism for
the remaining xattr consumers without claiming their protocol is implemented.

During this refactor, applying resumable resolution to the common metadata
helper initially caused hostfs inotify_add to defer unexpectedly. Both the broad
hostfs run and a focused retry reproduced it. The behavior is now scoped to the
active namespace operation, restoring inotify's original call path; the complete
hostfs suite subsequently passed 895 tests. The default suite passed 842 tests.
These full runs precede only the equivalent clippy-requested replacement of
`mem::replace(option, Some(value))` with `option.replace(value)`; final-source
clippy and guest/upstream verification are recorded below.

The initial persistent-store performance probe (300,000 calls per phase) timed
out on the **baseline** runner before yielding a comparison. A 3,000-call
progress-instrumented baseline pilot completed, with chmod/chown/utimens phases
of 24.31/23.54/23.09 seconds. Those artifacts remain intact. Source inspection
shows these metadata paths call the existing VFS checkpoint, which snapshots
the persistent root; the memory-backend comparison isolates syscall cost from
that existing storage work. It does not establish persistent-storage performance
or replace its acceptance. A longer final comparison is recorded below.

### Final cold continuation and measured ordinary metadata cost

The first correction still measured +41.30% chmod, +45.90% chown and +39.04%
utimens in a longer ordinary-memory comparison
(`attribute-scoped-memory-performance.json`). It was rejected as the final
performance result too. Source inspection identified the additional per-component
native/owner lookahead used by ResumeFuse on the initial walk, plus a shared
prepared-state borrow on every call. Initial namespace admission already handles
the first operand's native executor; those component checks are needed when
resuming a cold daemon walk, not on every ordinary initial metadata lookup.

The current implementation keeps the accepted single operand in the private
control view, without an added shared prepared-state borrow or operand table on
the ordinary path.
Only a suspended walk resumes through the existing scheduling advice. Cold
accepted entries still receive the existing inode/capability pin before the
metadata operation, preserving identity across native and owner handoffs.
The explicit metadata scope keeps unrelated inotify resolution unchanged.
No new thread, polling path, resource service, global metadata lock or ordinary
memory barrier was introduced.

`attribute-cold-memory-performance.json` records a tenfold longer static ELF:
3,000,000 calls per phase, one warmup pair then four measured pairs with both
execution orders balanced. It compares the immutable hardlink baseline and the
current interpreter on the existing ephemeral memory backend, using a fresh
ordinary tmpfs target for each observation. No build, test or VM job overlaps
these measurements. CLOCK_MONOTONIC uses seconds x 1,000,000,000 plus nanoseconds;
every phase sum is bounded by independent host elapsed time plus 50 ms.

| Current minus hardlink baseline | chmod | chown | utimens |
| --- | ---: | ---: | ---: |
| Longer ordinary-memory probe | -2.83% | +0.13% | -0.92% |

This removes the measured tens-of-percent regression in these tested ordinary
calls. It does not prove zero overhead everywhere, establish persistent-storage
latency, or pass the real FUSE application, transfer-throughput, HVF and physical
iPad performance gates. Both rejected comparisons and the baseline storage
timeout/pilot remain available; no historical timing was overwritten.

The final local runner is `attributes-cold-runner`, SHA-256
`e0da89bc9ea639d4d9b32752af341594194a1c676e15ba7eba8763cc30cc25e7`.
`attributes-cold-source` archives all 62 current source hashes, base commit
identities and the candidate patch. Both repository HEADs and product pins are
unchanged. `attributes-cold-audit.py` verifies current/archived source, runner and
fixture hashes, exact original passing XML, native and interpreter outcomes,
regression evidence and all three metadata performance comparisons. It writes
`attributes-cold-progress.json` and `attributes-cold-verified-results.json`.

Final-source checks pass: 842 default VFS, 895 hostfs VFS (including 146 FUSE),
all-target/all-feature VFS/Linux/session clippy, formatting and both execution
boundaries. The unchanged directory-inclusive ELF passes interpreter 1/2/4 CPUs
in 20.46/14.07/10.89 seconds; its existing isolated native Linux pass is reused.
Earlier 19 direct Linux file and four file-scheduling passes remain unaffected
and are reused. The final runner reruns all 88 original attribute/FUSE identities:
87 pass, one original skip, covering all 86 native-passing identities in that
selection. Combined with unaffected prior results, the ledger has 444 identities,
439 passes and five skips, covering all 437 native-passing identities. **88 were
rerun on this runner; 356 reuse previous unaffected evidence.** The native clone
errno and previously recorded native timing discrepancy remain outside the
native-passing oracle rather than becoming successful native comparisons.

The next group remains xattr GET/SET/LIST/REMOVE, including actual syscall buffer
capacity and final-inode retention. Concurrent attribute-version/bad-inode rules,
SETATTR size/truncation and open flags, other inode data behavior, the remaining
permission/writer/error audit, mmap, notifications, original applications and
throughput, and final platform/paired validation and delivery remain incomplete.
No commit, pin update or push was made for the unfinished FUSE batch; item 02 and
items 03-12 stay on the full follow-up queue.

## Xattr, ACL and capability wire checkpoint, 2026-11-24

This is a local item-02 checkpoint. The full FUSE batch and items 03-12 remain
open, with no commit, paired-pin update or push yet. Requests reuse the existing
FileWork/readiness and native execution routes. No coordinator, resource-service
thread, polling bus, ordinary memory barrier or new global algorithm lock was
introduced.

### Protocol and original resources

GETXATTR/SETXATTR/LISTXATTR/REMOVEXATTR now operate on the accepted canonical inode,
including data OFDs whose node is retained by the FUSE control resource. The
syscall's actual buffer capacity reaches the request. A zero-capacity ordinary
query consumes the eight-byte size reply and returns a count without allocating
a synthetic buffer. Capacity is clamped to 65,536; an ERANGE reply at that maximum
becomes E2BIG. Lists preserve daemon order and require nonempty NUL-terminated
names. Empty SET values remain distinct from REMOVE. Each opcode caches its own
ENOSYS-to-EOPNOTSUPP result in the mounted filesystem, using relaxed atomic bits.
These behaviors follow the [Linux FUSE xattr implementation](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/xattr.c).

A mutation retains the original mount's writer admission through the daemon
reply or cancellation. Read operations do not acquire a writer. The operation
retains the original open and inode across close/FD reuse, and cancellation
interrupts a sent request once while late replies release the correct resources.
There is no private-volume shadow xattr or ordinary filesystem attribute-budget
lock spanning a daemon wait. Successful changes update canonical ctime and ATTRIB
notifications. Pathname continuations use the existing lazy single-operand
metadata mechanism; ordinary calls allocate no accepted-path table.

The generic user/trusted/security namespace checks and the FUSE default permission
delegation are distinct. The test daemon observes ordinary read/write permission
delegation, while sticky-directory, inode-kind and trusted capability checks still
apply. Parameter import rejects an empty name before copying SET value bytes or
checking their length, following [Linux's xattr import and permission paths](https://github.com/torvalds/linux/blob/v7.0/fs/xattr.c).

Legacy ACL xattrs are supported for a FUSE mount owned by the initial user
namespace without negotiating FUSE_POSIX_ACL. ACL reads fetch 4 KiB before applying
client capacity and map named IDs into the reader namespace. ACL writes validate
records and ownership, use zero wire CREATE/REPLACE flags, and distinguish empty
ACL removal from a nonempty default ACL on a regular file. Clearing the latter's
nonexistent default ACL is a successful no-op, including for another user. Mode
updates remain the daemon's responsibility. The scope follows [Linux's FUSE ACL
path](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/acl.c); full negotiated
POSIX_ACL/default_permissions behavior remains a separate gate.

Capability writes apply SETFCAP and validate the record before sending it. Reads
query and fetch the daemon record before mapping namespace-relative root IDs and
applying client capacity. Chown of a non-directory checks security.capability,
removes an existing value, refreshes attributes and then issues SETATTR. The native
probe establishes that a capability GET denial does not fail chown, whereas a
REMOVE denial does; both are strict fixture assertions. This checkpoint does not
claim all malformed capability/ACL records, revisions or user-namespace edges
have been audited.

### Native counterexamples and final checks

The initial core ELF `fuse-filesystem-xattr` passed isolated Linux and failed the
previous `attributes-cold-runner` on its first SET with errno 95. Its first local
implementation passed that ELF, but an expanded diagnostic found four real
native differences: ACL CREATE on an existing ACL, invalid capability SET,
capability removal on chown and another user's ACL write. The before/native
outputs remain in `xattr-audit-*`; `xattr-audit.py` verifies the four differences.
After correction, all 24 expanded probe result/errno pairs match native Linux and
are strict assertions in the repository fixture.

The final immutable ELF `fuse-filesystem-xattr-final` also checks empty-name SET
with an invalid value pointer and an oversized value. It passes isolated native
Linux at `target/local-ci/io/fuse-xattr-final-20261124-native`. The intermediate
`xattr-acl-runner` fails the **same** ELF at the invalid-pointer assertion with
EFAULT rather than native ERANGE; that counterexample is retained. The final
runner passes the same ELF with interpreter 1/2/4 CPUs, in 21.08/18.73/13.40 seconds,
and all 24 diagnostic pairs match the native output on each CPU count. The VM
launch script stops its native VM after the test.

The final local runner is `xattr-final-runner`, SHA-256
`ab062a05e917f98e9ed54f57c985dcafebe93d0cbf3e9f4ea53bf3da6825fdd2`.
`xattr-final-source` and `xattr-final-source.json` archive 67 source files and their
hashes; `xattr-audit.py` checks them against current source, original HEADs,
runner/fixture identities, native/interpreter outcomes and exact passing XML.
It writes `xattr-progress.json` and `xattr-verified-results.json` under
`target/fuse-complete-20261123`.

Checks pass: 856 default VFS; 909 hostfs VFS, including 160 FUSE; 19 direct Linux
file tests; all-target/all-feature VFS/Linux/session clippy; formatting and both
execution boundaries. Four unchanged file-scheduling results are reused.
Fourteen new focused xattr tests cover protocol, permissions, ACL/capability,
writer, cancellation and OFD lifetime behavior.

Original gVisor xattr/posix_acl/capabilities/chmod/chown/utimes/FUSE comprise 260
identities. The first run is 244 passes and 16 skips. Three SetACLEmpty cases are
skipped by the original guest-version conditional but pass the original provided
userspace-kernel ABI mode on the same runner. Final results are **247 passes,
13 original skips**, covering all 246 native-passing identities in this selection.
All 247 passing cases have their exact original passing XML audited; no upstream
assertion was changed. Combined with 356 unaffected earlier identities, the
ledger is **616 identities, 599 passes, 17 skips**, covering all 597 reference
passes. These are scoped reruns plus reuse, not a new full gVisor/platform run.
The native unconnected-clone errno discrepancy stays outside the native-passing
oracle.

### Ordinary xattr performance

The same static `xattr-performance` ELF compares `attributes-cold-runner` with
`xattr-final-runner` on the existing ephemeral memory backend and an ordinary
tmpfs file. It measures SET, GET, LIST and REMOVE+SET pairs separately, preserving
ordinary xattr budget/checkpoint behavior. Each observation starts a fresh
instance. One warmup pair precedes four measured pairs with execution order
balanced; no build, test or VM workload overlaps timing. Guest monotonic time
uses seconds x 1,000,000,000, and phase sums are bounded by independent host
elapsed time plus 50 ms.

| Current minus attributes-cold | SET | GET | LIST | REMOVE+SET |
| --- | ---: | ---: | ---: | ---: |
| 1,000,000 iterations per phase | +4.10% | -1.70% | +3.25% | +2.41% |
| 3,000,000 iterations per phase | -1.81% | -3.60% | -0.19% | +1.80% |

Both observations are retained as `xattr-memory-performance.json` and
`xattr-long-memory-performance.json`; the longer measured phases span about
2.3-6.1 seconds each. They do not establish zero overhead or a consistent SET/GET
speedup. They also do not replace persistent storage, real application or daemon
transfer-throughput acceptance. This checkpoint adds no new performance claim
for Mac HVF or physical iPad.

### Remaining scope

Hostfs xattrs still return EOPNOTSUPP, including targets reached via FUSE or proc
links; this old rejection is not accepted as complete host interoperability.
Remaining gates include full ACL/default_permissions negotiation, namespace and
malformed-record/error ordering, concurrent attribute versions and bad-inode
lifetimes, size/truncation/open flags and other inode data behavior, asynchronous
mmap, notifications, original FUSE applications and throughput, and final
HVF/paired/platform validation and delivery. Item 02 remains unchecked.

## Native host data xattr interoperability checkpoint, 2026-11-24

The previous blanket hostfs EOPNOTSUPP has been removed for native data attributes.
This advances item 02; it does not complete host ACL/capability translation, FUSE
or the full follow-up queue. There is no commit, paired-pin update or push yet.
No new coordinator, resource service, polling bus or global algorithm lock was
introduced. Host work continues through the existing native executor and the
same retained VFS operand used by FUSE continuations.

### Native storage and original capabilities

Path and FD GET/SET/LIST/REMOVE now use the accepted native inode. Values remain
in the host filesystem instead of a private-volume xattr map. Guest user/trusted
checks apply before native access, including sticky directories, inode kind and
trusted-name filtering. Native names such as Darwin data attributes remain
visible subject to guest ordinary permissions and the host OS's own checks.
O_PATH f*xattr returns EBADF. An immutable read-only grant and the original guest
mount's read-only admission reject mutations; an admitted mutation retains that
mount's writer until completion. Native FD permissions refresh from the original
inode, so an independent host chmod is visible to later guest FD operations.

Darwin metadata and symlink FDs support direct f*xattr; a standalone native probe
at `host-xattr-native-probe.log` and the hostfs-enabled tests exercise this behavior.
The guest symlink policy remains separate: user.* on a symlink is rejected while
an allowed native data attribute can address the link itself without following
its target. The native API's own extended-attribute authorization remains in
place, as shown by [XNU's vnode xattr implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_xattr.c).

Legacy Linux f*xattr cannot use a metadata O_PATH descriptor. Regular/directory
metadata operands use an internally constructed `/proc/self/fd/FD` magic link to
the retained inode; the pathname contains no guest text and does not reopen the
original display name. The native C oracle demonstrates GET/SET/query/LIST/REMOVE
after unlink and confirms that a replacement at the old path remains unaffected.
Darwin CREATE/REPLACE bits and missing-attribute errno are translated to the Linux
ABI. CREATE|REPLACE uses the existing/missing error outcomes observed on native
Linux, without an added read-modify-write lock or guaranteed race winner.

The first symlink test exposed ELOOP from reopening the accepted symlink as a data
file. `host-xattr-all-unit2.log` preserves the failure. Pathname xattrs now pin a
metadata capability instead, including a symlink-capable descriptor, while
checking the accepted native identity. Existing cold/native/proc capabilities
are used directly. This correction passes the original regression and the added
Darwin no-follow link test.

Linux POSIX ACL and security.capability records still return EOPNOTSUPP after
the applicable guest checks. Their UID/GID/root-ID conversion and authorization
must be implemented explicitly; the current patch does not forward these records
unchanged into the host authority namespace. Linux O_PATH symlink attributes also
remain unsupported, rather than accidentally following the link target. Native
LSM/other host-specific attributes retain the host OS's actual restrictions.

### Verification and scoped reuse

`host-xattr-source` and `host-xattr-source.json` archive 68 Rust/C files and hashes.
The CLI runner is `host-xattr-runner`, SHA-256
`8ff8369bc733358c3229c736b0827a06b19624b165ba4f0e35f403bec9495e8f`.
**This CLI does not enable hostfs.** Its daemon fixture and performance results
cover the shared ordinary/FUSE paths. Native hostfs behavior is checked with the
hostfs-enabled Mac VFS and a static Linux VFS test binary, not claimed as guest
host-mount, HVF or physical-device acceptance.

Mac checks pass: 856 default VFS and 914 hostfs VFS, including 161 FUSE. Two
additional test-only regressions then verify FD permission refresh after external
chmod and Darwin link attributes; all six focused host xattr tests pass. The
914-case complete run predates only those two test additions and the Linux-only
rename portability fix, so its unchanged production coverage is reused. Current
all-target/all-feature VFS/Linux/session clippy passes, with a final VFS-only
clippy after the extra tests; formatting and both execution boundaries pass.
Nineteen direct Linux file and four file-scheduling results are unchanged and
reused.

The same strict `fuse-filesystem-xattr-final` ELF passes interpreter 1/2/4 CPUs in
20.81/10.52/10.25 seconds; its unchanged native pass is reused. All 24 diagnostic
result/errno pairs continue to match that native result. The new deterministic
FUSE→proc→hostfs regression covers SET, GET query/data, LIST and REMOVE, yields
to the existing native route, closes/reuses the original guest FD and replaces
the original path before completion. It still accesses the accepted old OFD.

A static hostfs-enabled Linux test binary runs on the native VM. Final xattr
coverage is 20 passes; 23 hostfs and 19 native-walk passes from the immediately
preceding identical production source are reused (the selections overlap).
The final xattr rerun includes the new external-chmod FD regression. Results are
under `target/local-ci/io/host-xattr-20261124-native` and
`target/local-ci/io/host-xattr-final-20261124-native`; both launch scripts stop the
VM. The first cross build exposed musl's missing renameat2 wrapper; the hostfs
Linux branch now invokes the same kernel syscall directly, and its native rename
regressions pass. Apple's archive tool also omitted the ELF DNS object from the
cross-test archive; the validation build links the freshly compiled existing
`trames-net/native/dns.c` object directly. No replacement DNS implementation or
production network change was introduced. Failed build logs are preserved.

The initial scoped gVisor launch hit its disk guard before executing cases:
14 disk-limit outcomes and 246 not-run outcomes, retained as `host-xattr-gvisor`.
Only the Linux cross-build incremental cache was removed. The retry uses the
supported 6 GiB free-space reserve, with scoped store cleanup, and preserves the
original test assertions and identities. From the 260 selected cases, 244 pass
and 16 skip; the same three ACL version-conditional cases pass the provided ABI
mode. Final current results are 247 passes/13 original skips, covering all 246
native-passing identities, with 247 exact original passing XML cases audited.
With 356 unaffected earlier results, the ledger remains 616 identities,
599 passes/17 skips, covering all 597 native passes. This is scoped validation,
not a new full 14,530-case or platform acceptance run.

`host-xattr-audit.py` checks current/archived source, runner/ELF hashes, native
oracle outputs, original XML, retained regression evidence and scoped reuse. Its
outputs are `host-xattr-progress.json` and `host-xattr-verified-results.json`.

### Ordinary-call cost

`host-xattr-memory-performance.json` compares the immutable previous xattr runner
with the current CLI on the existing ephemeral memory backend and an ordinary
tmpfs file. The same static ELF performs 3,000,000 SET, GET and LIST calls and
3,000,000 REMOVE+SET pairs per observation. One warmup pair precedes four measured
pairs with both orders balanced. Build, test and VM handles were terminal before
timing; phase sums are checked against independent host elapsed time plus 50 ms.

| Current minus previous xattr runner | SET | GET | LIST | REMOVE+SET |
| --- | ---: | ---: | ---: | ---: |
| 3M iterations per phase | +1.30% | +2.38% | +0.45% | -0.10% |

These observed differences are retained, without claiming zero overhead or a
stable speedup. The CLI has hostfs disabled, so this is a control for shared
ordinary xattr costs. Native host-data throughput, persistent storage and real
application performance remain separate acceptance work.

The next gates remain host ACL/capability and Linux symlink-attribute translation,
full FUSE ACL/default_permissions negotiation, namespace/malformed-reply/error
ordering and attribute-version rules, size/truncation/open flags and other inode
data, asynchronous mmap, notifications, real programs and throughput, and final
HVF/paired/platform acceptance and delivery. Item 02 and items 03-12 remain open.

## Local FUSE mode permissions checkpoint, 2026-11-24

Item 02 remains a local, uncommitted subsystem batch. This checkpoint adds the
`default_permissions` mount option and local mode checks, while keeping the
existing daemon-delegated model when that option is absent. It does not negotiate
FUSE_POSIX_ACL, complete the remaining permission/error audit, or close the full
FUSE, application, performance, platform or delivery gates. No coordinator,
resource-service thread, polling bus or new global algorithm lock was added.

### Accepted credentials, refresh and wait ownership

Local checks use the existing Credentials mode/capability model. Attribute reply
validity is retained on canonical FUSE leaves/directories as a relaxed deadline
counter; actual metadata still uses the existing inode/object synchronization.
A stale snapshot or denied cached mode triggers GETATTR before deciding. A
zero-timeout reply authorizes that completed check once, instead of requesting
GETATTR indefinitely. Mount allow_other/user-namespace checks and live readonly /
noexec stages remain in place. The local/delegated split and denied-cache refresh
are grounded in [Linux's FUSE permission path](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/dir.c#L1633).

The permission request retains the original directory/path walk, inode, mount and
caller credentials. It resumes the same walk for ordinary components, `.` and
`..`, including native/proc boundaries, rather than replaying the path text.
Access retains its real-ID authority across LOOKUP and permission waits. Local
access and chdir do not issue ACCESS to the daemon. Mode checks also cover open
(including access mode 3), create/mutation parents, xattr permission masks and
SETATTR ownership/timestamp rules. Readonly writer admission is retained only by
actual mutations, including while their permission refresh waits.

The initial new candidate lost the open intent when a parent permission refresh
suspended **before** LOOKUP. `permissions-mode-guest-2.stderr` preserves the
`FUSE open intent` panic. Early permission work now owns an open plan before the
caller attaches its original reserved FD, umask and publication resource. The
existing lookup continuation then adopts that reservation. The deterministic
open regression covers this early wait and a denied control-only open; no new
coordinator or alternate FD publication path was introduced.

### Native comparisons and two additional mutation fixes

The first `fuse-permissions-mode-v1` ELF completed its permission assertions on
native Linux but raced unmount against its last asynchronous RELEASE reply. That
native run is retained as a failure, not a pass. The release barrier in v2 fixes
the fixture lifecycle. The unchanged old `host-xattr-runner` rejects the mount
option with EINVAL. V2 then passes native Linux and the corrected interpreter
candidate. V3 adds the control-only open assertion and passes native plus the
local candidate with interpreter 1/2/4 CPUs.

An expanded, independently native-validated v4 fixture found two further gaps in
that candidate: a protected link from a file without read/write permission and
a cross-parent rename of a non-writable directory both incorrectly succeeded.
Native Linux returns EPERM and EACCES. `permissions-audit-before-*` retains a
diagnostic run on the same ELF: its process exits zero because diagnostics
continue, but both printed results differ from native and are **not** passing
compatibility outcomes. The final strict invocation asserts these results.

Protected hardlink checks now distinguish delegated FUSE permissions from local
modes, refresh the accepted source when needed, and preserve the owner's/FOWNER
bypass even if that source permission query fails. Cross-parent directory moves
check the moved directory's write permission; exchange checks both directions.
The driver holds the original lookup grants through those new GETATTR phases and
updates an existing canonical directory when one is retained elsewhere. These
rules are independently exercised by native v4 and follow the [Linux hardlink
and rename checks](https://github.com/torvalds/linux/blob/v7.0/fs/namei.c#L1222).
There is no inode guard held across a daemon wait or algorithm-wide lock added.

The strict final v4 ELF passes native at
`target/local-ci/io/fuse-permissions-mode4-20261124-native` and interpreter 1/2/4
CPUs in 11.60/10.03/10.10 seconds. The native scripts stop their VMs. The same
runner also passes the existing delegated-mode `fuse-filesystem-xattr-final` ELF
on 1/2/4 CPUs in 9.66/10.34/8.74 seconds, reusing that unchanged ELF's native pass.
Its 24 ACL/capability diagnostic result/errno pairs remain equal to native.

### Verification and evidence identities

Final production-source VFS runs pass 866 default cases and 926 hostfs cases,
including 171 FUSE cases in the hostfs build. Ten new focused permission tests
cover cached denial refresh, zero TTL, dot/dotdot search, original credentials,
cancellation/lookup cleanup, real-ID access, xattr error precedence, reserved
opens, writer release, hardlink query failure and both rename directions. A
following test-only clippy cleanup explicitly types its UID test data; production
source and those full-run results are reused. Formatting, clippy and execution
boundary outcomes are recorded by the final audit rather than triggering full
CPU/network/graphics reruns.

The final runner is `permissions-mutation-runner`, SHA-256
`a76bc0af81059da1b33be7f6bfeb218b612dfb793f90a5b8ca036819b99e7ff6`.
Earlier `permissions-mode-runner`, `permissions-reserved-runner` and
`permissions-final-runner` remain immutable, including the panic and the two
mutation counterexamples. The current source manifest records 71 Rust/C files.
The initial complete VFS and clippy traces, including interface-size and test
inference corrections, are preserved separately.

The expanded original gVisor selection has 535 identities. The first launch hit
the disk guard before execution (19 disk-limit and 516 not-run outcomes), retained
as `permissions-gvisor`. Only generated VFS incremental and cross-build debug
caches were removed, with paths/sizes recorded in `permissions-cache-cleanup.json`;
archived source, logs and copied validated executables remain intact. The retry
uses the existing supported 6 GiB reserve and yields 516 passes/19 skips. Six
version-conditional original cases then pass the provided userspace-kernel ABI
mode, producing **522 passes/13 original skips**, covering all 521 native passes.

After the final mutation fixes, affected FUSE/link cases and those six ABI cases
are rerun on the final runner. The current 535-case selection contains 50 final-
runner outcomes and 485 unchanged pre-mutation outcomes; the final fixes affect
local FUSE mutation checks plus the explicit delegated hardlink argument, while
the other original suites use ordinary filesystems. Original FUSE test helpers
do not mount with default_permissions. The shared ordinary hardlink result is
unchanged, and its affected suite is rerun. All 522 passing cases have exact
original passing XML. Combining this with 277 unaffected earlier identities gives
**812 identities, 795 passes, 17 skips**, covering all 793 native passes. This
is a scoped ledger with explicit origins, not a new full 14,530-case run.

The final current-source archive is `permissions-checked-source.json` (71 files).
It differs from `permissions-mutation-source.json` only in the test UID annotation;
`permissions-audit.py` checks both that relationship and the unchanged production
runner. `permissions-progress.json` and `permissions-verified-results.json` retain
the counts, origins and exact XML checks. The checked clippy, format and ten-test
traces use the `permissions-checked-*` prefix.

### Ordinary workload controls

All builds, tests and native VM launches had terminated before the sequential
performance runs. Both comparisons use the immutable host-xattr runner as baseline
and the final permissions-mutation runner. Each retains a warmup pair and four
balanced measured pairs, with the corrected nanosecond clock and independent host
process duration bounds. All ten observations per comparison pass those bounds.

| Operation | Iterations per observation | Median change |
| --- | ---: | ---: |
| stat | 1,000,000 | +0.84% |
| open/close | 500,000 | +2.09% |
| getcwd | 10,000,000 | +0.75% |
| chmod | 3,000,000 | -1.26% |
| chown | 3,000,000 | -0.96% |
| utimens | 3,000,000 | -0.48% |

`permissions-path-performance.json` uses copies of the same prepared private-volume
seed. Its last after-version open sample is roughly 10% slower; it is retained.
`permissions-attribute-performance.json` uses the RAM backend to isolate ordinary
syscall overhead. These observations establish neither zero overhead nor a stable
speedup, and do not replace persistent mutation, real FUSE application, host-mount,
HVF or transfer-throughput acceptance. No performance-specific production change
was made after these measurements.

Remaining work includes full negotiated POSIX ACL/default_permissions integration,
namespace/malformed-frame/error ordering and attribute-version/bad-inode rules,
remaining open/mutation protection checks (including sticky O_CREAT), host ACL /
capability and Linux symlink-attribute translation, size/truncation and other
inode data, asynchronous mmap, notifications, real FUSE tools/throughput, and
final HVF/paired/platform validation, complete local CI and delivery. The whole
12-item objective remains active and item 02 remains unchecked.

## Sticky O_CREAT and same-group proc FD search checkpoint, 2026-11-24

Existing-file O_CREAT on FUSE now applies the shared protected_regular/fifos rule
using the accepted final parent and inode. O_EXCL keeps EEXIST precedence; the
existing O_CREAT|O_DIRECTORY validation keeps EINVAL precedence. The open plan
retains a parent only for the actual pathname lookup or a file bind's outer
parent, before a daemon wait. A proc magic inode reopen does not acquire its old
filesystem parent. No path is replayed after suspension.

The common ordinary-filesystem sticky rule is factored without changing its
policy. FUSE local checks use mapped ownership and the live namei policy: levels
0/1/2, world/group writable directories, file-owner and directory-owner exceptions,
and the absence of a general root/capability bypass. Delegated FUSE directory
permissions are distinguished from default_permissions. The final strict fixture
also checks a FUSE file bound into an ordinary sticky directory: that outer
parent's protection applies in both FUSE modes.

This distinction is grounded in [Linux's existing-file creation rule](https://github.com/torvalds/linux/blob/v7.0/fs/namei.c#L1322)
and [FUSE's internal sticky-bit handling](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/inode.c).
An initial delegated invocation incorrectly asserted local-mode denial and fails
on native Linux; that test expectation is retained in its original trace. The
corrected fixture explicitly asserts delegated successes instead of weakening the
local or outer-bind checks.

### A second proc traversal gap and retained counterexamples

The native fixture passes proc FD reopening after dropping to UID/GID 1000. The
first sticky candidate and a following candidate still failed that positive case
with EACCES, despite passing their new sticky denials. The native directory is
root-owned after the process becomes non-dumpable; [Linux's proc FD permission
handler](https://github.com/torvalds/linux/blob/v7.0/fs/proc/fd.c#L311) allows its
own thread group to traverse the FD directory anyway. That exception was missing
from the common pathname walk. It is now checked only after a failed ordinary
search permission and only on the actual proc FD directory. The original proc
namespace/task observation determines thread-group membership. FD target
inspection, mount and inode checks remain in place; fdinfo and unrelated tasks
do not receive this exception. This checkpoint verifies search traversal, not a
claim that every proc FD access/open-directory permission hook has been audited.

The new focused test covers a non-dumpable leader, another thread in its group,
another process and fdinfo. Existing FUSE lookup/permission waits retain the same
credentials and object capabilities. There is no new coordinator/service thread,
polling bus, ordinary-memory barrier or global algorithm lock.

Immutable `fuse-sticky-create-v3` is the final strict ELF. The unchanged old
permissions-mutation runner incorrectly opens the foreign file in local mode and
the bound file in delegated mode; `sticky-create-final-before-*` preserves both
nonzero failures on this exact ELF. `sticky-create-final-*` and
`sticky-create-fixed-*` preserve the intermediate positive proc-reopen failures.
The first native build attempted the read-only source share and failed to link;
the later builds use the existing writable VM output share. Native scripts
restore both protection sysctls and stop the VM after each invocation.

### Verification and scope

The final ELF passes native Linux in both modes at
`target/local-ci/io/fuse-sticky-create4-20261124-native`. The same ELF passes both
modes on interpreter 1/2/4 CPUs: local 9.62/7.63/7.34 seconds and delegated
7.79/6.83/7.03 seconds. Every printed result/errno matches native, normalizing
successful FD numbers only. The existing delegated xattr-final ELF also passes on
2 CPUs; its 24 strict ACL/capability probe pairs match its unchanged native run.

The final runner is `sticky-create-proc-runner`, SHA-256
`31035510353090b7702be3072db97c84efd0a439ec062a6b88f1b3ff62f7b308`.
`sticky-create-proc-source.json` archives 72 Rust/C files. Its final hostfs build
passes 172 FUSE cases and three process-credential cases, including the two new
focused regressions. A namespace selection initially passed 45 cases and failed
one native network operation with NetError(1) under the sandbox. Only that case
is rerun with the required host access and passes; the original failure is kept.
Current all-target/all-feature VFS/Linux/session clippy, format and runtime
execution/session boundary checks pass. The product integration wrapper requires
a clean runtime and rejects this uncommitted subsystem as expected; it remains a
final integration check, not a passing checkpoint result. Unaffected earlier
module results are reused instead of repeating full CPU/network/graphics checks.

The final original open/open_create/FUSE/proc selection has **242 identities,
239 passes and three original skips**, covering all 238 native passes. Every
passing outcome has exact original passing XML. An earlier 82-case selection
passed 81/skip1 before the proc exception; the complete affected selection is
rerun on the final runner. Two attempts hit the existing 6 GiB disk guard
(42 disk-limit, 200 not-run each). The first has no case stdout; the second starts
the open chunk and prints partial successes before it is stopped, without a
complete XML result. None of those interrupted outcomes are counted as passes.
Generated VFS incremental caches are removed and their paths/sizes retained; after filesystem space
recovery, the same reserve and assertions pass. These stops are not functional
failures or passes.

`sticky-create-audit.py` verifies current/archive source hashes, immutable runner
and ELF identities, strict native/guest results, old counterexamples, retained
probe pairs, scoped XML, original commit identities and cache-cleanup boundaries.
`sticky-create-progress.json` and `sticky-create-verified-results.json` retain the
merged origins. With 730 unaffected earlier identities, the ledger is now
**972 identities, 953 passes and 19 skips**, covering all 951 native passes. This
is still a scoped compatibility ledger, not another full 14,530-case run.

Ordinary performance controls from the preceding local-mode checkpoint remain
recorded with their original runner identities and observations. No new timing
is claimed for the sticky/proc runner. The new proc exception is on the denied
search path; FUSE parent retention is part of its existing open plan. Real FUSE
applications, throughput and platform performance gates remain open.

Remaining work includes negotiated POSIX ACL, complete permission/error and
attribute concurrency audits, host authority/ACL/capability mapping and Linux
symlink xattrs, size/truncation/open flags/nonregular inode data, asynchronous
mmap, notifications, real applications/throughput, and final HVF/paired/platform
validation, full local CI and delivery. Item 02 is unchecked; items 03–12 and the
whole objective remain active. No commit, runtime pin or push was made here.

## Negotiated POSIX ACL and cache lifetime checkpoint, 2026-11-24

FUSE INIT now advertises and accepts POSIX_ACL, DONT_MASK and SETXATTR_EXT.
POSIX_ACL enables local permission checks even when the mount did not explicitly
request default_permissions. A pathname accepted before INIT completes waits on
the connection's existing readiness path, retaining its original walk, caller,
open reservation and mutation writer. Aborted initialization wakes that path too.
No coordinator/service thread, polling bus, global algorithm lock or ordinary
memory barrier is added. Blocking work continues to yield execution slots.

The common permission continuation obtains access ACLs on the accepted inode and
uses the existing credentials, ACL and namespace model. It covers search, open,
access/chdir, creation and parent mutations, protected hardlinks, source directory
write permission during cross-parent moves, NOW timestamps and ordinary xattrs.
Owner/zero-mask/mode fast paths avoid unnecessary ACL requests. The ordinary
non-FUSE `allows_node` method was restored exactly to its preceding source;
ordinary owner checks do not gain an extra xattr-map lookup.

ACL reads have a 4096-byte wire bound. ENODATA/empty results mean no ACL; ENOSYS
disables further GETXATTR attempts on that connection, while ERANGE/oversize
becomes E2BIG. Other daemon errors propagate. Named IDs are validated and mapped
from the mount's user namespace into the shared credential model. Negotiated ACL
set/remove works in a mapped noninitial namespace; legacy ACL handling retains its
initial-namespace restriction. DONT_MASK sends the raw creation mode and separate
umask to the daemon. Extended ACL SETXATTR sends Linux's ACL SGID-removal intent
and ACL operation flags; the SGID check uses one node borrow.

The canonical FUSE inode owns a bounded ACL observation plus an invalidation
version under an object-local mutex. No node/cache guard crosses a daemon wait.
Attribute refresh and attribute/ACL mutation invalidate cached ACL observations;
late ACL replies cannot repopulate a cache invalidated in the meantime. Permission
denial on cached metadata causes one GETATTR refresh, then a fresh ACL decision.
GETATTR also invalidates a continuation's old observation. Stat, parent refresh,
chown refresh and inode reopen use the same invalidation, and reopening updates
the canonical inode's attributes before proceeding.

This follows the ACL invalidation in
[Linux FUSE permission GETATTR](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/dir.c)
and [FUSE ACL operations](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/acl.c).
The root inode is created before INIT and remains uncached, matching the retained
native experiments even after a root SETATTR. A previous candidate cached the
root's initial ENODATA and incorrectly permitted the second foreign open. The
same v7 ELF passes natively and fails on that immutable candidate with an open FD
instead of EACCES; `posix-acl-cache-before-*` retains this counterexample. The
corrected runner re-queries and denies both the second open and the corresponding
open after SETATTR.

### Strict daemon/client and retained intermediate failures

`tests/fixtures/fuse-posix-acl.c` is a real daemon/client fixture mounted with
allow_other and without an explicit default_permissions option. Its ACL grants
read where mode bits alone deny it, denies a named user despite readable OTHER
bits, and checks masked write denial. The daemon rejects any unexpected ACCESS
RPC. It verifies raw creation mode/umask and assigns inherited ACLs; a second
foreign UID then reads/searches those objects while writes remain denied. An
original OFD pins a file across chmod, which changes the ACL mask seen on a later
foreign write. ACL SETXATTR verifies extended wire flags and SGID removal.

The final v8 ELF adds NOW utimens and user-xattr denial/grant roundtrips, protected
hardlink denial followed by a successful link/unlink after the mask change, and
cross-parent directory rename denial based on the source directory's ACL. Both
parents grant that caller full access, so the latter reaches the source-directory
write check. The separate root-cache profile warms stat to finish INIT before
testing its two negative-cache cycles. The mapped profile uses real UID/GID maps
`0 0 1; 1000 101000 1001`, exercising global identities rather than a single-UID
namespace. The native script saves/restores protected_hardlinks and stops the VM.

Earlier evidence is kept rather than relabeled. The old sticky/proc runner fails
both initial and mapped v3 profiles on the same native-passing ELF. Native v4
fails its compiler warning check and has no accepted ELF. Native v5 exposes a
fixture race with INIT, corrected by the explicit warmup; v6 disproves the
fixture's assumption that SETATTR enables root ACL caching. Neither failed
fixture is counted as a passing comparison. Native v7 then establishes the
correct root expectations; v8 extends the other operation assertions without
changing production code. The old delegated-unlink unit incorrectly applied
local sticky permissions; it now explicitly tests both permission modes.

### Verification and evidence identities

The final production runner is `posix-acl-cache-runner`, SHA-256
`2b2ad9be9f3bef2e732878501f0b5b72811078a8da31f6b4c251ed5e1e995f61`.
`posix-acl-checked-source.json` and its source directory archive 75 Rust/C files;
the only change from `posix-acl-cache-source.json` is the extended C fixture.
The immutable v8 ELF passes all three native profiles at
`target/local-ci/io/fuse-posix-acl8-20261124-native`. The same ELF passes initial,
mapped and root-cache profiles on interpreter 1/2/4 CPUs: nine combinations.
Printed protected-link, directory-move and root denial result/errno pairs match
native exactly. The previous delegated xattr-final ELF also passes on the final
runner at 2 CPUs, with all 24 strict probes matching its unchanged native result.
The CLI lacks hostfs; these interpreter runs are not guest host-mount or HVF
acceptance.

Full default VFS passed 898 cases and hostfs VFS passed 958 cases before the final
FUSE-only cache corrections, each with one existing ignored File Provider
manifest emitter. After those corrections the FUSE hostfs run passed 176 of 177
identities; one unit expected another ACL read after an already fresh grant.
Only that test expectation changed, and all five focused ACL tests then passed.
Their union covers all 177 FUSE identities; this is not a single all-177 green
run or a fresh full-module run. The focused tests also cover delayed INIT,
original credentials/reservations, cancellation, late replies, cache invalidation
and daemon errors including ERANGE-to-E2BIG conversion. Final all-target/all-feature
VFS/Linux/session clippy, formatting and runtime execution/session boundary checks
pass. The product wrapper's clean-runtime integration gate remains for delivery.

The affected original gVisor selection has 695 identities. Its first run has
674 passes/21 skips; six unchanged userspace-ABI outcomes from the preceding
ledger are reused, giving **680 passes/15 skips**, covering all 679 native passes.
The final cache correction reruns the original FUSE group: **23 passes/one skip**.
Thus 24 identities use the final cache runner, 665 retain the preceding ACL runner
and six retain their explicitly recorded older ABI results. Combined with 277
unaffected identities, the ledger remains **972 identities, 953 passes/19 skips**,
covering all 951 native passes. This is a scoped ledger, not a new full
14,530-case run. The native unconnected-clone errno and WaitFork anomaly remain
excluded from the native-passing oracle.

`posix-acl-checked-audit.py` verifies current/archive source hashes, immutable
runner/ELF identities, native/guest assertions, historical same-ELF counterexamples,
unit retry coverage, exact passing XML and the recorded commit identities. It
reopens all 953 accepted passing XML cases and saves their evidence origins in
`posix-acl-verified-results.json`; `posix-acl-checked-progress.json` records scope
and version-specific reuse. No result from an intermediate failed fixture is
promoted into that ledger.

The first final-cache gVisor attempt hit the existing disk guard for 24 identities.
Only generated incremental caches and 711 older VFS `.rcgu.o` objects were removed,
with paths and sizes retained. Source, executable fixtures, runners, XML and logs
were preserved. After the owning Cargo processes had finished and space recovered,
the same guard and FUSE selection passed. The interrupted attempt is neither a
functional pass nor a failure.

### Ordinary controls and remaining work

Balanced performance runs compare immutable sticky/proc runner `31035510…` with
pre-cache ACL runner `0123845d…`, using one warmup pair and four measured pairs
per workload. No Rust build, test or native VM run overlaps timing. Guest clocks
use the corrected nanosecond conversion and every sample satisfies the independent
host-duration bound. Private persistent-volume stat/open-close/getcwd median
changes are **-0.91%/-2.34%/-1.34%**; RAM chmod/chown/utimens changes are
**+1.01%/+0.72%/-2.59%**. All samples and identities remain in the two
`posix-acl-*-performance.json` files. The final cache/GETATTR corrections affect
only FUSE paths outside those ordinary workloads; these numbers are not measured
timings of the final cache runner, stable speedups, or real FUSE throughput/HVF
acceptance.

Further ACL namespace/malformed-frame/error/cache audit and metadata
attribute-version/bad-inode rules remain, along with host authority/ACL/capability
mapping and Linux O_PATH symlink attributes, size/truncation/open flags/nonregular
data, asynchronous mmap, notifications, real FUSE programs/throughput, and final
HVF/paired/platform checks, full local CI and delivery. Broader proc FD directory
permission hooks also remain outside the previous search-only proof. Item 02 is
unchecked, items 03–12 remain open and the whole objective stays active. No commit,
runtime pin or push was made at this checkpoint.

## ACL backing format, public cache and namespace checkpoint, 2026-11-24

The previous candidate applied full setter validation to ACLs returned by the
daemon. Native Linux accepts some noncanonical backing ACLs: unusual permission
bits, entry order and a named entry without a mask can survive decoding. An ACL
that decodes but cannot complete its permission walk returns EIO. Rejecting all
of these with EINVAL changed both public reads and permission decisions.

The shared ACL module now distinguishes backing-format decoding from setter
validation. FUSE permission evaluation preserves entry order, searches for a mask
after the matching entry and propagates the incomplete-walk EIO before capability
fallback. Ordinary stored-ACL `allows` and ordinary credential `allows_node` fast
paths retain their previous source. Setter conversion errors precede ownership,
but semantic validation follows it: a nonowner with invalid permission bits gets
EPERM, whereas the inode owner gets EINVAL. An unknown version combined with an
invalid entry length returns EOPNOTSUPP because version decoding comes first.
Header truncation still returns EINVAL.

These distinctions follow [Linux's backing conversion, setter and permission
functions](https://github.com/torvalds/linux/blob/v7.0/fs/posix_acl.c), and are
verified by the native probe below rather than inferred only from source.

Public GETXATTR of access/default ACLs now shares the canonical inode cache.
Previously each public read issued a separate request and did not populate the
permission cache. Positive/negative access and default entries are kept under
the existing inode-local cache lock and invalidation version. Cache hits use a
ready continuation without a daemon request. The original user buffer capacity
still determines count/ERANGE/bytes; cached global IDs are translated into the
requester's namespace on output. Both cache kinds are invalidated together by
the existing refresh and mutation paths. A late public read can return its own
accepted observation but cannot restore a cache invalidated during that wait.
No guard crosses a daemon wait, and no coordinator/service thread, polling bus,
global algorithm lock or ordinary memory barrier is added.

### Native assertions and exact counterexamples

New `tests/fixtures/fuse-acl-wire.c` reuses the daemon/client helpers from the
preceding POSIX ACL fixture. It strictly asserts 21 backing cases, including
version/length/tag/ID failures, noncanonical permission bits/order, missing mask,
incomplete ACLs, empty/absent ACLs, mapped/unmapped IDs and daemon error mapping.
It also checks nonowner versus owner setter errors. Access/default cache probes
change the daemon's second reply: repeated public reads and permission checks
must keep the accepted first cached observation, with one query per kind.

Three native profiles pass: initial namespace, a mapped mount namespace using
`0 0 1; 1000 101000 1001`, and a descendant reader whose local UID/GID 0 maps to
global 1000 while the mount stays in its ancestor namespace. The reader sees
matching named IDs as 0 and unrepresentable IDs as UINT32_MAX; cached permission
evaluation still uses global IDs. The daemon runs in the original mount context.
Every VM script stops its VM after the run.

The final immutable ELF is `fuse-acl-wire-v4`, from
`target/local-ci/io/fuse-acl-wire4-20261124-native`. It passes all three profiles
on interpreter 1/2/4 CPUs: nine combinations. Every printed setter/read/access,
reader ID/permission and per-inode query count matches its native profile
exactly. Earlier v1/v2 initial/mapped and v3 three-profile native results remain
separate records; v2 removed typed accesses into C byte buffers, v3 added owner
and descendant-reader assertions, and v4 added the combined header error.

The old `2b2ad9be…` runner fails the same native-passing v3 ELF in all three
profiles: invalid-permission setter ordering or noncanonical public ACL decoding.
`acl-wire-checked-before-*` retains these failures. The first corrected runner
`e532cf9a…` passes all v3 profiles on 1/2/4 CPUs, but fails the v4 combined-header
case in initial and mapped namespaces with EINVAL instead of EOPNOTSUPP.
`acl-wire-priority-before-*` retains that second exact-ELF counterexample. These
are distinct production regressions, not passing diagnostic invocations.

The previous valid-ACL v8 permissions fixture also passes all nine combinations
on the first corrected runner `e532cf9a…`. Those results retain that identity:
the final change only orders malformed header checks and does not enter the
valid v8 inputs. The final runner additionally passes the old delegated
xattr-final ELF on 2 CPUs, with all 24 strict probes matching native. The CLI
lacks hostfs; this does not establish guest host-mount or HVF acceptance.

### Scoped verification and retained origins

The final runner is `acl-wire-final-runner`, SHA-256
`cffec0ccf2df3d147c5ae03a63b212587cb1656489552962b17c8927015be559`.
`acl-wire-final-source.json`, its directory and patch archive 77 Rust/C files.
The final hostfs VFS run passes **961 tests, zero failures and one existing ignored
File Provider manifest emitter**, including all **179 FUSE tests** and seven
focused ACL tests. The two new tests cover public access/default cache sharing,
negative entries, original capacities and late public replies after mutation.
The first focused run passed six and failed a new test that assumed the namespace
wrapper completed a cache hit in its first stage. The corrected test drives its
existing ready phase; all seven then pass. No production assertion was weakened.

Earlier full hostfs/default runs in the sandbox passed 947/887 and failed the
same 14 native network/clock-event operations. Only those failed identities were
rerun with the required host access; all passed in both configurations. Thus the
pre-header-order default result covers 901 passes/one existing ignore, and is
retained with its original source scope. The final full hostfs run uses the last
header-order correction and the required host access from the start. Current
all-target/all-feature VFS/Linux/session clippy and formatting pass. Execution
and session boundary evidence remains valid; those owning sources did not change.
No full CPU/network/graphics/platform or 14,530-case run is claimed here.

The final original xattr/POSIX ACL/FUSE selection has **182 identities**. Its
ordinary run is 166 pass/16 skip; six selected SetACLEmpty-family cases then pass
under the existing userspace ABI mode. Three replace earlier skips, yielding
**169 pass/13 skip**, covering all **168 native-passing identities**. All accepted
results have exact original passing XML. An initial accidental invocation of
generic `run.py` failed at `env create` with exit 125 before case execution;
that setup failure is retained and counted as neither a pass nor a case failure.
The interpreter entry point then completes the selection successfully.

`acl-wire-audit.py` checks current/archive hashes, immutable runner/ELF identities,
strict native/guest results and query counts, historical counterexamples, unit
and retry origins, original commit identities and exact XML. Combining 790
unaffected earlier identities still gives **972 identities, 953 passes/19 skips**,
covering all 951 native passes. The audit reopens all 953 accepted passing XML
cases; `acl-wire-progress.json` and `acl-wire-verified-results.json` retain their
origins. No additional cache cleanup was needed in this phase.

No fresh performance measurement is claimed. Ordinary permission fast paths
retain their preceding source, and the earlier balanced controls retain their
original runner identities. This does not substitute for real FUSE application,
throughput or platform performance gates.

Next is a native probe for concurrent ACL cache fills and cancellation ownership:
the current version check prevents mutation-invalidated replies from refilling,
but simultaneous reads within one version need comparison with Linux's sentinel
ownership. This is an open audit question, not a verified completed behavior.
Metadata attribute-version/bad-inode rules, oversized protocol frames, host
authority/ACL/capability mapping and O_PATH symlink attributes, size/truncation/
open flags/nonregular data, async mmap, notifications, actual FUSE programs and
throughput, final HVF/paired/platform validation, full local CI and delivery also
remain. Item 02 and items 03–12 stay open; the whole objective remains active.
No commit, runtime pin or push was made at this checkpoint.

## Concurrent ACL fill and cancellation ownership checkpoint, 2026-11-24

The open same-version fill question now has a native counterexample. Two public
reads of one canonical inode enter the daemon before either reply. The first
reply supplies named permission 4 and completes its syscall; the second supplies
6 and then completes. Native Linux keeps the first request's cached 4, while the
previous `cffec0cc…` runner incorrectly returns cached 6. Both initial and mapped
profiles fail on that unchanged old runner using the same native-passing ELF.
`acl-race-before-*` retains those exact failures.

The fix models [Linux's ACL fill sentinel ownership](https://github.com/torvalds/linux/blob/v7.0/fs/posix_acl.c#L107)
with an owned claim for each access/default cache kind. Claim acquisition and
the observation snapshot use the existing inode-local mutex. The first reader
of an unknown kind can fill it; overlapping readers still send their independent
daemon requests and return/use their own replies. They do not overwrite the
claim owner's positive or negative cached observation, irrespective of completion
order. There is no request coalescing, new waiter queue or function-wide lock.

Errors and cancellation retire only the actual claim. An already pending reader
does not acquire fill rights just because the owner failed. A newly started
reader can claim the now-unknown cache, and an old follower's completion or
cancellation cannot clear or overwrite that replacement. Existing invalidation
versions still reject replies from before metadata refresh/mutation. The root
remains uncached. No guard spans a daemon wait, and no coordinator/service thread,
polling bus or ordinary memory barrier is introduced.

The claim is non-clonable and consumed on completion. Public xattr and permission
continuation destruction cancel an outstanding claim through their retained
canonical inode. Normal completion consumes it before result publication,
including daemon decode/error paths. Transferring a successful FUSE chdir inode
retains one Arc for publication while the permission continuation is destroyed.
Ordinary inode policy, credential fast paths, path-walk state, memory access and
shared executor sources are unchanged.

### Handshakes, signal cancellation and strict profiles

New `tests/fixtures/fuse-acl-race.c` uses the existing fixture helpers and a real
daemon/client. Pipe/request/completion handshakes establish both reads before
either response, and establish syscall completion before the next response.
No timed sleep is used to choose a winner. The test-only daemon waits for native
FUSE/control events with blocking poll; this is not a production worker or
resource-coordination path.

The final fixture asserts 12 scenarios: both reply orders, access/default ACLs,
owner EIO and negative ENODATA, owner/follower signal interruption, a replacement
owner started while an old follower remains pending, and overlapping public
reads with permission checks in either role. Both permission and public-read
owners/followers are interrupted using SIGUSR1 and real FUSE_INTERRUPT handling.
Every reader must still receive its own expected reply; the final cache and
per-inode query count assert the independent fill-ownership result. Failures
and canceled owners require a new third query where Linux leaves the cache
unknown. Cacheable success/negative scenarios retain exactly two queries.

The first native attempt has no accepted ELF: its C fixture failed -Werror for
a signed-length comparison and an unbraced close loop. Those compiler errors
were corrected without relaxing the flags. Native v2 then passes ten scenarios
in initial/mapped namespaces, providing the old-runner counterexample above.
Native v3 adds permission-path signal cancellation; its final immutable
`fuse-acl-race-v3` passes both profiles at
`target/local-ci/io/fuse-acl-race3-20261124-native`. Each script stops its VM.

The same final v3 ELF passes initial/mapped profiles on interpreter 1/2/4 CPUs:
six combinations. Every printed client return/errno/permission, final cache value
and query count matches native exactly. The preceding 21-case backing/public
cache ELF v4 also passes all nine initial/mapped/descendant-reader combinations
on this runner, with exact native values and counts. The old delegated
xattr-final ELF passes on 2 CPUs with all 24 strict probes matching native.
The CLI still lacks hostfs; these are not guest host-mount or HVF results.

### Scoped verification and retained evidence

The final runner is `acl-race-runner`, SHA-256
`06dfdf53e8e01f77b07c9af5cb619d341b1ab29e6244c4626f42e88d888c645e`.
`acl-race-source.json`, its directory and patch archive all 78 modified/untracked
Rust/C files. Relative to the preceding checkpoint, only the FUSE ACL cache,
xattr/permission continuations, focused ACL tests and new C fixture change.

All **182 hostfs FUSE tests** pass, including **ten focused ACL tests**. The three
new regressions cover both completion orders, cancellation of an old follower
while a replacement is pending, and cancellation of an owner without promoting
an old follower. The existing invalidation, late-response, negative-cache,
capacity, credentials and INIT tests remain passing. The preceding **782
unaffected non-FUSE VFS passes and one existing ignored manifest emitter** are
retained with their source/runner identities. This is not a new complete 964-pass
VFS invocation. All-target/all-feature VFS/Linux/session clippy, formatting and
runtime execution/session boundary checks pass. Complete product/platform CI
remains an integration gate.

Before the final scoped gVisor run, free space approached its existing 6 GiB
reserve. After all owned Cargo handles finished, nonblocking locks were obtained
for both debug targets and the release target. Only 827 generated VFS `.rcgu.o`
objects older than one hour were removed, totaling 542,563,240 logical bytes;
paths, sizes and free-space observations remain recorded. Source, executables,
XML and logs were retained. The unchanged disk guard then permits the normal
original FUSE selection: **23 passes/one skip**, covering all **22 native passes**.
There is no disk-interrupted case result in this phase.

`acl-race-audit.py` verifies current/archive source hashes and scope, immutable
runner/ELF identities, same-ELF native counterexamples, all strict guest/native
outputs and counts, unit coverage, scoped exact passing XML, cleanup boundaries
and original commit identities. With **948 unaffected earlier identities**, the
ledger remains **972 identities, 953 passes/19 skips**, covering all 951 native
passes. All 953 accepted passing XML cases are reopened; origins remain in
`acl-race-verified-results.json` and `acl-race-progress.json`. This is not another
full 14,530-case run.

No new performance measurement is claimed. Ordinary production files and their
fast paths retain their preceding source; earlier immutable controls are kept.
Real FUSE program/throughput and platform performance gates remain open.

The next group is metadata attribute-version and bad-inode behavior. Current
`directory::refresh_inode` updates canonical attributes after type/ID checks;
it has no request-version arbitration yet. A native request/reply handshake is
needed to determine which cache/stat observations survive a later mutation and
how a type-changing reply affects subsequent operations. Oversized protocol and
error ordering, host authority/ACL/capability mapping and O_PATH symlink attrs,
size/truncation/open flags/nonregular data, async mmap, notifications, actual
programs/throughput, final HVF/paired/platform checks, full local CI and delivery
also remain. Item 02 and items 03–12 stay open; the whole objective remains active.
No commit, runtime pin or push was made at this checkpoint.

## Metadata request epochs and bad-inode checkpoint, 2026-11-24

This continues item 02; it does not complete the FUSE batch or the twelve-item
objective. The preceding ACL checkpoint remains historical evidence with its
own immutable runner and sources. No commit, runtime pin or push is made here.

### Native observations and the old-runner counterexample

`tests/fixtures/fuse-metadata.c` uses a real FUSE daemon, blocking descriptor and
control-pipe waits, and request/completion handshakes. It holds original file
descriptions throughout the experiment; final permission checks use
`faccessat2(original_fd, "", R_OK, AT_EMPTY_PATH)` so that a new pathname LOOKUP
cannot replace the observation being measured. There are thirteen scenarios:

| Case | Native observation |
| --- | --- |
| 0 | GETATTR starts before chmod, replies later with 0666: its stat returns 0666, while cached mode remains 0600 and foreign access is denied. |
| 1 | Two GETATTR requests complete in reverse order: each returns its own reply, but the late older request does not overwrite cached 0640. |
| 2 | A newer alias LOOKUP updates the same inode to 0640; the held older GETATTR returns 0666 without replacing that cache. |
| 3 | GETATTR completes while SETATTR is pending: SETATTR still applies 0604, but expires the cache; foreign access refreshes from daemon 0600 and fails. |
| 4–6 | Wrong-type GETATTR, oversized GETATTR size, and wrong-type SETATTR each return EIO and leave a persistently bad original inode. |
| 7–8 | Ordinary accepted GETATTR/SETATTR nanoseconds above one second are clamped to 999,999,999. |
| 9 | Unmapped UID/GID are reported as 65534, including on the mapped mount; they do not make stat fail with EOVERFLOW. |
| 10 | A superseded GETATTR returns its own raw out-of-range nanoseconds without clamping; it leaves the newer canonical mode and timestamp intact. |
| 11–12 | Reuse of a nodeid with a different generation or type creates a usable new inode and makes the old open inode persistently bad. |

Bad-inode assertions include cached and forced statx, read, user xattr, chmod and
data-FD close. They fail with EIO; final RELEASE still reaches the daemon. New
O_PATH aliases close successfully. GETATTR counts per case are
`2,2,1,2,1,1,0,1,0,1,1,0,0`; all thirteen original data handles are released.

Native v1 and v2 each pass in initial and mapped namespaces. V2 changes the
foreign permission probe to the retained empty FD; the final immutable
`fuse-metadata-v2` is at
`target/local-ci/io/fuse-metadata2-20261124-native`, SHA-256
`d895bc80321b9870557504545ddf24dea24f2a7b2acb318fb2ad6d219190366d`.
The same ELF on the old `06dfdf53…` runner fails both profiles at case 0: its
cached mode becomes 0666 instead of native 0600. The first implementation
candidate protects the cache but then fails with EINVAL for AT_EMPTY_PATH.
Both failed runner/source/output sets are retained separately.

The behavior also agrees with the archived upstream v7.0
[inode.c](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/inode.c),
[dir.c](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/dir.c) and
[fuse_i.h](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/fuse_i.h):
GETATTR rejects stale cache publication before normalizing the reply, SETATTR
applies concurrent replies with a zero attribute timeout, and nodeid reuse
retires the previous inode. The downloaded reference files and hashes are
retained with the checkpoint artifacts; the native fixture is the behavioral
oracle for the cases above.

### Implementation and concurrency boundaries

Canonical leaf/directory attributes now keep their raw bytes and metadata
version under the existing inode attribute mutex. One relaxed connection epoch
is sampled for metadata requests; successful updates advance it. An older
GETATTR/LOOKUP reply cannot overwrite a newer canonical observation. SETATTR
still applies its daemon reply after a concurrent update and sets validity to
zero. Stat returns its request's reply independently of cache publication.
Accepted canonical attributes clamp nanoseconds and retain unknown IDs as
unmapped global IDs until reader-namespace projection.

A relaxed bad-inode bit persists independently of cached bytes. Invalid type or
size replies poison the original inode; existing handles check that state.
The identity table retires old generation/type entries before publishing a new
inode. Upgraded references stay alive until its existing table guard is dropped,
including error/unwind paths, so destruction cannot revisit that held guard.
The immutable inode type avoids acquiring a node guard merely to compare types
under the identity-table lock. RELEASE remains unconditional after badness.
CREATE/link-related publication uses its accepted daemon metadata rather than an
unversioned overwrite of a previously retained identity.

The empty-FD access dependency is handled by both Linux dispatch paths and the
shared VFS resolver. It retains the original descriptor or cwd inode, applies
real/effective credentials as requested and uses no replacement pathname search.
Ordinary permission policy remains shared. Tests cover an unlinked O_PATH inode,
different real/effective IDs, an inaccessible cwd, empty-path flag and bad-FD
errors, plus worker/owner ABI parity.

All waits still use existing FileWork/readiness workers and yield execution
slots. No lock is held over a daemon wait. This adds no coordinator or service
thread, polling bus, global algorithm lock, ordinary memory barrier or stronger
guest consistency policy. Attribute synchronization protects that inode's
existing multi-field invariant; epoch and bad-state atomics use relaxed ordering.

### Scoped verification and evidence identities

Final `metadata-final-runner` SHA-256 is
`220a4b30294cc5f54a8ce97ed4d693d3cb52a35b0fa285da3eb36c9d555b7248`.
`metadata-final-source.json` and its directory archive all 82 changed/untracked
Rust/C files; 21 differ from the preceding ACL checkpoint. The immediately prior
candidate also passes all metadata combinations. Its only later source changes
group directory parent/name arguments without changing behavior; final FUSE
tests, clippy and guest acceptance use the final source and runner.

The final metadata ELF passes initial/mapped namespaces on 1/2/4 interpreter
CPUs, six combinations. All 37 printed observations and request counts in each
combination match native exactly. The old twelve-case ACL race v3 passes six
combinations, the 21-case backing/public ACL v4 passes nine combinations, and the
delegated xattr-final fixture matches all 24 native probe pairs on two CPUs.
The CLI has no hostfs; these are not guest host-mount or HVF acceptance results.

Hostfs VFS verification has **968 passing tests and one existing ignored manifest
emitter**: the initial invocation has 954 passes, fourteen sandbox network/clock
failures and one ignore; exactly those fourteen failures pass with the required
host access. All **185 FUSE tests** also pass on the final parameter-grouping
source. The unrelated 783 non-FUSE passing results plus one ignore are reused
from that same phase's complete VFS invocation. The Linux worker/owner ABI test,
VFS/Linux/session all-target/all-feature clippy, formatting and runtime boundary
checks pass. Earlier unit failures, the intermediate directory FD-stat update
bug and the initial clippy argument-count failure remain in their original logs.

After all Cargo processes finished, nonblocking locks on both debug targets and
the release target protected a bounded cleanup of generated VFS `.rcgu.o` files
older than one hour. Its 3,082 paths and 3,029,928,464 logical bytes are recorded;
reported free space rises from 4,915,200,000 to 7,004,160,000 bytes. Source, runners,
fixtures, XML and logs are preserved. An initial read-only `ps` attempt was
denied by the sandbox before any removal; target locks provide the actual
cleanup exclusion.

The first scoped gVisor launch accidentally used the harness default 8 GiB
reserve and stopped: nineteen disk-limit records and twenty-four unrun records
are retained and receive no passing credit. The retry explicitly uses this
batch's preceding **6 GiB reserve** and completes original FUSE/access:
**42 passes and one skip**, including all reference-passing cases in that scope.
XML normalization verifies all 42 exact passing cases. Merging **929 unaffected
earlier identities** leaves **972 identities, 953 passes/19 skips**, covering all
951 native passing cases. This is a scoped update, not a new full-suite run.

A scratch launcher basename collision also selected the ACL race fixture where
the metadata launcher was intended. The properly selected ACL run is retained
as ACL evidence only. Two accidental repeat drivers were stopped with their own
child processes and receive no additional acceptance credit. The authoritative
metadata launcher is `guest-metadata-epochs.py`; `metadata-epochs-*` contains its
six final-runner results. Partial duplicate logs are preserved separately.

`metadata-audit.py` verifies current/archive hashes, runner/ELF identities,
old-runner counterexamples, native/guest observations and counts, merged VFS
outcomes, exact XML, cleanup paths and normal-path timing records. All 953
accepted passing XML cases are reopened; `metadata-verified-results.json` retains
their original evidence origins. `metadata-progress.json` is the stage manifest.

Normal-path performance observations are recorded in
`metadata-path-performance.json`: same fixture/seed, balanced before/after
ordering, one warmup pair and four measured pairs, with guest intervals bounded
against external monotonic elapsed time. For one million stat calls, 500,000
open/close pairs and ten million getcwd calls, measured median times change by
**+1.04%, +0.88% and +3.59%**, respectively. The four-pair control alone does not
identify the cause of those differences; getcwd production source is unchanged.
This is an interpreter/private-volume control, not actual FUSE application or
transfer throughput acceptance.

### Remaining scope

The next metadata group must audit canonical LOOKUP registration on early-return
paths (followed symlink, non-directory and exclusive-create errors), bad-inode
error ordering, local namespace/link/size invalidations and other metadata/protocol
reply limits. The thirteen scenarios above do not establish those paths.
Host authority/ACL/capability mapping and Linux O_PATH symlink attributes,
size/truncation/open flags/nonregular data, async mmap/notifications, actual FUSE
programs/throughput, final HVF/paired/platform checks, full local CI and complete
FUSE delivery remain open. Items 03–12 are still pending; the objective stays active.

## LOOKUP early-return publication checkpoint, 2026-11-24

This continues the metadata work within item 02. The complete FUSE batch remains
uncommitted and undelivered; items 03–12 and the overall objective remain active.

### Native lifetime and error precedence

The new [`fuse-lookup-lifetime.c`](../../tests/fixtures/fuse-lookup-lifetime.c)
retains sixteen original data descriptions, then returns controlled attributes
for distinct alias names. It examines the pathname operation, the original
FD's cached statx and final close independently. Four original inodes are first
made bad by a type-changing GETATTR. A real guest daemon, completion pipe and
blocking descriptor waits provide the synchronization; there are no timing
sleeps. The mapped profile also checks the non-directory error as a foreign user.

Native observations, followed by a separate strict-assertion ELF, establish:

| Cases | Pathname result | Original inode observation |
| --- | --- | --- |
| 0 | Following a type-reused symlink reaches its ordinary target successfully. | The replaced regular-file FD is already bad. |
| 1 | A generation-reused regular inode with a child suffix returns ENOTDIR. | The older-generation FD is bad. |
| 2–3 | O_CREAT\|O_EXCL on type-reused directory/symlink aliases returns EEXIST. | Both replaced regular-file FDs are bad; the exclusive symlink sends no READLINK. |
| 4–5, 11 | Same-identity aliases return EEXIST or ENOTDIR, including a trailing slash. | Their accepted LOOKUP still updates cached mode from 0666 to 0600. |
| 6 | O_NOFOLLOW on a type-reused symlink returns ELOOP. | The original regular-file FD is bad without READLINK. |
| 7–9 | A same-identity alias of an already bad inode returns EEXIST for exclusive create, EIO for stat, and opens successfully with O_PATH. | Badness persists; stat on the new O_PATH FD also returns EIO. |
| 10 | A newer-generation alias of a bad inode opens with O_PATH. | The new FD reports regular mode 0600; the old FD stays bad. |
| 12–14 | Invalid LOOKUP type or oversized size returns EIO, including exclusive create. | Those invalid replies neither poison nor change the unrelated valid original inode. |
| 15 | A foreign reader follows a regular alias with mode 0000 and a child suffix: ENOTDIR. | Its LOOKUP still publishes cached regular mode 0000. |

The native observational v1 and strict v2 runs each complete initial/mapped
profiles. Only v2 is the acceptance fixture. Its immutable ELF is
`fuse-lookup-lifetime-v2`, SHA-256
`845607e52ee924f31b4958982ce0672fa56a41638fcd22d033fccd44b0554b63`,
at `target/local-ci/io/fuse-lookup-lifetime2-20261124-native`. Native scripts stop
the existing VM after the run. All sixteen aliases issue one LOOKUP; only cases
7–10 issue an inode GETATTR, and only case 0 issues READLINK. All sixteen original
descriptions reach RELEASE even when close returns EIO.

The exact same strict v2 ELF on the preceding `220a4b30…` runner fails both
profiles at case 0: old cached stat still succeeds with mode 0666 instead of EIO.
Those counterexamples remain under `lookup-lifetime-before-*`; their failure is
not relabeled as current behavior. The final runner passes all six
initial/mapped × 1/2/4 CPU combinations, with every one of the 66 printed native
observations and request counts matching exactly.

The publication order also follows the archived upstream v7.0
[fuse_lookup_name/fuse_lookup](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/dir.c)
and [fuse_iget](https://github.com/torvalds/linux/blob/v7.0/fs/fuse/inode.c):
valid LOOKUP replies bind/update an inode before the later pathname outcome.
The native fixture, including the already bad inode cases, is the behavioral
oracle for the exact error ordering above.

### Implementation and synchronization

`advance_lookup` now publishes valid canonical metadata before exclusive-create,
symlink-follow and non-directory early returns. Invalid attributes remain
rejected before identity retirement. Root GETATTR remains an ordinary attribute
read, with its original bad-state check.

The attribute update origin is explicit: Lookup, Read or Set. Lookup may bind
and refresh an existing bad identity without clearing its bad flag; namei can
then choose EEXIST or publish an O_PATH capability. Actual stat, data-open,
permission and link-read operations check badness at their respective operation
boundaries. Reads and setters retain the preceding request-epoch arbitration;
SETATTR still expires concurrent cache publication. Three focused unit tests
cover early-return publication, bad-inode open/stat precedence and retirement
before an outstanding READLINK completes.

All seven changed production files are inside FUSE. Ordinary VFS permission,
pathname, syscall dispatch, FileWork, scheduler and guest memory sources are
byte-for-byte unchanged from the preceding checkpoint. Synchronization continues
to use the existing inode/table locks and relaxed metadata atomics. No new thread,
coordinator, service loop, polling bus, global algorithm lock or ordinary memory
barrier is added; daemon waits still yield existing execution slots.

### Scoped verification and retained evidence

The final `lookup-lifetime-runner` SHA-256 is
`2c12a0488761d029ca0508cfc7724dd86033c0a49abdd33acefc99d8d90b4a71`.
`lookup-lifetime-source.json` and its directory archive all 83 modified/untracked
Rust/C files. Nine differ from the preceding checkpoint: seven production FUSE
files, the focused attribute tests and the new C fixture. Original product/runtime
commit identities and pins are unchanged.

- All **188 hostfs FUSE tests** pass, including the three new regressions. The
  first test build's ambiguous generation-integer type error is preserved and was
  fixed explicitly to u64; it was not counted as a test pass.
- The prior **783 non-FUSE passes and one existing ignore** are reused with their
  original source identities. Together these provide 971 passing unit identities
  and one ignore; this is not a fresh complete 971-pass VFS invocation.
- The preceding thirteen-case metadata ELF passes all six initial/mapped ×
  1/2/4 CPU combinations with exact native results and counts. The twelve-case
  concurrent ACL ELF passes both profiles on two CPUs; the 21-case backing/public
  ACL ELF passes initial/mapped/descendant-reader profiles on two CPUs, all with
  exact native outputs. Other unchanged earlier results retain their old origins.
- All-target/all-feature VFS/Linux/session clippy, formatting and runtime
  execution/session boundary checks pass. The CLI has no hostfs; interpreter
  daemon results do not constitute guest host-mount or HVF acceptance.

After owned Cargo processes finished, nonblocking locks on both debug targets and
the release target protected deletion of only generated VFS `.rcgu.o` objects
older than one hour. The finite cleanup records 1,367 paths and 2,072,846,008
logical bytes; reported free space rises from 6,389,760,000 to 8,069,120,000 bytes.
Source, ELF, runners, XML and logs remain intact. The gVisor guard stays at 6 GiB;
there are no disk-interrupted cases in this phase.

The first 174-case original selection used the userspace ABI flag globally and
reported 171 passes/three skips. Two ordinary open cases were conditionally
skipped by that mode. They are not accepted as replacements for earlier passing
Linux-mode evidence. All 150 open/open_create/stat/symlink cases were therefore
rerun in the preceding ordinary Linux reference mode and pass; the FUSE group
retains its matching userspace ABI mode with 23 passes/one existing skip. The
combined scoped result is **174 identities, 173 passes/one skip**, preserving all
native passing cases. Both raw runs and their separate normalized XML evidence
remain available; no upstream assertion or skip condition was modified.

With **798 unaffected earlier identities**, the ledger remains **972 identities,
953 passes/19 skips**, covering all 951 native passes. `lookup-lifetime-audit.py`
verifies source/runner/ELF hashes, strict native observations and counts,
old-runner failures, unit reuse, test modes, exact passing XML and cleanup
boundaries. All 953 passing XML identities are reopened.
`lookup-lifetime-verified-results.json` and `lookup-lifetime-progress.json` retain
the acceptance origins. This is not a fresh full gVisor run.

No new ordinary-path timing is claimed: those production sources are unchanged.
The preceding immutable four-pair controls (+1.04% stat, +0.88% open/close,
+3.59% getcwd median elapsed time) remain observations with their original
runner/fixture identities, not a claim about this runner's performance. Actual
FUSE application/throughput and final platform performance gates remain open.

The next protocol audit includes root/invalid nodeids and generation treatment,
malformed or oversized replies, namespace/link/size invalidations and error
precedence beyond these sixteen scenarios. Host authority/ACL/capability mapping,
Linux O_PATH symlink attributes, size/truncation/open flags/nonregular data,
async mmap/notifications, real tools/throughput and final HVF/paired/platform/full
CI and complete FUSE delivery remain pending. No commit, runtime pin or push was
made at this checkpoint.
