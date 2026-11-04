# Shared Linux runtime and execution backends

The accepted target is three projects: one common Linux userspace runtime, the
iPad interpreter product, and an Apple Silicon Mac hardware-execution product.
Work starts in this workspace so boundaries can be checked before repository
extraction. [Issue #44](https://github.com/kb5000/trames/issues/44) tracks the
remaining integration and extraction gates. This foundation is not feature
parity between the Mac bring-up runner and the iPad application.

## Current boundaries

| Component | Responsibility |
| --- | --- |
| `trames-execution` | AArch64 architectural state, register access, advertised features and honest instruction-count availability. No dependencies, decoder or OS VM. |
| `trames-kernel` | Shared task signal state/ABI, fault policy and ready-task affinity placement. No interpreter or host execution transport. |
| `trames-linux`, `trames-elf`, `trames-memory`, VFS/network/storage | Shared Linux syscall and image ABI, virtual mappings and actual byte ownership. No interpreter/native-accelerator dependency. |
| `trames-cpu` and current `trames-core`/iPad composition | Existing interpreter, decoded state and product integration. Core's task/signal scheduler still needs its execution dependency extracted. |
| `trames-hvf`, `trames-mac` | Thread-affine Hypervisor transport and single-process Mac bring-up CLI. Hardware CPU execution; common Linux syscalls and process-entry stack. |

Task-state integration moves signal ownership, dispositions/queues,
alternate stacks and architectural frame entry/return into `trames-kernel`,
used by both Core and the Mac adapter. Real hardware fault handlers now recover
through that shared code. [Task-state boundaries](task-state.md) describes the
completed extraction and the process/scheduler work that remains.

`scripts/check-execution-boundaries.py` checks normal transitive dependencies.
The bridge's opt-in SHA-256 service is platform-neutral host functionality;
keeping it in `trames-accel` previously pulled native instruction helpers into
the entire VFS/Linux graph. Its implementation now lives in the bridge and the
old accelerator API re-exports it. Algorithms and wire accounting are unchanged.

Linux dispatch is generic over register access, rather than `trames_cpu::Cpu`.
The interpreter implements that small interface without changing normal slices,
deferred flags or decode caches. Architectural state is materialized only at an
explicit handoff; a regression preserves deferred carry, SIMD, TLS, FP state and
resume PC. The shared Linux stack builder receives the executor's HWCAP values
and caller-supplied extension auxv entries. Mac must not advertise the
interpreter's larger emulated ISA. Hardware reports instruction count as
unavailable; it does not invent an exact software instruction budget.

## External native completions

An asynchronous native producer retains the actual eventfd object, independently
of its descriptor number. A shared producer lease marks that event as an external
source while a live descriptor still refers to it. Plain guest eventfds do not
prevent deadlock detection; closing/reusing a descriptor does not make an old
callback signal its replacement. Cloning a callback shares the existing lease,
without changing per-frame liveness counters.

Completion uses the event counter's ordinary readiness subscriptions for workers
and unparks the joined owner captured when it created the native producer. The
park token survives completion between the final readiness check and idle wait.
With no native sockets to wait on, the joined scheduler parks until completion
or its existing deadline instead of sleeping in one-millisecond increments. Mixed
native-socket waits retain the existing bounded network wait. No new service
thread, polling bus or guest-wide lock is introduced. This fixes FFmpeg reporting
`all virtual processes are blocked without an event source` while VideoToolbox
still owns an outstanding hardware decode.

## Optional host directory capabilities

`trames-vfs` exposes `Vfs::mount_host(target, directory, readonly)` with the
opt-in `hostfs` feature on Apple/ARM64 Linux. The embedding product selects the
directory; Linux `mount(2)` cannot manufacture a host pathname grant. Mounts are
session-local and do not change the private object-store manifest. The iPad
product does not enable this feature by default.

Each mount retains an authorized native directory descriptor. Parent lookup
never follows native symlinks: Apple uses `O_NOFOLLOW_ANY`, while Linux walks
anchored components. Symbolic-link targets are interpreted by the guest path
resolver. Native inode handles are retained by open descriptions, cwd/directory
contexts and pending I/O, including across rename/unlink/FD reuse.
Closed cached metadata does not retain one native file descriptor per inode.
Bulk reads use the existing bounded disk pool. Native data is neither copied
into the private store nor charged to its logical-byte budget.

Normal files do not query the host backend or participate in a polling mirror.
Monotonic mount/target markers bypass unrelated mount-table scans; mount moves
and namespace copies mark new attachments and conservative positives remain safe.
The host identity index never spans native lookup or namespace-lock acquisition.
Metadata admission reconciles concurrent candidates, and dead weak registrations
are collected at allocation boundaries rather than on ordinary reads. Apple host
metadata lookup uses fstatat relative to the grant with AT_SYMLINK_NOFOLLOW_ANY,
avoiding an open/stat/close of each parent. Linux retains its component capability
walk, and older Darwin kernels rejecting the flag use the established path.
Final symlinks are reported as links and interpreted by the guest resolver, never
followed by the native lookup. See Apple's [flag contract](https://developer.apple.com/documentation/system/stat/flags-swift.struct/symlinknofollowany).

Joined newfstatat prepares the real query while observing its proc dependency.
An ordinary result is copied out directly; queries that touch proc are discarded
and repeated after the existing publication/refinement step. This avoids a
separate discovery-only pathname walk without caching results across syscalls,
namespace/credential changes or independent host mutations. Failed queries do
not change output memory. Joined positioned writes also reuse the existing
bounded service buffer instead of allocating and zeroing a buffer for every call;
no per-process cache, new service thread or additional I/O lock is introduced.

Host MAP_PRIVATE pages use retained native descriptors and the existing guest
COW/page-source model. Page bytes are read only on demand; no native writable
mapping, background mirror or shared-byte coherence is implied. Ordinary inode
I/O keeps its live native data path. Guest-known length changes invalidate EOF
checks through a relaxed metadata generation.

Initial session launch and guest exec share one shebang parser, including the
single optional interpreter argument and bounded recursion. Native executable
capabilities and mapping sources retain their original inode across replacement.
Native create/open also retains the creation descriptor, including when a new
file has read-only mode bits; cached weak handles preserve older open files
when the newest same-access description closes.

Current limits are explicit: host MAP_SHARED returns ENODEV, extended attributes
and special host files are unsupported. Resident private pages do not monitor
external native changes/truncation. A coherent MAP_SHARED backend additionally
needs bounded host-fault handling for external truncate and aliases usable by
both executors; simply exposing a raw file mapping is insufficient.

Host-file flock delegates to the native OFD. Its retained request, dup/fork and
mapping lifetime is independent of weak byte caches; final OFD release unlocks.
On macOS, contended blocking flock subscribes to NOTE_FUNLOCK before the deciding
retry. The existing worker poller or joined executor waits on that descriptor,
without a blocking worker thread or a periodic lock retry service. On Linux the
optional adapter supports native nonblocking flock; a contended blocking call
returns EOPNOTSUPP because this adapter has no Linux unlock notification source.
POSIX fcntl range locks remain guest-local. Forwarding them unchanged would merge
all guest owners into one native process; native interoperability needs a
separate guest-owner/OFD interval representation.

Host inotify instances lazily allocate a native event queue. Apple uses kqueue
vnode interests and shallow snapshots on directory namespace events; Linux uses
native inotify through retained descriptor paths. Directory child descriptors
are allocated only for content/attribute monitoring. Normal unwatched byte I/O
does not inspect native queues. The original guest event stream remains intact;
matching native echoes are suppressed during drain. Native events wake existing
read/poll/epoll/io_uring subscribers through HostEvents. The joined executor also
waits on the accepted pending resources alongside sockets and retries external
byte waits, including after numeric FD close/reuse. Unrelated unread watchers do
not become idle-loop wake interests. No coordinator, service thread or periodic tree scan is added.

External macOS notifications are coalesced observations: transient names may be
missed, moves across separately watched directories may appear as delete/create,
and external open/access/close events are unavailable. This is not complete
Linux inotify history conformance. Native overflow/admission errors remain
visible. Removing/consuming watches or closing the original OFD retires native
interests even if prepared queue capabilities survive.
Ordinary native reads/writes, offsets, append, sparse size,
fsync, metadata, hard links and namespace operations use the selected host
filesystem. Its case, ownership and native access rules remain applicable.
See the [Mac usage and native comparison](https://github.com/kb5000/trames-mac/blob/main/docs/guides/file-sharing.md).

## Mac hardware path

The Mac adapter creates a hardware VM/vCPU object without booting a Linux kernel,
firmware, initramfs or virtual device stack. Guest ARM64 runs at EL0. A small EL1
exception vector returns SVC and page faults to the host Linux implementation.
Four-level guest page tables preserve Linux's 4 KiB mappings independently of
the host's 16 KiB physical allocation granule. Host buffers are never executable;
the signed Mac executable needs the Hypervisor entitlement, not a JIT entitlement.

The vCPU remains on its creator thread. A virtual timer bounds each run, with no
polling message bus or service thread. A timer may exit after EL0 entered an EL1
exception vector but before its HVC. The adapter must recover the saved EL0
PC/PSTATE/exception in that case; treating the vector PC as EL0 would resume at
an inaccessible kernel address. The long memory fixture exposed this race.

The first access binds physical bytes to the existing Memory page, replacing
its earlier byte owner; there is no permanent second guest RAM image. Canonical
permissions, first-write quota admission and private COW remain in Memory.
Hardware runs while that Memory is exclusively owned, with no Rust byte slice
or concurrent View/pin spanning execution. Shared providers/pins that cannot
meet this contract are rejected explicitly. Host accesses use the established
SharedPage guards. Stopped hardware writes publish existing data, exclusive and
code invalidation state at the execution boundary, not on ordinary instructions.

Private file shadows preserve the backing until COW and refresh after backing
changes. Fork byte owners force a new physical binding before a parent write.
Partial unmap, protection and discard retire stage-one aliases before stage-two
unmap and physical release. Empty page tables retire and guest physical addresses
are reused. The sparse host allocation is independent of the configured RAM cap.

Instruction-cache maintenance applies only to initialized executable pages.
Applying it to the entire data RAM range prematurely populated that memory and
raised the measured 64 MiB fixture's peak physical footprint from roughly
76–79 MiB to roughly 141 MiB. An isolated negative control restores that mistake
and the physical-footprint test rejects it.

## Reclaimable physical memory

A RAM limit or low initial footprint is insufficient. The common runtime must
return released storage while the runtime/VM remains alive, and preserve data
that remains valid. These are separate responsibilities:

- Unmap, heap shrink, discard and exit retire actual byte owners. Cached
  preparation cannot extend an obsolete page's lifetime after its last View.
- A physical host granule is reclaimable only after all its 4 KiB byte/slot
  owners finish. Fork, pins and active snapshots retain their legitimate leases.
- Slot creation/final retirement uses an object-local metadata lock. Ordinary
  CPU/native loads and stores retain the existing ARM/region model.
- Linux punches empty granules in the shared memfd. Darwin marks them reusable
  and reactivates them before publishing a new slot. A partially occupied arena
  no longer keeps every previously touched granule charged until whole-arena drop.
- A unique quiescent snapshot retires unmapped/discarded frames and affected CPU
  aliases while retaining incremental preparation for surviving pages.

The existing interpreter-memory test fills 64 MiB, keeps one host granule in
every 1 MiB arena, frees the rest, and verifies three reuse cycles. On this Mac,
physical footprint falls from about 70 MiB to 8 MiB; the old implementation stays
near 70 MiB and fails. This checks OS accounting, not just the guest quota.

The actual static-musl hardware guest fills 64 MiB, blocks for a host footprint
sample, discards the range, verifies zero refill, unmaps and repeats without
process restart. A final private-file mapping verifies that COW does not alter
the file and discard restores its original contents. Current samples fall from
about 76–79 MiB populated to 13 MiB discarded. Remaining metadata/allocator
overhead is visible; these are bounded correctness probes, not product throughput
or whole-application memory guarantees.

Memory-pressure reclamation of reconstructible caches and live anonymous paging
remain separate gates. `free()` does not itself tell the kernel that an allocator
has returned a page. Still-live anonymous bytes cannot be discarded: reclaiming
their RAM needs preserved contents and a correct fault-recovery path. Host
pressure notifications must use existing host/event infrastructure, without an
extra coordinator thread or ordinary-access barriers.

## Build and validation

On Apple Silicon macOS, run `bash scripts/build-mac.sh` and then
`target/release/trames-mac-run --rootfs <verified-Alpine-archive> /bin/busybox echo hello`.
The archive uses the existing pinned distribution verification. A host static
ARM64 ELF can be passed directly without `--rootfs`. The same ELF loader and
Linux stack/syscall implementation serve both products.

The hardware entry example additionally verifies real SVC entry, sparse access,
resumed registers, fork COW, write protection and live VM reclamation. Sign its
executable with `apps/macos/Trames.entitlements` before running it. The original
musl memory fixture runs against the hardware backend, interpreter and independent
native Linux semantic oracle. `tests/integration/mac-execution.py` samples the
live child's physical footprint and rejects premature data-RAM population.

Full local CI precedes pushing. Preserve unchanged passing results; after a
test-only waiting correction, rerun that case and affected TSan checks rather
than repeating unrelated CPU/network/graphics acceptance. An older persistent
wait test cancelled after a fixed number of control checks; under TSan load that
could precede a reader's completion. Its guest now acknowledges both completed
reads before cancellation, retaining the original FD-reuse/cohort assertions.

The [source-bound validation summary](../validation/execution-backends-summary.json)
records the complete 80-stage native ARM64 Linux workflow, 71 passed iPad
simulator tests with one existing opt-in skip, hardware and interpreter memory
measurements, negative controls and the scoped test-only follow-ups. Physical
iPad release acceptance remains a separate gate.

## Remaining integration and repository extraction

The Mac runner currently covers one process, private mappings and shared signal
frame/state semantics. Common process scheduling and signal routing, clone/exec,
shared mapping/provider export, native
syscall admission and full application integration must move behind the executor
boundary before feature-parity claims or independent repository releases.
Hardware and interpreter capabilities/interrupt accounting remain distinct.

Keep the current iPad runtime as the reference while migrating these gates. After
both products run through the common task/memory model, extract the common
runtime, iPad product and Mac product into independently buildable repositories,
pin dependencies and preserve source pairing. Do not fork Linux semantics into
two product copies or infer completion from a renamed crate/backend selector.

## Guest and compositor clocks

A Linux session with Wayland uses the server's shared monotonic origin. The
server retains that origin across commands in its namespace. Input receipt and
presentation acknowledgements are timestamped against it before entering the
compositor command queue. Host uptime, UIKit event epochs and frontend timestamps
must not be forwarded as guest monotonic milliseconds: GTK clients reconstruct
input timestamps using their own `CLOCK_MONOTONIC`, including 32-bit wraparound.
A standalone native compositor keeps caller-supplied timestamps until it is
bound to a guest clock. This preserves native peer and presentation tests.

## Host input during indefinite waits

An owner-side ppoll/pselect or epoll wait can depend on host standard input even
when no PTY or native socket remains. The scheduler queries accepted poll/select
OFD identities and armed epoll watches before diagnosing an event-source deadlock.
It does not re-import mutable guest fd arrays, consume edge/one-shot events, or
assume every poll is external merely because fd 0 exists. Ordinary internal-pipe
waits retain the original deadlock behavior. This is shared Linux/session policy
for both interpreter/iPad and hardware/Mac adapters; it adds no platform branch,
resource thread, or new polling mechanism.

A regression covers infinite ppoll, pselect, epoll_pwait and epoll_pwait2 followed
by delayed input, mutation of an already accepted guest poll buffer, and an
internal-pipe control. Real Mac window acceptance also verifies that closing the
last native windows leaves the parent shell able to wait for and read new input.


## Resource scope during interactive execution

Anonymous and open-unlinked inodes have no directory-tree membership. Path
lookup returns immediately for them, and their metadata mutations do not commit
a persistent namespace. A memfd resize uses its shared-memory budget without
scanning persistent disk usage. A linked resize checkpoints its owning
filesystem, so named tmpfs buffers cannot serialize the persistent root's
manifest. Inode admission collects expired weak handles only when the node
limit is reached; the exact live-node quota remains enforced. Failure-injection
tests keep the root manifest unwritable while exercising anonymous and tmpfs
operations, and verify named persistent writes still report commit failures.

Timer deadline discovery keeps a membership-versioned index of unique weak
timer objects. Scheduler queries read current deadlines from those objects;
rearm/disarm never copies or caches a deadline. Closing/reusing descriptors,
fork and CLONE_FILES invalidate membership through the existing FD identity.
An empty index avoids walking unrelated descriptors. This creates no polling
bus, service thread or additional timer authority, and weak entries cannot keep
a closed timer alive.


## Optional SME streaming context (2026-10-29)

`Aarch64State` remains 816 bytes. `Cpu` has optional SME hooks with unsupported
interpreter defaults; iPad gains no capability bit, per-task matrix allocation,
or platform dependency. The bounded extended register profile holds up to
64-byte streaming vectors, predicates, ZA and one ZT register. A hardware backend
owns the optional buffer and supplies its actual supported vector lengths.
Non-streaming SVE and SME FA64/FFR are outside this profile.

The shared session implements Linux SME vector-length prctl, deferred/inherited
exec policy, CLONE_VM ZA/TPIDR2 clearing and fork preservation. Unused prctl
arguments are ignored, matching Linux. Syscall return clears streaming mode,
preserves low vector lanes and retains live ZA/ZT. Exec resets register state.
The signal kernel emits and validates streaming SVE, ZA, ZT and TPIDR2 records;
large contexts use Linux's contiguous `extra_context` layout. Handlers start
with SM/ZA/TPIDR2 cleared. Full frame validation precedes task/register changes.
An SME image receives AT_MINSIGSTKSZ=8192 for the bounded profile. Existing
non-SME signal and interpreter behavior remains available without these records.
Debugger regsets are not implemented by the session's existing ptrace boundary.

The Mac product validates actual EL0 matrix instructions, private context
permissions, preemption and host-thread migration. Its Linux fixture additionally
checks streaming signal restoration after a clobbering handler, fork, pthread
creation and exec. The common ABI follows the
[Linux SME documentation](https://docs.kernel.org/arch/arm64/sme.html) and
[signal-record layout](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/sigcontext.h).


## Bounded address-space checkpoint batches (2026-10-29)

Mapping checkpoints still quiesce their actual mm/backing closure, including
in-flight native and resource operations. A backend may publish a retained
`ExecutionInterrupt` for its worker assignment. Pause and publication share a
per-domain object lock, closing both pre-entry orders; no lock covers guest
execution or ordinary memory. The handle carries only exit authority and must
become inert before destruction or CPU identifier reuse. Interpreters return
`None` and retain their existing polling path.

Once these views have drained, an optional `run_quiesced` hook lets the existing
owner coalesce consecutive mapping syscalls in a 250 microsecond window shared
by all requesters in that checkpoint. This requires every admitted cohort job
to be in the checkpoint, reserving logical CPU capacity while unrelated address
spaces continue on the normal path. Mac supplies the remaining window duration to its hardware timer. Calls remain in the common Linux kernel and each accepted
mapping operation completes even when the window or epoch ends. All non-mapping
syscalls, native exits and faults are stored on the same job for ordinary worker
dispatch, or joined-kernel handling on stop, exactly once. Native bodies do not
run in this batch. A hardware-borrow yield can retry and park on its normal
worker. Preempted peers are requeued before mapping requesters. No extra worker,
resource service, polling bus or guest memory policy is introduced.

Checkpoint metrics separate quiescence, owner queue delay, commit, Linux calls,
view rebuild, resume and exclusive CPU time. Quiescence histograms and batch
counts distinguish shorter waits from excessive stop/wake cycles. Times can
overlap across independent domains; summing them is not session wall time.
Measured tradeoffs and the reproducible fixture are in the Mac
[execution design](https://github.com/kb5000/trames-mac/blob/main/docs/architecture/execution-backends.md).


## Worker wakeups and optional clock vDSO (2026-10-29)

The shared run queue retains its existing mutex and blocking event sources.
Each idle worker registers its slot under that mutex before atomically releasing
it in a condition-variable wait. Publication selects sleeping slots that can run
the ready jobs, honoring initial placement and affinity and preferring the last
worker. Each selected slot receives one notification. A claimant passes remaining
ready work on, covering flexible/pinned placement overlap. When no ready task is
eligible, one idle worker still observes I/O, deadline or control changes. Stop
wakes every registered sleeper. Existing host-event wakeups remain; no polling
bus, resource-service thread or lock around guest/native bodies is introduced.

`Cpu::clock_sample` is optional and defaults to unsupported. A backend that
supplies it must expose the same counter domain and frequency as guest
`CNTVCT_EL0`, including migration and host sleep behavior. Such images receive
an AArch64 ELF vDSO through `AT_SYSINFO_EHDR`, with versioned `LINUX_2.6.39`
symbols and ordinary guest RX code / read-only calibration pages. The common
Linux/session code owns the ELF, stack ABI, permissions and clock semantics;
platform counter APIs stay in the executor. The iPad interpreter advertises no
vDSO and retains its existing syscall behavior and capability profile.

The ELF has one zero-based RX `PT_LOAD`; the adjacent read-only calibration
page is a separate mapping. This also supports older glibc vDSO registration,
whose [zero-address sentinel](https://github.com/bminor/glibc/blob/glibc-2.31/elf/setup-vdso.h)
miscomputes the load bias if a second nonzero `PT_LOAD` follows it. A real
glibc-interpreted PIE is a regression, alongside static/dynamic musl lookup.

Initialization and exec bind the counter to the same session `Instant` origin
used by syscalls and Wayland. Eight bounded calibration brackets select the
narrowest sample; a bracket wider than one microsecond disables the fast clock.
While tasks are stopped, initialization preserves the data page's guest
permissions and skips a removed/replaced optional mapping. No recurring updater
or shared fast-path lock is needed. The generated machine code is checked in;
`crates/trames-linux/src/vdso/rebuild.py` reproduces it with Clang and rust-lld,
without adding an assembler dependency to normal Cargo builds.

The current session's monotonic IDs 1/4/6/7 use a counter read and integer
conversion, with quotient/remainder arithmetic before multiplication to avoid
long-uptime overflow. Realtime IDs 0/5 retain the syscall so host wall-clock
adjustments remain observable. Unsupported IDs, `gettimeofday`, unavailable
calibration and unsupported executors retain syscall fallback. Resolution
queries retain the existing 1 ns ABI value; this is not a precision guarantee.
Clock IDs use Linux's low 32-bit `clockid_t` argument on both paths. These hooks
do not change the session's existing clock-ID/suspend policy.

Regression coverage includes actual blocked affinity/stop wakeups, dynamic
metadata state, real Linux libc/versioned symbol lookup, clock/syscall agreement,
concurrent callers, fork/exec, long elapsed-time arithmetic and realtime fallback.
The Mac product records full-application and targeted measurements in its
[execution design](https://github.com/kb5000/trames-mac/blob/main/docs/architecture/execution-backends.md).

## Staged distribution population

The Mac environment manager uses `Vfs::populate_staged` only while populating an
unpublished private store, before any guest executes. It defers per-operation
namespace checkpoints, retaining normal inode capacity, data ownership and sync
rules, then flushes data and publishes one final manifest. A scope guard restores
normal checkpointing on errors and unwinding. The caller discards the entire
staging store on failure; this API is not a transaction for a running or shared
filesystem. Normal private and hostfs runtime I/O use their existing paths.

The shared distribution importer now also accepts the pinned official Debian
13/trixie slim ARM64 OCI gzip layer. It retains SHA-256 verification, checked
paths/types/capacity and guest-only extraction. Hard links use the VFS inode
operation; merged-/usr symlinks remain guest symlinks. Debian's larger archive
bounds apply only to that pinned image; Alpine keeps its existing input bounds.
Mac setup normalizes the new environment's build-container DNS configuration;
existing stores and iPad distribution selection are unchanged.

## Worker pathname metadata (2026-11-02)

The shared process kernel admits `newfstatat`, `fstat`, `statx`, `faccessat`,
`faccessat2` and `readlinkat` on existing CPU workers. The worker uses the same
VFS path resolver, inode metadata, credentials, mount policy and guest-memory
contract as the joined Linux implementation. Eligible calls complete without
an owner RPC or a whole-cohort join. A lone runnable task can retain the ordinary
serial path; worker counts therefore need not equal the workload's total calls.

`PathQueries` retains the original `FsHandle`/inode objects and the actual shared
FD membership. It does not copy the directory tree or cache stat results. Host
lookups still observe host replacement/unlink and virtual queries read live file
metadata. The source root/cwd/mount topology is captured at the existing epoch
boundary: chdir/chroot, mount changes, credentials and remaining namespace mutations still
join before changing this authority. This step does not make these mutations
concurrent with queries or remove their remaining owner dependency.

The query capability builds an exclusively owned control view solely to reuse
the existing resolver. Every Rc/RefCell/Cell in that view is private to the view;
source filesystem, inode, mount resources, host handles and FD membership cross
only as their existing Send+Sync Arc capabilities. The view has a fresh empty
control FD table, so its destruction cannot drain the real process membership.
Its sealed API returns owned bytes/results or numeric FDs and exposes no VFS reference,
Rc or mutable control handle. `unsafe impl Send` moves this complete private
control island between execution workers; the capability is neither Sync nor
Clone. Tests assert Send+Sync on the captured resource types and move the query
capability between real threads. Extending the API or capturing another owner
field requires reviewing this ownership proof. No raw guest pointer/lifetime
rule is changed by this control-view transport.

Directory/O_PATH metadata admission is separate from byte/control admission.
An owner FD slot can publish a weak metadata lease on its actual open description
when its node and mount support it. Lookup accepts that current OFD under the
existing Files membership lock, then releases the lock before resolving/statting.
No numeric-FD snapshot or owner-Rc address cache is used. The lease does not keep
an unlinked file open, move a directory cursor, or make directory I/O worker-local.
Close/reuse and accepted-operation lifetime retain the existing OFD rules.

Potentially dynamic proc/sys/dev endpoints, namespace controls and unsupported
FD kinds defer before guest output. Traversal decides this, including symlink
aliases and dirfd-relative paths; there is no new guest race errno or a textual
admission bypass. An internal deferred marker is consumed by the query wrapper
and never returned as a guest concurrency error. Filtered calls use the existing
entry-decision token: successful queries run once, and a deferred/denied call
returns its exact original entry to the joined kernel without repeating BPF.

Owner and worker path strings use the same bounded page-fragment scan. It keeps
address tagging, EOF, permission and NUL/length behavior, without a byte-at-a-time
translation loop. `statx` obtains both stat fields and mount ID from one accepted
path/FD query, then shares the owner's AArch64 output encoder. The ordinary
memory and native-function concurrency model is unchanged.

The production choice is direct shared resources with their existing object
synchronization. Retaining an owner service would remove peer drain but keep two
request/return handoffs per query. Sending these reads to another existing worker
would retain those handoffs and add resource-owner scheduling without removing
path lookup work. Neither alternative is used; no coordinator/resource thread,
busy-poll mailbox, global VFS call lock or ordinary-memory barrier is added.

Validation covers owner/worker ABI and untouched error buffers, non-UTF-8/page
boundary strings, symlinks and permissions, rename/unlink and live FD reuse,
mount/chroot/readonly rules, directory cursor and last-close lifetime, host
replacement, deferred pseudo paths and one-time seccomp admission. Mac hardware
and iPad interpreter checks share this source. The product's measured comparison
and remaining migration work are maintained in the
[coordinator audit](https://github.com/kb5000/trames-ipad/blob/main/docs/architecture/coordinator-removal.md).

## Worker regular-file opens and publication (2026-11-02)

`openat` and `openat2` now reuse the same resolver and open-description constructor
on the existing execution worker for ordinary plain regular files, including
`O_CREAT`, `O_EXCL`, `O_CLOEXEC` and `O_PATH` on a regular inode. Eligibility is
decided by actual traversal and inode/backing kind, before creation, truncation,
notifications or descriptor publication. Dynamic proc/sys/dev endpoints,
directory cursors, lower-overlay files and other owner controls retain their
joined path. Truncation is deferred before effects because changing an existing
mapped backing still needs its original VM synchronization boundary.

A Files transaction reserves a free numeric slot before opening the resource.
The reservation is absent from visible membership, owns no fake guest descriptor
and releases its number on errors or deferral. Publication installs the complete
Arc-backed OFD and CLOEXEC bit in the real membership under its existing lock.
Filesystem lookup, host I/O, notification delivery and preparation do not hold
that lock. An explicit dup-to collision with an in-progress open returns Linux's
`EBUSY`; close sees an unpublished slot as `EBADF`. Other allocations skip it.
Creation tests cover one winner for `O_EXCL`, ordinary creators reopening the
winning inode, distinct live FD numbers and reservation rollback. Private create
checks insertion atomically under the existing filesystem namespace lock; host
creation uses the native exclusive create and accepts an existing winner for
non-exclusive `O_CREAT`. No deterministic winning thread is imposed.

New OFDs publish immutable, weak prepared-file authority once on the actual OFD,
before making the numeric FD visible. Existing worker captures first use their
unchanged prepared map; a new OFD supplies its own prepared authority without a
shared publication-cache lookup or a fresh path/stat walk on every read/write.
The weak publication token is bound to its original execution epoch; a later
checkpoint must recapture changed backing and policy through normal admission.
Accepted I/O retains the original OFD across close/reuse. The authority does not
retain the OFD, inode or data; last-close and open-unlinked lifetime stay real.
Caller-specific FSETID and file-size-limit policy remain in the accepting capture,
so another thread does not inherit the opener's write policy. New-file growth,
append and other existing file-I/O deferrals can use the original per-caller
owner service even though the FD was absent from the startup mask. This still
has an owner hop, but does not stop peer CPUs to recapture the FD table.

Only completed file-registration metadata uses the cohort's existing epoch
lifetime, via a short registration lock. Actual resource preparation happens
outside that lock. Joined completion merges the same live inode metadata as
before. Open-description IDs use the session's shared relaxed atomic counter;
worker-local copies must not create duplicate flock/OFD owners. Umask and the
record-lock registry are the original shared capabilities. The private resolver
view never exposes or publishes an Rc control, and its dummy FD table stays
empty, so dropping the view cannot close real descriptors. The prior `Send`
proof now covers this sealed open API as well as owned metadata results.

Concurrent preparation no longer recursively borrows the inode while obtaining
its flock capability. Ordinary open does not take an unused inode write lock;
notification delivery uses its existing immutable Marks API. Reverse path lookup
acquires the namespace read guard before the inode guard, matching insertion and
checkpoint lock order. Tests exercise concurrent create, directory stat, close,
FD reuse, distinct OFD lock owners, live umask and once-only seccomp decisions.
No coordinator, resource thread, polling bus or ordinary-memory barrier is added.

This is the second migration stage, not full FD/resource or coordinator removal.
Pipe/socket/accept/event/timer creation, directory mutation, signal/task state,
structural VM changes and native-device registration remain separate stages.

The production systemd check also exposed a joined refresh of an unreached deferred
page: its mutable storage had never been materialized. Refresh now goes through
the same fallible source/private-COW load contract before updating the bytes.
A deterministic regression covers shared physical identity, private isolation and
backing I/O errors. Unchanged, untouched pages remain deferred; no new ordinary
CPU memory check or barrier is introduced.

## Worker anonymous-resource creation (2026-11-02)

`pipe2`, `eventfd2`, `timerfd_create` and `inotify_init1` now create and publish
resources on existing execution workers. `DescriptorFactory` is an ordinary
Send+Sync capability containing only the real SharedFiles membership, the shared
relaxed OFD ID allocator and the caller's captured filesystem UID/GID. It has no
VFS reference, Rc control, namespace projection or new resource-service thread.
Credential and Files-domain changes still use their existing lifecycle boundary.

The owner VFS and worker share the original pipe and anonymous-OFD constructors.
Event counters, timers and inotify retain their existing shared control objects;
pipe endpoints retain the same real reader/writer and last-close accounting.
The factory publishes complete descriptions into actual Files membership rather
than returning fake FDs or registering an additional endpoint for a snapshot.
Existing DirectFds immediately accept the new objects and retain their original
OFD during I/O, poll and blocked waits. Closing/reusing the numeric slot does not
retarget an accepted operation. Timer rearm/disarm notifications, changing wait
deadlines, pipe EOF and inotify notifications use the existing resource signals.
No resource lock becomes a whole-function or global kernel lock.

A pipe reserves both numeric slots under one Files transaction. Guest output is
written before either endpoint is published, without holding the Files lock.
Failure or unwinding drops both reservations and original endpoints. Successful
publication installs both complete OFDs and their CLOEXEC bits under one lock and
updates the normal membership revision once. Another allocator skips reservations;
a peer that sees the output before installation can observe ordinary EBADF, as
with the existing unpublished-open protocol. No deterministic racing winner is
promised. FD-limit and flag errors leave no partial pair. Owner pipe2 uses the
same checked CpuMemory transport and rollback implementation as workers.

Creation syscalls use the existing dedicated seccomp entry-decision path.
Allowed calls complete locally; denied entries retain their exact token for
normal joined signal/tracing/rejection effects. No filter runs twice and no
resource or output is created before permission to execute that entry. The
existing worker FD counter includes completions; no production profiling counter,
ordinary-memory barrier, polling bus or new coordinator is added.

Byte-I/O admission now classifies the syscall number before resolving argument
zero as an FD. Creation, pathname, clock and other non-I/O calls skip that unused
shared-table lookup. Actual I/O still accepts the original OFD under the existing
membership lock and releases that lock before resource handling.

Validation covers existing-view visibility, actual pipe UID/GID, flags, failed
copyout and unwind rollback, FD limits, concurrent unique slot/OFD allocation,
owner/worker ABI and error ordering, once-only filtered/unfiltered creation, and
blocked reads on all four resource kinds after close/reuse. The same source is
built with Mac's hardware executor and iPad's interpreter. Fixed-work measurements
and native references live in the product's coordinator audit.

This does not migrate epoll creation/watch ownership, signalfd/task masks,
socket/connect/accept/SCM_RIGHTS publication, inotify add-watch pathname control,
signal-producing pipe operations, structural VM changes or native-device
registration. Their existing owner/synchronization boundaries remain explicit.

### Live TCP publication and short socket services (2026-11-02)

Unfiltered Internet `socket`, `bind`, `listen`, address/option queries and updates,
`shutdown`, and nonblocking `connect`/`accept` use the existing single-caller owner
service. Only the caller releases its execution slot; peer CPUs and their memory
views continue. The original namespace, hybrid routing and connection state stay
on their owner. No Rc/RefCell graph is sent to workers, and no resource thread,
polling bus or second network-policy implementation is introduced. This removes
cohort drains, **not** the owner hop for control operations.

The shared OFD publishes a weak connected-TCP capability under its own mutex.
Actual Files membership carries a socket-only weak projection of that OFD.
Existing worker captures consult live membership, so connections established or
accepted during an epoch immediately support the existing direct TCP byte path.
Accepted lookup retains the actual transport while holding the existing Files
lock; stored publications and overlap captures remain weak and do not delay FIN.
Metadata admission remains separate. In particular, unrelated owner resources
such as io_uring retain their exclusive-construction contract.

Socket creation and accept reserve an FD using the same Files allocator as CPU
worker resource creation. Accept validates the destination first, copies the
address before publishing its complete descriptor, and releases the reservation
and accepted endpoint if copyout fails. Every admitted result is final, including
EAGAIN and EINPROGRESS; fallback is allowed only before effects. The common Linux
ABI accepts the caller's CpuMemory view and retains the original buffer checks.

Blocking connect/accept retain their joined wait/restart path. AF_UNIX/SCM_RIGHTS,
netlink, namespace/routing/firewall mutation, socket close/replacement, and
seccomp-filtered socket controls retain their prior boundaries. Seccomp decisions
and denied-entry effects are unchanged. Pending TCP I/O's existing close/join
contract is preserved; this stage does not claim arbitrary cross-epoch FD reuse
for an unfinished numeric-FD TCP request. Connection/options updates publish only
that OFD; namespace authority is refreshed at the original joined boundary.

### Idle TCP close and live Files identity (2026-11-02)

Unfiltered close of native TCP in its original Idle state can use the existing
single-caller owner service. Hybrid sockets must have no peer, listener or guest
stack branch. The owner still performs admission and the original VFS close;
no new endpoint/control projection crosses threads. Connected, connecting,
failed, listening, virtual and non-TCP sockets retain their joined close path.
The worker's candidate check recognizes actual socket membership, so unrelated
owner resources keep their original checkpoint behavior. Shared-file close
continues on its existing worker path. Seccomp admission remains unchanged.

NetworkEpoch now keys captures by the actual Files membership allocation rather
than its descriptor-content version. Forks may retain an equal content version
while owning independently mutable tables: attaching a live membership query to
the old content key could bind a child's new FD to its parent's table. Captures
retain the actual membership allocation, preventing address reuse within an
epoch; CLONE_FILES tasks continue to reuse the one correct capture.

FdFlags also resolves new socket flags through the socket-only weak OFD
projection already published in membership. This exposes only the original
atomic status/cloexec words, not native controls or namespace state. New sockets,
aliases and reused numbers therefore work in existing worker snapshots. The
ordinary shared-file branch keeps its borrowed flag access and gains no extra
reference-count increment. No additional memory ordering or global lock is used.

### Direct native TCP controls (2026-11-02)

Unfiltered getsockname/getpeername, TCP_NODELAY set/get and immutable TCP
SO_TYPE/SO_DOMAIN/SO_PROTOCOL queries now execute on the guest's current worker.
They operate on the original host endpoint, using the same Linux address/option
ABI helpers and native option methods as the owner. Unsupported/stateful options,
SO_ERROR/connection completion and seccomp-filtered controls keep their original
owner path. The new dispatch arm applies only to those four socket syscall
numbers; unrelated clock, file and futex calls gain no extra control admission.

The shared OFD optionally publishes a SocketControl for native TCP. Its weak
native projection contains no Rc, namespace graph, DNS service or route authority.
Snapshot publication does not retain the endpoint. An executing operation takes
this socket's read gate and an actual transport lease before accessing memory or
host controls. The existing worker TCP byte path does not acquire this gate.
Files membership is released before waiting for the gate or copying guest bytes;
no Files-to-object/object-to-Files lock cycle is introduced.

Owner control transitions take that same socket's write gate, including the
normal network ABI and io_uring bind/connect on retained descriptors. The original
OFD is retained for this synchronous operation and refreshed afterward, regardless
of whether its numeric slot was closed/reused. This preserves other aliases and
cannot publish an old object's control into a replacement FD. TCP control replay
uses the actual shared hybrid option list: TCP_NODELAY host update and saved-option
replacement synchronize that socket's two-field invariant. Guest/native routing
transitions then replay the same saved options. No global network lock is added.

Native projection is absent for guest-stack branches, UDP and DNS transport. A
control transition retires it as needed; explicit owner sendto/sendmsg also takes
the gate because a DNS destination can lazily create that transport even without
connect. Ordinary direct byte I/O remains unchanged. Errors after admission are
final results; fallback occurs before memory or native effects. Copyout preflight
and SO_ERROR consumption ordering are shared with the existing owner ABI.

Regression coverage includes original-endpoint agreement, weak snapshot/final-close
lifetime, aliases and FD reuse, object-gate ordering while Files and other sockets
continue, actual guest-option replay, virtual/DNS exclusions, owner/worker output
and fault ordering, filtered allow/deny entries evaluating once on the owner,
and two CPUs doing controls without any service requests or cohort checkpoints.
The implementation uses safe Rust and shared resource objects; no new thread,
message bus, busy loop or guest-memory ordering rule is introduced.

### Quiescent connected TCP close (2026-11-02)

The existing single-caller close service now accepts connected native TCP when
no worker transport lease is outstanding. Pure connection/DNS/firewall metadata
admission is factored from the existing native byte capability; the close check
performs no host address query or transport I/O under Files. Admission and FD
removal occur in the same Files transaction. Worker TCP lookup takes its actual
endpoint lease under that membership lock, so a new operation cannot enter
between the quiescence check and removal. Native control operations remain
excluded by the existing per-socket writer gate. Resource teardown, record-lock
release and mount cleanup occur after the membership transaction.

TCP byte entry now resolves one actual transport for its complete attempt,
readiness registration, nonblocking/deadline decisions and same-cohort retries.
Completion accounting also uses that accepted transport, without re-resolving a
possibly reused numeric FD. Stored snapshots stay weak; ready attempts allocate
no new wait object. Blocking requests use the existing host event subscription
and give up their execution slot. No polling loop or new resource thread is used.

A passive TcpLease also survives PendingIo -> IoCall -> Process -> queued-job
handoffs. A task awaiting re-admission still prevents a quiescent fast close.
That token exposes no byte/namespace policy authority: the new cohort resolves
its current FD and policy normally, and unsupported re-admission checkpoints
before effects. Completion, cancellation, signals and exit release it. Joined
policy/signal behavior is preserved; this stage does not export a stale native
TCP data capability across such transitions.

Busy connections, virtual/DNS transports, listeners, connecting/failed sockets,
rule-bearing native transports and filtered controls retain their old boundaries.
Idle close continues through the same conditional owner path. Neither socket
creation nor close itself is moved to a worker in this stage: it removes the
remaining unnecessary cohort drains for quiescent connected close, while the
owner still tears down its Rc control projection. There is no new guest quota,
race errno, global lock or stronger guest-memory ordering.

## Shared native TCP connection state and controls (2026-11-02)

The original host transport now owns connection progress, pending errors and the
blocking-connect failure marker. Owner and worker calls use that same state;
there is no worker connection-state copy to reconcile. One relaxed atomic word
contains the connection state, failure cause and consumable error bit. Concurrent
SO_ERROR readers consume the pending error once. An object-local completion lock
covers the readiness/error sampling and connection transition; ordinary TCP byte
operations acquire neither it nor the keepalive-parameter lock.

Unfiltered native TCP SO_ERROR can complete a connection on its executing worker.
Completion uses the original helper, with the namespace policy callback retained
on owner-only paths. Captures with live firewall rules do not admit worker
completion; DNS, virtual and guest-routed branches retain their previous authority.
Filtered network controls keep the existing owner entry. There is no new guest
policy, race errno, resource-service thread or polling bus.

Worker controls also cover SO_KEEPALIVE, SO_REUSEADDR, socket buffers,
SO_ACCEPTCONN, TCP keepalive parameters, relevant IPv4/IPv6 options and shutdown,
in addition to the earlier address/TCP_NODELAY/identity controls. Shared host
option helpers preserve the serial implementation and hybrid branch option replay.
The keepalive helper's host enable/restore sequence synchronizes only setters of
that same socket's keepalive state. Guest timeout setters remain owner-side.

A successful worker completion publishes weak native byte authority on the
original OFD, using its live flags and original timeout capture. Existing workers
and FD aliases can immediately use it. Files membership is released before
control, host calls and guest copyout; no numeric-FD relookup publishes onto a
replacement descriptor. The existing socket gate excludes owner transitions, and
weak captures do not extend endpoint lifetime or delay FIN. Failed connections
publish no byte capability. Address and option copyout still use the common Linux
ABI preflight, including not consuming an error on an invalid destination.

This stage migrates state/control ownership, not socket factory and full teardown
ownership. Socket creation, bind/connect/listen/accept, owner projections, broader
close, AF_UNIX/SCM_RIGHTS and epoll registration remain follow-up work. Short
admitted calls keep their existing single-caller owner service; their existence
must not be counted as a whole-cohort pause.

## Live epoll interests and worker inotify registration (2026-11-02)

Admitted epoll interests now belong to the original object's shared live index.
ADD/MOD/DEL and waits use that same index, watch state and delivery cursor. The
index publishes immutable Arc vectors; updates reuse their allocation when no
reader retains a version. There is no per-wait vector allocation in the normal
shared-only case. ET, ONESHOT rearm, duplicate-FD keys and cursor rotation retain
their original per-object synchronization. Removed interests disarm outstanding
read snapshots, and resource destructors/notifications run after index locks.

The key remains (numeric FD, original OFD ID); stored interests do not retain a
watched OFD. Closing/reusing a number does not retarget a watch, and a surviving
alias preserves the original interest. Poll admission of an epoll core is separate
from descriptor transfer/dup/close authority: it does not turn an owner projection
into a transferable shared descriptor. Owner-only interests retain their original
Rc/weak targets in the owner projection, not in the Send+Sync core. The original
combined watch bound is preserved, including reclamation after last close.

Worker epoll control handles retained shared byte/poll resources, including pipes,
eventfds, timerfds, inotify and admitted Unix/PTY resources. Allowed seccomp entries
use one decision; denied or unsupported calls carry the existing entry token to
the owner without effects or a second BPF evaluation. Nested epoll, task-signal
sources and unsupported/native-TCP poll interests retain owner authority. Admitted
interest changes no longer invalidate global descriptor snapshots; only changes
to owner-only captures keep that boundary. Blocking waits resubscribe when the
same object's control revision changes, using existing run-queue notifications.

Epoll creation now uses the existing single-caller owner service, publishing the
actual descriptor to already-running workers. It no longer needs a whole-cohort
join. Factory and epoll close/dup ownership themselves remain owner-side. This
stage does not introduce a resource thread, message bus or polling loop.

Inotify add-watch runs through the existing sealed PathQueries resolver and the
actual Arc-backed instance/inode marks. Its API returns only an owned result;
query-private Rc state never escapes. Host-directory registration uses the same
native attachment/rollback code as the owner. Existing subscriptions can acquire
or retire a native event source through HostSource: resource topology changes
notify their existing listeners, and those tasks refresh registrations on the
existing host poller. Ordinary subscriptions keep their static representation;
dynamic state is boxed only for resources that need it. Host-source notifications
and cancelled registrations are released outside resource/publication locks.

Tests cover live ADD/MOD/DEL through an old view, original aliases and FD reuse,
concurrent ADD/one-shot delivery, mixed owner/shared limits and fair delivery,
parked-wait resubscription, first host-watch attachment to an already-subscribed
read or epoll, guest ABI layout/fault ordering, single seccomp decisions and
owner-only fallback. Native ARM64 Linux tests additionally exercise its distinct
inotify/epoll host backend. Guest CPU, memory permissions and ordering models are
unchanged; there is no new guest quota, race errno or guest-memory barrier.

Remaining work includes socket factory/full teardown, connection/accept and
namespace-dependent controls, native TCP/signal/nested epoll interests, task and
signal ownership, and scoped structural VM/device registration. The shared live
index is not a claim that all epoll or coordinator paths have been removed.

## Connected TCP poll/epoll ownership (2026-11-02)

Connected native TCP now exports a poll-only capability containing one weak
endpoint pointer. It has no byte, DNS, routing or namespace-control authority.
DirectFds resolves new requests through actual Files membership and the existing
TCP publication; frozen watches retain the original weak OFD identity. Byte
admission and policy checks are unchanged. Once connected, a native TCP socket
cannot switch to a guest route or a DNS endpoint. Later packet-filter changes
therefore do not invalidate its transport-only readiness. Pending connections,
DNS/virtual sockets, nested epoll and signal interests retain their owner paths.

TCP interests installed before connect completes move into the actual live epoll
index at execution-capture boundaries. The existing watch state and cursor move
with them: consumed ONESHOT interests stay disarmed and ET history is preserved.
Worker ADD/MOD/DEL, shared/owner waiters and subsequent captures then use the same
index. This is not a shadow registration or a global FD-table rebuild per ctl.

Poll and epoll subscribe through the existing executor's host poller to duplicates
of the original persistent edge-observer queue. They do not duplicate the watched
socket or retain Endpoint. Thus a blocked poll, a watch or a stale snapshot cannot
delay FIN, endpoint destruction or quota return. Persistent read/write edges wake
the queue; the original poll and epoch sampler drain it and test requested guest
bits. An unrequested writable level does not repeatedly wake a readable-only
waiter. Native-only IoSubscription stores no synthetic Readiness object and takes
no global listener lock. Its optional resource reference uses the existing field
space; the one-pointer TCP token also leaves the ordinary DirectFd footprint
unchanged. Host registration failures retain the original checkpoint fallback.

Tests cover queued edges, no spurious writable-level wake, true blocked ppoll and
epoll completion, registration before connect, promotion of consumed ONESHOT,
concurrent single delivery, original aliases, FD reuse and final close while a
poll subscription still exists. Both Apple kqueue and Linux epoll host observers
are exercised. The guest CPU/memory model, resource limits and ordinary TCP byte
path are unchanged; there is no new service thread, bus or polling loop.

Socket factory/full OFD teardown, bind/connect/listen/accept ownership, AF_UNIX
control/SCM_RIGHTS, task/signal ownership and scoped structural VM/device changes
still need migration. Connected TCP readiness is one completed part of that work,
not completion of the coordinator-removal objective.

## Shared native network lifetime and socket reservations (2026-11-02)

The native transport namespace is now an Arc-owned, Send+Sync resource by
composition. Its immutable mode, original host-socket quota, DNS service and
atomic link counters have one authority. The existing timed interface cache
uses its own mutex. This is not the complete Linux network namespace: topology,
netlink/virtual stacks, routing and owner socket projections still need migration.

Native socket construction separates the actual prepared endpoint from its
owner projection. PreparedSocket owns the one host descriptor, its original
quota reservation and creating native namespace. It can be constructed and
cancelled on a worker; attaching owner controls reuses that same endpoint and
quota. The production guest socket syscall still uses its existing owner route.
No worker socket opcode or complete shared OFD publication is claimed here.

The Linux namespace's existing aggregate socket bound now also uses a shared
reservation, acquired before socket creation or accept. Failure/cancellation
returns the slot; successful construction transfers it into the actual Socket.
Final teardown releases it after the backend and namespace projection, without
calling back into Rc state. Native transport and aggregate guest counts retain
their distinct original scopes and limits, using the same reservation primitive.
Metadata counters use relaxed atomics; they do not publish guest memory.

The native DNS service and endpoints likewise use actual Arc/Weak ownership.
Only this namespace's resolver table/receiver and each endpoint's queues are
synchronized. Pending-plus-reply capacity is reserved atomically under the
endpoint queue lock; malformed/local replies and host results convert that same
reservation into a reply. Resolver backpressure rolls it back. Outstanding
requests keep weak endpoints, so they cannot prolong socket lifetime.

Stream input/framing has its own per-endpoint transaction. It may call the
resolver and complete a reply without recursively borrowing the input buffer.
The lock order is input -> resolver -> endpoint state; no state guard calls the
resolver or takes input. UDP does not take the stream-input lock. Completion
updates the existing readiness epoch with a relaxed atomic under the queue
boundary. Buffered frames survive backpressure and half-close; concurrent writers
and readers cannot duplicate frames or overrun the original eight-entry bound.
Submitting a complete frame now borrows the owned input slice instead of making
an intermediate packet copy. Ordinary native TCP bytes/poll never take these DNS
or interface-cache locks. Existing bounded host resolver workers are unchanged;
no new service thread, bus, polling loop or guest-memory synchronization is added.

Tests exercise parallel real endpoint construction/cancellation at the existing
bound, exact endpoint/creating-namespace identity across projection attachment,
last native namespace release on a worker, aggregate socket quota rollback and
worker release, and accept-at-capacity preserving the queued host connection.
DNS coverage includes simultaneous datagrams, concurrent framed stream writes
with partial reads, shared asynchronous resolver results, dead weak requests,
backpressure rollback and half-close retry. Mac/iPad share this implementation.
Remaining work is complete Linux namespace/policy ownership, shared socket OFD
publication and production factory/control/accept routing, plus Unix/task/VM
ownership. These prerequisites do not themselves remove more cohort joins or
establish an application performance gain.

## Shared routing, filtering and connection tracking (2026-11-02)

The actual topology and View now use Arc/RwLock ownership. Spaces retain the
same Arc rule and connection-state objects, with no owner Rc/RefCell graph in
these resources. Loopback is one shared relaxed atomic flag used by both topology
and its packet-stack view. The complete Linux namespace, virtual fabric/socket
projections and production guest socket factory remain owner-side.

Topology readers coexist; only structural changes acquire its writer. Packet
tracking synchronizes the original mutable NAT/flow invariants per namespace,
never a global networking lock. A route releases one namespace's conntrack guard
before entering another namespace or bridge. Packet lock order is topology read,
namespace conntrack, then ruleset read. Rule/ctnetlink handlers capture their
resource under topology read and release topology before taking the object
transaction lock. Native interface queries also finish before topology access.
Nested topology read acquisitions in route selection were removed, so a waiting
writer cannot deadlock a reader trying to re-enter a writer-preferring RwLock.

Native refresh first compares current metadata under a reader. The unchanged
path allocates no address vector and never obtains a topology writer. Changed
metadata is rechecked/published under the original writer transaction. Existing
mode, route and interface-comparison semantics are preserved. Packet accounting
also needs no writer: each stored link owns its actual relaxed atomic counters;
Device remains an owned public reporting snapshot. Cross-namespace link moves
carry the same counter resource. These statistics do not publish packet or guest
bytes, and they do not add ordinary guest-memory barriers.

nf_tables batches hold the original ruleset's writer from cloning through
validation, output-capacity preflight and publication. Concurrent batches cannot
both clone an old generation and silently overwrite a successful commit. Dumps
clone under a reader and format privately. Existing counters use relaxed atomic
RMWs, preserving wrapping totals under packet readers. Batch publication excludes
those readers while copying counters, so it does not discard intervening packet
counts. Redirect previews still use private rule/conntrack copies and have no
live counter, NAT or flow effects.

ctnetlink's original staged mutation similarly holds its namespace state mutex
through output preflight and commit. A concurrent delete cannot restore another
delete's records or erase new packet state by publishing an obsolete clone.
The production owner handlers and shared-resource tests invoke the same protocol
transaction helpers; there is no alternate parser, shadow authority, new errno,
quota, resource-service thread, message bus or polling loop.

Concurrency tests cover independent namespace progress while another namespace's
state is locked, simultaneous topology readers, exact packet/drop counts with no
writer, link-move counter continuity, unchanged native refresh under a held
reader, concurrent batch generations, counters surviving live rule publication,
and concurrent flow deletion/insertion. Original routing, bridge/NAT/firewall,
netlink, rollback and permission coverage is retained on Apple and ARM64 Linux.
These changes remove ownership and per-packet writer dependencies, not production
socket dispatch. Namespace/fabric lifetime, full shared socket OFDs, factory and
bind/connect/listen/accept dispatch still need migration, alongside Unix/task/VM
work. No whole-app performance gain is inferred from the resource tests.


## Shared complete sockets and worker creation (2026-11-02)

The complete Network, Socket and virtual Fabric graphs now satisfy Send + Sync
by composition. Native, hybrid, netlink and packet-stack handles use Arc; scalar
metadata uses relaxed atomics and compound state synchronizes on its actual
object. No unsafe Send/Sync override wraps an owner Rc graph. Mac and iPad use
the same implementation; ordinary native TCP bytes retain the existing direct
weak-endpoint path, without the fabric, topology or socket control gate.

Socket control transitions use one socket-owned writer, while normal socket I/O
can share its reader. Legitimate nested immutable metadata reads use recursive
read admission so a queued writer cannot deadlock the same thread's second read.
The old independent VFS control-publication lock is removed. VFS now keeps only
a weak full-socket control reference, admitted under the socket's own gate.

The virtual packet stack still owns one mutable fabric transaction. Lock order
is fabric then socket metadata. Binding reserves/checks/publishes namespace ports
under one binding transaction; automatic binding and lazy native/guest/DNS branch
initialization recheck their actual state under their initialization lock. The
existing socket and namespace limits use atomic RAII reservations before effects,
with rollback on errors and release by the real final owner. Namespace topology
admission and insertion share the same topology writer. Initial root-stack
creation uses a cold per-namespace initialization gate and OnceLock publication.

Packet observers retain only metadata, not Socket or Namespace close authority.
The real controls own teardown. Thus an observer upgraded by a tick cannot become
the final close callback while the fabric is locked and recursively acquire that
lock. Observer metadata carries no such destructor. Netlink listener registries
likewise upgrade under the registry lock but release it before enqueue/callbacks
or final owner destruction. Reply and port registries retain their object locks;
read epochs and namespace counts use relaxed atomic RMWs.

Actual Arc<Socket> ownership moves into SharedOpenDescription. Files duplication,
close and replacement can therefore retain/drop the complete network OFD on the
executing worker, outside Files membership. Epoll and io_uring distinguish shared
ownership from direct byte/poll eligibility: pre-connect, UDP and virtual targets
keep the existing fallback until admitted. Epoll watches stay weak and preserve
edge/oneshot state; accepted native io_uring I/O retains a real transport lease.
Capturing or polling a socket does not itself extend its last-close lifetime.

Owner/service syscall admission retains one complete original socket OFD too.
Service eligibility reads that OFD's live flags; bind/connect/accept, address
copyout and TCP publication then use the same accepted object. A worker may
close and reuse its old numeric FD without retargeting an in-progress operation.
Accept never repeats the original numeric lookup after output preflight. The
old OFD owns publication even if its number now names another socket or file.
A deterministic regression closes/reuses a listener FD on a worker, connects to
the retained original listener, and accepts from that listener while the new
listener remains untouched.

DescriptorFactory captures the creating Network and guest credentials. The
production worker handles syscall 198 (IP and netlink socket creation) through
the original permission/flag/error ordering and actual Files reservations.
AF_UNIX defers before effects. seccomp decisions are evaluated exactly once;
unsupported, traced and mutable-authority operations retain their existing joined
fallback. This adds no coordinator/resource thread, message bus, spin loop, new
quota, guest-race errno or ordinary guest-memory barrier.

Regression coverage includes complete auto-trait checks, concurrent exact socket
admission, competing binds, parallel UDP transfers on one fabric, observer-only
last release under the fabric guard, creating authority surviving setns, real
worker close, original epoll/io_uring lifetimes, two-CPU socket creation/close
loops with zero service requests, and allow/deny seccomp loops with one decision
per syscall. Apple and ARM64 Linux affected tests and strict checks pass. The
remaining network dispatch includes bind/connect/listen/accept and blocking or
policy-aware byte operations; AF_UNIX/SCM_RIGHTS, task and VM dependencies remain.
No whole-application performance claim follows from this migration alone.


## Worker full socket controls (2026-11-02)

Production worker captures now use the actual shared socket OFD and the creating
credential/Files factory for short control calls. bind/listen, nonblocking TCP
connect/accept/accept4, getsockname/getpeername, setsockopt/getsockopt and shutdown
run on the executing worker. Blocking UDP and netlink connect also complete
there because they cannot wait for a TCP handshake. Blocking TCP connect/accept
still defer before effects to their original scheduler path; their retained
cross-cohort wait lifetime is the next migration, not claimed complete here.
AF_UNIX owner resources and traced operations retain their existing fallback.

Owner and worker paths invoke one original control ABI implementation. It keeps
copyin/copyout validation and error order, namespace/low-port authority, socket
flags, existing limits and timeout semantics. Filtered captures evaluate their
exact entry once; successful calls complete on the worker and rejected/deferred
entries keep the same decision through the joined fallback. Native-only explicit
captures retain compatibility with the previous limited controls; production
captures carry DescriptorFactory and use the full socket ABI.

The common ABI preflights peer output before any accept effect. The factory then
reserves in the actual Files domain, consumes the connection, writes peer output,
constructs the complete original OFD, and prepares its native TCP view before
publishing its number. No follow-up lookup by the new
number can race another worker's close/reuse. Failed output or construction
returns the existing reservations and real socket. No Files lock covers host
accept, guest output or another resource callback.

Control mutations and their resulting byte-capability/timeouts view form one
transaction under the existing per-OFD TCP admission/publication mutex. The
mutation callback never enters Files membership. Lock order is Files admission,
then publication, then the socket's backend operation gate. Queries/shutdown do
not republish an unchanged view; SO_ERROR completion and relevant mutations do.
accept uses separate unpublished output ownership and never holds its listener's
publication lock while reserving Files. Legacy native completion, owner refresh
and capture follow the same publication-before-operation order. Normal native
TCP bytes keep their original path; no extra service thread, bus, loop, guest
quota, metadata fence or global network lock is introduced.

Coverage exercises native and virtual full connections, output rejection before
accept consumes a connection, pre-visible TCP capability publication, captured
low-port permissions, immediate UDP/netlink connect, and blocking TCP deferral
without effects. A concurrent test holds the admission transaction and proves a
control cannot mutate the socket before publication ownership, while unrelated
Files operations continue. Two interpreter CPUs exercise all ten short control
numbers with native/virtual networking and allow/deny/unfiltered policies: sixty
cases, zero service requests for allowed calls and one seccomp decision per
filtered syscall. Original VFS/ABI/epoll/io_uring regressions remain applicable.

## Retained blocking socket controls (2026-11-02)

Blocking TCP connect/accept/accept4 now execute on the calling worker. A blocked
operation keeps its original socket OFD, creating Files/credentials, entry ABI,
absolute timeout and handshake phase. Numeric close/reuse, a later cohort or an
owner fallback cannot retarget it. Connect resumes the already-started handshake;
it never repeats connect or reads a changed peer-address buffer. Accept keeps the
original output preflight, reservations and pre-visible TCP publication.

Workers subscribe to the endpoint's existing edge queue and the packet stack's
existing transport/timer sources, drain stale edges before the deciding retry,
then park the virtual task and release its execution slot. Existing workers
dispatch those events; no dedicated reactor, service thread or polling bus is
added. Fabric deadlines retain the current stack's timer semantics. A missing
host event registry hands the accepted operation to the existing joined executor
without replaying effects. Related full-socket waits remain eligible across
cohorts, including when all related tasks are parked and no GUI service exists.

The accepted syscall keeps its original seccomp decision across parking and
fallback. A subsequent SVC evaluates the current filter normally. Stop retains
the operation; caught signals, exit and exec release it, using the existing
restart and timed-socket interruption rules. Ordinary guest memory and native
byte I/O are unchanged. Coverage includes a single execution worker, all-blocked
cohorts, native event idleness, virtual handshake recovery/timeout, original Files
after close/reuse, filtering and signal cleanup. AF_UNIX/SCM_RIGHTS, task/signal
authority and structural VM/device ownership remain separate migration work.

## Worker Unix ancillary messages (2026-11-02)

Paired Unix stream, datagram and seqpacket sendmsg/recvmsg use one original
ancillary ABI on the executing worker. Portable messages own the actual shared
OFDs in their packet; they no longer refer to an owner-only rights ledger. Files,
pipes, event/timer/inotify objects and network sockets keep their real identity,
offsets, flags and close behavior. Descriptor admission and import use the actual
Files membership and its existing limit. Owner-only objects defer before effects;
mixed messages are never partially sent. Existing Unix control/creation, addressed
datagrams, ownership-cycle policy and native service pumping remain joined.

The message imports its header, iovecs, credentials and source descriptors once.
An accepted wait retains those references and the creating Files/authority;
close/reuse or changed guest headers cannot change the message on retry. Receive
rechecks the original output ranges after a possible VM transaction before
consuming a packet. Ready calls need no retained-message allocation, and messages
without rights avoid Files locking. Metadata is captured under the existing
channel lock rather than re-locking the channel for each option.

Blocked messages release their execution slot and reuse the existing resource
subscriptions. Their typed shared state contains no Rc/RefCell. Unix control
objects remain owner projections: on a cohort handoff, the joined executor retains
the original local OFD before any returned owner mutation executes. That owner
lease stays outside worker state and is released on completion, signal or exit.
Fallback uses the accepted message and original transport, not a fresh numeric
lookup or another header import. Filtered entries keep one decision across this
handoff; subsequent SVCs evaluate the current filter normally.

Peek, truncation, CMSG_CLOEXEC, credentials, timestamps and no-rights byte behavior
retain the common ABI. Payload/descriptor references are released outside channel
and Files locks, including truncation and receiver close, so final-close callbacks
cannot invert the resource/run-queue lock order. No new thread, bus, unsafe trait
override, guest-memory barrier, resource quota or global network lock is added.

## Worker directories and portable memfd ownership (2026-11-02)

Static directory OFDs now use the same complete shared ownership as ordinary
files. Their actual `FilePosition` owns the enumeration cookie: owner/worker
`getdents64`, `lseek`, dup/fork, fdinfo and Unix rights all observe that one cursor.
Private and host enumeration use the original resolver and one common encoder;
only encoding and cursor commit hold the OFD position lock. Namespace lookup,
resource destruction and guest-memory writes remain outside that lock.

The existing sealed `PathQueries` control island can open static directories,
read their entries and seek them on the executing worker. It accepts the original
FD before output preflight, so another worker's close/reuse cannot redirect that
accepted operation. Dynamic pseudo directories and excluded mounts defer before
cursor effects. Regular-file seek retains its existing byte capability and
pending-operation policy. O_PATH enumeration returns EBADF on both paths.
Directory traversal retains the actual mount identity and one counted directory
lease per OFD. Lazy-unmounted subtrees retain their existing topology while these
leases are live; aliases and rights retain the same lease, and last-close or the
next owner mount cleanup can retire it. No directory contents/cursor authority is
mirrored in a worker cache, and no resource-service thread is introduced.

Memfd OFDs also use complete shared ownership. Portable Unix rights therefore
retain the original content, offset, seals and backing after sender FD close or
reuse. This grants no new direct byte or VM access: FileEpoch still rejects
sealed/shared storage, and mapping, truncation and seals keep their original
joined implementation. io_uring uses the same unpublished backing constructor,
but publishes an owner OFD from the start because its ring controls are still Rc
objects; a published shared OFD is never demoted or given hidden owner controls.

Object sharing avoids normal directory lifecycle/enumeration cohort joins. A
worker message/RPC alternative would add communication to the same operations,
and the old coordinator would still stop unrelated CPUs; neither is used.
Full Unix creation/listener/connection controls still own Rc graphs that can
retain PTYs, signalfds, namespace and ring rights. These, directory mutations,
task/signal/namespace transitions and structural VM/device operations remain
separate migration work. This stage is progress, not complete coordinator removal.

## Shared descriptor controls and worker signalfd (2026-11-03)

Signalfd masks and verified BPF programs are now complete shared OFD controls.
The signal mask is one relaxed atomic u64; descriptor aliases, fdinfo and
ancillary transfers observe the original mask, while CLOEXEC stays per FD.
Signalfd creation and mask updates use the original shared Files factory on the
executing worker. Owner and worker decode the same size/memory ABI, sanitize
SIGKILL/SIGSTOP identically, and preserve the original flags/error ordering.
Existing owner-only wrong-type FDs defer before resource effects.

Sharing a signalfd never captures its creator's pending signals. Reads and
signal-dependent poll/epoll still use the current reading task through the
original joined kernel path. These controls grant no generic direct byte/poll
capability. BPF verification, loading, attachment and execution policy are
unchanged; shared descriptors retain the same immutable program, weak registry
identity and quota until its last actual reference, including worker last-close.

UTS, PID, IPC and cgroup namespace OFDs can also retain their actual shared
namespace resource through Unix rights and worker descriptor lifecycle calls.
IPC/cgroup namespace identities, weak snapshots and quota leases now use Arc;
quota reservation/release is atomic and rolls back an identity allocation
failure. IPC mqueue filesystem association is initialized once, so all users
retain one original filesystem. Setns/unshare still use the original owner task
and permission/type checks. Network/mount namespace control graphs and nsfs
mount topology stay excluded from complete shared ownership.

Proc namespace reopen constructs the complete resource before publication,
retaining namespace capability in a fresh OFD. Namespace mount association is
also supplied before ownership classification; changing a temporary shared
projection cannot silently drop that association. Bound nsfs descriptions keep
the original owner mount pin until topology itself is shared.

No coordinator/resource thread, owner RPC, polling bus, global task lock or
ordinary guest-memory barrier is added. The original coordinator would still
join unrelated CPUs for these lifecycle/control operations; worker messages would
add a hop to the same objects. Direct shared ownership is used instead. Full
Unix control ownership, owner-only PTY/ring/task/namespace graphs, task signal
queues, directory mutation and structural VM/device transitions remain pending.

### Concurrent directory namespace snapshots (2026-11-03)

A cold directory benchmark exposed a recursive namespace read in getdents64:
while holding the filesystem read guard, parent/mount resolution could acquire
that same read lock. A queued namespace writer could then block the recursive
reader behind itself, while waiting for the first read guard to leave. Live
thread stacks showed directory readers in mount root/parent resolution and
creators waiting in insert_entry on the same filesystem.

Directory child metadata now comes from a closed helper returning owned values.
The namespace guard does not escape, and the caller resolves parent/mount paths
outside that scope. Encoding/cursor commit remain separate. This removes the
recursive lock dependency without adding a lock, check, coordinator hop or guest
memory barrier. A bounded concurrent creation/enumeration regression fails on
the committed unfixed code and completes on the corrected code. Cold concurrent
creation remains part of functional validation; timing comparisons can prepare
contents sequentially to compare identical hot-loop work without concealing the
recorded baseline deadlock.

## Shared PTY ownership and worker controls (2026-11-03)

A PTY's actual open description now owns an `Arc<PtyEnd>`. Its pair retains the
original terminal queues, slave inode and shared devpts mount resources, with no
owner-local `Rc` graph admitted across a worker boundary. The weak pair registry
is shared under its own short object lock; registry enumeration releases that
lock before filesystem, terminal or notification work. Original single-field
lock, resize, signal and hangup states use relaxed atomics. Host signal publication
uses fetch-or and consumption uses swap, preserving concurrent pending bits.

Shared Files operations, dup/close, flags and portable Unix rights operate on the
same original PTY OFD. An accepted byte/control operation retains the complete OFD
through completion or a parked wait, so numeric close/reuse cannot redirect it.
Prepared byte/poll snapshots retain only weak OFD identity and the queue resource;
they do not keep guest endpoints alive. Independently opening a slave creates a
new slave lease; aliases and rights retain the original open. Final master drop
marks it dead, notifies waiters and unlinks only its original devpts slave inode.
Final slave drop updates its real endpoint count and notifies after resource locks
have been released. Shared OFD final close invalidates cached descriptor watches.

TIOCGPTN, TIOCSPTLCK, TIOCGPTLCK, TIOCPKT and TIOCGPKT use one common owner/worker
ABI implementation. A worker accepts the original full OFD before accessing guest
memory; prepared queue capabilities alone grant no endpoint control authority.
Slave requests retain ENOTTY before pointer faults, and failed setters leave state
untouched. Existing terminal attributes/window queries and ordinary foreground
byte I/O continue using the same terminal object and original process authority.
No resource server, message bus, global terminal lock or additional memory barrier
is introduced.

PTY allocation, pathname/open permissions and TIOCGPTPEER still use namespace and
device-cgroup authority on the joined path. Controlling-terminal/session changes,
background job checks requiring signals, host resize/signal routing and master
hangup task effects also retain their joined task boundary. A shared close does
not bypass SIGHUP/SIGCONT delivery or imply that every terminal ioctl is direct.
These are remaining ownership migrations, rather than byte-queue performance
fallbacks. The implementation is common to macOS and the iPad interpreter.

### Joined terminal retries retain the accepted endpoint

Production multi-terminal FFI validation also exercises the single-thread joined
entry. It supplies the same frozen TerminalAccess for ordinary shared PTY waits.
A byte attempt that requires task-level terminal signals returns a retained PTY
checkpoint; worker retry metadata supplies its original syscall arguments without
adding per-read argument storage. Joined terminal handling takes flags and the
endpoint from that accepted OFD, rather than looking up a numeric slot again.
Completion releases the lease; blocked signal/job-control calls keep it. The same
handoff applies when a previously parked PTY operation becomes a task-control
case. A regression closes and reuses both the slave waiting for input and the
master publishing control-C, proving original bytes/signals and final close.

## Worker devpts creation and live device policy (2026-11-03)

Device cgroup attachments now live in their original shared per-group DeviceAccess
objects: immutable parent Arcs and one object lock for that group's actual program
list and attachment flags. Owner attach/detach/query and worker access checks use
these same fields and immutable BPF programs. No copied effective-policy list,
allow/deny cache, whole-cgroup lock or policy service thread is introduced. Cgroup
structure/task membership remains joined; a worker capture retains the actual
current task domain and original credentials for that execution epoch. Attachment
changes remain visible to retained captures through the same objects. Ordinary
inode permission checks use one common Credentials implementation.

TIOCGPTPEER accepts an original full master OFD and reserves a real live Files slot
before permissions, preserving the existing type/flag/lock/FD-limit/permission/device
policy error order. It opens the original slave inode and devpts mount even after
namespace changes; it does not reopen a pathname or resolve its numeric FD again.
Owner and worker use the same factory/constructor. Failed permission and policy
checks release the hidden FD reservation without opening a slave lease. CLOEXEC
stays per FD; status flags and endpoint counts retain their original semantics.

The existing sealed PathQueries resolver can now publish PTY masters and explicit
O_NOCTTY slave opens from real shared devpts mounts. The query view shares the real
PTY registry and device-policy capability, while its Rc namespace/control island
remains exclusively owned. Allocation validates its resource boundary before any
PTY effects. Scheduler ID selection/publication share the existing short registry
lock; a devpts-local number and its node are selected/inserted under one filesystem
write guard. Concurrent creators cannot publish the same number or replace a live
slave node. No registry lock spans a notification callback or normal terminal I/O.

Tests cover eight simultaneous creators retaining unique scheduler IDs, unique local
numbers and the original slave nodes; worker final closes remove those nodes. Other
checks cover live ancestor device deny/detach through an already captured factory,
original credentials, failed FD reservation/permission/policy/quota rollback, locked
slaves, namespace-pinned peers, and explicit task-transition fallback. A filtered
two-task interpreter test runs create/unlock/peer/close on one and two slots, with
zero coordinator services and exactly one filter decision per entry.

Legacy pseudo-devpts allocation still owns its dynamic pseudo-node cache and remains
joined. Non-O_NOCTTY slave pathname opens may acquire a controlling terminal, and
therefore defer before effects. O_PATH/dynamic pseudo controls, task/job-control
ioctls, SIGHUP/SIGCONT and host signal/resize routing retain their original task
boundary. This migration grants no arbitrary device native-memory authority.

## Shared Unix control ownership and worker creation (2026-11-03)

The complete Unix socket resource is an `Arc<LocalResource>` owned by its actual
shared OFD. Its network identity, abstract namespace, pathname routing, address
and credential tuples, listener/pending queue, connection and option state are
shared original objects. The graph contains no owner `Rc` or `RefCell`; ordinary
Rust Send/Sync derivation checks this boundary. Network identities and their quota
leases are consequently shared too, including complete network-namespace OFDs.
Unshare/setns, proc network mutation and mount topology still use the joined path.
Retained factories and sockets keep their original namespace and credentials.

A connected socket has one immutable connection publication. Its binding is
initialized once after peer names, credentials and queue options are ready, with
the unpublished accepted endpoint installed before the client. Ordinary byte and
message I/O reads this canonical binding directly, without acquiring connection
control locks or consulting a duplicated cache. The original preconnect readiness
source is retained by the connected channel; existing subscriptions remain valid
without notification forwarding or a polling/service thread. Resource locks and
structural transition guards are released before notification callbacks.

AF_UNIX socket/socketpair creation uses the common actual Files reservation and
OFD constructors on execution workers. Pair output is checked/written before the
reserved numbers become visible; errors and unwinding release reservations and
endpoint quota. Dup, flags and close operate on these full shared descriptions.
An accepted operation owns its original full OFD across close/numeric reuse;
prepared maps and epoll watches remain weak and do not prolong endpoint lifetime.
Fresh pair publication uses the existing Files revision. Connecting an existing
published socket still invalidates its previous direct-resource eligibility.

Listen, address/peer queries, original Unix options and shutdown use one ABI
decoder on owner and worker execution paths. Calls accept the complete original
OFD before acting. Effective credentials initialize creation/listening identity;
peer credentials are translated through the calling process's PID namespace.
The original option, permission and copyout error order is retained. There is no
additional native permission policy, global socket/VFS lock, message bus or guest
memory barrier. Bind, connect, accept and addressed datagram routing still retain
their joined entry while their namespace/task/wait admission is migrated.

Legacy ancillary payloads containing Unix sockets or other owner-only graphs
remain owner-thread objects. A small owner projection refers to the same socket
core and a shared-with-owner-clones Rc journal; no address/connection state is
copied into that view. Shared packets carry only opaque legacy IDs. Portable
SharedRights deliberately exclude Unix-bearing OFDs until owning-cycle handling
is shared; existing owner graph checks and error behavior remain authoritative.
Non-Unix complete shared rights continue to travel directly with their packets.

A worker's final close closes and notifies the real endpoint immediately. Legacy
queued owner rights are released at the next joined cleanup, never dropped on a
worker. The existing cohort-control check requests that boundary only when a
journal has closed destinations to reap. Reaping removes entries under the owner
borrow, drops them outside it and drains newly closed entries iteratively, keeping
long descriptor chains bounded in stack use. Owner-view/VFS teardown also reaps
after endpoint release. This is an explicit remaining ancillary boundary rather
than a claim that arbitrary owning Unix graphs can already cross workers.

Regressions cover eight concurrent creators across all three Unix kinds, original
network/credentials after unshare, copyout and panic rollback, original accepted
OFD lifetime and weak watch cleanup, preconnect notifications and queue options,
legacy final-close cleanup and existing deep/cyclic ancillary cases. A filtered
two-task test runs 176 creation/control/byte/membership calls plus two final futex
waits on one/two execution slots, with zero coordinator services and exactly one
filter evaluation per entry. The same implementation is built for Mac and iPad.

### Joined raw reads and worker reply handoff

The production systemd boot exposed an older assumption that every shared raw
byte call can finish without legacy ancillary handling. A read/readv of queued
owner metadata now returns a retained Unix byte handoff, then uses the same
original socket and ABI on the joined path. Parked reads retain that actual OFD
through close/reuse and metadata arrival. The owner path can discard legacy
rights without consuming bytes twice or looking up a replacement descriptor.

Prepared message replies likewise transfer the worker's accepted full OFD into
the owner projection. They no longer assume Unix membership stayed unchanged
until reply collection. Socket-control transport admission performs one fget
before choosing Unix or IP, so concurrent numeric reuse cannot redirect a second
lookup. Tests exercise immediate and parked raw read/readv with legacy rights,
replacement eventfds, final peer hangup, and a message handoff whose descriptor
is closed/reused before the owner receives the worker reply.

## Worker Unix namespace controls and connection waits (2026-11-03)

Ordinary pathname and abstract bind/connect, and accept/accept4, now use the
executing worker. Pathname operations use the same sealed PathQueries resolver,
original filesystem/inode objects, credentials and shared pathname routing domain.
Only that actual Arc routing resource is added to the private control island;
returned LocalConnection capabilities cannot reach its Rc/RefCell control state.
Excluded owner paths defer before effects and retain the accepted original full
OFD plus copied address bytes for the original VFS resolver on joined execution.

Binding uses exclusive filesystem insertion. Two concurrent pathname binders
cannot overwrite the winning inode between existence checking and insertion;
losers retain EADDRINUSE and an unbound endpoint. Abstract namespace lookup and
publication use the original namespace object lock. There is no global socket,
VFS or algorithm service lock.

A resolved connection keeps the original client resource and a weak target
listener identity, together with the listener's original readiness source. A
backlog wait cannot prolong the listener's open lifetime or follow a pathname or
abstract-name replacement. Final listener close wakes it and returns the original
connection-refused result. Per-client transition and per-listener queue guards
cover actual structural changes; ordinary byte I/O does not acquire them.
Accepting an item frees backlog capacity and notifies after releasing the queue
lock. Blocking connect/accept park the task and release its execution slot.

Accept selects its peer address and preflights that exact item under the same
listener guard. It preserves the guest ABI's pending-item/preflight/flags/capacity
error order, reserves an actual Files number, removes the chosen item, then drops
the queue guard before callbacks and output. Copyout and unwind cannot publish a
partial FD or retain its reservation. The common original OFD constructor preserves
per-description status flags and per-FD CLOEXEC. Concurrent acceptors publish
distinct FDs, without relooking up a closed/reused listening number.

Unix and IP control waits share retained-call scheduling. Unix waits subscribe to
actual internal resource notifications; IP waits retain their original host wait
sources/timeouts. Merely having a socket control call no longer classifies a wait
as an external host-network event. This distinction is required both for keeping
a single execution slot available and for headless runs without a host event hub.
No timer polling, busy wait, forwarding bus or new service thread is introduced.

Tests exercise eight competing pathname binders, eight concurrent acceptors,
exact peer address/item association, preflight/panic rollback, backlog wakeups,
last-listener close and name replacement, original accepted endpoints after FD
reuse, and copied address bytes across an owner fallback. Filtered/unfiltered
one-slot accept/connect tests use only internal notifications. A filtered two-task
lifecycle covers 192 bind/listen/connect/accept/flags/byte/membership calls plus two
final waits with one filter decision per entry and no coordinator services.
The same implementation is built for Mac and iPad. Addressed unpaired-datagram
I/O, Unix-bearing ancillary owning graphs, native-service adapters and structural
task/mount/VM transitions remain separate ownership migrations.

Worker task identity is applied to DescriptorFactory in either builder order,
without altering its captured effective credentials or adding permission checks.
This keeps forked children from reporting a retained parent PID through socket
creation or SO_PEERCRED on connect/listen. Separate one/two-slot saturated-backlog
tests verify that connect parks until accept releases capacity, with one filter
decision per entry and zero coordinator services.

## Worker addressed Unix datagrams (2026-11-03)

Unpaired AF_UNIX datagrams now use the same actual endpoint queues from the
owner, native interfaces and workers. Source address, sender credentials and
portable shared OFDs travel with their packet; a byte-only datagram no longer
needs an owner ancillary-ledger entry. Unix-bearing owning graphs retain their
original owner ledger, bounded cycle rejection and reclamation path. No Rc graph
is made Send, and passive byte snapshots do not keep a peer endpoint open.

Worker read/write, readv/writev, sendto/recvfrom and sendmsg/recvmsg retain the
accepted full source OFD and import their input/output records once. Vector I/O
keeps the existing one-packet semantics. Send binds one target per accepted call
using the original pathname resolver or abstract network namespace. Its capability
holds a weak peer plus the original queue/notification source: blocked sends
cannot keep the receiver open or follow an unlinked/rebound address. A sender
waiting for capacity subscribes to that destination queue as well as its source;
related-wait admission includes the actual target resource. Receives recheck the
original output ranges before consuming, without rereading changed vector/header
metadata. An owner handoff keeps the original OFD and accepted ABI records.

Filtered entry admits these addressed operations through the existing dedicated
worker path; each syscall has one filter decision. Queue waits release their
execution slot and use internal resource notifications, with subscribe/retry on
the original worker or owner to close the unlock-before-park race. Notifications
and final OFD destruction stay outside queue and name/peer guards. No global
socket/VFS lock, service thread, bus, polling loop, ordinary-memory fence or extra
native permission policy is introduced. Existing paired stream hot paths retain
their original byte/control handling.

Regression coverage includes packet/source/credential association under concurrent
writers, portable rights without ledger entries, late passcred activation, native
default-connected sends, target-space notification, final receiver close, pathname
rebind, sender FD reuse, frozen send bytes and receive vectors, original owner-only
rights fallback, and one/two-slot filtered and unfiltered capacity waits. Batch
sendmmsg/recvmmsg, Unix-bearing ancillary ownership, native-service adapters,
structural VM/task transitions and remaining owner controls are still separate
migration boundaries; this is not a claim that coordination has disappeared.

## Retained Unix batches and paired packet bytes (2026-11-03)

AF_UNIX sendmmsg now runs on workers for stream, datagram and seqpacket endpoints.
The accepted full source OFD owns a per-call progress record. This record holds only
completed count, the current accepted message and its resolved target; later headers
are imported lazily using the original sendmsg decoder. Each addressed item gets its
own canonical weak destination/notification capability. A waiting item keeps its
copied bytes, rights, input records and original target, while a subsequent unaccepted
item can legitimately observe a newer pathname binding or guest header.

Errors after prior successes return the completed message count; EAGAIN after
progress does not park the entire batch. First-item capacity waits subscribe/retry
on the actual resource and release their execution slot. A short stream send ends
the batch. The original compat-flag check, 1,024-message cap and post-transport
msg_len copyout order remain: a length-copyout EFAULT cannot undo delivery.
Owner fallback retains the original source and completed progress, so earlier
messages are not replayed. Already accepted portable messages use their same
prepared records through fallback. A still-unaccepted owner-only rights item keeps
the original owner decoder/ledger boundary; its owner-only rights graph has not
been made portable by this change.

Partial EPIPE without MSG_NOSIGNAL preserves both the positive completed count
and task-level SIGPIPE delivery. The worker records the terminal result and hands
only task effects to the original owner; no packet is resent to rediscover EPIPE.
The accepted syscall's mutex does not serialize unrelated calls or protect the
socket algorithm: actual queue/Files/resource synchronization remains object-local.
Single-message records stay inline in their existing Arc allocation; only the cold
batch state is separately allocated. No service thread, bus or polling is added.

Paired datagram/seqpacket read/write, readv/writev and sendto/recvfrom also use the
same retained packet ABI as addressed datagrams. Vector calls preserve one packet,
and legacy ancillary receive defers before dequeue using the original full OFD.
The existing immediate paired sendmsg/recvmsg and stream hot paths are preserved.
Filtered operations retain one entry decision across waits and owner/task handoff.

Tests exercise lazy later faults, first-item waits, positive partial EAGAIN, short
streams, post-send copyout faults, caps/empty batches, distinct addressed targets,
close/reuse/rebind, legacy rights after earlier success and partial SIGPIPE delivery.
Real guest tests cover all packet byte/message pairs on one/two slots and paired
or addressed transports, plus batch-capacity and filtered signal handoff. Native
TCP/UDP batches and owner-only ancillary/task effects remain boundaries. recvmmsg
is currently unimplemented, rather than a migrated coordinator path.

## Shared stateless memory devices (2026-11-03)

Null, zero, full, random and urandom endpoints are admitted by immutable inode
behavior, not by their pathname. Original mknod nodes, renamed nodes and opened
mount identities use the same typed endpoint. Complete OFDs enter shared Files
and portable SCM_RIGHTS; source close/reuse or a namespace change cannot replace
the accepted object. The original device algorithms still perform byte operations.
Owner/native and worker interfaces share access, mount, timestamp and notification
handling, including the original raw versus positioned error order. No storage or
RLIMIT_FSIZE charge is added to these stateless operations.

The inode's device type is fixed at creation. Existing content replacement changes
ordinary file backing or refreshes the same pseudo-device type; replacing a path
installs a different inode. Actual inode/OFD metadata remains synchronized by the
existing object mechanisms. Hot reads/writes do not acquire the pseudo cache or
re-resolve the name. Direct capabilities retain the full OFD only when accepted;
passive caches neither own its close notification nor keep an endpoint open.

Fixed synthetic /dev devices are looked up in the original shared pseudo-inode
cache, including concurrent first opens. The cache protects only registration,
identity allocation and pruning. A hit releases the cache guard before refreshing
mutable content; fixed device behavior needs no content rewrite. PathQueries still
has its sealed private Rc/control island; only the actual Arc-backed inode cache
crosses the boundary. Runtime/task pseudo state does not become shared or Send.
Proc, sysfs, magic device links, terminals, PTMX, render, bridge, block and kernel-log
controls retain their explicit owner boundary. Ordinary /dev filesystem fallback
uses the common walker, credentials, nodev, permissions and actual device policy.

Scalar/vector and positioned I/O, seek and stat use their original ABI. Access
checks run once in the common device operation; compile-time raw/positioned paths
preserve mount-versus-access error order. Existing synchronous device-write results
are retained. Notifications and final OFD release occur outside inode/cache/Files
guards. A remount changes the original mount's policy; a later mount-namespace copy
does not substitute a different mount into an already open descriptor.

Tests cover five device types, concurrent cold opens sharing one inode with distinct
OFDs, renamed mknod devices, readonly/nodev and namespace changes, actual access/
modify/open/final-close notifications, FD reuse, fixed error results and original
owner-only paths. Real filtered guest lifecycles cover null/zero on one/two worker
slots, with all 122 calls completing on workers and one filter decision per entry.
Dynamic device controls, Unix owning graphs, task effects and structural operations
remain separate migration boundaries.

## Retained IP messages and batches (2026-11-03)

IPv4/IPv6 sendto, recvfrom, sendmsg, recvmsg and sendmmsg use the actual shared
socket OFD on the calling worker. Native, hybrid and packet-stack IP transports
keep their original Socket algorithms, policy, accounting and object locks. The
common message decoder is also used by owner execution; netlink namespace/control
messages retain their owner boundary before guest buffer import or transport
side effects. Ordinary connected TCP byte I/O keeps its existing direct path.

An accepted message retains copied send bytes/destination/packet info or the
original receive scatter/address/ancillary destinations. Blocking EAGAIN uses the
existing socket event sources and packet-stack deadline, releases its execution
slot, then retries after subscribing. Only parked receive destinations are
rechecked before dequeue; normal ready calls do not repeat preflight. Numeric FD
reuse and later guest header edits cannot redirect an accepted operation. The
original descriptor flags remain live, while MSG_DONTWAIT and the accepted socket
timeout still govern the call. Cancellation releases the actual OFD and interests.

A batch retains completed count and its current prepared message, importing later
headers lazily. The original 1,024-message cap, compat rejection, empty-batch FD
validation, requested-length checks, short stream termination, positive partial
errors and post-send msg_len copyout order remain. Delivery followed by EFAULT is
terminal and is never replayed. First-item EAGAIN can park; EAGAIN after progress
returns the count. The progress mutex belongs only to one accepted call. Each
message uses the pre-existing TCP publication boundary separately; the batch adds
no socket-wide algorithm lock. No global lock, new service thread, polling bus,
ordinary guest-memory barrier or new native access policy is introduced.

SIGPIPE records a relaxed per-call atomic flag plus the saved terminal result.
Workers hand only the original task effects to the owner; owner retry observes the
same completed result without resending. MSG_NOSIGNAL keeps the entire completion
on the worker. Partial batch EPIPE retains both positive progress and SIGPIPE.
The existing accepted-entry handoff preserves one seccomp decision across waits
and signal delivery. Actual guest tests cover IPv4/IPv6 pairs on one/two execution
slots and native stream EPIPE for scalar, message and batch sends. ABI tests cover
lazy batch input, first-item waits, short/partial errors, post-send copyout faults,
close/reuse, captured receive outputs, remap faults before dequeue, truncation and
packet-info output, nonblocking/timeout behavior and netlink exclusion.

This does not remove raw UDP read/write ownership, netlink control, Unix owning
ancillary graphs, io_uring owner controls, task/job control, or structural VM/task
transitions. recvmmsg remains unimplemented, not a removed coordinator dependency.

## Retained raw IP byte operations (2026-11-03)

IPv4/IPv6 read, write, readv and writev no longer require the owner when the
socket lacks a connected-native TCP byte capability. UDP, packet-stack TCP and
other admitted IP transports use the original full SocketOperation and the
existing retained-message/event-wait mechanism. Native connected TCP still takes
its existing capability before this fallback; admitted pipe/device/Unix byte
resources also return before any new socket lookup. No extra membership lookup,
heap allocation or publication guard is added to those accepted paths.

Raw calls use the original Linux scalar/vector preparation helpers rather than
the sendmsg decoder. Scalar transfer caps, vector count/signed-length errors,
empty-vector behavior, access-versus-buffer fault order, and one-packet UDP
gather/scatter are preserved. The common scalar receive preflight is factored out
without adding a second check. Input bytes or receive destinations are captured
once for an accepted operation; only a parked receive rechecks its original output
ranges before dequeue. Numeric FD reuse or a later iovec edit cannot redirect it.
The original VFS access check follows raw buffer import; no native-only policy is
added. Socket transport algorithms, namespace policy and accounting remain shared.

The original live O_NONBLOCK status and accepted SO_RCVTIMEO/SO_SNDTIMEO govern
waiting. Existing host events/packet-stack timers release execution slots;
cancellation releases their interests and the real OFD. Raw IP writes do not gain
a TCP-publication algorithm lock that the original raw VFS path did not have.
Virtual TCP EPIPE retains its terminal result and original socket through task
handoff, so SIGPIPE needs no resend or numeric-FD lookup. Filtered real guest tests
cover native/packet-stack IPv4/IPv6 TCP/UDP with one/two execution slots: all ten
calls, including the final waits, finish on workers with one decision per entry
and no coordinator service. Netlink byte/control operations remain owner-bound
before guest input import. Structural VM/task, Unix owning ancillary graphs and
native-service/io_uring controls are separate remaining boundaries.

## Retained Netlink data and resource wakeups (2026-11-03)

NETLINK_ROUTE and non-publishing NETLINK_NETFILTER data calls use the same retained
raw/message/batch ABI and actual shared socket OFD as IP calls. Route/conntrack
queries and supported route/link/address changes execute on the calling worker;
reply and multicast readiness belong to their real socket queue. Existing resource
subscriptions wake reads, poll and epoll without a reactor, periodic service or a
new coordination thread. Poll captures remain weak, so subscriptions and watches
cannot pin final socket close. Ready IP/TCP/pipe paths gain no new resource lookup.

Notifications are collected during the original queue/topology operation and
flushed after queue, registry, topology and outer Socket gates release. A callback
may safely receive and change options on the same socket. Namespace-FD targets
are accepted through actual shared namespace OFDs before taking the topology
writer; canonical validation still selects the original errors and their order.
Their complete OFDs and namespace identities survive close/reuse and are released
after the source Socket gate and notification flush. Source socket namespace and
accepted caller credentials retain the same semantics on owner and worker paths.

Already connected native TCP endpoints retain their selected transport across
route/link updates; hybrid send routing only reselects non-stream transports.
Only an nf_tables batch beginning with NFNL_MSG_BATCH_BEGIN retains its joined
publication boundary. Such publication can invalidate previously captured native
TCP policy-free byte capabilities. This stage preserves that invariant without
adding a permission check, policy generation load or barrier to every native TCP
byte operation. An accepted batch can finish earlier messages before this owner
handoff; the same source, current item and completed count survive, without replay
or a second seccomp decision. Read-only NF/conntrack messages and replies use their
existing object transactions directly. This is a remaining policy-publication
migration, not a claim that all Netlink operations are coordinator-free.

Tests cover raw/vector/message/batch route queries, retained receive and poll
identity after close/reuse, reentrant callbacks, real namespace FD/error/capability
handling and target teardown outside locks. Filtered guest link changes on one/two
workers wake a distinct process's poll and recvmsg; all six calls finish on workers
with one filter decision per entry and zero coordinator services. Unix owning
ancillary graphs, policy publication, native services, io_uring controls and
structural VM/task transitions remain separate boundaries.

## Worker nf_tables publication and live native TCP policy (2026-11-03)

nf_tables batches now execute in the calling worker using the existing ruleset
writer and bounded transaction. There is no whole-cohort publication barrier.
Validation, rollback, generation, response capacity, permission checks and shared
counters remain in the original algorithm. Route, conntrack and Netlink queue
notifications keep their existing object transactions and post-lock callbacks.

The actual firewall object stores its rules and a relaxed atomic empty-hook
selector. Successful publication updates both under the existing rules writer;
failed/over-capacity batches update neither. TCP capabilities refer to their original shared socket and this actual object,
rather than a captured allow decision. Policy attachment is immutable before
socket publication; byte/poll capability size and per-admission reference-count
operations stay unchanged. Each byte attempt reads the selector.
With no hook, the existing host data path takes no namespace/rules lock or new
allocation. With active hooks, it invokes the original socket's packet policy,
conntrack, counters, error and receive-shutdown behavior. Rule removal restores the
same fast path. This necessary live-state read replaces the former all-worker join;
no guest-memory fence, generation polling, message bus or service thread is added.
The selector publishes no packet/guest bytes; active evaluation still synchronizes
through the real rules object. Calls overlapping publication may observe either
policy in the original concurrency model; an accepted wait does not cache an allow.

Accepted TCP leases retain the complete original shared native socket, including
its creating namespace, across close/reuse and parked retries. Capability/control
and poll snapshots remain weak and cannot extend final transport/namespace close.
The existing conditional-close admission checks both socket and transport leases.
Host wait registries retain the same Arc without allocating a wrapper. SO_ERROR
also selects live policy before connection completion; a control captured before
new rules cannot complete a connection with a stale unfiltered callback. Ordinary
byte calls do not take the connection-completion or socket-control algorithm lock.

Actual guest tests on one/two execution slots publish DROP rules, use a previously
captured native TCP path, remove rules and send again while another process uses
an eventfd. All seven calls finish on workers with seven filter decisions and zero
services. Network tests cover active counters, existing-capability send/receive,
rule removal, retained close identity, namespace teardown and SO_ERROR denial.
Unix owning ancillary graphs, native services, io_uring, task/job control and
structural file/VM/task transitions remain separate coordinator dependencies.

## Shared Unix owning rights and worker reclamation (2026-11-03)

Complete shared Unix OFDs can travel through sendmsg/sendmmsg and recvmsg on the
calling worker. The real owning relation belongs to one shared object inherited
across fork and CLONE_FILES, including later network-namespace changes. Its entries
hold the actual accepted OFDs. Queues hold reference-counted links with weak graph
identity, not strong Unix OFDs or an owner-thread ledger ID. Consequently a queue
cannot form a strong ownership cycle back through the graph; closing a receiver
or consuming/truncating its rights releases them immediately on that worker.
Receiver identities and ordinary capability caches stay weak; queued contents
retain the actual carried OFDs.

The graph's existing owning-map responsibility becomes an object-local metadata
transaction: cycle validation and a provisional entry publish together, including
another send not yet enqueued. Failed, empty-stream or backpressured sends retire
that entry. The guard spans no Files lookup, queue I/O, notification or resource
destruction. Actual FDs and upgraded endpoint leases release after it; cascading
queue destruction drains iteratively on the same thread. Final-close callbacks
can reenter the same graph. No coordinator/resource thread, message bus, polling
loop, unsafe code, ordinary guest-memory fence or native-only access rule is added.

Original queued-rights cycles remain rejected. Validation also follows a listener's
unaccepted server ownership, preventing a listener from being sent into its own
pending connection. It reads that real listener state only during Unix-rights
validation; connect retains its original object locks and gains no graph gate.
Non-Unix portable rights keep direct queue storage without this graph transaction.
Portable receive moves its existing rights Arc instead of cloning it; owning
receive resolves its actual entry only after releasing the queue guard.
Paired resources reuse their existing weak endpoint identities instead of adding
a second set. Ordinary bytes and socket creation acquire no ownership-graph lock.

The original ancillary ABI, exact source OFDs, credentials, flags, message progress,
peek, truncation, faults and accepted output ranges are reused. Raw reads discard
shared ancillary outside queue locks without owner handoff. Snapshot-only message
entry still defers metadata it cannot import; it cannot silently discard a CMSG.
Truly owner-only control projections, such as sysctl OFDs, retain their original
fallback. Mixed legacy sets contribute weak graph edges, so owner and worker
paths apply the same cycle policy without sharing any Rc controls across threads.

Actual guest tests with distinct processes/file tables and one/two slots close and
reuse both original numeric slots, transfer a Unix endpoint and operate on that
same endpoint through its imported FD. All ten calls finish on workers, with ten
filter decisions and zero coordinator services. Tests also cover reciprocal sends,
owner/shared mixed cycles, listener children, 600-level iterative release, reentrant
close, original identity after reuse, peek/import and fault before dequeue. Native
services/device and io_uring controls, task/job control, mount/proc ownership and
structural file/VM/task transitions remain separate coordinator dependencies.


### Event-driven native Unix adapters (2026-11-03)

Wayland/XWM listeners, connections and clipboard relays contain actual shared
endpoints and OFDs, with no VFS Rc/owner ledger in their transport state. A guest
queue notification advances its connection on the calling worker. Native socket
and pipe interests are one-shot registrations in an adapter event queue nested in
the existing idle executor's HostEvents. Subscribing an accepted guest resource
attaches that queue to its current executor; no resource/service thread, polling
bus or cohort-control pump is introduced. The joined single-task executor waits
on that same queue and dispatches actual events, without scanning connections.
The existing native compositor/presenter thread and UI affinity are unchanged.

Only connection membership/auth revisions use a registry mutex; callbacks, native
connect/I/O and final connection destruction occur outside it. Partial messages,
native read/write interest and pipe relay state synchronize per connection.
Reentrant readiness coalesces on the original signal: a contended callback returns,
and the current driver drains pending changes before and after releasing its gate.
This is a resource retry protocol, not a worker polling loop or message bus.

Native import allocates inode identity from the original shared filesystem and
uses original open IDs. Ancillary transfers carry complete shared OFDs without
installing guest FDs on a service thread. The existing Files/guest ABI publishes
them on the receiving task. Shared-file export acknowledgement notifies after the
inode registry unlocks. Export-command capacity is subscribed only on real
backpressure; ordinary compositor commands do not wake every connection. Pipe
relays use their original PipeGuard notifications and real host readiness, pause
native reads while the guest queue is full, and rearm when a guest drains it.
All readiness/driver edges back to adapters are weak. Existing native protocol
resource limits and original unsupported ancillary-type errors are retained.

Ordinary Unix bytes, connected/addressed messages, control operations and
Unix-bearing SCM_RIGHTS are worker paths. Passing an actually owner-only task,
mount or proc control projection still crosses that resource's owner boundary;
sharing a Unix carrier cannot manufacture Send/Sync authority for it. GPU auth
snapshot refresh and structural VM/task/mount changes are separate subsystems.

## Live native device authority — 2026-11-03

Native device controls form one shared Mac/iPad subsystem batch. Audio OPEN,
video CREATE_SURFACE, WSI connection authorization and explicit Vulkan
device/instance destruction no longer return a cohort solely for owner-side
resource lookup or destruction. Workers use the existing shared Context and
original Files domain; no new service thread, message bus, ordinary guest memory
fence or native-only permission policy is introduced.

`NativeEvents` captures live Files membership and the joined executor's fallback
wake token before dispatch. A worker-created eventfd can be accepted immediately.
The accepted counter, rather than its numerical FD, remains in each native
callback. Closing/reusing a slot cannot redirect a late callback. A weak readiness
driver is installed only when a native producer actually appears. Both first
admission and last producer release notify existing subscriptions; classification
is live even if the original FD has closed. Ordinary eventfd construction and
notification keep their previous path. The existing idle executor initializes its
host wait source under the run-queue arm lock when a late native producer appears;
it does not require a new resource thread or guest polling.

`WaylandAuth` resolves one live original OFD for the duration of a native call.
It neither snapshots the descriptor table nor retains unqueried inodes. Actual
connection identity, original flags, permissions and backend error behavior are
shared with owner-side calls. A new connection is visible without a membership
revision; copied bytes do not grant access. Invalid/unregistered FDs finish with
the backend's original error rather than triggering an authorization refresh.
Native image publication uses the Files domain's actual descriptor limit.

Explicit GPU close accepts its original target once. Unfinished native compilation
and observed GPU submissions become existing asynchronous jobs, subscribed to
the original completion readiness; the caller gives up its execution slot while
unrelated CPUs run. Native Wayland frame fences use that same pinned completion
observer. The original final native idle/destruction algorithm remains on the
calling worker, preserving safety against concurrent native submissions. No
claim is made that native driver destruction itself has zero cost. Drivers without
the completion observer retain their original native drain behavior.

Compiler tasks publish a release completion flag after delivering the result or
disconnecting and after their Send-owned work ends. Polling acquires that flag
before consuming results and dropping backend-owned dependencies. Completed tasks
do not join notification delivery while holding a context lease. Only Send-owned
arrays/handles and Arc native devices reach the existing compiler thread; private
Rc resource graphs stay under the existing context mutex. Final cancellation of
unfinished tasks retains the original join/lifetime boundary. No new production
unsafe or broader Send implementation is required by this batch.

Structural guest mapping import, task-exit/context cancellation, io_uring controls
and filesystem/VM/task topology still have genuine owner boundaries. This batch
does not claim a whole application or the complete runtime is coordinator-free.


## Canonical io_uring subsystem (2026-11-03)

The original Arc<Uring> owns shared SQ/CQ/SQE pages, registration tables and all
pending/overflow/link/timer/multishot state. Worker and joined paths share one
importer and progression engine. The per-ring mutex protects metadata claims;
resource algorithms, guest byte accesses, notifications and final OFD release run
outside it. Live Files authority admits newly created/transferred rings directly.
A blocked enter carries its accepted original ring across epochs and numeric FD
reuse; no queue snapshot/handoff restoration is required.

Each source task lazily retains a private sealed path-query island over original
shared Files/namespace/device resources. Accepted requests retain a cleanup token
with a weak actor link; rings never own the source task or Files root. Pending
owner-accepted SQEs acquire this source context before worker maintenance without
re-reading guest metadata. Existing run-queue jobs service actual notifications
and deadlines while the source guest sleeps or waits elsewhere. The unrelated
main wait is preserved. Real owner fallback is remembered until owner progress,
so a compatibility request cannot repeatedly stop an otherwise empty cohort.
No new coordinator/service thread, polling bus or per-poll RPC is introduced.

Original native TCP/Unix controls and message algorithms remain responsible for
resource semantics. Pinning is an affected-mm mutation through the original VM
checkpoint; supported fixed buffers then share canonical guest pages with CPU
and native memory access. Provided-buffer unregister/reuse cannot retarget an
in-flight buffer generation. Unix SCM_RIGHTS and ring fixed/pending resources use
one owning graph, with retired original handles dropped outside graph/ring locks.
Owner-only Rc descriptions remain in their original owner ledger; their worker
tokens cannot clone/drop Rc or bypass the existing supported-resource filter.

Plain disk fsync submits an original retained OFD/job to the existing bounded disk
pool and wakes the source directly through readiness. No coordinator response is
required. Disk/mapped/overlay allocation and truncation, O_TRUNC open, backing
write growth/append, owner-only task/mount/proc resources and lifecycle/VM topology
remain explicit compatibility checkpoints. Common code is shared by Mac/iPad;
HVF only supplies CPU/MMU execution.

## Regular-file data, EOF and durability subsystem (2026-11-03)

Regular-file scalar/vector/positioned I/O, append/growth, seek/stat, truncate,
fallocate, fsync/fdatasync/syncfs/sync, O_TRUNC and file-to-file transfers now use
one accepted FileWork contract. Normal calls and io_uring retain the original full
OFD, copied inputs and output description once. Short data calls execute on their
source worker using the original descriptor algorithms; they allocate no temporary
Files table. Large or blocking work uses the existing bounded disk pool and sends
readiness directly to its source. Source tasks retain completion/checkpoint state
across cohort stops, FD reuse and signals; guest pointers never enter native jobs.
There is no Session disk request/reply service, recycled owner buffer protocol or
ring-specific disk executor. Pure VFS legacy disk helpers remain compatibility APIs.

The original byte/position locks protect actual shared resources. Private quota
uses one original shared atomic account and transactional per-file EOF charges;
failed or partial growth reconciles its reservation. Host-directory bytes stay
outside the private-store quota. Canonical file mode/times live on the same data
object, including owner writes and checkpoint/stat readers. FileEpoch no longer
scans or copies metadata back at each cohort. Algorithms retain their existing
permissions, seals, RLIMIT_FSIZE, append, notification and durability semantics.

A mapped backing layout change identifies affected original mm instruction views.
Only those views quiesce before the accepted job runs on the same disk pool;
completion releases their pause counts. Ordinary data and unrelated CPUs do not
require a global stop. Writable hardware-backed resident pages participate in
writeback; unmaterialized pages are not falsely marked dirty. Queued filesystem
sync captures its original files and marks actual in-flight resources, without
including later-created files in that accepted byte-lock operation.

O_TRUNC reserves an unpublished numeric slot and retains the resolved inode;
only successful truncate publishes the FD. Pathname truncate captures the original
OFD without publishing a temporary guest FD. Copy retains accepted input bytes and
offsets across an output-layout checkpoint. io_uring provided-buffer selection
retains its original group generation and pin until completion/cancellation.

Namespace/directory mutations, owner-only task/proc/mount controls, cross-resource
file-to-pipe/socket transfers, structural VM/task topology and unfinished context
cancellation remain separate boundaries. This common implementation is shared by
Mac HVF and the iPad interpreter. No new resource thread, polling bus, global
algorithm lock, ordinary guest memory fence or unsafe block is introduced here.

## Namespace, metadata and canonical fs_struct (2026-11-03)

Directory create/remove, link/symlink/rename, chmod/chown/times/xattrs, cwd/chdir/
fchdir/chroot and statfs use one imported namespace ABI on the caller, worker and
joined compatibility entry. Canonical cwd/root and detached traversal pins are
original shared fs_struct resources; each control island retains only its private
Rc mount projections. CLONE_FS shares the original resource; fork/unshare copies
it. The canonical state is compile-time checked Send+Sync, without widening the
existing sealed PathQueries Send boundary.

Short worker calls borrow their current island, and joined memory-only calls use
their original VFS. Only native or retained work builds a fresh private island.
Inputs and actual dirfd/OFD identities are accepted once; queued work owns no guest
pointers. The old joined namespace/xattr ABI duplication is removed. Actual flat
filesystem namespace transactions protect create/remove/link/rename and their
checkpoint/rollback, including PTY creation/final-close. Original inode metadata
transactions protect their multi-field changes; normal byte operations do not
acquire these namespace/metadata transaction locks.

Disk-backed namespace work uses the existing bounded pool and direct source
completion. An owner-only proc/task/mount projection defers before effects and
keeps copied inputs plus accepted shared FDs in FileOutcome::Owner. This is distinct
from a mapped-file layout checkpoint. Existing persistence, permission, error-order,
notification and supported-operation semantics remain. No namespace io_uring SQE
extension, new service thread or production unsafe block is added by this batch.

The [consolidated coordination/fallback audit](coordination-boundaries.md) is the
current architecture inventory. Structural mount/task/VM and owner control paths
remain. The following transfer migration updates the mixed-I/O boundary.


## Cross-resource stream transfer (2026-11-04)

The normal sendfile/splice contract covers regular-file/pipe, pipe/pipe,
file/Unix-stream or TCP, pipe/Unix-stream or TCP, and stream/pipe pairs. One ABI
import captures both original OFDs and offset values before queueing. The same
StreamTransfer algorithm serves worker and joined execution. Closing/reusing a
numeric FD, changing guest inputs or handing the task to another cohort cannot
retarget accepted resources. Unsupported owner/dynamic resources defer before
effects; tee/vmsplice are not introduced by this migration.

Pipe prefix and capacity reservations belong to the original pipe mutex and are
also respected by ordinary reads, writes, polling and native relay. No pipe mutex
spans disk I/O or a parked task. A blocked sink releases an uncommitted pipe prefix;
a destination pipe reserves capacity before a stream source consumes bytes.
Cancellation/drop returns reservations and publishes original readiness. Memory
and socket byte operations execute on the source worker. Disk/native file work
uses the existing bounded pool and copied staging, never borrowed guest pointers.

A resource wait retains its operation and subscribes to the original endpoint's
readiness, native event source and deadline. It gives up its execution slot and
can be interrupted/restarted by the existing signal ABI. In-flight disk work
retains its existing accepted-result/copyout policy. A true mapped-file output
layout change retains staged input through the existing affected-domain boundary;
it is distinct from ordinary backpressure and from owner-only compatibility work.

Immediately completing joined calls use the original VFS, with no retained file
island/result/subscription allocation. The existing below-16-KiB short native
read/write policy also applies to these joined transfers, unless an original
inode already has queued work or output requires synchronous I/O. Bulk and worker
native I/O stay on the original disk pool. Its completion notifies the existing
source target; the joined scheduler parks on that notification rather than polling
with a fixed sleep. Resumption retains access to the same executor.

EOF, short results, EAGAIN, offset/error ordering, append rejection, SIGPIPE,
caught-signal cancellation and SA_RESTART are covered against native Linux. Original
file position/byte synchronization and the existing bounded transfer staging are
retained. No new coordinator/resource thread, message bus, ordinary-memory fence,
unsafe block, CPU quota or global transfer lock is added. This is common Mac/iPad
code; no whole-application or entirely coordinator-free claim follows from it.


## Overlay checkpoint and stat lock order (2026-11-04)

A Docker useradd on an overlay-backed Debian container exposed a namespace/inode
cycle: checkpoint held the overlay filesystem for rename and needed an inode
write guard, while FileEpoch scalar stat held that inode read guard and queried
the mount device through the filesystem. The owner stalled during cohort setup,
so unrelated guest exec requests also stopped progressing.

Device numbers now belong to immutable mount identity and require no filesystem
or inode lock after mount construction. Scalar stat/capability formatting touches
only its accepted inode fields. Directory stat releases scalar inode guards before
namespace traversal, follows filesystem -> inode order for reverse lookup/children,
and releases both before pseudo-child lookups can re-enter the namespace. Overlay
copy-up follows upper filesystem -> merged inode too, dropping the filesystem
before bulk copy/sync. Existing capacity checks use the byte-account snapshot
without an unrelated inode-count scan. Layer device identity also avoids a root
inode re-borrow under checkpoint. Two import/hard-link limit checks use one
filesystem read guard rather than recursively taking read locks while a writer
could be queued.

The focused audit also checked chmod/times/xattr rollback, reverse-path lookup,
host identity publication and filesystem-sync checkpoint handoff: their scoped
inode guards are released before entering the filesystem, or their lookup order
already follows filesystem -> inode. This is a scoped source audit, not a proof
that every runtime lock graph is cycle-free. No global lock, service/coordinator
thread, try-lock polling loop, new guest error or ordinary-memory fence is added.

Bounded regressions force the namespace writer during FileEpoch preparation,
contend copy-up against the upper namespace and inode, and run rename/checkpoint
against file/directory stat concurrently. They release forced locks before failure
or use receive deadlines, so the old cycle fails rather than hanging the suite.
The original unmodified Docker repro is run separately against an APFS clone of
the frozen Debian environment, without changing its project data or credentials.


## Retained event-wait subsystem (2026-11-04)

Admitted pselect6, ppoll, epoll_pwait and epoll_pwait2 share one accepted
RetainedWait contract on Mac HVF and the iPad interpreter. Entry imports the
original descriptor sets/OFDs or epoll object, absolute deadline, output locations
and optional temporary signal mask once. Parking, readiness rearming and cohort
handoff keep this contract: numeric FD close/reuse, guest input edits or a later
FD epoch do not retarget the accepted wait. Epoll interest revision changes
refresh subscriptions on that same epoll object. Owner/mixed poll/select imports
retain the original owner-control identity before their existing joined path.

A ready call uses a stack wait wrapper. Only actual parking/checkpoint allocates
its shared retained wrapper; unchanged rearm clones that Arc rather than every
captured descriptor. Shared epoll results scatter their original records directly
on both joined and worker paths. Ordinary readiness executes on the source worker;
a blocked task returns its execution slot and subscribes to original resources,
host events and deadlines. Existing io_uring pumps remain source-owned. A source
pump that cannot run returns a typed WaitCheckpoint with the accepted wait rather
than silently re-importing guest input on the owner.

Only a truly blocked masked wait publishes the temporary mask. The previous mask
lives in shared per-task signal context across handoff. Caught I/O signals enter
the ARM64 frame on that task's worker: the handler runs with the temporary mask
plus its action/current-signal mask, while ucontext records the pre-wait mask.
Sigreturn restores that original mask. Event waits report EINTR even under
SA_RESTART; ordinary completion restores the old mask without constructing a
signal frame. Actual legacy owner-queue signal delivery still uses task control.
An actual mask unblock synchronizes with the existing private/process inbox
mutexes, closing the enqueue/unmask lost-wake window; unchanged or blocking-only
masks do not acquire these locks. No new global lock or ordinary-memory fence is
used. Default signal termination/stop remains a lifecycle effect.

Raw pselect6/ppoll timeout copyout follows native Linux: remaining time updates on
readiness, timeout and EINTR are best effort. A final write fault does not replace
the syscall result. epoll_pwait2 does not modify its timeout. Entry seccomp is
judged once before wait-input effects; ALLOW can execute/park locally and a
non-ALLOW or resource fallback preserves the exact original decision. Tracing,
excluded owner/dynamic resources and unsupported source pumps retain explicit
boundaries. No new coordinator, reactor or resource service thread, polling bus,
per-call algorithm lock or unsafe block is introduced.

Concentrated acceptance compares all four families against the same static ARM64
ELF on native Linux, Mac HVF and the production interpreter, including queued and
arriving FASYNC signals, handler/sigreturn masks and read-only timeout copyout.
Source-worker regressions assert zero service requests for masked EINTR/sigreturn,
original epoll identity after close/reuse, and once-only seccomp evaluation across
parking. This does not claim every signal source or owner FD has been migrated.


## Shared POSIX and real interval timers (2026-11-04)

timer_create/gettime/getoverrun/settime/delete and getitimer/setitimer use one
shared execution-independent Timer ABI on Mac HVF and the iPad interpreter.
A read-shared timer namespace retains original timer objects; each timer protects
its own armed state, period, overrun and deletion. Create/delete transactions
protect the ID namespace. A separate short deadline-index transaction changes
only the deadline set and its atomic next-expiry hint. No registry write lock
spans ordinary timer queries or another timer's algorithm. Existing metadata and
signal-queue bounds are not a guest resident-memory charge.

The current cohort binds this registry to its existing execution queue. Only an
actual earlier deadline wakes an idle executor; unchanged/disarmed updates do not
notify. CPU dispatch tests the cached expiry hint, while an idle executor sleeps
until the next actual resource/timer deadline. An existing executor removes a
bounded due batch, releases the queue/index locks, and delivers on original
signal mailboxes. Rearming and deletion serialize on the original timer before
committing their deadline changes. Sub-microsecond periods do not spin inside
maintenance. No timer/reactor/resource service thread or polling bus is created,
and a timer expiry alone no longer requests a whole-cohort join.

SIGEV_NONE needs no asynchronous observation: it retains its absolute origin and
period, computes current periodic phase on a query and reports zero overrun.
It installs neither a signal target nor a host/execution deadline. Ordinary
short joined timer calls also keep their CPU quantum; they do not rescan every
blocked process after each query. Real signal/control work and normal bounded
execution polls remain.

A process-directed target retains its original process inbox and group
incarnation; a thread-directed target weakly names the original task. Later PID
reuse cannot redirect a notification. Standard signals coalesce and queued timer
records accumulate overruns under the original inbox mutex. Source workers use
the same caught-signal frame, temporary-mask restoration and sigreturn as I/O
signals. Default stop/termination still requests task lifecycle handling. Legacy
owner signalfd/sigwait waiters can consume the same shared pending timer records;
those owner waits have not been migrated by this batch. libc SIGEV_THREAD uses
its existing helper-thread/SIGEV_THREAD_ID ABI, without a new host timer thread.

Entry seccomp is evaluated once before timer ABI effects. ALLOW executes locally;
non-ALLOW carries its exact decision to the original owner policy action. The
common ABI preserves copied input/old-output aliasing, fault-without-mutation,
clock origins, original ownership and timer retirement. Native Linux comparison
also corrects two prior discrepancies: POSIX timer_settime ignores non-ABSTIME
flag bits, and exec removes POSIX timers while preserving ITIMER_REAL. Fork starts
with no inherited timers; final process exit removes its remaining timers.
CPU-clock POSIX timers and ITIMER_VIRTUAL/PROF keep their previous explicit
unsupported behavior. No new ordinary-memory fence, unsafe block or global
algorithm lock is added.


## Shared signal queues, controls and reader-scoped waits (2026-11-04)

This supersedes the signal-reader limitations in the earlier descriptor, event
wait and timer sections. Signals has no duplicate Rc pending queues: owner
producers, guest senders, timers and FASYNC use the original task/process inboxes.
An immutable reader capability binds the current task and PID namespace at
execution admission, not signalfd creation. Scalar/vector reads dequeue one
whole record before each copyout; partial success, faults, coalescing, realtime
FIFO and namespace translation retain the Linux ABI. Accepted blocking plans
keep the original OFD and copied iovecs across close/reuse and source handoff.

poll/epoll and their nested owner observations carry the current reader context.
The live epoll index stores an OFD weak identity, not a creator queue. Queue and
OFD-mask subscriptions wake the existing execution queue. io_uring reads,
readv, fixed buffers/files and poll retain their submitting task and original
OFD; a pinned-buffer read targets the original pin even after VA remapping.
The joined adapter reuses the same record-copy algorithm.

sigaltstack, rt_sigaction, rt_sigprocmask and rt_sigpending execute on their source
worker. Disposition mutation/discard synchronizes with enqueue on the original
sighand table; notification never runs under sighand/pending locks. Query-only
owner calls avoid unnecessary context transfer and publication. Caught delivery,
rt_sigreturn, sigsuspend temporary-mask restoration and rt_sigtimedwait use shared
task context. Accepted waits copy their set/deadline once, dequeue before handler
delivery and copyout, and preserve their state through cohort collection.

Ordinary kill/tkill/tgkill routes use published original task/group incarnations,
PID namespaces and credentials. A separate weak presence token distinguishes a
zombie from a reaped task even when a retained reader keeps its inbox alive.
Source ALLOW/ERRNO and unsupported TRACE/USER_NOTIF decisions are applied once;
TRAP/KILL and tracing keep the real task-policy boundary. STOP/CONT group state,
default termination, parent wait/SIGCHLD, exit resource cleanup and reaping still
require the lifecycle migration described in coordination-boundaries.md. They
are not hidden behind the new source entry path or counted as removed here.


## Stream prefixes and logical futex retirement (2026-11-04)

TCP is a byte stream. The existing 1 MiB transfer staging bound limits one
accepted prefix, not the application's logical write size. `sendto`, `sendmsg`,
`sendmmsg` and retained/uring socket operations prepare only that prefix for a
stream; applications may retry the remaining bytes. Immutable socket type is
retained across native/virtual endpoint transitions and accept, without a host
query or new data-path lock. Datagram messages keep their atomic size bound and
EMSGSIZE. A short batch send compares the result against the original vector
length, stops the batch and never replays the accepted prefix. An unmapped suffix
outside that prefix is not borrowed or copied.

Futex registration lifetime is separate from Rust ownership lifetime. A source
worker can interrupt a wait while an owner checkpoint still retains the same
`Arc<Wait>`. Dropping only the worker's clone leaves the old ticket eligible:
a later wake can select that stale ticket instead of the task's new wait. In Go,
this can strand a GC safe-point handshake indefinitely. Caught-signal delivery
on both worker and owner paths, and exit from active/stopped waits, explicitly
cancel the logical registration. Final-owner Drop remains a cleanup backstop.
Cancellation uses the original winner CAS and keyed bucket unlink, including
requeue races; it adds no coordinator request, service thread, polling, global
algorithm lock or ordinary-memory barrier. Wake/timeout/interruption still race
according to the existing ticket protocol. No Go preemption workaround is used.

Deterministic tests retain owner clones across interruption and stopped exit,
then create a new wait on the same or requeued key and require its first wake to
succeed. External acceptance uses stock Debian Go tools with normal async
preemption, repeated Docker health/exec/stop/remove cycles and an unmodified
Python `sendall` reproducer transferring 3,777,458 bytes.
