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
