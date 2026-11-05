# Coordination and fallback boundaries

This is the consolidated implementation audit through source process exit and
CPU/mm return, 2026-11-05. Mac HVF and the iPad interpreter use the same userspace Linux
kernel. The remaining boundaries below are still present; completing the latest
batch does not make the whole runtime coordinator-free. The Docker I/O additions
below, 2026-11-04, use calling workers and shared resources from their first implementation.

## Execution model

```mermaid
flowchart LR
    CPU[Mac HVF or iPad interpreter] --> Entry[Calling worker and original guest View]
    Entry --> Shared[Original shared file, socket and native resources]
    Entry --> Wait[Existing execution queue and readiness]
    Wait --> Entry
    Shared --> Disk[Existing bounded native disk pool]
    Disk --> Wait
    Entry --> VM[Affected mm or backing checkpoint]
    VM --> Owner[Kernel owner and task control]
    Entry --> Compat[Unsupported owner resource or task policy]
    Compat --> Owner
    Owner --> Entry
```

The Kernel owner admits and collects execution cohorts, manages processes and
publishes structural changes. An admitted short operation runs on its calling
worker. A blocked resource operation can return its execution slot and resume
from original readiness without a syscall RPC to that owner. Native disk jobs own
copied inputs and original resources, and publish results directly to the source.

The relevant scopes are:

- **Resource wait:** only the caller parks; other CPUs continue.
- **In-cohort owner service:** the caller's View is loaned to the existing owner;
  other CPUs can continue. Refusal before effects can end the cohort.
- **Affected-domain checkpoint:** only the required mm/backing users quiesce;
  the owner publishes their structural change.
- **Joined owner path:** the current cohort ends, its Views return, then the owner
  runs task/control or compatibility work. This is broader than one-resource wait.
- **Local execution fallback:** a different implementation runs on the same worker;
  the word `fallback` alone does not identify a coordinator transition.

## Remaining owner dependencies

### Docker I/O additions

| Interface | Normal execution | Current limits |
| --- | --- | --- |
| FIOASYNC / O_ASYNC, F_SETOWN/EX and F_SETSIG | OFD-owned subscriptions on pipe, Unix-socket and PTY readiness enqueue into shared task/process signal mailboxes. The target worker enters the existing ARM64 signal frame and restores it with local sigreturn. PID namespaces, group/TID ownership, credentials, standard coalescing and realtime queues use original identities. Only status/list changes synchronize per OFD; byte I/O and GETFL keep atomic flag reads. | Native TCP and other unsupported FASYNC descriptor kinds return EOPNOTSUPP. Reader-scoped signalfd reads and admitted waits execute on the source worker. STOP/CONT uses shared group control; default termination and actual lifecycle/owner resources retain their boundary. |
| io_setup/destroy/submit/cancel/getevents | One demand-zero, read-only context-header page is reserved during ELF load. Setup changes only the shared per-mm context registry. Buffered scalar/vector reads/writes and fsync/fdatasync use the existing disk pool, park the source task, copy results on its worker and publish CQ then eventfd. Accepted waits retain their original context across destruction, handle reuse and cohort handoff. | Buffered io_submit can return a submitted prefix and wait for its batch, as Linux permits; accepted payload staging uses the existing MAX_WRITE byte bound, with at most one additional preparation buffer and 64 request records; this is not an O_DIRECT DMA/pinned-buffer implementation. Context metadata is bounded to 128 contexts and 65,536 requested credits per context. Zero ring magic selects the library syscall fallback; userspace ring reaping is not advertised. Unsupported opcodes, I/O priority/RWF flags, temporary pgetevents masks and live mapped-file layout work return explicit errors instead of requesting a new owner service. In-flight buffered cancellation returns EAGAIN; already-completed requests return EINVAL. |
| EPOLLEXCLUSIVE | Shared readiness wakes ordinary subscribers and selects an eligible exclusive waiter per original OFD. Native one-shot registrations are driven by an existing idle executor and rearmed as interests retire. No polling bus or reactor thread is added. | ADD-only, no ONESHOT or nested-epoll target; MOD of an exclusive registration returns EINVAL. Existing owner-only descriptors and traced epoll waits retain their prior boundaries. Admitted masked epoll waits use the source worker. |

The signal-frame implementation is shared by owner delivery, source-worker I/O
delivery and sigreturn. The normal caught-SIGIO worker test asserts zero service
requests and a worker-retired sigreturn. The C fixture `tests/fixtures/async-io.c`
in trames-ipad compares the same AIO, SIGIO and epoll cases against native Linux
on one and four CPUs. Mac acceptance additionally runs the unmodified Debian
Docker/containerd/runc packages and the default four-worker nginx container.

### Shared signals and remaining lifecycle dependency

Signal delivery no longer selects between owner-private and resource queues.
The original task owns one private inbox and one process-shared inbox. Reader
capabilities belong to the syscall caller, so inherited/passed signalfds and
shared epoll interests never retain their creator's task as reader authority.
Accepted blocking reads and signal waits keep their imported operands, original
OFD, mask and deadline across parking, close/reuse and cohort handoff. They
subscribe to original queue/mask readiness and return their execution slot.
io_uring READ/READV/READ_FIXED/POLL use the same submitter-scoped capability,
including fixed files and buffers retained across unmap/unregistration.

Sighand changes serialize with guest enqueue/discard only on the actual table
and queues. Enqueue notification runs after those locks are released; removing
pending records changes the poll epoch without creating a readiness wake.
Owner/source context copies occur only at custody handoff. The short owner mask
ABI uses the same decoder without an unnecessary context mutex roundtrip.

STOP/CONT now uses the original shared thread-group control and parent wait
objects described below. It no longer requires the entire cohort to return.
Ordinary exit, group/default-fatal termination, clear_tid, accepted-operation
cancellation, namespace-init victim termination and original family completion
now use source resources. Full returned CPUs and metrics are adopted while other
CPUs continue. Private Rc projections still return to their existing owner through
an asynchronous completion event. A cold group member sharing an executing mm
uses a byte checkpoint of that mm alone. It does not stop unrelated mm/backing
users or rebuild its mappings. External guarded mm borrows retain physical custody
independently of guest parent notification, keyed by the original mm identity.
Structural fork/exec, tracing and non-ALLOW security-policy effects retain their
actual boundaries. Robust-futex owner-death support is not added by this work.


### Other boundaries

| Area | Actual trigger / examples | Current scope and status | Authoritative implementation |
| --- | --- | --- | --- |
| Task lifecycle and process graph | clone/fork/vfork, exec/execveat, exit/group exit, wait/waitid, reparenting and cancellation | Shared wait4/waitid, STOP/CONT, set_tid_address and admitted vfork waits run on source workers. Individual exit(93), exit_group(94) and default-fatal termination retire original resources on their source workers, including the final member and Files with opaque owner controls. Namespace-init victims use original groups. Full returned CPUs and cold Rc projections are collected while peer CPUs continue; cold same-mm peers need only that mm byte checkpoint. Structural creation/exec, tracing, non-ALLOW policy and legacy unadmitted waiter adoption retain their boundaries. The current whole-cohort scope is an implementation boundary, not a claim that every unrelated address space fundamentally needs pausing. | [process lifecycle](../../crates/trames-session/src/process.rs) (`fork_state`, `exec_at`, `exit_one`, `wait`, `syscall`) |
| Signals and mutable security/task policy | Default termination, credentials/capabilities, affinity, seccomp installation/TSYNC and non-ALLOW actions | One private/process mailbox serves ordinary guest sends, timers, FASYNC, faults and owner producers. Ordinary kill/tkill/tgkill routing, altstack/actions/masks/pending, sigtimedwait/sigsuspend and signalfd read/readv run on the source worker. Caught handlers and sigreturn share the same frames. STOP/CONT uses the original group state and parent wait/SIGCHLD; default termination uses source group cleanup. Signal-control seccomp ERRNO/unsupported TRACE/USER_NOTIF complete locally; TRAP/KILL and tracing retain their explicit task-policy boundary. | [entry and delivery](../../crates/trames-session/src/process.rs), [shared I/O signals](../../crates/trames-kernel/src/signal/io.rs), [worker decisions](../../crates/trames-session/src/workers.rs), [seccomp](../../crates/trames-session/src/process_seccomp.rs) |
| Structural namespaces and administrative controls | mount/umount/pivot_root, unshare/setns, BPF syscall/control installation, dynamic proc/sysfs projections | Joined owner path. Mount and task namespace topology, credentials and remaining owner Rc control graphs have not been migrated. Cgroup paths, controls, membership and notifications use the shared resource graph described below; cgroup namespace/mount changes and structural fork entry still join. Ordinary mkdir/unlink/rename/metadata and shared cwd/root are separate shared resources. | [owner syscall dispatch](../../crates/trames-session/src/process.rs), [mount topology](../../crates/trames-vfs/src/mounts.rs), [namespace topology](../../crates/trames-vfs/src/linux_namespace.rs) |
| Dynamic/special pathname and FD resources | Dynamic proc/sys refresh, non-admitted nsfs/mqueue mounts, dynamic file bodies, controlling-terminal acquisition and excluded open types | Before-effects defer. Actual cgroup mounts are admitted through their original shared graph and OFDs. Namespace calls preserve copied operands and accepted shared FDs in `FileOutcome::Owner`; the joined resolver handles remaining owner controls. Other path queries return `None` for their owner entry. A typed defer is not a new guest errno. | [path authority](../../crates/trames-vfs/src/path_queries.rs), [node/open admission](../../crates/trames-vfs/src/lib.rs), [proc synthesis](../../crates/trames-vfs/src/pseudo.rs), [namespace handoff](../../crates/trames-vfs/src/namespace_work.rs) |
| Residual generic FD/network compatibility service | A direct descriptor/control admission does not handle the actual resource; generic network controls, old epoll creation, lseek/fstat or eligible stream byte paths reach `service_candidate` | In-cohort owner service where admitted. Dynamic proc, tracing/filter restrictions, unsupported kind, blocking EAGAIN, EPIPE and internal unsupported results can reject it and request a joined owner path. Ordinary shared file/socket hot paths precede this service; its existence does not show their normal calls use it. | [candidate numbers](../../crates/trames-session/src/worker_syscalls.rs), [actual admission and effects](../../crates/trames-session/src/process_service.rs) |
| Cross-resource transfer | sendfile/splice between admitted regular files, pipes, Unix streams and TCP | Original OFD pairs execute on the calling worker. Backpressure parks only that task on original readiness; native disk jobs reuse the existing pool. Joined short operations borrow the original VFS without building a retained island. Actual mapped-file layout changes keep affected-domain checkpoints; excluded owner/dynamic resources defer before effects. tee/vmsplice remain unsupported. | [accepted transfer](../../crates/trames-vfs/src/stream_transfer.rs), [source execution and waits](../../crates/trames-linux/src/direct/file.rs) |
| POSIX and real interval timers | timer_create/gettime/getoverrun/settime/delete and getitimer/setitimer | Shared timer objects execute on the caller. A short deadline-index transaction updates the original execution queue; existing workers process a bounded batch of due timers outside that queue's mutex. SIGEV_NONE keeps lazy periodic phase without an armed host deadline. Process/thread signal targets retain their original incarnation. Timer STOP/CONT uses shared group control. Default termination uses original source group cleanup; unsupported CPU-clock/virtual/profiling timers are not added. | [shared timer ABI and index](../../crates/trames-kernel/src/timers.rs), [original signal targets](../../crates/trames-kernel/src/signal/io.rs), [execution queue](../../crates/trames-session/src/run_queue.rs) |
| Event waits and remaining owner/mixed cases | Admitted pselect6, ppoll, epoll_pwait and epoll_pwait2, including temporary masks, use workers; excluded owner/dynamic FDs, tracing, unavailable source pumps and actual lifecycle/task-policy effects retain their boundary | One imported wait retains original OFDs/sets, mask and deadline through parking and cohort handoff. Source I/O signals interrupt locally and sigreturn restores the pre-wait mask. All pending sources now use the same queues. Caught signals interrupt locally; STOP/CONT retains the original wait and uses shared group control. Default termination uses original source group cleanup. | [poll ownership](../../crates/trames-linux/src/poll.rs), [wait admission](../../crates/trames-session/src/process.rs), [cohort control](../../crates/trames-session/src/process_vm.rs) |
| Unix ancillary owner controls | SCM_RIGHTS that contains an actual excluded owner control; owner-ledger reaping and a legacy destination/control projection | Retained original endpoint/rights handoff and owner graph work. Portable Unix sockets/rights and ordinary native Wayland transport already share the real resource graph. A mixed owner set is still excluded. | [message handoff](../../crates/trames-linux/src/direct/local_message.rs), [rights ledger](../../crates/trames-vfs/src/ipc.rs), [portable graph](../../crates/trames-vfs/src/ipc/shared_rights.rs) |
| VM and pin topology | brk growth, munmap/mremap, non-additive mmap, mprotect, mincore/madvise and io_uring buffer pin/register variants requiring mm edits | Affected mm/backing checkpoint on the existing run queue. The owner commits and rebuilds the required Views; unsupported/external generations, tracing or non-ALLOW policy can escalate to a joined path. Additive private-anonymous mmap has a separate in-cohort owner publication path. | [VM ABI classification](../../crates/trames-session/src/worker_syscalls.rs), [domain queue](../../crates/trames-session/src/run_queue.rs), [VM commit](../../crates/trames-session/src/process_vm.rs), [View admission](../../crates/trames-memory/src/parallel.rs) |
| Mapped-file layout | Truncate/growth/allocate that changes a live mapped backing layout | Only affected original mm instruction views are quiesced, then the same disk pool runs the accepted file operation. Completion releases overlapping pause counts. Byte transfer and sync alone do not imply this checkpoint. | [file checkpoint](../../crates/trames-session/src/process_file_io.rs), [original file job](../../crates/trames-vfs/src/file_work.rs), [resize](../../crates/trames-vfs/src/memfd.rs) |
| io_uring owner escalation | Actual owner resource/SQE, unavailable event subscription or source pump, mapped layout; buffer pins requiring structural authority | Canonical ring state stays shared. `owner_required` hands real owner work back to the Kernel; accepted SQEs keep their original source context. Source background progress on sleep/futex is ordinarily event-driven. No separate ring service thread exists. New namespace SQE opcodes are not added by the namespace batch. | [actor](../../crates/trames-linux/src/direct/uring/actor.rs), [source maintenance](../../crates/trames-linux/src/direct/uring/background.rs), [subscriptions](../../crates/trames-linux/src/direct/uring/wait.rs), [file results](../../crates/trames-linux/src/direct/uring/actor_file.rs) |
| Native guest mapping and exceptional native memory entry | Vulkan shared host-allocation mapping import where `can_import_mapping` is false; unstable native entry code; live-private backing or a native access mode requiring a checkpoint | GPU/native typed checkpoint before body effects; current worker returns the pending HLT to the owner. Ordinary CPU/native bytes keep the common permission/backing model. The GPU context mutex and compiler/fence waits are normally resource waits. | [Vulkan import](../../crates/trames-vulkan/src/backend.rs) (`Invocation::Checkpoint`), [native memory](../../crates/trames-memory/src/parallel/native.rs), [entry registry](../../crates/trames-accel/src/native.rs), [GPU wait](../../crates/trames-session/src/gpu.rs) |
| Scheduler/cohort membership | Legacy futex wake target cannot schedule into its current epoch; a newly eligible nonmember, affinity/control change, instruction allowance or actual owner signal or task event requires scheduling | Current cohort scheduling boundary. Existing epoch members and ordinary readiness continue locally. Idle or periodic host-control checks do not automatically imply teardown: `cohort_control` decides whether to join. | [legacy wake](../../crates/trames-session/src/futex.rs), [worker stop](../../crates/trames-session/src/workers.rs), [cohort selection/collection](../../crates/trames-session/src/process.rs), [control checks](../../crates/trames-session/src/process_vm.rs) |
| Embedding and terminal/session lifecycle | Transfer/timezone command, pause/cancel, terminal create/close/resize, foreground group signal/hangup, actual systemd supervision event; Mac admin/shutdown/deadline/memory-pressure request; host-authorized exec process creation and process-group signal | Host control requests a join for actual lifecycle work. Routine FFI status snapshots, retained exec pipe I/O and live PTY byte pumping can run without a join. Host exec reuses the same process kernel, ELF/script loader, shared resources and memory budgets; it creates no additional runtime owner or service thread. FileProvider writeback deliberately pauses the session when applying staged edits, as chosen by the owner. | [FFI adapter](https://github.com/kb5000/trames-ipad/blob/80304113124ba34a829c4f61f2cb65bc7dad0e39/crates/trames-ffi/src/session.rs), [iPad lifecycle](https://github.com/kb5000/trames-ipad/blob/80304113124ba34a829c4f61f2cb65bc7dad0e39/apps/ios/Trames/TerminalSession.swift), [Mac control](https://github.com/kb5000/trames-mac/blob/aed5daab61092b468bb89a1af5159cc935dd5ea5/crates/trames-mac/src/session.rs) |
| Final teardown and faults | Last/group/default-fatal task completion, final CPU/Memory projections, actual non-notifying native-driver idle/stop, synchronous faults or backend failure | Original GPU/video/audio roots follow actual mm references; pending GPU cancellation/retirement uses completion/unlock notifications. Final task entry and CPU/Memory custody remain owned. CPU View collection does not wait for unrelated accepted native disk work. Guest faults use the original signal path; a host backend error is an error, not an automatic full-VM or software CPU fallback. | [task exit/fault](../../crates/trames-session/src/process.rs), [native lifecycle contract](execution-backends.md#live-native-device-authority--2026-11-03), [HVF error mapping](https://github.com/kb5000/trames-mac/blob/aed5daab61092b468bb89a1af5159cc935dd5ea5/crates/trames-hvf/src/kernel.rs) |

## Fallbacks that do not identify an owner transition

- The native libc registry can return `fallback=true` for a size/operation it does
  not accelerate. The guest implementation continues on the same executor. Its
  `checkpoint_retries` counter represents a different event: an owner boundary.
- A DirectFile fast-path miss (contention, seals, finite limit, mapped or disk
  representation) can enter the common full FileWork path. An ordinary full
  result or native disk wait does not require a coordinator syscall service.
- HVF's mapping diagnostic `Fallback` means delta-range history was unavailable;
  it compares persistent coarse mapping stamps and changed chunks. It does not
  switch to an interpreter or a Linux-kernel VM.
- Single-CPU/solo execution or failed parallel View admission can choose the
  existing coordinated caller path. Mac still executes instructions through HVF;
  iPad still uses its interpreter. A recorded backend failure is surfaced.
- Unsupported syscall/driver functionality can return its existing errno or API
  result. This is not evidence of a successful compatibility fallback.
- AppKit/UIKit presentation has its own UI-thread affinity. Ordinary window input,
  Wayland bytes and frame presentation are not the Kernel's owner syscall RPC.
  HiDPI events use the existing Wayland queue. iPad PiP retains the selected
  session's normal background lifecycle control; GPU suspension waits on actual
  context locks/readiness rather than creating a coordinator or service thread.
  See [display lifecycle](display-lifecycle.md) for the background GPU limitation.

## Remaining cost and interpretation of evidence

The per-filesystem namespace transaction, original inode metadata/byte/position
locks, GPU context/device locks, native disk-pool capacity, manifest durability,
View generations/dirty commit and HVF mapping synchronization still cost time.
They must be measured as actual resource work or publication, rather than counted
as coordinator messages. In particular, private namespace mutations retain their
original durable manifest checkpoint; native filesystem lifecycle references do
not make the same per-operation persistence promise.

`service_requests=0` is insufficient to prove owner independence. A direct
checkpoint, unsupported SVC/HLT, signal/control action or legacy scheduling wake
can end a cohort without sending a Service event. Conversely an in-cohort service
can complete while peer CPUs continue. Inspect together:

1. source worker/direct/file/socket/uring completions and retained identities;
2. Service requests and caller wait;
3. cohort rounds and stop/dispatch time;
4. affected-mm VM checkpoint groups, wait/commit/resume timing;
5. native entry retries, mapping delta/coarse comparisons, resource and disk time;
6. the actual before-effects defer, terminal errno, or source-copyout boundary.

The source audit lists reachable current implementation boundaries. The namespace
acceptance verifies its admitted workflows, not the frequency of every remaining
boundary in Firefox or a complete server workload. No whole-application trace or
claim that all these owner paths were exercised is made here. The 2026-11-04 transfer, event-wait, timer and signal migrations update this inventory; the remaining owner
boundaries are still reachable.

### Shared child waits and lifecycle publication (2026-11-05)

The parent process now owns an original shared `Children` object. CLONE_THREAD
shares it; a fork starts a new family. Each child group owns one original
wait-event object, also shared by its threads. Birth, credentials, process-group
changes, reparenting and completed group exit publish structural metadata at
actual custody boundaries. Ordinary owner waits do not rebuild the process
directory after every query, and worker waits never access that directory.

Supported wait4/waitid selection, WNOHANG, WNOWAIT, stopped/continued events,
namespace PID translation and result formatting use this same object from the
owner and source workers. A blocked accepted wait subscribes to both its parent
family and original task/process signal queues before checking readiness. It
returns the execution slot, resumes on existing executors and preserves caught
signal EINTR/SA_RESTART behavior without a service request. Sibling waiters
consume an event once under the parent's object lock. Guest copyout and wake
callbacks run after releasing resource locks.

A consumed exit retires shared PID presence immediately, so kill(0), prlimit and
proc observations cannot expose a reaped child while its owner projection is
awaiting collection. Task visibility handles and original child objects prevent retained
completion handles from keeping a PID visible or retargeting its replacement.
Native ARM Linux oracle checks also corrected pre-existing ABI differences:
WNOHANG without a result does not preflight output pointers; a copyout EFAULT
after consumption does not restore the event; waitid copies rusage before
siginfo while wait4 copies status first. WNOWAIT still preserves the event.

**The remaining lifecycle migration is still open.** Default termination,
live task exit/group-exit cleanup, clear_tid,
parent-death/reparenting policy, namespace-init teardown and CPU/Memory/VFS
projection collection still run at their existing lifecycle boundaries.
`Epoch::finish` still stops its cohort. Exit events become waitable only after
the current cleanup has finished and all group members have exited. None of
these remaining dependencies is relabelled as a worker fast path or hidden RPC.

Cross-cohort adoption keeps child waits disjoint from generic I/O retry
transport. A previously blocked wait4/waitid owns its accepted `ChildWait`
request; importing a second `IoCall` for the same syscall would replay it as
unsupported I/O after the child event completed. The real Kernel adoption test
covers both APIs. Existing owner-event resource envelopes remain an explicit
compatibility boundary; they are not erased by this lifecycle change.

Completed owner projections are collected after worker Views return and before
processing the next returned owner syscall. This makes an immediate getpgid (and
other owner PID queries) observe the same reaping as signal/limit directories;
collection is not deferred to the next cohort's admission. The adoption test
follows each successful source wait with an owner getpgid and requires ESRCH.


### Original thread-group stop/continue control (2026-11-05)

Each original `IoTask` belongs to one shared `task_control::Group`; CLONE_THREAD
adopts the same object and a fork starts a new one. This is an overlay over the
original ready/futex/sleep/signal/child/I/O/GPU state, replacing the owner-private
`State::Stopped` and saved-state wrapper. It does not copy waits or repeat an
accepted syscall. Guest kill/tkill/tgkill, timer targets, FASYNC, resource signals
and parent-death producers use the same generation path. Opposing STOP/CONT
queues are cleared under this group's control lock; notifications run afterward.
SIGCONT resumes the group even when its disposition is ignored or masked.
The same-session permission exception applies to all three guest send APIs.

A running assignment holds a group execution lease. Actual CPU backends can
bind their neutral `ExecutionInterrupt`; STOP requests exits only for this
group's active members. The control lock does not cover guest execution or
native work. The relaxed stop flag is scheduling state, not a guest-memory
barrier. WUNTRACED/SIGCHLD is published only after every live member returns its
CPU and finishes accepted uninterruptible kernel work. Pending KILL suppresses
a late stop acknowledgement. An existing owner VM batch also holds this lease
and skips further guest execution after a stop request.

STOP preserves original subscriptions, operands, OFDs, deadlines and results.
Interruptible user waits stay parked; accepted disk/GPU work, hardware readiness
and ring background work can finish on their existing executors. Expired user
poll/socket/signal deadlines do not spin while stopped. The run queue rearms the
original task wake under its mutex before checking level state and parking.
This closes the real STOP -> CONT notification-coalescing race without a new
transport, polling loop or service thread. A one-slot/four-slot regression runs
four consecutive group stop/wait/continue/wait cycles without an owner request.

Birth, process-group/session changes, namespace changes and reparenting still
publish structural relationships at their existing boundaries. Orphaned groups
ignore default TSTP/TTIN/TTOU; SIGSTOP keeps its unconditional disposition.
Tracing and an actual excluded owner resource retain their existing boundary.
In particular, vfork and accepted mapped-file/legacy-owner work cannot be
acknowledged away: those original dependencies still finish before the group
reports stopped. No all-resource or all-lifecycle owner-independence claim is made.
`Epoch::finish`, exit/group-exit, clear_tid and final resource teardown remain.

The Linux signal-generation and group-stop behavior was checked against
[Linux v6.18 signal.c](https://github.com/torvalds/linux/blob/v6.18/kernel/signal.c).
The paired product evidence includes native ARM Linux, the Mac HVF backend,
the production interpreter and an iPad device-target compile. It does not claim
physical-iPad execution or a whole-browser speedup.

### Shared cgroup hierarchy, freezer and control events (2026-11-05)

The original cgroup v2 hierarchy, TID incarnations, pids counters and device
attachments are now shared resource state. Actual cgroup mounts participate in
the ordinary source pathname/namespace algorithms. Their control OFDs retain
the original inode and hierarchy, rather than an owner VFS or a copied file
body. Read/write, vector and positioned I/O, seek, directory operations and
poll/epoll use these resources from the owner and source workers. The caller's
PID namespace and credentials bind each operation; passing an OFD does not
pass its creator's administrative authority.

Each IoTask retains its original membership capability. Moves update that
member, so a previously retained device factory observes the current cgroup's
policy. Member retirement validates original identity; a late handle cannot
remove a replacement that reused its numeric TID. Hierarchical population and
frozen counts update at birth, move, acknowledgement and retirement, instead
of scanning every task for each pids.current/cgroup.events read. Hierarchy
transactions use the actual resource lock. Ordinary executor freeze tests
read the member's relaxed atomic flag without acquiring that hierarchy lock.

Freeze interrupts only affected active CPUs using the existing group execution
lease and backend interrupt. The normal owner CPU quantum also holds this
lease, as does the existing VM batch. A request is distinct from completion:
`cgroup.events:frozen=1` waits for execution and accepted uninterruptible work
to relinquish each member. Ancestor freeze, nested local freeze, live migration,
SIGKILL and thaw preserve original waits and their execution-slot ownership.
No message bus, service thread, guest-memory barrier or shadow task registry
is introduced. A non-leader exec can rekey a running lease; completion finds
that same original member after the key changes.

The actual control inode owns its event generation and readiness. Population,
completed freeze and pids limit events notify existing epoll/inotify channels
after resource locks are released. Poll does not acknowledge a change; reading
the original OFD does. Initial and removed control files expose Linux kernfs
ERR/PRI behavior. Deletion/recreation and controller removal keep old FD
identity, wake its waiters and return ENODEV rather than redirecting a retained
operation to a replacement control file. The implementation was compared with
[Linux kernfs](https://github.com/torvalds/linux/blob/v6.18/fs/kernfs/file.c),
[the freezer](https://github.com/torvalds/linux/blob/v6.18/kernel/cgroup/freezer.c)
and the [cgroup v2 interface](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

This removes the cgroup resource dependency, not the remaining task-lifecycle
entry. Structural fork admission and final exit still call the same hierarchy
at their current joined boundaries. BPF control installation, cgroup
namespace/mount topology, full exit cancellation and final Files/mm/native
ownership remain explicitly joined. A standalone VFS without a bound TaskSignal
retains its legacy kill-ID collection API; production tasks bind the original
IoTask and receive cgroup.kill directly. The fatal signal still reaches the
documented exit cleanup boundary. No owner-independence claim is made for that
remaining lifecycle chain.


### Original task addresses and resource retirement (2026-11-05)

Each original task now owns one `ThreadAddresses` object. Worker snapshots,
the Linux ABI and successful exec retain that same object; fork creates a new
one and exec clears the original registration. `set_tid_address` runs on the
calling worker, including existing ALLOW/ERRNO filter decisions, without joining
peer CPUs. Registration stores an address; it does not touch or preflight user
memory. Actual exit later attempts the write and ignores its fault, matching
[Linux fork.c](https://github.com/torvalds/linux/blob/v6.18/kernel/fork.c).
The real multithread acceptance registers a read-only address, makes it writable
later and observes clear_tid/futex completion. A denied registration leaves the
original CLONE_CHILD_CLEARTID address intact.

`FileTableOwner` represents one real task reference to the original Files
membership. Cloning a capability retains that reference; CLONE_FILES creates a
new task reference. Final retirement atomically wins once, removes real numeric
membership under its existing object mutex, then releases POSIX locks and drops
complete original OFDs outside that mutex. Accepted operations keep their own
OFD leases. Old factories, late reserved publications and late owner projections
cannot resurrect a closed table. No Rc strong count decides shared resource
lifetime. The existing owner exit path now uses this algorithm too.

Complete descriptions share lifetime even when their bytes require another
entry: stdio, terminal, volatile proc nodes, bridge/log and native image resources
are not excluded merely by kind. Actual owner epoll watch graphs, non-shared
namespace projections, OOM/network proc controls and mount-watch objects remain
explicit owner destructors. Retirement reports their count. Dynamic content,
path authority and task policy keep their actual admission; shared lifetime does
not manufacture worker byte authority. A fixed io_uring proc file retains its
original identity after close/reuse, while its body still defers before effects.

`ProcessRecordLocks` exposes the original process registry/owner pair for
resource-local retirement. `UringActor::cancel_task` cancels only the original
mm/submitter's requests, even after ring close and numeric FD reuse. Owner exit
and source cancellation use the same algorithm. CQ publication and retired lease
callbacks follow the original ring lock; accepted native jobs retain staging.
Legacy owner-ledger reaping remains explicit. These capabilities add no resource
thread, bus, polling loop, global algorithm lock or guest memory barrier.

Sharing complete descriptions also required removing a temporary-position
assumption: volatile file bytes and cgroup read/write/seek now use their original
OFD position, including owner/source and dup interleaving. Positioned writes
keep their no-f_pos-update behavior. The regression checks EOF, seek and mixed
owner/source writes on the same control OFD.

**Actual exit is still a joined lifecycle entry.** The new retirement APIs remove
resource dependencies; they do not by themselves migrate `exit_one`, group exit,
parent-death/reparenting, namespace-init teardown, robust-futex handling, final
mm/native maps or CPU/VFS projection collection. `Epoch::finish` still stops its
cohort. The next dependency migration must address those actual graphs, not
label an owner cleanup request as a source exit. Tracing, vfork and accepted
mapped-file/owner work keep their existing custody boundaries.


### Source individual thread exit and original parent-thread links (2026-11-05)

The original group arbitrates individual exit under its existing control lock.
It keeps one actual last member for final process cleanup; sixteen simultaneous
exitters leave exactly one live member. An allowed exit(93), with another live
member, cancels the submitter's ring requests, retires
cgroup membership, clears its original clear_tid address, wakes one original
futex waiter and retires Files on the calling worker. Non-leader PID visibility
is retired immediately. A leader's waitable process identity remains, and
ordinary process signals still reach its live group after that leader exits.

`Parents` owns the actual parent-thread graph; each task has one original
`Parentage` with relaxed scalar registration. Source and owner paths share this
graph. PR_SET/GET_PDEATHSIG run on the calling worker under existing filter
semantics. Death updates only that parent's original children, selects a live
survivor within the relationship transaction and notifies after unlocking.
A retained task cannot target a new task that reused its TID. Non-leader exec
retains the actual surviving thread through future-TID publication. Normal
cohort capture does not lock/rebuild this graph. Childless retirement does not
search a process table, select a survivor or acquire another group lock.

Already accepted source exit returns its CPU/View to the existing queue without
stopping unrelated jobs or sending an owner service. Remaining owner projections
are collected from an event on their existing owner after the exiting View
returns, without joining the other CPUs. CPU metrics remain with the returned
CPU until cohort drain; final group exit still joins before completing. Their collection is not presented as
already performed on the source. Clear_tid joins can proceed before that cold
collection, as ordinary exit already permits before all teardown completes.
Actual legacy futex-wait adoption keeps its existing scheduling boundary.

Removing the unconditional stop exposed a missing mm completion notification.
If another task had requested a mapping checkpoint, an exiting peer could return
the final active View without publishing VmReady. The owner then waited while
the requester remained held, although its futex ticket was already woken.
`Epoch::finish` now notifies original domain quiescence. A deterministic test
fails without this notification and passes with it; it asserts that the cohort
continues. No all-CPU stop, timer retry, polling loop or service thread substitutes
for the missing notification. Temporary diagnostic code was removed.

Owner group exit and exec also mark every removed original task dead; group exit
uses the same original parent-death and ring-cancellation resources instead of
silently dropping those threads. The Linux reference is
[exit.c](https://github.com/torvalds/linux/blob/v6.18/kernel/exit.c).

**The full lifecycle migration remains open.** The last member, exit_group,
default fatal termination, full process reparenting/subreaper and namespace-init
teardown, robust-futex support/cleanup and final mm/native ownership still need
their actual dependency migration. Operations on owner epoll/namespace/proc/mount
controls keep their explicit before-effects boundary; their presence no longer
refuses an otherwise admitted non-last exit. Tracing, legacy ancillary reaping
and accepted owner/mapped-file operations retain their documented custody.
Vfork creation and successful exec still use their structural owner entry; its
original release event and admitted parent wait now have source paths.
The ordinary syscall/native hot paths gain no new policy or guest-memory fence.

### Original process families and completion notifications (2026-11-05)

`Family` is the process group's actual shared parent/subreaper state. Threads
share it; a fork gets a fresh subreaper flag. Source getppid and
PR_SET/GET_CHILD_SUBREAPER read/write those original scalars, including the
existing ALLOW/ERRNO filter decision and checked guest copyout. They do not copy
parentage into a worker-only policy table or broadcast a change across Process
projections. Scalar accesses remain relaxed atomics.

`Families` owns the original parent/children graph. Structural registration,
adoption, final-status publication and PID-namespace victim selection transact
there; callbacks follow its lock. Parent wait membership and the parent signal
group are one Child relationship, so later STOP/CONT notifications reach the
same original parent as waits. Adoption updates the shared process parent and
all original live parent-thread links. Subreaper search stays within the active
PID namespace. A zombie adopted by an ignoring/NOCLDWAIT parent retires its
original wait/PID presence directly. Disposition comes from an actual live
parent member even if its leader thread has already exited.

Nonleader exec keeps the original Family, Child and descendants while replacing
the original task-presence binding. Registration must refresh that identity even
when numeric PID, process group and UID do not change. Pruning retains a live
family through this handover. The deterministic regression loses the original
children/wait result without these changes, and passes with them. This fixes the
full namespace program's blocked parent without a timeout, retry or polling fix.

This is dependency migration, **not final source process exit**. The existing
lifecycle owner still determines the last-member boundary and holds CPU/VFS/mm
and native-context teardown. It calls the same Family retirement/completion API;
namespace victims are original identities, then their remaining CPU projections
are collected by their existing custodian. Last-member exit, exit_group/default
fatal exit, robust-futex support and final mm/native ownership remain open, as do
actual owner epoll/namespace/proc/mount destructors, tracing/vfork and accepted
owner/mapped-file work. No resource thread, message bus, ordinary guest-memory
barrier or extra native permission model is added.

Namespace shutdown passes each original victim group to the existing full-group
cleanup, retaining its waitable leader until its peers retire. Removing the
leader projection first used to skip original group completion, including when
that leader was already a zombie. The regression covers both live and previously
exited leaders and fails against the old per-thread collection loop. This fixes
resource retirement; the final cleanup itself is still owned, not a source exit.

### Original native address-space lifetime and completion retirement (2026-11-05)

Native GPU, video and audio contexts belong to one actual mm resource, not the
Kernel's maps keyed by a projected vm_id. A real CLONE_VM task acquires one mm
reference. Capturing or cloning a worker capability retains that same task
reference; it cannot postpone logical retirement. Fork gets a separate native
space. Successful exec retires the old task's reference and creates a fresh
space; other real CLONE_VM users retain their original devices. Failed exec does
not change ownership. Source individual exit and owner lifecycle cleanup retire
the same original reference, idempotently.

The final reference takes original resources under their membership mutex and
releases them after unlocking. Device/context leases accepted earlier keep their
actual native dependencies. Weak caches do not own contexts: initialized ordinary
lookups bypass mm membership locking, and source native calls keep their existing
captured context/stream leases. No device is created for an ordinary headless mm.
The private Rc Vulkan graph remains behind its existing exclusive context lease;
this batch adds no unsafe Send/Sync declaration or guest-memory access policy.

Canceled native compilation and final GPU retirement use original completion
and availability subscriptions. A temporary keepalive retains the original graph
until its native work finishes, then breaks outside both object locks. Driver
callbacks try the context once and return when busy; an actual unlock retries the
pending event. A notification state machine closes completion/unlock races and
coalesces reentrant notifications. Its loop drains actual events, never polls a
busy mutex. Signals are rearmed for later completions, and reaper unlock also
notifies displaced normal native callers. An unlock also collects a completion
already observed by another native caller. The reaper excludes its own listener
when publishing its unlock, so it cannot create self-triggered polling. Only
actual retirement work registers these callbacks. Normal context leases gain no new retirement check.

Kernel-owned GPU/video/audio lifetime maps, ProcessMap native-liveness scans and
the owner drive-loop abandoned-GPU poll are removed. Group exit/exec also abandon
the removed original threads' accepted GPU jobs. Tests prove that unrelated
headless execution continues while another native context is occupied, and that
last-mm release returns before two gated native compilation jobs complete.
Reintroducing the old owner poll or removing completion-owned retirement makes
those guarded regressions fail. They release their gates before failing; a test
failure cannot strand a compiler or Kernel test thread.

The existing native final idle/destruction algorithms are retained. MoltenVK
observed fences provide asynchronous pending-submission retirement on Mac/iPad.
A backend without native fence notifications retains its actual native idle call;
this is not advertised as a new asynchronous fence implementation for that
backend. Native audio/decoder stop APIs retain their existing behavior. Last/group
and default-fatal task entry, final CPU/Memory projection custody, robust futex and
actual owner controls still need their connected migration. This batch removes
the native ownership/polling dependency, not the remaining full process boundary.

## Original thread-group exit completion — 2026-11-05

The original Group now separates execution retirement from cleanup completion.
Begin-exit marks the original IoTask dead under the group lock, decrements its
live membership, and retains its member until cleanup finishes. Source non-last
exits finish membership after Job::finish drops their retained guest View and
the existing owner collects the returned Memory/private-control projections.
Owner exits finish after original resources and local projections have returned.
The last begin-exit fixes an ordinary final status; an earlier explicit group
termination fixes it once. Cleanup finish order cannot change this status.

The same original group supplies last-member and final completion decisions to
process locks, family publication and host completion. These decisions no longer
scan ProcessMap or infer death from a temporarily absent owner-held caller. Live
membership is maintained under the existing group mutex; no ordinary guest
access gains a fence or a new global/resource lock. Member identity still uses
the original IoTask, including nonleader exec rekeying. A late stop/hold
projection cannot register a retired task as a new member.

Returning source-exit CPUs collect only owner-local Memory/VFS and scheduling
projections. They do not repeat io_uring cancellation, parent-death delivery,
clear_tid, descriptor/native retirement or native-job abandonment. A guarded
regression holds the original native context occupied while this collection
finishes; injecting legacy native cleanup makes it fail without hanging.
Original owner-local ancillary-rights and detached-mount projection collection
still runs after source descriptor retirement; original OFDs are not retired
again. Ordinary owner exits use that same collector once.

The completion phases are a prerequisite for, not completion of, source last-
member/group/default-fatal exit. Their entry still joins the cohort. Final
CPU/Memory custody, source namespace-init termination of actual victims, robust
futex support and operations on actual owner controls remain connected work.
Original vfork release and namespace completion dependencies are implemented below. No new service thread, polling bus, owner RPC or admission gate
is introduced in this batch.

## Original vfork release and cold projection completion — 2026-11-05

A vfork parent and its actual child share one release object. Creation still
uses the structural clone owner entry. The admitted parent parks on original
readiness in the existing execution queue and returns its slot. A source exit
publishes release after dropping the dying CPU's View; it does not wait for the
old owner to destroy private controls or drain unrelated CPUs. Owner exit and
successful exec finish the same object once. No numeric-PID ProcessMap scan,
new service thread, periodic retry or message bus is used. Linux's
[mm_release](https://github.com/torvalds/linux/blob/v6.18/kernel/fork.c) completes
vfork before full process/FD destruction, even when other child threads remain.
Release/acquire is confined to this actual parent/child completion event.
Pending vfork preserves uninterruptible stop custody; a finished release permits
STOP acknowledgement without running guest instructions. Background io_uring
CQ progress cannot retire that lifecycle wait or replace its clone return value.

Non-last source exit no longer rejects a Files table containing opaque owner
controls. Original logical descriptor retirement happens on its caller; the
private Rc controls remain on their actual owner. A coalesced event on the
existing completion channel collects those controls and the exited Memory
wrapper while other CPU Views continue. Group cleanup membership finishes after
that cold collection. CPU/metrics adoption still occurs once at cohort drain.
The event is asynchronous cleanup, not a source syscall RPC or a new owner poll.

Weak, owner-local references, captured only when a source exit actually returns
its wrapper, preserve final backing publication if the dispatched wrapper retired but an undispatched
CLONE_VM task retains the actual graph. They add no real mm owner, keep no RAM
alive and do not change private-view admission. A guarded mapped-file test drops
the wrapper before commit and verifies both the retained peer and real backing.
A full queue regression also leaves the only other mm owner undispatched and
checks the real backing, not merely a still-cached guest view. Disabling the
retired-root commit makes it fail. Ordinary capture allocates no weak-root
registry; unchanged live wrappers use the prior commit deduplication.

A sole runnable original vfork child can now admit its actual waiting parent by
release-object identity. It no longer needs an unrelated runnable task to enter
the source queue. Removing this admission fails the same full-queue regression
before dispatch. Structural clone/exec authority remains on its existing owner.

Original Families now store final status, optional host completion and pending
namespace dependencies in their existing relationship graph. Retiring nested
init records original victim families even if an ancestor already marked that
namespace dead. Each actual completion releases its dependents; init status and
parent/host notification are published once after its victims complete. This
removes cleanup-order assumptions, not the current joined execution of namespace
shutdown. Victim control references are original Groups for the next connected
source-termination migration.

Validation covers an occupied owner while a vfork parent resumes and another
CPU spins, an actual unique legacy epoll control, release while STOP is pending,
background ring CQ progress, cold private-control destruction while source
captures remain live, backing publication and nested namespace completion. Two
negative controls disable direct source release and ancestor-dead namespace
tracking separately; both fail their corresponding behavioral guard. The same
static C vfork fixture runs under native ARM Linux, Mac HVF and the iPad-shared
interpreter. Product evidence lives in trames-ipad's
`docs/validation/source-completion-20261105.json`.

Last-member exit(93), exit_group(94), default-fatal cleanup, final mm/CPU custody,
source namespace victim termination and excluded control operations remain open.
The current source path keeps one live group member for that joined completion;
this batch does not add another admission gate or claim full owner independence.

## Source process exit and CPU/mm return — 2026-11-05

This supersedes the historical last/group-exit and final-CPU restrictions above.
An original Group records one terminal request and kicks its existing execution
interrupts. Running, parked, stopped/frozen and traced peers observe that request
before executing more guest code. Normal traced syscalls and non-ALLOW seccomp
effects keep their explicit policy boundary. The caller retires original parents,
cgroup membership, clear_tid/futex wake, Files, process locks, timers, ring work
and native-space references once. Namespace-init retirement returns original
victim groups, including nested dependencies whose ancestor is already dead.

The existing completion queue hands the full Done CPU, metrics and actual exit
resources to its owner immediately, rather than saving a PID-only projection
until cohort drain. The owner destroys its local Rc controls, publishes necessary
backing writes and finishes original group/family cleanup. Parent waits may then
resume in the same execution cohort while unrelated CPUs are still busy. No new
service thread, syscall RPC, polling bus, ordinary guest barrier or unsafe block
is introduced.

Cold members outside the cohort retire through the same original resources.
If another live process shares their mm, a byte-only mm checkpoint returns its
private execution actors and clears their exclusive reservations. Cleanup borrows
the unchanged snapshot and restores those CPUs without a mapping rebuild or
backing-domain closure. A concurrent structural request upgrades that checkpoint
before it resumes. Original task identity guards cold work; original mm identity
guards detached physical memory, so PID reuse cannot redirect either completion.

Guarded external borrowers may outlive a task. Retired publication keeps the mm's
dirty-word journal until those generations return, including a borrower marking a
second frame while the provider publishes the first. Lazy original readiness
notifies the existing owner when the last View returns. Logical group/parent
completion does not wait for that external reference. Private execution is never
concurrent with coordinator byte publication; actual object locks and existing
private-view admission retain the same memory contract on Mac and iPad.

Validation includes parent resumption before unrelated CPUs finish for individual,
group, default signal and synchronous fatal exits; running, sleeping, traced and
cold group members; clear_tid visible to a surviving CLONE_VM process; an external
mm borrow held across wait/reap/PID reuse; and a deterministic late dirty-bit
publication race. Linux semantics are checked against original
[exit_mm and exit task work](https://github.com/torvalds/linux/blob/v6.18/kernel/exit.c).
Remaining boundaries include structural clone/exec, mapping topology, tracing and
non-ALLOW policy, excluded owner resources and original legacy waiter adoption.
