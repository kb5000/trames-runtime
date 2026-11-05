# Coordination and fallback boundaries

This is the consolidated implementation audit through the source thread-exit and parent-thread resource
batch, 2026-11-05. Mac HVF and the iPad interpreter use the same userspace Linux
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
    Entry --> Compat[Unsupported owner resource or final group exit]
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
The remaining connected lifecycle unit is default termination -> task/group
exit -> clear_tid/robust-futex and accepted-operation cancellation -> final
files/mm/native-context release -> reparenting and reaping. Structural fork/exec
and security-policy mutation retain their actual boundaries. The full lifecycle
chain is still open; forwarding an entry alone does not remove those dependencies.


### Other boundaries

| Area | Actual trigger / examples | Current scope and status | Authoritative implementation |
| --- | --- | --- | --- |
| Task lifecycle and process graph | clone/fork/vfork, exec/execveat, exit/group exit, wait/waitid, reparenting and cancellation | Shared wait4/waitid, STOP/CONT and set_tid_address run on source workers. Individual exit(93) with another live group member retires original resources on its source worker. Final group exit, actual excluded control destructors, structural child/task/VM ownership and projection collection retain their boundaries. The current whole-cohort scope is an implementation boundary, not a claim that every unrelated address space fundamentally needs pausing. | [process lifecycle](../../crates/trames-session/src/process.rs) (`fork_state`, `exec_at`, `exit_one`, `wait`, `syscall`) |
| Signals and mutable security/task policy | Default termination, credentials/capabilities, affinity, seccomp installation/TSYNC and non-ALLOW actions | One private/process mailbox serves ordinary guest sends, timers, FASYNC, faults and owner producers. Ordinary kill/tkill/tgkill routing, altstack/actions/masks/pending, sigtimedwait/sigsuspend and signalfd read/readv run on the source worker. Caught handlers and sigreturn share the same frames. STOP/CONT uses the original group state and parent wait/SIGCHLD; default termination still requires exit cleanup. Signal-control seccomp ERRNO/unsupported TRACE/USER_NOTIF complete locally; TRAP/KILL and tracing retain their explicit task-policy boundary. | [entry and delivery](../../crates/trames-session/src/process.rs), [shared I/O signals](../../crates/trames-kernel/src/signal/io.rs), [worker decisions](../../crates/trames-session/src/workers.rs), [seccomp](../../crates/trames-session/src/process_seccomp.rs) |
| Structural namespaces and administrative controls | mount/umount/pivot_root, unshare/setns, BPF syscall/control installation, dynamic proc/sysfs projections | Joined owner path. Mount and task namespace topology, credentials and remaining owner Rc control graphs have not been migrated. Cgroup paths, controls, membership and notifications use the shared resource graph described below; cgroup namespace/mount changes and the structural fork/exit entry still join. Ordinary mkdir/unlink/rename/metadata and shared cwd/root are separate shared resources. | [owner syscall dispatch](../../crates/trames-session/src/process.rs), [mount topology](../../crates/trames-vfs/src/mounts.rs), [namespace topology](../../crates/trames-vfs/src/linux_namespace.rs) |
| Dynamic/special pathname and FD resources | Dynamic proc/sys refresh, non-admitted nsfs/mqueue mounts, dynamic file bodies, controlling-terminal acquisition and excluded open types | Before-effects defer. Actual cgroup mounts are admitted through their original shared graph and OFDs. Namespace calls preserve copied operands and accepted shared FDs in `FileOutcome::Owner`; the joined resolver handles remaining owner controls. Other path queries return `None` for their owner entry. A typed defer is not a new guest errno. | [path authority](../../crates/trames-vfs/src/path_queries.rs), [node/open admission](../../crates/trames-vfs/src/lib.rs), [proc synthesis](../../crates/trames-vfs/src/pseudo.rs), [namespace handoff](../../crates/trames-vfs/src/namespace_work.rs) |
| Residual generic FD/network compatibility service | A direct descriptor/control admission does not handle the actual resource; generic network controls, old epoll creation, lseek/fstat or eligible stream byte paths reach `service_candidate` | In-cohort owner service where admitted. Dynamic proc, tracing/filter restrictions, unsupported kind, blocking EAGAIN, EPIPE and internal unsupported results can reject it and request a joined owner path. Ordinary shared file/socket hot paths precede this service; its existence does not show their normal calls use it. | [candidate numbers](../../crates/trames-session/src/worker_syscalls.rs), [actual admission and effects](../../crates/trames-session/src/process_service.rs) |
| Cross-resource transfer | sendfile/splice between admitted regular files, pipes, Unix streams and TCP | Original OFD pairs execute on the calling worker. Backpressure parks only that task on original readiness; native disk jobs reuse the existing pool. Joined short operations borrow the original VFS without building a retained island. Actual mapped-file layout changes keep affected-domain checkpoints; excluded owner/dynamic resources defer before effects. tee/vmsplice remain unsupported. | [accepted transfer](../../crates/trames-vfs/src/stream_transfer.rs), [source execution and waits](../../crates/trames-linux/src/direct/file.rs) |
| POSIX and real interval timers | timer_create/gettime/getoverrun/settime/delete and getitimer/setitimer | Shared timer objects execute on the caller. A short deadline-index transaction updates the original execution queue; existing workers process a bounded batch of due timers outside that queue's mutex. SIGEV_NONE keeps lazy periodic phase without an armed host deadline. Process/thread signal targets retain their original incarnation. Timer STOP/CONT uses shared group control. Default termination and lifecycle cleanup retain their actual boundary; unsupported CPU-clock/virtual/profiling timers are not added. | [shared timer ABI and index](../../crates/trames-kernel/src/timers.rs), [original signal targets](../../crates/trames-kernel/src/signal/io.rs), [execution queue](../../crates/trames-session/src/run_queue.rs) |
| Event waits and remaining owner/mixed cases | Admitted pselect6, ppoll, epoll_pwait and epoll_pwait2, including temporary masks, use workers; excluded owner/dynamic FDs, tracing, unavailable source pumps and actual lifecycle/task-policy effects retain their boundary | One imported wait retains original OFDs/sets, mask and deadline through parking and cohort handoff. Source I/O signals interrupt locally and sigreturn restores the pre-wait mask. All pending sources now use the same queues. Caught signals interrupt locally; STOP/CONT retains the original wait and uses shared group control. Default termination still requests exit cleanup. | [poll ownership](../../crates/trames-linux/src/poll.rs), [wait admission](../../crates/trames-session/src/process.rs), [cohort control](../../crates/trames-session/src/process_vm.rs) |
| Unix ancillary owner controls | SCM_RIGHTS that contains an actual excluded owner control; owner-ledger reaping and a legacy destination/control projection | Retained original endpoint/rights handoff and owner graph work. Portable Unix sockets/rights and ordinary native Wayland transport already share the real resource graph. A mixed owner set is still excluded. | [message handoff](../../crates/trames-linux/src/direct/local_message.rs), [rights ledger](../../crates/trames-vfs/src/ipc.rs), [portable graph](../../crates/trames-vfs/src/ipc/shared_rights.rs) |
| VM and pin topology | brk growth, munmap/mremap, non-additive mmap, mprotect, mincore/madvise and io_uring buffer pin/register variants requiring mm edits | Affected mm/backing checkpoint on the existing run queue. The owner commits and rebuilds the required Views; unsupported/external generations, tracing or non-ALLOW policy can escalate to a joined path. Additive private-anonymous mmap has a separate in-cohort owner publication path. | [VM ABI classification](../../crates/trames-session/src/worker_syscalls.rs), [domain queue](../../crates/trames-session/src/run_queue.rs), [VM commit](../../crates/trames-session/src/process_vm.rs), [View admission](../../crates/trames-memory/src/parallel.rs) |
| Mapped-file layout | Truncate/growth/allocate that changes a live mapped backing layout | Only affected original mm instruction views are quiesced, then the same disk pool runs the accepted file operation. Completion releases overlapping pause counts. Byte transfer and sync alone do not imply this checkpoint. | [file checkpoint](../../crates/trames-session/src/process_file_io.rs), [original file job](../../crates/trames-vfs/src/file_work.rs), [resize](../../crates/trames-vfs/src/memfd.rs) |
| io_uring owner escalation | Actual owner resource/SQE, unavailable event subscription or source pump, mapped layout; buffer pins requiring structural authority | Canonical ring state stays shared. `owner_required` hands real owner work back to the Kernel; accepted SQEs keep their original source context. Source background progress on sleep/futex is ordinarily event-driven. No separate ring service thread exists. New namespace SQE opcodes are not added by the namespace batch. | [actor](../../crates/trames-linux/src/direct/uring/actor.rs), [source maintenance](../../crates/trames-linux/src/direct/uring/background.rs), [subscriptions](../../crates/trames-linux/src/direct/uring/wait.rs), [file results](../../crates/trames-linux/src/direct/uring/actor_file.rs) |
| Native guest mapping and exceptional native memory entry | Vulkan shared host-allocation mapping import where `can_import_mapping` is false; unstable native entry code; live-private backing or a native access mode requiring a checkpoint | GPU/native typed checkpoint before body effects; current worker returns the pending HLT to the owner. Ordinary CPU/native bytes keep the common permission/backing model. The GPU context mutex and compiler/fence waits are normally resource waits. | [Vulkan import](../../crates/trames-vulkan/src/backend.rs) (`Invocation::Checkpoint`), [native memory](../../crates/trames-memory/src/parallel/native.rs), [entry registry](../../crates/trames-accel/src/native.rs), [GPU wait](../../crates/trames-session/src/gpu.rs) |
| Scheduler/cohort membership | Legacy futex wake target cannot schedule into its current epoch; a newly eligible nonmember, affinity/control change, instruction allowance or actual owner signal or task event requires scheduling | Current cohort scheduling boundary. Existing epoch members and ordinary readiness continue locally. Idle or periodic host-control checks do not automatically imply teardown: `cohort_control` decides whether to join. | [legacy wake](../../crates/trames-session/src/futex.rs), [worker stop](../../crates/trames-session/src/workers.rs), [cohort selection/collection](../../crates/trames-session/src/process.rs), [control checks](../../crates/trames-session/src/process_vm.rs) |
| Embedding and terminal/session lifecycle | Transfer/timezone command, pause/cancel, terminal create/close/resize, foreground group signal/hangup, actual systemd supervision event; Mac admin/shutdown/deadline/memory-pressure request; host-authorized exec process creation and process-group signal | Host control requests a join for actual lifecycle work. Routine FFI status snapshots, retained exec pipe I/O and live PTY byte pumping can run without a join. Host exec reuses the same process kernel, ELF/script loader, shared resources and memory budgets; it creates no additional runtime owner or service thread. FileProvider writeback deliberately pauses the session when applying staged edits, as chosen by the owner. | [FFI adapter](https://github.com/kb5000/trames-ipad/blob/80304113124ba34a829c4f61f2cb65bc7dad0e39/crates/trames-ffi/src/session.rs), [iPad lifecycle](https://github.com/kb5000/trames-ipad/blob/80304113124ba34a829c4f61f2cb65bc7dad0e39/apps/ios/Trames/TerminalSession.swift), [Mac control](https://github.com/kb5000/trames-mac/blob/aed5daab61092b468bb89a1af5159cc935dd5ea5/crates/trames-mac/src/session.rs) |
| Final teardown and faults | Unfinished compiler/native context cancellation, task/context destruction, guest synchronous fault delivery or backend failure | Owner lifecycle remains. CPU View collection does not wait for unrelated accepted native disk work. Guest faults use the original signal path; a host backend error is an error, not an automatic full-VM or software CPU fallback. | [task exit/fault](../../crates/trames-session/src/process.rs), [native lifecycle contract](execution-backends.md#live-native-device-authority--2026-11-03), [HVF error mapping](https://github.com/kb5000/trames-mac/blob/aed5daab61092b468bb89a1af5159cc935dd5ea5/crates/trames-hvf/src/kernel.rs) |

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
member and complete shared OFDs, cancels the submitter's ring requests, retires
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
are collected after all Views return and before another returned syscall can
query them or complete final group exit. Their collection is not presented as
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
their actual dependency migration. Owner epoll/namespace/proc/mount controls keep
their explicit before-effects boundary; a source table cannot admit those owner
projections while the cohort is active. Tracing, vfork, legacy ancillary reaping
and accepted owner/mapped-file operations retain their documented custody.
The ordinary syscall/native hot paths gain no new policy or guest-memory fence.
