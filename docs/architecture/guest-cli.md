# Host and guest interoperability CLI design

Status: **Implemented**, 2026-11-16. Shared static guest CLI, Mac owner commands
and iPad adapters are in source; platform validation is recorded below.

This replaces the initial injected shell helper with a coherent guest-side
`trames` command and matching host-side interoperability operations. It applies
to Linux and Android guests on both Mac and iPad. The host keeps `-e NAME_OR_UUID`
selection and its existing environment lifecycle commands. No new execution
backend or ordinary filesystem/network/native GPU data path is introduced.

Owner clarification, 2026-11-16: supported interoperability permissions default
to allowed and may be restricted as needed. The host owns permission mutations;
the guest permission interface is read-only. File transfer works in either
direction whenever the applicable permission and path access allow it, without
requiring a separate dynamic-mount grant or a per-copy Trames confirmation.

## Starting point

Before this change, `resources/guest/trames` implemented `info`, clipboard read/write,
file listing, `host-cli`, `host-exec` and raw RPC. Linux injection targets
`/usr/local/bin/trames`; Android injection targets `/system/bin/trames`.
The helper exposes JSON frames directly and depends on guest shell/awk.

Mac already has independent host grants, argv subprocess execution, scoped
Trames CLI delegation, clipboard, URL opening, port publication and mount
controls. Its former subprocess adapter supplied null stdin and text output.
iPad has clipboard, URL/device information and Files listing/import/export;
arbitrary host execution and Mac mount/network administration are unavailable.
A shared wire method name alone does not establish product support.

On 2026-11-16 a live Dev Debian guest could run `trames info`. The running
Stable Debian guest had the script but no `/dev/trames` directory. The new CLI
must diagnose this distinct attachment problem; writing a binary alone cannot
fix it. These observations are a baseline, not a promise about future sessions.

## User contract

- Bare `trames` shows concise help and examples. It works without a bridge.
- `status` answers which environment/host is in use and what is available.
- Normal output is readable text. Clipboard and command streams are real data,
  not JSON strings requiring manual unescaping.
- Each group has `--help`. No argument causes a usage error rather than a hang
  or an unexpected privileged action. There are no interactive permission grants.
- `--json` supplies a versioned machine interface. Redirected output has no
  color, cursor movement, spinner or progress messages.
- Guest commands implicitly address the current environment. There is no
  guest `-e` selector for administering another environment.
- The host controls permission policy and can allow or deny capabilities. The
  guest permission interface only reports effective access. Platform restrictions
  remain explicit, even when the configured permission is allowed by default.
- A permitted file transfer works in both directions through the existing file
  backend. A visible mount is optional; its absence alone does not deny copying.

## Command surface

| Command | Behavior |
| --- | --- |
| `trames status` | Current environment identity, host, bridge and network mode |
| `trames doctor` | Read-only diagnosis of injection, PATH, protocol and device availability |
| `trames permissions` | Allowed / not allowed / unsupported capability summary |
| `trames clipboard get` | Write clipboard text to stdout, preserving its bytes and final newline state |
| `trames clipboard set [TEXT]` | Set literal text, or read UTF-8 stdin when TEXT is absent |
| `trames files ls` | List authorized share aliases, access and guest mount paths |
| `trames files path ALIAS` | Print an existing visible guest mount path; its absence does not prevent permitted copying |
| `trames files cp SOURCE DEST` | Copy between guest paths and `share:ALIAS/PATH` |
| `trames mount ls` | List current authorized host mounts |
| `trames mount add ALIAS TARGET [--read-only]` | Mount an authorized share at a guest path for this boot |
| `trames mount rm TARGET` | Unmount a controlled host mount for this boot |
| `trames port ls` | List this environment's published ports |
| `trames port publish HOST:GUEST [--listen IP] [--protocol tcp\|udp]` | Publish a bridge-network port for this boot |
| `trames port unpublish HOST [--listen IP] [--protocol tcp\|udp]` | Remove exactly that publication |
| `trames host cli -- ARGS...` | Invoke the permitted subset of the host Trames CLI |
| `trames host exec -- PROGRAM [ARG...]` | Run a host program under the environment's effective host-execution permission |
| `trames host open URL` | Open an HTTP(S) URL in the host browser |
| `trames host gui` | Open/navigate to the host environment manager where supported |
| `trames completion bash\|zsh\|fish` | Emit shell completion definitions |
| `trames debug rpc DEVICE METHOD JSON_PARAMS` | Low-level diagnostic escape hatch, under the same permissions |

Canonical spelling uses `ls` and `rm`; help describes the action in plain words.
The old shell helper's command spellings need no compatibility shim. Every
release must document the actual supported subset; an unsupported operation
returns an explanation rather than being advertised as working.

Examples:

```sh
trames status
trames permissions
printf 'Hello from Linux\n' | trames clipboard set
trames clipboard get > clipboard.txt
trames files cp ./report.pdf share:project/reports/report.pdf
trames mount add project /work
cp ./large.iso /work/large.iso
trames port publish 8080:80
trames port publish 8443:443 --listen 0.0.0.0
trames host cli -- config show
trames host exec -- /usr/bin/uname -s
printf 'hello' | trames host exec -- /usr/bin/shasum
trames host open https://example.com
trames host gui
```

`clipboard set` with no TEXT and a terminal stdin reports usage; it does not
wait for accidental interactive input. Neither clipboard command requires JSON
quoting. Clipboard is text-only and rejects invalid UTF-8 instead of corrupting
it. Host-advertised size restrictions are reported, never silently truncated;
control-frame size is not a bulk-file or subprocess-output limit.

Host argv is passed literally. No shell interpretation, expansion or implicit
`sh -c` occurs. Shell syntax requires an explicitly chosen host shell. Initially
host executables use absolute paths, matching existing host policy. This does
not imply that a Linux `/usr/bin` executable exists on macOS.

## Matching host operations

Resource groups use the same verbs on both sides. Host `-e` selects the target
environment; the guest implicitly addresses its current environment. Local host
paths are host paths, local guest paths are guest paths, and `guest:/PATH` lets
the host explicitly name the selected environment's filesystem.

| Operation | Host | Guest |
| --- | --- | --- |
| Status / diagnosis | `trames -e work status` / `doctor` | `trames status` / `doctor` |
| Read permissions | `trames -e work permissions` | `trames permissions` |
| Allow permissions | `trames -e work permissions allow clipboard files` | No mutation command |
| Deny permissions | `trames -e work permissions deny host-exec` | No mutation command |
| Allow all supported controls | `trames -e work permissions allow --all` | No mutation command |
| List shares | `trames -e work files ls` | `trames files ls` |
| Send a local file to the other side | `trames -e work files cp ./in.txt guest:/tmp/in.txt` | `trames files cp ./out.txt share:project/out.txt` |
| Retrieve a file from the other side | `trames -e work files cp guest:/tmp/out.txt ./out.txt` | `trames files cp share:project/in.txt ./in.txt` |
| Clipboard | `trames -e work clipboard get/set` | `trames clipboard get/set` |
| Mount an authorized share | `trames -e work mount add project /work` | `trames mount add project /work` |
| Publish a port | `trames -e work port publish 8080:80` | `trames port publish 8080:80` |
| Execute on the other side | `trames -e work exec -- /bin/uname -a` | `trames host exec -- /usr/bin/uname -s` |
| Open the host manager at this environment | `trames -e work gui` | `trames host gui` |

The clipboard commands refer to the selected environment's host clipboard, not
to a second private clipboard. Host `exec` keeps its established meaning of
executing a guest command; guest `host exec` explicitly executes on the host.
`host cli` invokes the scoped host Trames interface. It does not gain permission
mutation merely because the actual host CLI has that capability.

`trames permissions defaults` shows host-global defaults for future environments;
`trames permissions defaults deny host-exec` and `allow --all` edit them. This
explicit global scope cannot be combined with `-e`. The ordinary per-environment
permission command updates one selected environment, preserving unrelated
settings and share restrictions. Both APIs and the manager use the same policy
model and persistence path, not separately implemented authorization rules.

Host copies into/out of an environment obey its file interoperability policy,
with applicable path/read-only restrictions. An owner-supplied local host path
is authorized for that requested copy; it does not register a persistent share
or expose its parent directory to future guest requests. Guest-originated host
file locators continue to use configured share aliases.

A running environment services host file operations through its original VFS
and existing bounded I/O workers: one typed owner-side operation supplies paths
or retained file resources, while bytes move through the normal filesystem
backend. Do not open a second independent VFS/store over a running environment.
For a stopped environment, use the existing offline VFS under its normal owner
lock. A host file copy needs neither booting a guest nor stopping a running one.
Control mutations such as live mount/port changes still require the environment
to be running; read-only policy/status inspection remains available while stopped.

## Defaults and permission authority

All supported interoperability controls start allowed for newly owner-created
environments: clipboard, files, mounts, ports, host UI, delegated host CLI and
host command execution. New local UUID-bound authorization records and generated
configuration must agree with that host default. Importing an image/profile
through the owner's environment creation flow uses the same defaults, with
explicitly authored restrictions preserved.

Defaults are host policy, not a grant inferred from an arbitrary guest file.
Changing defaults does not erase existing explicit denials or read-only share
settings. A missing/malformed authorization record is an attachment/configuration
error, not permission for the guest to fabricate its own authority. OS sandbox
and privacy permissions remain supplied by the platform. iPad host execution
continues to report unsupported; an allowed configuration flag cannot implement
an unavailable platform operation. Component/hardware defaults are outside this
CLI permission change.

Host-configured shared folders default to bidirectional read/write access unless
the owner chose read-only or a narrower allowlist. The default scope is all
registered shares available to this environment, not an empty list requiring a
second permission toggle. The planned schema must distinguish an omitted share
allowlist (all registered shares) from an explicit empty list (none). This
changes the current empty-Vec behavior and must be implemented explicitly rather
than documented as already working. Registering a share remains a host operation;
there is no implicit whole-host-root share.

The host command/manager is the permission mutation interface; the guest has
only listing and diagnostics. Existing grants authorize ordinary operations
without an extra Trames confirmation for each file copy or command. iPad should
reuse its already authorized Files roots instead of adding a second per-copy
Trames approval. Required OS picker/privacy decisions still follow the platform.

Unrestricted `host-exec` runs with the host user's authority in the present
architecture. Therefore "guest permissions are read-only" is an interface rule,
not an immutable security boundary against host-user code editing policy files
or invoking the owner CLI. Strictly restricted environments must deny host-exec
or use a genuinely reduced-authority executor; a blacklist of permission command
names cannot provide that boundary. The owner-trusted default intentionally
allows host execution. This clarification adds no new sandbox or service thread.

Effective permission changes that require reattachment show "applies on next
start". Setting a permission does not silently restart a live environment. The
info/permission-query endpoint stays available even when every optional control
is disabled, so the host cannot accidentally lock itself out of policy editing.

## Help and output

Root help fits an ordinary 80-column terminal, groups commands by purpose and
shows three common examples. Group help lists arguments, defaults, scope,
permissions and applicable platforms. Unknown commands suggest the nearest
known spelling and exit with a usage error. Help/version/completion never open
host devices, read the clipboard, trigger a permission sheet or launch a GUI.

A normal status display is small:

```text
Environment  work (Linux)
Host         macOS
Bridge       ready
Network      host

Run 'trames permissions' to see available host features.
```

Permission output has one effective state per capability, matching the manager:

```text
FEATURE           ACCESS
Clipboard         allowed
Shared files      allowed
Host Trames CLI   allowed
Host commands     allowed
Port publishing   allowed (bridge networks)
```

Do not expose two independent configuration-request/grant switches to the user.
Detailed reason codes may distinguish unsupported platform, denied capability,
missing share, or settings pending restart. Show a reason only when the host
actually supplied enough information to establish it.

List commands write tables to stdout; `--json` is the supported parsing API.
UUIDs and verbose transport details belong in structured/detailed output, not
all default tables. Narrow terminals wrap help and shorten display columns
without changing the operation's real arguments or silently truncating data.

Data-producing commands keep stdout clean. Successful copies are quiet by
default. Progress, when supported, goes to stderr on a TTY and advances on real
copy events; unknown totals are not invented. Quiet mode suppresses client
status messages, never the remote program's stdout/stderr.

Human messages support English and Chinese. Use existing `LC_ALL`,
`LC_MESSAGES`, then `LANG`, with optional `TRAMES_LANGUAGE=en|zh` override and an
English fallback. Do not install locales, modify guest locale settings or copy
the host app language into the guest environment. Commands, flags and JSON keys
always use the same ASCII spelling; user content/child output is untranslated.

## Script behavior and errors

Initial global options: `--help`, `--version`, `--json`, `--quiet`, `--no-color`,
`--timeout DURATION`, and `--verbose`. The outer parser stops at `--` before
host argv; child flags must never be interpreted as Trames flags. Respect
`NO_COLOR` and non-TTY output. Do not print command arguments, stdin, clipboard
contents or shared-file contents in ordinary verbose diagnostics.

Ordinary `--json` operations emit one object, including on failure:

```json
{"schema_version":1,"command":"clipboard.get","ok":true,"data":{"text":"hello\n"}}
```

```json
{"schema_version":1,"command":"host.exec","ok":false,"error":{"code":"permission_denied","message":"Host command execution is not allowed.","hint":"Enable Host commands in the host manager, then restart this environment when convenient."}}
```

For an ordinary command, failure JSON goes to stdout and diagnostics remain on
stderr. In normal mode errors go to stderr without a Rust error chain:

```text
trames: host commands are not allowed for this environment.
Enable Host commands in the host manager, then restart this environment.
```

Missing `/dev/trames/info` instead produces:

```text
trames: the host control connection is unavailable in this session.
The command is installed, but /dev/trames/info is missing.
Run 'trames doctor'; restart with an updated Trames runtime when convenient.
```

Never label a missing bridge as a denied capability or tell the guest to run
`sudo`, `mknod`, or install another package. `doctor` diagnoses without changing
settings, stopping a service, granting access or reading private payloads.

| Exit status | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Operation/I/O failure |
| 2 | Invalid command or arguments |
| 69 | Feature/host/transport unavailable or unsupported version |
| 77 | Permission denied |
| 124 | Explicit operation timeout |
| 130 | Interrupted locally without a final remote status |
| 141 | Local output pipe closed |

After a remote program starts, `host exec`/`host cli` preserve its final status,
including nonzero values. A child may naturally return one of the same numbers;
structured records distinguish remote exit from a client failure. Do not retry
mutations automatically after a lost response: report that the outcome may be
unknown and offer a corresponding read-only inspection command.

## Host command streams

Default host command execution preserves stdout, stderr and binary bytes and
returns promptly after target completion. Pipe input supports normal tools such
as `shasum`. No pseudo-terminal, interactive host shell, password prompting,
background detachment or automatic host shell is promised in the first version.
Commands requiring a TTY fail clearly; they must not sit waiting for input the
client cannot provide.

The current null-stdin/text-only adapter needs work before meeting this contract.
Add explicitly advertised byte-stream and stdin-EOF support. Use bounded frames
with binary encoding, full-duplex backpressure and explicit stdout/stderr/exit
events. `--json` for an executing command is an NDJSON event stream, not a
buffered final document: output events carry channel and byte encoding, followed
by an exit event. Version this stream separately from the normal JSON envelope.

Negotiate protocol/features once per invocation. An old host lacking the
required stream feature gets an update/restart explanation, not a lossy fallback
that claims binary safety. Keep legacy diagnostic discovery small; do not build
a parallel full implementation of the old client.

Ctrl-C cancels only the original owned host job/process group. Connection close,
broken pipe and guest exit clean up that job through existing ownership. A
bounded cancellation grace may end with connection close; received child exit
status wins, otherwise local interruption returns 130. Host execution and large
copies have no arbitrary 120-second total deadline. Existing broker request
expiry must be adjusted for accepted long-running jobs; short control requests
retain a finite advertised timeout and `--timeout` adds an explicit deadline.

Host CLI delegation stays scoped to the current UUID and an explicit allowlist.
It never accepts arbitrary environment selectors, grants, global writes, debug
backends or guest-supplied host paths. GUI opening uses host-UI authority, not a
host-CLI permission shortcut. Self-stop/restart requires an acknowledgement
before disconnecting the guest; reject those operations until that ordering is
implemented rather than promising a return code that cannot arrive.

## Shares, copies and network behavior

`share:ALIAS/PATH` is the only special file locator. Other paths are guest paths;
spaces and Unicode are literal. Aliases are stable host-authorized names, not
raw host paths or guessed folder display names. Never accept `/Users/...` as a
host locator from the guest or resolve `..` outside the original share resource.

On Mac, resolve an authorized alias once and use the existing hostfs resource.
A visible mount can be reused. If none exists, the file adapter must supply a
copy-scoped file handle/view backed by that same hostfs implementation; this is
an additional control/descriptor operation to implement, not a new filesystem
or byte transport. It does not create a public mount or require the separate
mount-control permission. Files permission plus valid source/destination access
is sufficient for copying. Do not send file contents over NDJSON or introduce
another storage/transfer backend. Normal `cp`, `mv`, tar and rsync retain the
existing mounted path and its performance.

`files cp` supports one file/tree source and a destination, with ordinary copy
semantics, including `-r`, `--no-clobber` and explicit `--interactive` when a
terminal is present. Default copy overwrite behavior follows `cp`; it does not
bypass an independent read-only mount/grant. Do not add a second synchronization
or mirroring engine. iPad provider transfers reuse its existing Files adapter;
when a provider cannot offer a direct mount, only operation metadata crosses the
control channel. The shared CLI uses advertised capabilities to choose that
existing adapter and gives unsupported-option errors where semantics differ.

Mounting uses approved aliases and the original hostfs implementation. Removing
a mount neither deletes files nor revokes the host grant. Hostfs mounted data
access remains governed by its original filesystem permissions; disabling a
control device does not silently unmount existing shared directories or revoke
already-open file descriptions.

Host networking remains the default: normal guest bind addresses and host port
collisions apply, with no publisher inserted. `port publish` in host mode reports
that the requested service should bind normally; it does not pretend to install
a forwarding rule. In bridge mode `HOST:GUEST` means numeric ports; `--listen`
selects the host address, default `127.0.0.1`, and protocol defaults to TCP.
Wildcard publication is explicit. All rules/mount controls affect this
environment and current boot only; help/success output says so. Persistence is
configured in TOML on the host, with no misleading `--save` option initially.

## Common implementation and injection

Build one small static AArch64 Linux executable in a new shared Runtime crate,
provisionally `trames-guest`. It must not depend on the guest's Python, jq, awk,
shell quoting or distro package version. Use baseline guest ISA settings rather
than compiling for the developer Mac's native CPU. The same artifact runs under
Mac HVF, the iPad interpreter and Android's userspace; product adapters supply
capabilities rather than separate CLI implementations.

Keep parsing/formatting, command handlers and device transport separate inside
that crate. Share a wire-only type module with the host broker without linking
the Linux kernel, CPU executor or host readiness implementation into the guest
client. Do not parse TOML independently
or recreate authorization inside the client. Build/embed the verified guest
artifact with the existing guest-resource pipeline; reuse it when unchanged.
Do not recursively cross-build it during an ordinary host Cargo build.

Keep the managed Linux entry at `/usr/local/bin/trames` and provide a standard
`/usr/bin/trames` entry where needed for minimal PATHs; Android uses
`/system/bin/trames`. The installer owns its injected locations, replaces its
older helper and reports unrelated custom-rootfs collisions instead of silently
overwriting user programs. Inject completion files only for supported shell
layouts; do not install shells or edit user rc files. Initial completion is
static, including normal path completion, with no permission prompts or slow
host requests on Tab.

A client invocation opens only the required `/dev/trames/*` devices and exits
when done. Blocking device/pipe waits yield through the existing runtime. Reuse
host embedding readiness, original subprocess resources, VFS and object-level
authorization. No resident guest agent, coordinator, busy-polling message bus or
additional host service thread is allowed. Vulkan, VA-API and thunking keep the
CPU interception path; ordinary file/packet I/O gains no control-channel work.

## Delivery and acceptance

1. Implement the complete common CLI surface, help, text/JSON errors, feature
   discovery, language handling and injection as one coherent client change.
2. Complete matching host operations, host-only permission mutations/defaults,
   product adapters, share metadata and stream protocol/stdin/cancellation work.
   Mark unsupported platform features honestly.
3. Concentrate tests: parser/help without devices; argument/Unicode/binary
   round-trips; stdout/stderr/EOF; nonzero status, Ctrl-C and broken pipe; jobs
   longer than the former broker deadline; missing/denied/unsupported devices;
   share boundaries, host-to-guest and guest-to-host copy both with and without
   visible mounts, read-only restrictions, host/bridge modes and current-UUID
   delegation. Cover default-allowed creation, explicit denials, global/per-env
   defaults, malformed authority and read-only guest permission commands.
4. Validate real Alpine, Debian, Android and iPad injection with one artifact,
   and run affected local CI before integration. Compare share-copy throughput
   with ordinary guest `cp` and host native copy; keep bulk data on the original
   path. A pre-injection Stable session is a required diagnostic regression.

A release is not complete merely because the executable exists. Both products
must attach the info endpoint before declaring managed guest startup ready and
verify command discovery through their actual session paths. These checks belong
to startup/acceptance, not every terminal attach or ordinary read/write. Stable deployment
and restarts of live environments are separate operational steps; this proposal
neither restarts them nor changes their grants. This document changes no source,
on-disk format, live permission setting, environment configuration or product
Runtime pin. The default-allow policy and matching host commands remain proposed
until their source and product rollout are implemented and validated.

## Implementation and validation (2026-11-16)

`trames-control` is a small shared crate without a kernel, executor or product
adapter dependency. `scripts/build-guest-cli.py` builds one static AArch64 musl
ELF for all products; distro injection checks the source and artifact hashes.
Linux installs `/usr/local/bin/trames` plus `/usr/bin/trames`; Android installs
`/system/bin/trames`. Help, version and shell completion need no control device.
Injection recognizes the previous managed helper/hash and refuses to overwrite
an unrelated rootfs command.

The host grants remain independent UUID-bound authority. Missing grants deny;
new owner-created records use host `permission_defaults` (all supported flags
allowed). Existing explicit denials, share allowlists and read-only folders stay
intact. `shares` omitted means all registered aliases; an explicit empty list
means none. Owner permission changes apply on the next environment start;
default changes affect future creations, and `permissions defaults` rejects `-e`.
Guest `permissions`/`permissions show` never mutate policy. Full host execution
can still indirectly edit host files as the host user, as discussed above.

Mac guest file copies resolve file-authorized aliases onto private hostfs views
under `/run/trames/shares/<hex alias>`. These reuse the original hostfs backend
and require only file permission, independently of dynamic mount permission.
Host-selected copies use the existing live exec pipe and a bounded tar stream;
the original guest VFS owns every operation. A scoped encoding/decoding worker
exists for one explicit owner copy and ends with it; no resident service,
coordinator or polling bus is added. Completed staging entries are renamed in
the destination filesystem, avoiding a second bulk data copy for ordinary
new files/trees. Offline copies use the existing locked VFS. Existing directory
merges may need ordinary copy work. Host `files ls guest:/PATH` works in both
states. Neither operation boots/stops the guest merely to exchange files.

iPad Files copies use the existing security-scoped provider adapter, including
its single-file/1 GiB limit; recursive and no-clobber provider operations report
unsupported rather than inventing a second storage path. Native folder IDs are
stable share aliases. Explicit provider scopes are enforced by the broker.
Following the owner's explicit confirmation, native actions execute according
to environment policy without the old per-request Trames consent sheet; OS
privacy and Files folder authorizations still apply. iPad host-exec, delegated
host CLI, port and dynamic-mount administration remain unsupported.

Host commands use advertised `exec_bytes`/`exec_stdin` features, base64 byte
frames, one bounded in-flight stdin chunk and EOF acknowledgement. stdout and
stderr stay separate, with a final remote exit status. Accepted streams and
provider copies have no fixed total broker timeout; original producer readiness
remains registered even without a deadline. Explicit client timeouts,
interrupts, output closure, connection loss and policy revocation retain the
existing cancellation/resource ownership. Scoped host CLI delegation cannot
change permissions, select another environment, or stop/restart its own bridge.
Use the separately granted host UI operation to open the manager.

Validation: complete local shared-runtime CI; Mac unit/static/package checks;
real disposable Alpine tests for owner defaults and denials, read-only guest
permissions, literal argv, binary stdin/stdout/stderr, exit status, explicit
timeout, independent file/mount permissions, and live/offline bidirectional
file/tree copying. iPad Rust cross-check and Swift syntax validation cover the
source adapter; no physical iPad deployment is claimed for this change.
