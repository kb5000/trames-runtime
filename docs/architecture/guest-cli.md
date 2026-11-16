# Guest CLI design

Status: **Proposed, not implemented**. Owner review draft, 2026-11-16.

This replaces the initial injected shell helper with a coherent guest-side
`trames` command. It applies to Linux and Android guests on both Mac and iPad.
It does not redesign the host CLI, introduce another execution backend or
change ordinary filesystem/network/native GPU execution paths.

## Starting point

`resources/guest/trames` currently implements `info`, clipboard read/write,
file listing, `host-cli`, `host-exec` and raw RPC. Linux injection targets
`/usr/local/bin/trames`; Android injection targets `/system/bin/trames`.
The helper exposes JSON frames directly and depends on guest shell/awk.

Mac already has independent host grants, argv subprocess execution, scoped
Trames CLI delegation, clipboard, URL opening, port publication and mount
controls. Its subprocess adapter currently supplies null stdin and text output.
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
- Permissions stay in the environment configuration and host authorization.
  The CLI reports effective access; it cannot grant itself access or create a
  missing device. Platform restrictions remain explicit.

## Command surface

| Command | Behavior |
| --- | --- |
| `trames status` | Current environment identity, host, bridge and network mode |
| `trames doctor` | Read-only diagnosis of injection, PATH, protocol and device availability |
| `trames permissions` | Allowed / not allowed / unsupported capability summary |
| `trames clipboard get` | Write clipboard text to stdout, preserving its bytes and final newline state |
| `trames clipboard set [TEXT]` | Set literal text, or read UTF-8 stdin when TEXT is absent |
| `trames files ls` | List authorized share aliases, access and guest mount paths |
| `trames files path ALIAS` | Print the mounted guest path, or explain that the share is not mounted |
| `trames files cp SOURCE DEST` | Copy between guest paths and `share:ALIAS/PATH` |
| `trames mount ls` | List current authorized host mounts |
| `trames mount add ALIAS TARGET [--read-only]` | Mount an authorized share at a guest path for this boot |
| `trames mount rm TARGET` | Unmount a controlled host mount for this boot |
| `trames port ls` | List this environment's published ports |
| `trames port publish HOST:GUEST [--listen IP] [--protocol tcp\|udp]` | Publish a bridge-network port for this boot |
| `trames port unpublish HOST [--listen IP] [--protocol tcp\|udp]` | Remove exactly that publication |
| `trames host cli -- ARGS...` | Invoke the permitted subset of the host Trames CLI |
| `trames host exec -- PROGRAM [ARG...]` | Run an explicitly authorized host program |
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
Host Trames CLI   not allowed
Host commands     not allowed
Port publishing   not applicable (host network)
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

On Mac, resolve an authorized mounted alias once, then use ordinary guest file
I/O through the existing hostfs mount. Do not send file contents over NDJSON or
introduce another storage/transfer backend. A share requiring mounting returns
a clear hint; files permission alone does not grant dynamic mount authority.
Normal `cp`, `mv`, tar and rsync retain the same existing path and performance.

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
2. Complete the corresponding product adapters, share metadata and stream
   protocol/stdin/cancellation work. Mark unsupported platform features honestly.
3. Concentrate tests: parser/help without devices; argument/Unicode/binary
   round-trips; stdout/stderr/EOF; nonzero status, Ctrl-C and broken pipe; jobs
   longer than the former broker deadline; missing/denied/unsupported devices;
   share boundaries, normal mounted-file copy, read-only mounts, host/bridge
   modes and current-UUID delegation.
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
on-disk format, environment configuration or product Runtime pin.
