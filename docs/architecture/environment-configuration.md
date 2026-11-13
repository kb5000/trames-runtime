# Environment configuration

An environment is declared by a versioned TOML manifest. The shared
`trames-distro::environment` model is used by both products; native UIs call the
Rust codec instead of implementing another TOML parser.

An explicitly selected host profile is authoritative. Without one, the runtime
reads `/etc/trames/env.toml` from the installed guest filesystem, using product
and image defaults for omitted fields. A registered environment's host identity
and image provenance cannot be replaced by guest declarations. Unknown fields
and unsupported versions are errors. There is no legacy configuration reader or
migration path. Existing stores can receive newly authored host profiles.

```toml
version = 1

[environment]
name = "work"
uuid = "5c9c4027-e8e3-459f-b512-7a3bf15f76f6"
type = "linux" # linux | android

[image]
distribution = "debian" # alpine | debian | custom | android
# source = "/absolute/path/to/rootfs.tar.gz" # directory/archive for initial import

[resources]
cpus = "all" # or a positive integer
memory = "auto" # or, for example, "4GiB"; never preallocates that amount

[network]
mode = "host" # host | bridge | none
# bridge = "development" # required only with mode = "bridge"
# publish = [{ protocol = "tcp", host = "127.0.0.1:8080", guest = 80 }]

[components]
vulkan = true
vaapi = false
thunking = "auto"
audio = false
audio_input = false

[boot]
mode = "shell" # shell | systemd | android

[session]
shell = ["/bin/sh", "-l"]
cwd = "/root"

[display]
windows = true

[[mounts]]
share = "project"
target = "/work"
readonly = false

[interop.clipboard]
enabled = true

[interop.files]
enabled = true
shares = ["project"]

[interop.mounts]
enabled = true
shares = ["project"]
```

Android defaults to its own init and `/system/bin/sh` sessions. Linux shell and
systemd boot share the same kernel. Init preparation remains an explicit product
operation. Memory is backed on demand; `auto` does not reserve a RAM-sized
buffer. Locale remains a property of the guest distribution.

## Independent host grants

A manifest requests capabilities. Host-owned grants are separately bound to the
registered UUID. Effective authority is the intersection of the request, the
host grant, and platform support. For example:

```toml
environment_uuid = "5c9c4027-e8e3-459f-b512-7a3bf15f76f6"

[grant]
clipboard = true
host_ui = false
host_cli = false
host_exec = false
files = true
ports = false
mounts = true

[grant.shares.project]
host = "/Users/example/Projects"
readonly = false
```

Owner-created environments retain the product's existing clipboard default;
other host command capabilities are opt-in. Grants are not guest files and are not included in portable backups. Guest
paths cannot create host authority, including with `mknod`. Static mounts need
an independently granted share; `interop.mounts` additionally controls dynamic
mount commands. Read-only grants remain read-only when the guest requests a
writable mount. Ordinary file I/O uses the existing hostfs resources without
command RPCs or additional per-operation grant checks.

## Control devices

| Device | Requested capability | Purpose |
| --- | --- | --- |
| `/dev/trames/info` | Always available when the product attaches controls | Protocol discovery |
| `/dev/trames/clipboard` | `interop.clipboard` | Host text clipboard read/write |
| `/dev/trames/host-control` | `interop.host_ui` or `interop.host_cli` | Host UI actions or delegated Trames CLI |
| `/dev/trames/host-exec` | `interop.host_exec` | Explicit host argv execution |
| `/dev/trames/file-transfer` | `interop.files` | Authorized file/share control |
| `/dev/trames/port-forward` | `interop.ports` | Private-network port publication |
| `/dev/trames/mount-control` | `interop.mounts` | Mount authorized share aliases |

Unsupported or ungranted devices are absent. Open handles also enforce revoked
method authority. A UI/clipboard grant does not grant host CLI or execution.
Control devices use bounded, versioned NDJSON messages and existing resource
readiness. They are not a data plane for Vulkan, VA-API, thunking, or bulk files.
Clipboard control text uses the existing bounded RPC format; Wayland clipboard
transfers retain their streaming pipe path.

The guest `trames` helper provides `info`, `clipboard`, `files`, `host-cli`,
`host-exec`, and `rpc DEVICE METHOD JSON_PARAMS`. Host command output is returned
in streaming JSON frames. Host CLI delegation is limited to read-only settings
and this environment's lifecycle; it cannot modify grants, run debug backends,
or administer other environments. General host administration requires the
separate host-exec grant.

## Network topology and execution

`host` is the default and uses native host sockets. Port binds have the host's
normal loopback/wildcard visibility and collision rules. No port publisher is
inserted in this path.

On Mac, named Trames networks connect independent environment processes using
private Unix datagram links and the existing userspace IP stack. Networks can
reuse the same private addresses and ports independently. The initial private
address plan is `10.0.0.0/24` and `fd00::/64`; registered UUIDs retain their address.
Optional NAT and TCP/UDP publication reuse the existing native gateway. Network
definitions, memberships and endpoint directories belong to Trames, not to a
macOS bridge. No host interface, route, privileged daemon, or service thread is
created.

Cold configuration and control work stays outside normal syscall execution.
Guest I/O retains original resource ownership and readiness. Native API calls
continue through their existing CPU interception ABI. Blocked control requests
return their execution slot; host subprocess pipes and exit events use the
existing embedding wait loop. The embedding retains one host control view
of the original environment namespace and network before execution starts. It
holds no guest task/mm admission across callbacks and keeps no guest open file
descriptions alive; host subprocess output cannot block an unrelated guest mmap.

Platform support is explicit: iPad reads the same manifest and authorization
schema, while arbitrary host execution and Mac network/mount administration are
not exposed. Security-scoped Files operations remain handled by the iPad host
adapter. An unsupported bridge attachment fails at startup rather than silently
using host networking.
