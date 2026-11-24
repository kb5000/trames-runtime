# Host CLI prerequisite fixes — 2026-11-25

Real KVM CLI tests exposed `//tmp` from getcwd after a host filesystem was mounted
at the guest root. The mount path renderer now joins the root and child with one
separator. Both internal cwd rendering and the getcwd renderer have a host-root
regression. Existing mount/proc path behavior is covered by the VFS suite.

An earlier iPad ARM64/musl CI could not link DNS native code: a GNU C frontend
selected glibc-private res_n* APIs from its headers while Rust targeted musl.
The build now passes the actual Cargo target libc to the C bridge. The musl path
uses the public stateless res_send ABI, comprising only int and byte pointers;
no private resolver structure or host-header libc layout crosses the call.
GNU and Apple targets retain their original resolver implementation.

Two localhost DNS protocol tests assumed a resolvable IPv6 localhost on every
host. The debug VM lists ::1 as ip6-localhost, while libc/NSS configurations can
synthesize different localhost families. Tests now compare to the original
family-specific native resolver, preserving actual host behavior rather than
changing production answers to satisfy a fixture assumption.

Validation:

- macOS: full VFS unit suite 1038 passed, one existing ignored; network 205 passed;
  VFS/network all-target/all-feature strict Clippy passed.
- ARM64 Linux/4096-byte pages: full VFS unit suite 1035 passed, one existing
  ignored. ARM64 musl network tests 205 passed using the GNU C frontend and
  linker that previously failed. The pipeline adds an x86_64-musl regression.
- KVM frontend callers pass binary stdin/stdout/stderr, literal environment/cwd,
  PTY size/restoration and CPU-busy/sleeping cancellation under SMCCC and MMIO,
  plus the original 21 native/session comparison records per transport.

The previous runtime Mac CI job at
https://github.com/kb5000/trames-runtime/actions/runs/45443561922 failed to acquire
a hosted runner; it did not compile or run tests. The separate iPad guest FFmpeg
artifact failure used a host strip tool on an ARM64 library. Its product workflow
now selects the target strip tool. No failed cloud job is counted as passed.
