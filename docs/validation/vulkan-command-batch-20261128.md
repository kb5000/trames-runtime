# Vulkan pre-HLT recording packets — 2026-11-28

The shared backend advertises capability bit 65536 and accepts operation 276:
`[device, command_buffer, records_address, record_count, payload_address,
payload_bytes]`. At most 64 records (operation + 16 arguments) and 16 KiB of
payload are admitted. Inner payload addresses are owned byte offsets, with
zero reserved for NULL. The original HLT transport and executing worker remain
unchanged; no extra thread, global lock, polling ring or UI control is added.

All guest transport reads precede native command recording. Envelope validation
rejects foreign devices/buffers, non-recording operations and nested packets
before effects. Existing per-operation resource, feature and driver validation
is reused. Execute-secondary retains its original completion collection
boundary. A malformed inner offset returns the existing Vulkan error rather
than a guest-memory retry after an accepted prefix. The guest clears its pending
record count before publishing, so a failed prefix is never replayed.

The actual-driver regression records UpdateBuffer, FillBuffer and a transfer to
host barrier; submits the native command buffer, waits its fence, maps back and
checks `0x1122334455667788`. It also verifies invalid envelope rejection before
effects, a malformed second payload after a valid prefix, and a protected guest
snapshot page fault before effects. Run with an original Vulkan driver:

```sh
cargo test -p trames-vulkan command_batch -- --include-ignored --nocapture
```

Mac uses the existing source-checked static MoltenVK/Metal driver. ARM64 Linux
uses original Mesa Lavapipe (`VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json`).
Both real-driver tests pass. Mac's ordinary Vulkan suite passes 67 tests with
16 hardware tests ignored; its focused packet test is explicitly run on Metal.
Linux's ordinary Vulkan suite passes 68 tests with
two hardware tests ignored; the focused command-packet test is then explicitly
run with Lavapipe. Clippy and iOS target compilation pass.

An additional attempt to run every ignored Mac hardware test concurrently
aborted in the original sync2 test while loading `enumerate_physical_devices`.
That same sync2 test passes when run by itself, as do the focused packet tests.
The concurrent all-ignored invocation is not counted as a passing full suite.

The paired guest ICD and transport tests live in trames-ipad. Its ASan/UBSan
test verifies that 200 draw records require four publications instead of 200,
plus the unchanged end-command call. It covers copied input lifetime, nested
sync/rendering arrays, capacity and oversized fallback, externally synchronized
thread handoff, command-pool isolation, allocation callback/OOM fallback and
no failed replay. Linux passes the same C test with UBSan. Both GCC and Clang
ASan in the current Linux VM fail during sanitizer startup (`ReadFileToBuffer`,
before the test); Mac ASan/UBSan passes. This is not a Linux ASan pass.

The full guest compute/render regression compares the previous immediate ICD
and the packet ICD on the same original native driver at one and four CPUs.
All ten pairs have identical output. Example whole-run worker GPU calls:
compute 183 → 159, persistent-coherent compute 182 → 158, descriptor-template
compute 185 → 161, dynamic graphics 149 → 104, clear-attachment graphics
146 → 119. These counts include unchanged object/query/submit/sync operations;
they are not application speedup measurements or full Vulkan conformance.
