# Native audio

Trames exposes interleaved PCM through a standard ALSA ioplug terminal plugin.
Linux applications keep their original ALSA, FFmpeg and cubeb implementations;
Apple AVAudioEngine/AVAudioSourceNode supplies pull-based output, conversion
and mixing; Audio Queue Services supplies capture.
No sound server, full Linux kernel VM or additional Trames service thread is
required. Audio does not require Vulkan or a window.

## Host opt-in and guest setup

The Mac runner accepts `--audio` for playback and `--audio-input` for playback
plus capture. Both are off by default. Environment configuration persists these
with `env configure NAME --audio on --audio-input on`; existing configurations
deserialize with both disabled. The iPad transport compiles, but the iPad product
does not yet enable audio or configure an AVAudioSession.

Build `scripts/build-audio-guest.sh` from the iPad integration repository on
AArch64 Linux with alsa-lib development headers. Supply `CC` and `PKG_CONFIG`
for a matching glibc or musl sysroot when cross-compiling. The generated
`libasound_module_pcm_trames.so` belongs in the guest ALSA plugin directory.
The supplied `asound.conf` includes the distribution configuration and exposes
the native PCM through ALSA's normal `plug` conversion layer.

An isolated configuration can instead contain:

```text
pcm.trames { type trames }
pcm.!default { type plug slave.pcm trames }
```

Set `ALSA_PLUGIN_DIR` to the imported plugin directory and `ALSA_CONFIG_PATH` to
that configuration. This avoids replacing an existing guest `/etc/asound.conf`.
The Mac `scripts/run-firefox-gpu.py --audio-plugin PATH` imports a versioned copy,
enables output, and seeds `media.cubeb.backend="alsa"` only when no explicit
profile preference exists. Add `--audio-input` to permit microphone use. Firefox
and macOS permission checks remain enabled.

macOS capture requires microphone permission. On the first undetermined request,
the backend initiates the system prompt and returns EACCES; retry after approval.
The kernel owner does not wait for a human response. The signed Mac bundle
contains the usage description and audio-input entitlement. For device selection,
`TRAMES_AUDIO_INPUT_DEVICE` and `TRAMES_AUDIO_OUTPUT_DEVICE` accept CoreAudio
device UIDs for this process only; system defaults are not modified.

## Transport and scheduling

The negotiated NativeCall profile is `0x00010008`, auxiliary key `0x5452000a`.
The independent host capability bits at `0x5452000b` are output=1 and input=2.
The entry stub and guest memory use the existing native-call authorization and
the same access model as the CPU interpreter. Guest preferences cannot grant an
audio direction not enabled by the host.

Each request contains sixteen little-endian u64 words. Operations are capability
query (0), open (1), close (2), start (3), stop (4), prepare (5), transfer (6),
status (7), and pause/resume (8). Open supplies eventfd, direction, rate, channels,
format, period frames and buffer frames. The baseline supports S16_LE/FLOAT_LE,
one or two channels, 8–192 kHz, and read/write interleaved access. Apple audio
APIs negotiate the actual device conversion. ALSA `plug` remains available
for other application formats. Actual supported devices must be tested rather
than inferred from these negotiated formats.

Open resolves the guest eventfd on the namespace owner. Other operations execute
on the existing CPU worker. Transfers return partial frame counts or EAGAIN;
ALSA waits through ordinary eventfd/poll, releasing the execution slot. There is
one object lock per stream for guest operations, plus a short handle-table lock
for lookup. Native device callbacks exchange PCM blocks through a SPSC ring using
release/acquire publication, and never retain guest pointers or borrows. Ring and diagnostic counters use atomic scalar operations.
A short per-stream metadata lock publishes the multi-field device-time mapping. No global audio lock is
held across streams or native callbacks.

Ring capacity follows the requested ALSA buffer. A reusable 64 KiB staging block
bounds each native transfer, not the stream's total allocation. Output is pulled
by AVAudioSourceNode at the device's render cadence. It does not pre-read three
Audio Queue period buffers or insert silence while waiting for a guest refill.
Only a real render underrun produces silence, with a short boundary fade to avoid
a discontinuity. Steady PCM is unchanged. Capture retains three Audio Queue period
buffers and copies into its separate ring.

Playback position uses render host timestamps and a bounded, preallocated anchor
history mapping hardware time to actual PCM frames. Position interpolates within
the active device quantum, rather than jumping on buffer-completion callbacks.
The clock metadata lock covers a few scalar fields only. Physical A/V offset and
long-term drift still require separate acceptance.

Prepare after use allocates fresh render state; it never resets a ring that a
late callback could touch. Output render closures retain that state and a shared
notification lease through their final callback. Native input dispose joins its
callbacks. The Rust notification box is released exactly once by the final lease.
A never-started queue can be reused. Stop/pause remain per-stream operations.

The ALSA plugin reports monotonic positions using `SND_PCM_IOPLUG_FLAG_BOUNDARY_WA`
and the ALSA software boundary. Reducing positions modulo only the small buffer
size loses a complete buffer when capture fills it before the next observation.
Capture data are copied only on application reads; the test retains aggregate
levels rather than recording files. Applications should reopen streams after a
fork that creates a separate address space; handles are scoped to the guest VM.

## Integration findings

Initial Audio Queue output attempts showed another integration hazard: its
converter can prefetch several returned buffers ahead of actual playback. Filling
those temporary shortages with zeros produced discontinuities, and treating
completion callbacks as playback position made the browser clock advance in
coarse batches. Continuous device time alone did not remove the inserted silence.
The final output backend uses device pull callbacks instead.

Adding a timed audio worker exposed an existing persistent-cohort problem:
`parallel_timeout` reused an expired owner snapshot of a futex waiter already
retained by the worker deadline queue. Repeated zero timeouts made the owner
rescan instead of blocking for worker events. Same-VM retained futex deadlines
are now excluded from that owner cutoff, as retained sleeps already were.
Foreign-VM deadlines and owner-side signal waits retain their cutoffs. A regression
checks all three cases.

See the iPad integration repository's audio validation record for measured
playback/capture results, exact artifacts and remaining hardware limitations.

## Primary interfaces

- [ALSA ioplug SDK](https://www.alsa-project.org/alsa-doc/alsa-lib/pcm_external_plugins.html).
- [ALSA ioplug pointer/boundary implementation](https://github.com/alsa-project/alsa-lib/blob/master/src/pcm/pcm_ioplug.c).
- [Apple Audio Queue Services](https://developer.apple.com/documentation/audiotoolbox/audio-queue-services).
- [Alpine Firefox ALSA build configuration](https://github.com/alpinelinux/aports/blob/3.23-stable/community/firefox/mozconfig).

## Elapsed playback stalls and profile storage

A separate Firefox 151.0.3 investigation correlated a later video-frame gap with
repeated Glean local database replacements (`datareporting/glean/db/data.safe.tmp`).
The private store serializes and commits a full namespace manifest for these
mutations. On this accumulated test store, each observed slow create took roughly
30–40 ms, and the burst coincided with a multi-second frame-callback gap.
This is separate from output-device crackle and from the first playback frame.

Using the existing host-directory mount for an isolated Linux Firefox profile
removed the multi-second later gap in two 35-second tests; normal Glean recording,
profile persistence, graphics and audio preferences were preserved. The Mac test
launcher exposes this with `--host-profile`. This is an opt-in storage placement,
not a general private-store persistence fix. An experimental broader namespace
service path did not establish a stable benefit and was reverted. No such
experiment or sampling instrumentation remains in the common runtime.

## Descriptor exhaustion during the actual browser launch

The regular Firefox launcher reproduced another failure absent from the minimal
initial playback measurements: the old 256-entry guest FD ceiling. The parent
had 254 occupied slots when it received three SCM_RIGHTS handles; its ancillary
buffer had room for 204, but only two handles were installed. Firefox rejected
the truncated control message and restarted its video bridge. This can cause
severe playback and hover stalls while decoding counters alone look healthy.

The common runtime now uses Linux's default `nr_open` ceiling (1,048,576).
Membership remains sparse; immutable epoch classification masks allocate only
words actually needed and share their storage. No million-entry table, bitmap
or host-FD reservation is made at startup. io_uring captures actual membership
instead of walking every possible number. Proc limits, `nr_open` and `FDSize`
reflect the new representation.

The existing files_struct lock also protects a free-interval index, so lowest-FD
allocation and reuse do not scan all earlier occupied numbers. Insert, replace,
close, clear and fork maintain this same resource's index; no new service thread
or global lock is added. A small test-only allocator domain exercises exhaustion
and pending-accept retention without filling a million real slots. Separate
regressions cross 300 descriptors, retain immutable old masks, verify complete
SCM_RIGHTS transfer and compare split/merge allocation against a reference model.

The extended ceiling follows [Linux's documented default](https://docs.kernel.org/admin-guide/sysctl/fs.html#nr-open).
Actual host resource failures still return normal OS errors. The physical screen
cadence remains separate from decoded-frame counts and JavaScript frame callbacks.

## Large stream IPC and content-process exits (2026-11-01)

The same local video page later logged `pipe error: Message too large` from a
content process's main and ImageBridge threads, followed by channel-error exit.
This is a separate failure from FD exhaustion. The Linux iovec importer rejected
sendmsg payloads over the 1 MiB transfer staging size even for AF_UNIX streams.
Firefox treats this Linux send error as a broken IPC channel; its normal short
write handling can instead continue a partially transferred message. See the
[upstream channel implementation](https://searchfox.org/firefox-main/source/ipc/chromium/src/chrome/common/ipc_channel_posix.cc).

Both owner and worker AF_UNIX stream sends now import a bounded prefix and return
the actual short count. The staging size is not a maximum logical stream message.
Signed iovec-total and descriptor-count validation remain; datagrams and
SOCK_SEQPACKET preserve atomic-message behavior and reject oversized packets.
The regression transfers more than 2 MiB through short writes, checks every byte,
and verifies that SCM_RIGHTS is delivered once on the first successful send.
It covers owner and worker continuations, backpressure and atomic-message errors.
This fixes a deterministic transport bug consistent with the observed log; it
does not prove that every intermittent browser exit has the same cause. A large
document-title experiment did not reproduce the original exit and is not claimed
as an end-to-end negative control.
