# Display density, background previews and host sleep

The compositor and Linux clock semantics are shared by the iPad interpreter and
Mac HVF executor. UIKit, AppKit and host-specific native timer mechanisms stay at
their respective platform boundaries. No Linux kernel image or resource-service
thread is added.

## Wayland density

Host windows publish integer output density (1–4) through `wl_output.scale` and
surface enter/leave events. Version 6 surfaces also receive
`preferred_buffer_scale`. Older clients can use the output events. Each root
window can change density independently; children inherit their parent's output.
Buffer pixels scale while window geometry and pointer coordinates remain logical.
The SHM dimension limit accommodates HiDPI buffers; backing allocation checks and
budgets remain in effect.

iPad uses the window's screen scale. Mac updates scale when a window changes
screen or backing properties. These outputs describe virtual workspaces with the
existing logical viewport; they do not publish physical monitor geometry or
fractional-scale protocol support.

## iPad Picture in Picture

The selected terminal or Wayland window provides a live AVKit sample-buffer
source. Terminal text uses SwiftTerm's existing CoreText drawing. SHM surfaces
use retained original frame capabilities. Pixel buffers are IOSurface-backed so
the system's separate PiP presenter can read them. The pool is bounded to three
buffers, capture is capped at 960×720 and 5 fps, and idle apps have no capture
timer or pixel pool. A foreground GPU window can provide a bounded readback of
its selected scene; this work is enabled only for the selected preview.

An active, playing PiP keeps only its environment's CPU session running after
backgrounding. Closing or pausing PiP restores normal background pausing.
Foregrounding resumes normal sessions and staged FileProvider edits are still
committed only on a foreground return. AVKit's audio background mode is used;
no silent audio loop is created. iPadOS retains control of suspension and resource
termination, so PiP is not an unconditional execution guarantee.

iPad background transitions fence native GPU entry on the actual Vulkan context
locks. In-flight calls finish; later calls wait through existing readiness
subscriptions and release their execution slots. Resume wakes those waiters.
CPU and SHM terminal rendering can continue; native GPU applications display
their last foreground frame while backgrounded, because iPadOS disallows normal
background Metal submissions. This lifecycle gate does not add a CPU/memory
permission policy or a new coordinator thread.

## Sleep and clocks

Mac's HVF counter and host `Instant` use the awake Mach clock domain. System
sleep does not require reconstructing guest RAM, mappings or CPUs. AppKit sleep
notifications cancel retained presentations and release pressed keys/buttons;
wake invalidates static scene revisions, refreshes density/size and schedules
the existing UI run loop so a non-animating window redraws.

`CLOCK_BOOTTIME` uses the host continuous clock, includes sleep, and keeps its
session origin through fork and exec. It takes the syscall path rather than the
awake-only counter vDSO path. `CLOCK_MONOTONIC` retains its existing fast path.
Boottime timerfds use an Apple continuous-time kqueue timer or Linux boottime
timerfd, consumed by the existing event hub. Periodic expiration counts and
phase use continuous deadlines; no clock polling or new timer thread is needed.

Validation simulates a sleep jump to verify missed periodic expirations and
unchanged monotonic deadlines, exercises real native readiness, and runs the
same Linux ELF on native Linux, Mac HVF and the interpreter. Actual host sleep
has deliberately not been triggered. This is not exhaustive clock conformance:
the existing realtime-based wait paths and wall-clock adjustment behavior are
outside this change.
