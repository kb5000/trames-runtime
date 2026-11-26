# Retained Vulkan queues for Linux desktop composition

Linux native desktop presenters can sample the shared Wayland compositor's
original Vulkan images. `GpuImage::vulkan_queue()` returns an optional retained
queue capability; the default remains absent for existing non-Vulkan producers.
The capability retains the native device/instance separately from the frame's
swapchain-slot lease. A presenter may retain its pipelines and native swapchain
without permanently reserving the producer's first image.

Only Linux virtual-Wayland devices allocate per-native-queue synchronization.
Guest queue submit, submit2, virtual present, native present and device idle use
the same actual queue locks. Device idle takes those locks in raw-handle order.
Apple builds compile the queue wrapper directly to the original operation;
ordinary CPU execution, guest memory access and headless resource creation do
not acquire these locks. No coordinator or resource-service thread is added.

Native XCB/Wayland surface extensions and native swapchain support are enabled
only for the Linux virtual-WSI path when available. The guest still sees its
existing virtual surface contract. Presentation capabilities identify the
original instance/device/queue; an unrelated device or queue is not silently
substituted. The Linux frontend samples GPU planes on their original producer
queue, keeps frame leases until its submission fence completes, and uploads
only SHM planes. Cross-device/mixed-queue composition is outside this delivery.

This implements the native queue external synchronization required by the
[Vulkan queue specification](https://docs.vulkan.org/spec/latest/chapters/devsandqueues.html).
All exported handles originate in retained native objects, rather than guest
integers or pointers.

Validation on 2026-11-26:

- ARM64 Linux shared libraries: graphics 3, Vulkan 67 and Wayland 27 tests pass;
  one pre-existing native Vulkan test remains explicitly ignored.
- Linux product strict all-target clippy and Apple product all-target clippy and
  compilation pass, including these shared libraries.
- The product's new desktop matrix passes 32 cells: 8 native references and 24
  real ARM64 KVM cells covering SMCCC/MMIO and 1/4 vCPUs. Each KVM Vulkan cell
  executes an unmodified guest ICD and original Vulkan ELF for 16 frames over
  two swapchain generations, verifies actual host pixels and successful teardown.
- Both host X11 and host Wayland native targets pass. The available VM exposes
  Mesa software Vulkan and no physical GPU; this is functional interoperability
  evidence, not physical acceleration or performance qualification.

Raw logs, frozen executable identities and source hashes are retained in the
[Linux product report](https://github.com/project-trames/trames-linux/blob/main/docs/validation/desktop-interop-20261126.md).
