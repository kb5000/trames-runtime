# Native image and shared-file resources

Implemented 2026-11-25. Graphics, Vulkan, video and Wayland share a tagged
`NativeHandle` contract. Metal textures, Vulkan images and DMA-BUF layouts retain
their actual platform identity. Apple presentation explicitly requests Metal;
unsupported handle/device combinations fail instead of casting another handle.
An image owns its allocation independently of guest descriptors and frame leases.

`SharedMapping` retains initialized bytes, complete host-page geometry and an
optional owned FD plus file offset. Clones reuse one weak `SharedPage` cache, so
safe repeated imports into different address spaces share region guards, byte
identity and native ownership. Attaching file metadata after live pages exist is
rejected. Independent foreign mappings remain an unsafe producer contract: the
FD must describe exactly the original MAP_SHARED bytes, and producers must retain
storage and preserve their original CPU/device synchronization.

Linux linear R8/RG8/RGBA8/BGRA8 planes use sealed, demand-zero memfd storage.
CPU mapping granules follow the real host page size. Larger device alignment uses
owned padding and never changes the guest CPU page size. A regular memfd is not
a DMA-BUF, Vulkan image, or presentable texture. Those exports remain unsupported
until a real provider supplies them.

The shared Vulkan backend queries external host-buffer import support and declares
HOST_ALLOCATION_EXT when creating compatible buffers. Only explicit dedicated
coherent buffers use the retained host allocation path. Linux allocations on that
path use the same sealed-file storage; Vulkan and CPU engines access the original
bytes. Generic allocations retain driver ownership and existing image/buffer alias
semantics. No opaque-FD-to-mmap equivalence is inferred. Unsupported hardware
imports fail rather than installing a shadow byte store.

Native buffer declarations and import checks follow the Vulkan
[external buffer contract](https://docs.vulkan.org/refpages/latest/refpages/source/VkExternalMemoryBufferCreateInfo.html),
[bind requirements](https://docs.vulkan.org/refpages/latest/refpages/source/vkBindBufferMemory.html)
and [host pointer allocation contract](https://docs.vulkan.org/refpages/latest/refpages/source/VkImportMemoryHostPointerInfoEXT.html).

Owned fence FDs distinguish sync_file from ordinary notification descriptors and
register with the existing HostWait. DMA-BUF exports describe retained objects,
per-plane offsets/pitches, modifiers and an optional acquire sync_file. Actual
producer provenance, native image layouts and API access dependencies remain the
provider's responsibility. These contracts add no coordinator or resource thread.

This batch does not implement Linux presentation, hardware image export, VA-API,
V4L2, PipeWire or ALSA providers. Native CPU image allocation and Vulkan buffer
interop do not establish hardware graphics/audio/video readiness.
