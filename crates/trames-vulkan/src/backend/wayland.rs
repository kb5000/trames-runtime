// SPDX-License-Identifier: GPL-3.0-or-later
//! Standard guest Wayland WSI over owned native GPU images. Native fence polling
//! never blocks the VM coordinator, and presentation transports no pixel bytes.
use super::*;
use std::{
    io,
    sync::atomic::{AtomicU8, Ordering},
};
use trames_wayland::{GpuImage, Server, SurfaceInfo};

#[derive(Default)]
pub(super) struct Wayland {
    pub server: Option<Server>,
    pub authenticated: Option<(Server, u64)>,
    pub surfaces: BTreeMap<u64, Rc<Surface>>,
    chains: BTreeMap<u64, Chain>,
    pending: Vec<Pending>,
}
pub(super) struct Surface {
    server: Server,
    connection: u64,
    protocol: u32,
    id: u64,
    owner: Arc<AtomicU64>,
    gpu_budget: trames_wayland::GpuBudget,
}
impl Surface {
    fn info(&self) -> Result<SurfaceInfo> {
        self.server
            .snapshot()
            .surfaces
            .get(&(self.connection, self.protocol))
            .filter(|i| i.id == self.id)
            .cloned()
            .ok_or(Failure::Vk(vk::Result::ERROR_SURFACE_LOST_KHR))
    }
}
struct NativeImage {
    device: Arc<Device>,
    image: vk::Image,
    memory: vk::DeviceMemory,
    texture: usize,
    width: u32,
    height: u32,
    format: vk::Format,
    state: AtomicU8,
    budget: crate::Budget,
    bytes: u64,
}
impl Drop for NativeImage {
    fn drop(&mut self) {
        // Pool/backend/frame leases prove all producer and UI work has completed.
        unsafe {
            self.device.native.destroy_image(self.image, None);
            self.device.native.free_memory(self.memory, None);
        }
        self.budget.release(self.bytes);
    }
}
struct Completion {
    device: Arc<Device>,
    fence: vk::Fence,
}
impl Completion {
    fn ready(&self) -> std::result::Result<bool, vk::Result> {
        unsafe { self.device.native.get_fence_status(self.fence) }
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        unsafe {
            self.device.native.destroy_fence(self.fence, None);
        }
    }
}
struct Frame {
    image: Arc<NativeImage>,
    completion: Arc<Completion>,
    mailbox: bool,
    _permit: trames_wayland::GpuPermit,
}
impl Drop for Frame {
    fn drop(&mut self) {
        self.image.state.store(0, Ordering::Release);
    }
}
// SAFETY: Arc owns image/memory/fence and the same native Device. Pending retains
// this frame through producer completion; UI's scene lease outlives Metal reads.
// No native handle is obtained from the guest and no coordinator Rc crosses.
unsafe impl GpuImage for Frame {
    fn dimensions(&self) -> (u32, u32) {
        (self.image.width, self.image.height)
    }
    fn metal_texture(&self) -> usize {
        self.image.texture
    }
    fn ready(&self) -> io::Result<bool> {
        self.completion
            .ready()
            .map_err(|e| io::Error::other(format!("native GPU presentation: {e:?}")))
    }
    fn mailbox(&self) -> bool {
        self.mailbox
    }
}
struct Pending {
    frame: Arc<Frame>,
    _resources: Vec<Rc<Object>>,
}
pub(super) struct Pool {
    device: Arc<Device>,
    surface: Rc<Surface>,
    claim: Claim,
    images: Vec<Arc<NativeImage>>,
}
struct Claim {
    owner: Arc<AtomicU64>,
    token: u64,
}
impl Drop for Claim {
    fn drop(&mut self) {
        let _ = self
            .owner
            .compare_exchange(self.token, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        unsafe {
            let _ = self.device.native.device_wait_idle();
        }
    }
}

struct Chain {
    pool: Rc<Pool>,
    images: Vec<u64>,
    acquired: Vec<bool>,
    retired: bool,
    mailbox: bool,
}
impl Wayland {
    pub(super) fn has_chain(&self, id: u64) -> bool {
        self.chains.contains_key(&id)
    }
    pub fn collect(&mut self) {
        self.pending
            .retain(|p| matches!(p.frame.completion.ready(), Ok(false)));
    }
    pub fn clear_device(&mut self) {
        self.pending.clear();
        self.chains.clear();
    }
}
impl Backend {
    pub(super) fn wayland_entry(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        if op == 109 {
            return write(
                m,
                a[0],
                &u64::from(self.wayland.server.is_some()).to_le_bytes(),
            );
        }
        let (server, connection) =
            self.wayland
                .authenticated
                .take()
                .ok_or(Failure::Vk(if a[4] == 1 {
                    vk::Result::NOT_READY
                } else {
                    vk::Result::ERROR_SURFACE_LOST_KHR
                }))?;
        if !self.wsi_enabled || !self.virtual_wsi {
            return unsupported();
        }
        if op == 110 {
            if a[0] != self.instance_id || a[2] > u32::MAX as u64 {
                return invalid();
            }
            output(m, a[3], 8)?;
            self.room(self.wayland.surfaces.len() + 1)?;
            let snapshot = server.snapshot();
            let info = snapshot
                .surfaces
                .get(&(connection, a[2] as u32))
                .ok_or(Failure::Vk(vk::Result::NOT_READY))?;
            let surface = Rc::new(Surface {
                server,
                connection,
                protocol: a[2] as u32,
                id: info.id,
                owner: info.owner.clone(),
                gpu_budget: info.gpu_budget.clone(),
            });
            let id = self.id();
            self.wayland.surfaces.insert(id, surface);
            if let Err(e) = write(m, a[3], &id.to_le_bytes()) {
                self.wayland.surfaces.remove(&id);
                return Err(e);
            }
            return Ok(());
        }
        if a[0] != self.physical_id {
            return invalid();
        }
        let families = unsafe {
            self.instance
                .as_ref()
                .unwrap()
                .native
                .get_physical_device_queue_family_properties(self.physical)
        };
        let supported = families
            .get(a[2] as usize)
            .is_some_and(|q| q.queue_flags.contains(vk::QueueFlags::GRAPHICS));
        write(m, a[3], &u32::from(supported).to_le_bytes())
    }
    pub(super) fn wayland_query(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        if !self.wsi_enabled {
            return unsupported();
        }
        if a[0]
            != if op == 82 {
                self.instance_id
            } else {
                self.physical_id
            }
        {
            return invalid();
        }
        if op == 82 {
            self.wayland.surfaces.remove(&a[1]);
            return Ok(());
        }
        self.wayland.surfaces[&a[1]].info()?;
        match op {
            83 => {
                let families = unsafe {
                    self.instance
                        .as_ref()
                        .unwrap()
                        .native
                        .get_physical_device_queue_family_properties(self.physical)
                };
                let q = families
                    .get(a[2] as usize)
                    .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                write(
                    m,
                    a[3],
                    &u32::from(q.queue_flags.contains(vk::QueueFlags::GRAPHICS)).to_le_bytes(),
                )
            }
            84 => {
                // Wayland clients choose their image extent, following xdg configure. There
                // is no synthetic fixed-size display or host layer address in this API.
                let caps = [
                    2u32,
                    4,
                    u32::MAX,
                    u32::MAX,
                    1,
                    1,
                    4096,
                    4096,
                    1,
                    1,
                    1,
                    1,
                    // The same native images are sampled directly by Metal.
                    // Mesa Kopper also samples its swapchain resources.
                    0x17,
                ];
                write(
                    m,
                    a[2],
                    &caps
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
            }
            85 | 86 => {
                let values = if op == 85 {
                    vec![44u32, 0]
                } else {
                    vec![2u32, 1]
                };
                let total = if op == 85 { 1 } else { 2 };
                let capacity = read32(m, a[2])? as usize;
                let count = if a[3] == 0 {
                    total
                } else {
                    total.min(capacity)
                };
                output(m, a[2], 4)?;
                if a[3] != 0 && capacity != 0 {
                    let words = count * if op == 85 { 2 } else { 1 };
                    write(
                        m,
                        a[3],
                        &values
                            .iter()
                            .take(words)
                            .copied()
                            .flat_map(u32::to_le_bytes)
                            .collect::<Vec<_>>(),
                    )?;
                }
                write(m, a[2], &(count as u32).to_le_bytes())?;
                if a[3] != 0 && capacity < total {
                    return Err(vk::Result::INCOMPLETE.into());
                }
                Ok(())
            }
            _ => unsupported(),
        }
    }
}

impl NativeImage {
    fn allocate(
        backend: &Backend,
        device: Arc<Device>,
        width: u32,
        height: u32,
        usage: u32,
    ) -> Result<Arc<Self>> {
        let d = &device.native;
        #[cfg_attr(not(target_vendor = "apple"), allow(unused_mut))]
        let mut info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .format(vk::Format::B8G8R8A8_UNORM)
            .extent(vk::Extent3D {
                width,
                height,
                depth: 1,
            })
            .mip_levels(1)
            .array_layers(1)
            .samples(vk::SampleCountFlags::TYPE_1)
            .tiling(vk::ImageTiling::OPTIMAL)
            // The host compositor samples this same exported texture. This is
            // an internal producer requirement, independent of guest usage.
            .usage(vk::ImageUsageFlags::from_raw(usage) | vk::ImageUsageFlags::SAMPLED)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::UNDEFINED);
        #[cfg(target_vendor = "apple")]
        let mut export = vk::ExportMetalObjectCreateInfoEXT::default()
            .export_object_type(vk::ExportMetalObjectTypeFlagsEXT::METAL_TEXTURE);
        #[cfg(target_vendor = "apple")]
        {
            info = info.push_next(&mut export);
        }
        let raw = unsafe { d.create_image(&info, None) }?;
        let requirements = unsafe { d.get_image_memory_requirements(raw) };
        let types = unsafe {
            device
                .instance
                .native
                .get_physical_device_memory_properties(backend.physical)
        };
        let index = (0..types.memory_type_count)
            .filter(|i| requirements.memory_type_bits & (1 << i) != 0)
            .max_by_key(|&i| {
                let flags = types.memory_types[i as usize].property_flags;
                // Producer, compositor and retained frame leases all use this
                // image on the GPU. Prefer private device memory over equally
                // local host-visible memory: the latter makes MoltenVK upload
                // undefined initial bytes during bind and crashes Paravirtual
                // Metal's replaceRegion path. UMA drivers may report every
                // memory type as DEVICE_LOCAL, so that flag alone is insufficient.
                (
                    flags.contains(vk::MemoryPropertyFlags::DEVICE_LOCAL),
                    !flags.contains(vk::MemoryPropertyFlags::HOST_VISIBLE),
                )
            });
        let Some(index) = index else {
            unsafe {
                d.destroy_image(raw, None);
            }
            return Err(vk::Result::ERROR_FEATURE_NOT_PRESENT.into());
        };
        let bytes = requirements.size;
        if bytes > backend.budget.max_allocation() || !backend.budget.reserve(bytes) {
            unsafe {
                d.destroy_image(raw, None);
            }
            return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
        }
        let memory = match unsafe {
            d.allocate_memory(
                &vk::MemoryAllocateInfo::default()
                    .allocation_size(bytes)
                    .memory_type_index(index),
                None,
            )
        } {
            Ok(memory) => memory,
            Err(e) => {
                unsafe {
                    d.destroy_image(raw, None);
                }
                backend.budget.release(bytes);
                return Err(e.into());
            }
        };
        if let Err(e) = unsafe { d.bind_image_memory(raw, memory, 0) } {
            unsafe {
                d.destroy_image(raw, None);
                d.free_memory(memory, None);
            }
            backend.budget.release(bytes);
            return Err(e.into());
        }
        #[cfg_attr(not(target_vendor = "apple"), allow(unused_mut))]
        let mut image = Self {
            device: device.clone(),
            image: raw,
            memory,
            texture: 0,
            width,
            height,
            format: vk::Format::B8G8R8A8_UNORM,
            state: AtomicU8::new(0),
            budget: backend.budget.clone(),
            bytes,
        };
        #[cfg(target_vendor = "apple")]
        {
            let mut texture = vk::ExportMetalTextureInfoEXT::default()
                .image(raw)
                .plane(vk::ImageAspectFlags::COLOR);
            let mut output = vk::ExportMetalObjectsInfoEXT::default().push_next(&mut texture);
            unsafe {
                let extension = ash::ext::metal_objects::Device::new(&device.instance.native, d);
                (extension.fp().export_metal_objects_ext)(d.handle(), &mut output);
            }
            image.texture = texture.mtl_texture as usize;
            if image.texture == 0 {
                return unsupported();
            }
        }
        // The original VkImage owns its exported MTLTexture; image/pool/frame Arcs
        // keep its VkDeviceMemory alive through the UI command-buffer completion.
        Ok(Arc::new(image))
    }
}
impl Backend {
    pub(super) fn wayland_device(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<()> {
        let device = self.device(a[0])?;
        match op {
            87 => {
                output(m, a[10], 8)?;
                let surface = self
                    .wayland
                    .surfaces
                    .get(&a[1])
                    .cloned()
                    .ok_or(Failure::Vk(vk::Result::ERROR_SURFACE_LOST_KHR))?;
                surface.info()?;
                if !(2..=4).contains(&a[2])
                    || a[3] != 44
                    || a[4] != 0
                    || a[5] == 0
                    || a[6] == 0
                    || a[5] > 4096
                    || a[6] > 4096
                    || a[7] & !0x17 != 0
                    || a[7] & 0x10 == 0
                    || a[9] > 1
                    || a[11] > 1
                {
                    return unsupported();
                }
                let expected = if a[8] == 0 {
                    0
                } else {
                    let old = self
                        .wayland
                        .chains
                        .get(&a[8])
                        .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_DATE_KHR))?;
                    if !Rc::ptr_eq(&old.pool.surface, &surface) {
                        return invalid();
                    }
                    old.pool.claim.token
                };
                self.room(
                    a[2] as usize + self.wayland.surfaces.len() + self.wayland.chains.len() + 1,
                )?;
                let owner = self.id();
                surface
                    .owner
                    .compare_exchange(expected, owner, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| Failure::Vk(vk::Result::ERROR_NATIVE_WINDOW_IN_USE_KHR))?;
                let claim = Claim {
                    owner: surface.owner.clone(),
                    token: owner,
                };
                if a[8] != 0 {
                    self.wayland.chains.get_mut(&a[8]).unwrap().retired = true;
                }
                let mut images = Vec::new();
                for _ in 0..a[2] {
                    images.push(NativeImage::allocate(
                        self,
                        device.clone(),
                        a[5] as u32,
                        a[6] as u32,
                        a[7] as u32,
                    )?);
                }
                let pool = Rc::new(Pool {
                    device,
                    surface,
                    claim,
                    images,
                });
                let mut ids = Vec::new();
                for image in &pool.images {
                    let id = self.put(
                        Kind::SwapchainImage,
                        image.image.as_raw(),
                        vec![],
                        0,
                        a[7] as u32,
                    );
                    let object = &self.objects[&id];
                    *object.wayland_pool.borrow_mut() = Some(pool.clone());
                    object.image.set(Some(ImageShape::d2(
                        image.width,
                        image.height,
                        image.format,
                    )));
                    ids.push(id);
                }
                if a[8] != 0 {
                    self.wayland.chains.get_mut(&a[8]).unwrap().retired = true;
                }
                self.wayland.chains.insert(
                    owner,
                    Chain {
                        pool,
                        images: ids,
                        acquired: vec![false; a[2] as usize],
                        retired: false,
                        mailbox: a[9] == 1,
                    },
                );
                if let Err(e) = write(m, a[10], &owner.to_le_bytes()) {
                    self.drop_wayland_chain(owner);
                    return Err(e);
                }
            }
            88 => {
                self.drop_wayland_chain(a[1]);
            }
            89 => {
                let chain = &self.wayland.chains[&a[1]];
                let capacity = read32(m, a[2])? as usize;
                output(m, a[2], 4)?;
                let count = if a[3] == 0 {
                    chain.images.len()
                } else {
                    capacity.min(chain.images.len())
                };
                if a[3] != 0 {
                    write_words(m, a[3], &chain.images[..count], count * 8)?;
                }
                write(m, a[2], &(count as u32).to_le_bytes())?;
                if a[3] != 0 && count < chain.images.len() {
                    return Err(vk::Result::INCOMPLETE.into());
                }
            }
            90 => {
                output(m, a[4], 4)?;
                let chain = &self.wayland.chains[&a[1]];
                if chain.retired {
                    return Err(vk::Result::ERROR_OUT_OF_DATE_KHR.into());
                }
                chain.pool.surface.info()?;
                let semaphore = if a[2] == 0 {
                    None
                } else {
                    Some({
                        let semaphore = self.object(a[2], Kind::Semaphore)?;
                        if semaphore.flags != 0 {
                            return invalid();
                        }
                        semaphore
                    })
                };
                let fence = if a[3] == 0 {
                    None
                } else {
                    Some(self.object(a[3], Kind::Fence)?)
                };
                if semaphore.is_none() && fence.is_none()
                    || semaphore.as_ref().is_some_and(|s| s.state.get() != 0)
                {
                    return invalid();
                }
                if let Some(f) = &fence {
                    if f.acquisition.borrow().is_some()
                        || Self::fence_ready(f)?
                        || self.submissions.iter().any(|s| Rc::ptr_eq(&s.fence, f))
                    {
                        return invalid();
                    }
                }
                let index = chain
                    .pool
                    .images
                    .iter()
                    .position(|image| {
                        image
                            .state
                            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    })
                    .ok_or(Failure::Vk(vk::Result::NOT_READY))?;
                let image = chain.pool.images[index].clone();
                let object = self.objects[&chain.images[index]].clone();
                let fence = match fence {
                    Some(f) => f,
                    None => match self.private_fence(device.clone()) {
                        Ok(f) => f,
                        Err(e) => {
                            image.state.store(0, Ordering::Release);
                            return Err(e);
                        }
                    },
                };
                let signals = semaphore
                    .as_ref()
                    .map(|s| vk::Semaphore::from_raw(s.raw))
                    .into_iter()
                    .collect::<Vec<_>>();
                let info = vk::SubmitInfo::default().signal_semaphores(&signals);
                if let Err(e) = unsafe {
                    device
                        .native
                        .queue_submit(self.queue, &[info], vk::Fence::from_raw(fence.raw))
                } {
                    image.state.store(0, Ordering::Release);
                    return Err(e.into());
                }
                let mut resources = vec![object];
                if let Some(s) = semaphore {
                    s.state.set(1);
                    resources.push(s);
                }
                self.submissions.push(Submission {
                    fence,
                    commands: vec![],
                    _resources: resources,
                    timeline_completion: Vec::new(),
                    timeline_signals: Vec::new(),
                    commands_complete: false,
                    coherent_scope: Default::default(),
                });
                self.wayland.chains.get_mut(&a[1]).unwrap().acquired[index] = true;
                if let Err(e) = write(m, a[4], &(index as u32).to_le_bytes()) {
                    self.wayland.chains.get_mut(&a[1]).unwrap().retired = true;
                    return Err(e);
                }
            }
            91 => {
                if a[1] != self.queue_id {
                    return invalid();
                }
                if self.wayland.pending.len() >= 64 {
                    return Err(vk::Result::NOT_READY.into());
                }
                let chain = &self.wayland.chains[&a[2]];
                if chain.retired
                    || a[3] >= chain.images.len() as u64
                    || !chain.acquired[a[3] as usize]
                {
                    return invalid();
                }
                chain.pool.surface.info()?;
                let mut dependencies = Vec::new();
                let mut waits = Vec::new();
                for id in words64(m, a[4], bounded(a[5], 64)?)? {
                    let s = self.object(id, Kind::Semaphore)?;
                    if s.flags != 0 {
                        return invalid();
                    }
                    if s.state.get() != 1 || dependencies.iter().any(|x| Rc::ptr_eq(x, &s)) {
                        return invalid();
                    }
                    waits.push(vk::Semaphore::from_raw(s.raw));
                    dependencies.push(s);
                }
                let permit = chain
                    .pool
                    .surface
                    .gpu_budget
                    .reserve()
                    .ok_or(Failure::Vk(vk::Result::NOT_READY))?;
                let completion = Arc::new(Completion {
                    device: device.clone(),
                    fence: unsafe {
                        device
                            .native
                            .create_fence(&vk::FenceCreateInfo::default(), None)
                    }?,
                });
                let stages = vec![vk::PipelineStageFlags::ALL_COMMANDS; waits.len()];
                let submit = vk::SubmitInfo::default()
                    .wait_semaphores(&waits)
                    .wait_dst_stage_mask(&stages);
                if let Err(e) = unsafe {
                    device
                        .native
                        .queue_submit(self.queue, &[submit], completion.fence)
                } {
                    self.wayland.chains.get_mut(&a[2]).unwrap().retired = true;
                    return Err(e.into());
                }
                for s in &dependencies {
                    s.state.set(0);
                }
                let image = chain.pool.images[a[3] as usize].clone();
                image.state.store(2, Ordering::Release);
                dependencies.push(self.objects[&chain.images[a[3] as usize]].clone());
                let frame = Arc::new(Frame {
                    image,
                    completion,
                    mailbox: chain.mailbox,
                    _permit: permit,
                });
                // This extra producer lease prevents cancellation/disconnect from releasing
                // a slot/fence before native writes finish. UI leases extend it afterward.
                self.wayland.pending.push(Pending {
                    frame: frame.clone(),
                    _resources: dependencies,
                });
                let server = chain.pool.surface.server.clone();
                let surface = chain.pool.surface.id;
                self.wayland.chains.get_mut(&a[2]).unwrap().acquired[a[3] as usize] = false;
                if server.present_gpu(surface, frame).is_err() {
                    self.wayland.chains.get_mut(&a[2]).unwrap().retired = true;
                    return Err(vk::Result::ERROR_SURFACE_LOST_KHR.into());
                }
            }
            _ => return unsupported(),
        }
        Ok(())
    }
    fn drop_wayland_chain(&mut self, id: u64) {
        if let Some(chain) = self.wayland.chains.remove(&id) {
            for id in chain.images {
                self.objects.remove(&id);
            }
        }
    }
}
