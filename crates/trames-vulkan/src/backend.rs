// SPDX-License-Identifier: GPL-3.0-or-later
//! Driver objects stay on the host. IDs and copied bytes are the only wire data.
use ash::{vk, Entry};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::{Rc, Weak},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
#[cfg(test)]
use trames_memory::Memory;
use trames_memory::{Access, CpuMemory, MemoryError};
use vk::Handle;
mod coherent;
mod feedback;
mod graphics;
mod textures;
mod wayland;
mod wsi;
mod zink;
use graphics::{ImageShape, PassInfo, Recording};

// Mesa/glamor caches descriptors, shaders and pixmaps across X11 windows. The
// old smoke-test ceiling of 256 exhausted even xterm + xclock. This bounds
// object metadata; native allocations still charge the separate GPU budget.
const LIMIT: usize = 16_384;
// Match the pool bound for allocation/free batches as well. Original Zink
// grows its descriptor cache in batches of 100 after the first ten sets.
const MAX_DESCRIPTOR_SETS: usize = 4096;
const MAX_ALLOCATION: u64 = 64 << 20;
static DOMAIN: AtomicU64 = AtomicU64::new(1);
type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
enum Failure {
    Memory(MemoryError),
    Vk(vk::Result),
}
impl From<MemoryError> for Failure {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
impl From<vk::Result> for Failure {
    fn from(e: vk::Result) -> Self {
        Self::Vk(e)
    }
}
#[track_caller]
fn invalid<T>() -> Result<T> {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *TRACE.get_or_init(|| std::env::var_os("TRAMES_VULKAN_TRACE").is_some()) {
        eprintln!(
            "trames-vulkan invalid state at {}",
            std::panic::Location::caller()
        );
    }
    Err(Failure::Vk(vk::Result::ERROR_UNKNOWN))
}
fn unsupported<T>() -> Result<T> {
    Err(Failure::Vk(vk::Result::ERROR_FEATURE_NOT_PRESENT))
}

struct Instance {
    native: ash::Instance,
    _entry: Entry,
    queries2: bool,
}
impl Drop for Instance {
    fn drop(&mut self) {
        unsafe { self.native.destroy_instance(None) }
    }
}
struct Device {
    anisotropy: bool,
    features: vk::PhysicalDeviceFeatures,
    maintenance1: bool,
    timeline: bool,
    renderpass2: bool,
    imageless: bool,
    format_list: bool,
    maintenance2: bool,
    feedback: Option<vk::PhysicalDeviceTransformFeedbackPropertiesEXT<'static>>,
    feedback_extension: bool,
    divisor: Option<zink::Divisor>,
    portability: Option<vk::PhysicalDevicePortabilitySubsetFeaturesKHR<'static>>,
    native: ash::Device,
    instance: Arc<Instance>,
    atom: u64,
    map_alignment: u64,
    viewport_dimensions: [u32; 2],
    viewport_bounds: [f32; 2],
}
impl Drop for Device {
    fn drop(&mut self) {
        // Final teardown only: no guest memory/worker guard is held here.
        unsafe {
            let _ = self.native.device_wait_idle();
            self.native.destroy_device(None);
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Buffer,
    BufferView,
    Image,
    SwapchainImage,
    ImageView,
    Sampler,
    RenderPass,
    Framebuffer,
    Memory,
    Shader,
    DescriptorLayout,
    PipelineLayout,
    Pipeline,
    PipelineCache,
    DescriptorPool,
    DescriptorSet,
    CommandPool,
    CommandBuffer,
    Fence,
    Semaphore,
    QueryPool,
}
type DescriptorResources = BTreeMap<(u32, u32), Vec<Rc<Object>>>;
struct Object {
    kind: Kind,
    raw: u64,
    device: Arc<Device>,
    deps: RefCell<Vec<Rc<Object>>>,
    bindings: RefCell<BTreeMap<u32, (u32, u32, u32)>>,
    bound_resources: RefCell<DescriptorResources>,
    dynamic_ranges: RefCell<BTreeMap<(u32, u32), (u64, u64)>>,
    descriptor_epoch: Cell<u64>,
    push_ranges: RefCell<Vec<(u32, u32, u32)>>,
    size: u64,
    flags: u32,
    state: Cell<u8>,
    command_usage: Cell<u32>,
    pending_submissions: Cell<u32>,
    mapped: Cell<usize>,
    image: Cell<Option<ImageShape>>,
    image_flags: Cell<u32>,
    pass: Cell<Option<PassInfo>>,
    attachment_specs: RefCell<Vec<graphics::AttachmentSpec>>,
    recording: RefCell<Recording>,
    vertex_inputs: RefCell<Vec<graphics::VertexBinding>>,
    static_states: Cell<u8>,
    swapchain: RefCell<Option<Rc<wsi::Swapchain>>>,
    wayland_pool: RefCell<Option<Rc<wayland::Pool>>>,
    // Acquire backing is private per use. Original MoltenVK can re-signal an
    // acquire fence at presentation completion, after the guest has reset it.
    // Keep that signal isolated from a later use of the guest's logical fence.
    acquisition: RefCell<Option<Rc<Object>>>,
    budget: crate::Budget,
}
impl Object {
    fn retain(&self, other: Rc<Object>) {
        let mut deps = self.deps.borrow_mut();
        if !deps.iter().any(|x| Rc::ptr_eq(x, &other)) {
            deps.push(other);
        }
    }
}
impl Drop for Object {
    fn drop(&mut self) {
        let d = &self.device.native;
        // References from bindings, recorded commands and in-flight submissions
        // keep every dependency alive until the native driver has finished.
        unsafe {
            match self.kind {
                Kind::BufferView => d.destroy_buffer_view(vk::BufferView::from_raw(self.raw), None),
                Kind::Buffer => d.destroy_buffer(vk::Buffer::from_raw(self.raw), None),
                Kind::SwapchainImage => {}
                Kind::Image => d.destroy_image(vk::Image::from_raw(self.raw), None),
                Kind::Sampler => d.destroy_sampler(vk::Sampler::from_raw(self.raw), None),
                Kind::ImageView => d.destroy_image_view(vk::ImageView::from_raw(self.raw), None),
                Kind::RenderPass => d.destroy_render_pass(vk::RenderPass::from_raw(self.raw), None),
                Kind::Framebuffer => {
                    d.destroy_framebuffer(vk::Framebuffer::from_raw(self.raw), None)
                }
                Kind::Memory => {
                    if self.mapped.get() != 0 {
                        d.unmap_memory(vk::DeviceMemory::from_raw(self.raw));
                    }
                    d.free_memory(vk::DeviceMemory::from_raw(self.raw), None);
                    self.budget.release(self.size);
                }
                Kind::Shader => d.destroy_shader_module(vk::ShaderModule::from_raw(self.raw), None),
                Kind::DescriptorLayout => d.destroy_descriptor_set_layout(
                    vk::DescriptorSetLayout::from_raw(self.raw),
                    None,
                ),
                Kind::PipelineLayout => {
                    d.destroy_pipeline_layout(vk::PipelineLayout::from_raw(self.raw), None)
                }
                Kind::Pipeline => d.destroy_pipeline(vk::Pipeline::from_raw(self.raw), None),
                Kind::PipelineCache => {
                    d.destroy_pipeline_cache(vk::PipelineCache::from_raw(self.raw), None)
                }
                Kind::DescriptorPool => {
                    d.destroy_descriptor_pool(vk::DescriptorPool::from_raw(self.raw), None)
                }
                Kind::DescriptorSet => {
                    let dependencies = self.deps.borrow();
                    let pool = &dependencies[0];
                    if self.descriptor_epoch.get() != pool.descriptor_epoch.get() {
                        return;
                    }
                    let _ = d.free_descriptor_sets(
                        vk::DescriptorPool::from_raw(pool.raw),
                        &[vk::DescriptorSet::from_raw(self.raw)],
                    );
                }
                Kind::CommandPool => {
                    d.destroy_command_pool(vk::CommandPool::from_raw(self.raw), None)
                }
                Kind::CommandBuffer => {
                    let pool = self.deps.borrow()[0].raw;
                    d.free_command_buffers(
                        vk::CommandPool::from_raw(pool),
                        &[vk::CommandBuffer::from_raw(self.raw)],
                    );
                }
                Kind::Fence => d.destroy_fence(vk::Fence::from_raw(self.raw), None),
                Kind::Semaphore => d.destroy_semaphore(vk::Semaphore::from_raw(self.raw), None),
                Kind::QueryPool => d.destroy_query_pool(vk::QueryPool::from_raw(self.raw), None),
            }
        }
    }
}
struct Submission {
    fence: Rc<Object>,
    commands: Vec<Rc<Object>>,
    _resources: Vec<Rc<Object>>,
    timeline_completion: Vec<(Rc<Object>, u64)>,
    timeline_signals: Vec<(Rc<Object>, u64)>,
    commands_complete: bool,
}
struct Mapping {
    memory: Rc<Object>,
    guest: u64,
    offset: u64,
    size: u64,
    coherent: Option<coherent::CoherentBytes>,
}
#[derive(Default)]
struct SubmitBatch {
    waits: Vec<vk::Semaphore>,
    stages: Vec<vk::PipelineStageFlags>,
    commands: Vec<vk::CommandBuffer>,
    signals: Vec<vk::Semaphore>,
    wait_values: Vec<u64>,
    signal_values: Vec<u64>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    Complete(u64),
    Pending(u64),
}
#[derive(Clone, Copy, Debug, Default)]
pub struct TransferMetrics {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub direct_bytes: u64,
    pub buffered_bytes: u64,
}
struct CompiledPipeline {
    device: Arc<Device>,
    raw: vk::Pipeline,
}
impl Drop for CompiledPipeline {
    fn drop(&mut self) {
        if self.raw != vk::Pipeline::null() {
            unsafe {
                self.device.native.destroy_pipeline(self.raw, None);
            }
        }
    }
}
struct Compile {
    // Task drops first: it must finish before these Rc-owned dependencies drop.
    task: crate::task::Task<std::result::Result<CompiledPipeline, vk::Result>>,
    dependencies: Vec<Rc<Object>>,
    bind_point: vk::PipelineBindPoint,
    vertex_inputs: Vec<graphics::VertexBinding>,
    static_states: u8,
    output: u64,
    abandoned: bool,
}

pub struct Backend {
    budget: crate::Budget,
    domain: u64,
    next: u64,
    instance: Option<Arc<Instance>>,
    physical: vk::PhysicalDevice,
    instance_id: u64,
    physical_id: u64,
    device_id: u64,
    queue_id: u64,
    device: Option<Arc<Device>>,
    queue: vk::Queue,
    family: u32,
    objects: BTreeMap<u64, Rc<Object>>,
    retained: Vec<Weak<Object>>,
    mappings: BTreeMap<u64, Mapping>,
    submissions: Vec<Submission>,
    compiles: BTreeMap<u64, Compile>,
    pub transfers: TransferMetrics,
    display: crate::Display,
    wsi: wsi::Wsi,
    wsi_enabled: bool,
    wayland: wayland::Wayland,
    virtual_wsi: bool,
    capabilities: zink::Capabilities,
}
impl Default for Backend {
    fn default() -> Self {
        Self::new()
    }
}
impl Backend {
    pub fn new() -> Self {
        Self::with_budget(crate::Budget::default())
    }
    pub fn with_budget(budget: crate::Budget) -> Self {
        Self {
            budget,
            domain: DOMAIN.fetch_add(1, Ordering::Relaxed),
            next: 1,
            instance: None,
            physical: vk::PhysicalDevice::null(),
            instance_id: 0,
            physical_id: 0,
            device_id: 0,
            queue_id: 0,
            device: None,
            queue: vk::Queue::null(),
            family: 0,
            objects: BTreeMap::new(),
            retained: Vec::new(),
            mappings: BTreeMap::new(),
            submissions: Vec::new(),
            compiles: BTreeMap::new(),
            transfers: TransferMetrics::default(),
            display: crate::Display::default(),
            wsi: wsi::Wsi::default(),
            wsi_enabled: false,
            wayland: Default::default(),
            virtual_wsi: false,
            capabilities: Default::default(),
        }
    }
    pub fn with_display(mut self, display: crate::Display) -> Self {
        self.display = display;
        self
    }
    pub fn with_wayland(mut self, server: Option<trames_wayland::Server>) -> Self {
        self.wayland.server = server;
        self
    }
    pub fn authenticate_wayland(&mut self, authenticated: Option<(trames_wayland::Server, u64)>) {
        self.wayland.authenticated = authenticated;
    }
    fn id(&mut self) -> u64 {
        let id = (self.domain << 32) | self.next;
        self.next += 1;
        id
    }
    fn room(&self, n: usize) -> Result<()> {
        if self
            .retained
            .iter()
            .filter(|x| x.strong_count() != 0)
            .count()
            + self.compiles.len()
            + n
            > LIMIT
        {
            Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into())
        } else {
            Ok(())
        }
    }
    fn device(&self, id: u64) -> Result<Arc<Device>> {
        if id != self.device_id || id == 0 {
            return invalid();
        }
        self.device
            .clone()
            .ok_or(Failure::Vk(vk::Result::ERROR_DEVICE_LOST))
    }
    fn object(&self, id: u64, kind: Kind) -> Result<Rc<Object>> {
        self.objects
            .get(&id)
            .filter(|x| x.kind == kind || kind == Kind::Image && x.kind == Kind::SwapchainImage)
            .filter(|x| {
                x.kind != Kind::DescriptorSet
                    || x.descriptor_epoch.get() == x.deps.borrow()[0].descriptor_epoch.get()
            })
            .cloned()
            .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))
    }
    fn put(&mut self, kind: Kind, raw: u64, deps: Vec<Rc<Object>>, size: u64, flags: u32) -> u64 {
        let object = Rc::new(Object {
            kind,
            raw,
            device: self.device.as_ref().unwrap().clone(),
            deps: RefCell::new(deps),
            bindings: RefCell::new(BTreeMap::new()),
            bound_resources: RefCell::new(BTreeMap::new()),
            dynamic_ranges: RefCell::new(BTreeMap::new()),
            descriptor_epoch: Cell::new(0),
            push_ranges: RefCell::new(Vec::new()),
            size,
            flags,
            state: Cell::new(0),
            command_usage: Cell::new(0),
            pending_submissions: Cell::new(0),
            mapped: Cell::new(0),
            image: Cell::new(None),
            image_flags: Cell::new(0),
            pass: Cell::new(None),
            attachment_specs: RefCell::new(Vec::new()),
            recording: RefCell::new(Recording::default()),
            vertex_inputs: RefCell::new(Vec::new()),
            static_states: Cell::new(0),
            swapchain: RefCell::new(None),
            wayland_pool: RefCell::new(None),
            acquisition: RefCell::new(None),
            budget: self.budget.clone(),
        });
        let id = self.id();
        self.retained.push(Rc::downgrade(&object));
        self.objects.insert(id, object);
        id
    }
    fn remove(&mut self, id: u64, kind: Kind) -> Result<()> {
        let parent = self.object(id, kind)?;
        if parent.kind == Kind::SwapchainImage {
            return invalid();
        }
        if matches!(kind, Kind::CommandPool | Kind::DescriptorPool) {
            self.objects.retain(|_, x| {
                !x.deps
                    .borrow()
                    .first()
                    .is_some_and(|p| Rc::ptr_eq(p, &parent))
            });
        }
        self.mappings.remove(&id);
        self.objects.remove(&id);
        Ok(())
    }
    fn submit(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
        dev: Arc<Device>,
    ) -> Result<()> {
        if a[1] != self.queue_id {
            return invalid();
        }
        if self.submissions.len() >= 64 {
            return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
        }
        // Keep operation 52 readable for the initial ICD. Operation 56 retains
        // each VkSubmitInfo boundary instead of merging semaphore dependencies.
        let stride = if op == 120 { 9 } else { 7 };
        let wire = if op == 52 {
            vec![0, 0, 0, a[2], a[3], 0, 0]
        } else {
            words64(m, a[2], bounded(a[3], 64)? * stride)?
        };
        let mut batches = Vec::new();
        let mut commands = Vec::new();
        let mut semaphores = Vec::new();
        let mut semaphore_states = BTreeMap::new();
        let mut timeline_completion = Vec::new();
        let mut timeline_signals = Vec::new();
        let mut timeline_ready = BTreeMap::<u64, u64>::new();
        let (mut total_waits, mut total_commands, mut total_signals) = (0, 0, 0);
        for record in wire.chunks_exact(stride) {
            timeline_completion.clear();
            let waits = bounded(record[1], 64)?;
            let count = bounded(record[4], 64)?;
            let signals = bounded(record[6], 64)?;
            total_waits += waits;
            total_commands += count;
            total_signals += signals;
            if total_waits > 64 || total_commands > 64 || total_signals > 64 {
                return unsupported();
            }
            let mut batch = SubmitBatch {
                wait_values: if op == 120 {
                    words64(m, record[7], waits)?
                } else {
                    vec![0; waits]
                },
                signal_values: if op == 120 {
                    words64(m, record[8], signals)?
                } else {
                    vec![0; signals]
                },
                ..Default::default()
            };
            let stages = words32(m, record[2], waits)?;
            for (i, (id, stage)) in words64(m, record[0], waits)?
                .into_iter()
                .zip(stages)
                .enumerate()
            {
                let semaphore = self.object(id, Kind::Semaphore)?;
                let state = semaphore_states.entry(id).or_insert(semaphore.state.get());
                // There is one queue. A wait consumes an earlier signal, even
                // if the driver has not completed it yet. Commit only on success.
                if semaphore.flags == 0 && *state != 1 {
                    return invalid();
                }
                if semaphore.flags == 0 {
                    *state = 0;
                } else if op != 120 || !dev.timeline {
                    return unsupported();
                }
                if semaphore.flags != 0 {
                    let api = ash::khr::timeline_semaphore::Device::new(
                        &dev.instance.native,
                        &dev.native,
                    );
                    let native = unsafe {
                        api.get_semaphore_counter_value(vk::Semaphore::from_raw(semaphore.raw))
                    }?;
                    let ready = timeline_ready.entry(id).or_insert(native);
                    *ready = (*ready).max(native);
                    let queued = self.submissions.iter().any(|submission| {
                        submission.timeline_signals.iter().any(|(s, value)| {
                            Rc::ptr_eq(s, &semaphore) && *value >= batch.wait_values[i]
                        })
                    });
                    if *ready < batch.wait_values[i] && !queued {
                        // Drivers may block vkQueueSubmit on future host signals.
                        // Poll before submitting so peer guest threads can signal
                        // even with one worker. No queue/ledger changes yet.
                        return Err(vk::Result::NOT_READY.into());
                    }
                }
                if semaphore.flags == 0 {
                    batch.wait_values[i] = 0;
                }
                batch.stages.push(dev.stage(stage)?);
                batch.waits.push(vk::Semaphore::from_raw(semaphore.raw));
                semaphores.push((id, semaphore));
            }
            for id in words64(m, record[3], count)? {
                let command = self.object(id, Kind::CommandBuffer)?;
                let simultaneous = command.command_usage.get() & 4 != 0;
                if !(command.state.get() == 2 || simultaneous && command.state.get() == 3)
                    || !simultaneous && commands.iter().any(|c| Rc::ptr_eq(c, &command))
                {
                    return invalid();
                }
                batch
                    .commands
                    .push(vk::CommandBuffer::from_raw(command.raw));
                commands.push(command);
            }
            for (i, id) in words64(m, record[5], signals)?.into_iter().enumerate() {
                let semaphore = self.object(id, Kind::Semaphore)?;
                let state = semaphore_states.entry(id).or_insert(semaphore.state.get());
                if semaphore.flags == 0 && *state != 0 {
                    return invalid();
                }
                if semaphore.flags == 0 {
                    *state = 1;
                } else if op != 120 || !dev.timeline {
                    return unsupported();
                }
                if semaphore.flags == 0 {
                    batch.signal_values[i] = 0;
                } else {
                    timeline_completion.push((semaphore.clone(), batch.signal_values[i]));
                    timeline_signals.push((semaphore.clone(), batch.signal_values[i]));
                    let ready = timeline_ready.entry(id).or_insert(0);
                    *ready = (*ready).max(batch.signal_values[i]);
                }
                batch.signals.push(vk::Semaphore::from_raw(semaphore.raw));
                semaphores.push((id, semaphore));
            }
            batches.push(batch);
        }
        let d = &dev.native;
        let fence = if a[4] != 0 {
            let f = self.object(a[4], Kind::Fence)?;
            if f.acquisition.borrow().is_some()
                || unsafe { d.get_fence_status(vk::Fence::from_raw(f.raw)) }?
                || self.submissions.iter().any(|s| Rc::ptr_eq(&s.fence, &f))
            {
                return invalid();
            }
            f
        } else {
            self.private_fence(dev.clone())?
        };
        let mut timelines: Vec<_> = batches
            .iter()
            .map(|batch| {
                vk::TimelineSemaphoreSubmitInfo::default()
                    .wait_semaphore_values(&batch.wait_values)
                    .signal_semaphore_values(&batch.signal_values)
            })
            .collect();
        let infos: Vec<_> = batches
            .iter()
            .zip(&mut timelines)
            .map(|(batch, timeline)| {
                let mut info = vk::SubmitInfo::default()
                    .wait_semaphores(&batch.waits)
                    .wait_dst_stage_mask(&batch.stages)
                    .command_buffers(&batch.commands)
                    .signal_semaphores(&batch.signals);
                if op == 120 {
                    info = info.push_next(timeline);
                }
                info
            })
            .collect();
        self.coherent_sync(m, true)?;
        unsafe { d.queue_submit(self.queue, &infos, vk::Fence::from_raw(fence.raw)) }?;
        for c in &commands {
            c.state.set(3);
            c.pending_submissions.set(c.pending_submissions.get() + 1);
        }
        for (id, semaphore) in &semaphores {
            semaphore.state.set(semaphore_states[id]);
        }
        let mut resources = Vec::new();
        let mut pending = commands.clone();
        pending.extend(semaphores.into_iter().map(|(_, s)| s));
        while let Some(object) = pending.pop() {
            if resources.iter().any(|other| Rc::ptr_eq(other, &object)) {
                continue;
            }
            pending.extend(object.deps.borrow().iter().cloned());
            resources.push(object);
        }
        self.submissions.push(Submission {
            fence,
            commands,
            _resources: resources,
            timeline_completion,
            timeline_signals,
            commands_complete: false,
        });
        Ok(())
    }
    fn fence_ready(fence: &Object) -> Result<bool> {
        let binding = fence.acquisition.borrow();
        let native = binding.as_deref().unwrap_or(fence);
        Ok(unsafe {
            native
                .device
                .native
                .get_fence_status(vk::Fence::from_raw(native.raw))
        }?)
    }
    fn private_fence(&self, device: Arc<Device>) -> Result<Rc<Object>> {
        let d = &device.native;
        let raw = unsafe { d.create_fence(&vk::FenceCreateInfo::default(), None) }?;
        Ok(Rc::new(Object {
            kind: Kind::Fence,
            raw: raw.as_raw(),
            device,
            deps: RefCell::new(Vec::new()),
            bindings: RefCell::new(BTreeMap::new()),
            bound_resources: RefCell::new(BTreeMap::new()),
            dynamic_ranges: RefCell::new(BTreeMap::new()),
            descriptor_epoch: Cell::new(0),
            push_ranges: RefCell::new(Vec::new()),
            size: 0,
            flags: 0,
            state: Cell::new(0),
            command_usage: Cell::new(0),
            pending_submissions: Cell::new(0),
            mapped: Cell::new(0),
            image: Cell::new(None),
            image_flags: Cell::new(0),
            pass: Cell::new(None),
            attachment_specs: RefCell::new(Vec::new()),
            recording: RefCell::new(Recording::default()),
            vertex_inputs: RefCell::new(Vec::new()),
            static_states: Cell::new(0),
            swapchain: RefCell::new(None),
            wayland_pool: RefCell::new(None),
            acquisition: RefCell::new(None),
            budget: self.budget.clone(),
        }))
    }
    fn collect(&mut self) {
        self.reap_abandoned();
        self.wayland.collect();
        self.retained.retain(|x| x.strong_count() != 0);
        self.submissions.retain_mut(|s| {
            let done = unsafe {
                s.fence
                    .device
                    .native
                    .get_fence_status(vk::Fence::from_raw(s.fence.raw))
            } == Ok(true);
            // A final-batch timeline signal proves commands have completed,
            // even if the private bookkeeping fence is signaled slightly later.
            // Allow reset/re-record immediately; keep the native fence and the
            // captured resource graph alive until its own completion. Never
            // decrement again or overwrite newly recorded command state later.
            let logical = done
                || !s.commands_complete
                    && s.timeline_completion.iter().any(|(semaphore, value)| {
                        let dev = &semaphore.device;
                        let api = ash::khr::timeline_semaphore::Device::new(
                            &dev.instance.native,
                            &dev.native,
                        );
                        unsafe {
                            api.get_semaphore_counter_value(vk::Semaphore::from_raw(semaphore.raw))
                        }
                        .is_ok_and(|counter| counter >= *value)
                    });
            if logical && !s.commands_complete {
                for command in &s.commands {
                    let remaining = command.pending_submissions.get() - 1;
                    command.pending_submissions.set(remaining);
                    if remaining == 0 {
                        command.state.set(2);
                    }
                }
                s.commands_complete = true;
            }
            !done
        });
    }
    pub fn reap_abandoned(&mut self) {
        self.compiles
            .retain(|_, c| !c.abandoned || matches!(c.task.poll(), Ok(None)));
    }
    pub fn invoke(
        &mut self,
        memory: &mut impl CpuMemory,
        operation: u64,
        address: u64,
        size: u64,
    ) -> std::result::Result<Invocation, MemoryError> {
        if size != 128 {
            return Ok(Invocation::Complete(
                vk::Result::ERROR_UNKNOWN.as_raw() as i64 as u64,
            ));
        }
        let mut bytes = [0; 128];
        memory.read(address, &mut bytes)?;
        let a: [u64; 16] = std::array::from_fn(|i| {
            u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
        });
        static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let trace = *TRACE.get_or_init(|| std::env::var_os("TRAMES_VULKAN_TRACE").is_some());
        if trace {
            eprintln!("trames-vulkan op={operation} args={a:x?}");
        }
        self.collect();
        let result = if operation == 27 {
            self.start_compile(memory, a).map(Invocation::Pending)
        } else if operation == 70 {
            self.start_graphics_compile(memory, a)
                .map(Invocation::Pending)
        } else {
            self.call(memory, operation, a)
                .map(|()| Invocation::Complete(0))
        };
        match result {
            Ok(value) => Ok(value),
            Err(Failure::Vk(e)) => {
                if trace {
                    eprintln!(
                        "trames-vulkan op={operation} result={e:?} budget={}/{}",
                        self.budget.used(),
                        self.budget.limit()
                    );
                }
                Ok(Invocation::Complete(e.as_raw() as i64 as u64))
            }
            Err(Failure::Memory(e)) => Err(e),
        }
    }
    fn start_compile(&mut self, m: &impl CpuMemory, a: [u64; 16]) -> Result<u64> {
        let device = self.device(a[0])?;
        self.room(1)?;
        output(m, a[4], 8)?;
        let layout = self.object(a[1], Kind::PipelineLayout)?;
        let shader = self.object(a[2], Kind::Shader)?;
        let name = std::ffi::CString::new(guest_string(m, a[3], 256)?)
            .map_err(|_| Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
        let wire = words64(m, a[5], bounded(a[6], 64)? * 3)?;
        let data_size = bounded(a[8], 65536)?;
        let entries = specialization_entries(&wire, data_size)?;
        let mut data = vec![0; data_size];
        if data_size != 0 {
            m.read(a[7], &mut data)?;
        }
        let permit = self
            .budget
            .compile()
            .ok_or(Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        let raw_shader = vk::ShaderModule::from_raw(shader.raw);
        let raw_layout = vk::PipelineLayout::from_raw(layout.raw);
        let cache = if a[9] == 0 {
            None
        } else {
            Some(self.object(a[9], Kind::PipelineCache)?)
        };
        let raw_cache = cache.as_ref().map_or(vk::PipelineCache::null(), |c| {
            vk::PipelineCache::from_raw(c.raw)
        });
        let task = crate::task::Task::spawn(move || {
            let _permit = permit;
            let specialization = vk::SpecializationInfo::default()
                .map_entries(&entries)
                .data(&data);
            let stage = vk::PipelineShaderStageCreateInfo::default()
                .stage(vk::ShaderStageFlags::COMPUTE)
                .module(raw_shader)
                .name(&name)
                .specialization_info(&specialization);
            let info = [vk::ComputePipelineCreateInfo::default()
                .stage(stage)
                .layout(raw_layout)];
            match unsafe {
                device
                    .native
                    .create_compute_pipelines(raw_cache, &info, None)
            } {
                Ok(p) => Ok(CompiledPipeline { device, raw: p[0] }),
                Err((p, error)) => {
                    for raw in p {
                        unsafe {
                            device.native.destroy_pipeline(raw, None);
                        }
                    }
                    Err(error)
                }
            }
        })
        .map_err(|_| Failure::Vk(vk::Result::ERROR_OUT_OF_HOST_MEMORY))?;
        let job = self.id();
        self.compiles.insert(
            job,
            Compile {
                task,
                dependencies: {
                    let mut d = vec![layout, shader];
                    d.extend(cache);
                    d
                },
                bind_point: vk::PipelineBindPoint::COMPUTE,
                vertex_inputs: Vec::new(),
                static_states: 0,
                output: a[4],
                abandoned: false,
            },
        );
        Ok(job)
    }
    pub fn abandon(&mut self, job: u64) {
        if let Some(c) = self.compiles.get_mut(&job) {
            c.abandoned = true;
        }
    }
    pub(crate) fn subscribe_compile(
        &self,
        job: u64,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        self.compiles.get(&job).map(|c| c.task.subscribe(signal))
    }
    pub fn poll(
        &mut self,
        m: &mut impl CpuMemory,
        job: u64,
    ) -> std::result::Result<Option<u64>, MemoryError> {
        let result = match self.compiles.get_mut(&job) {
            Some(c) => c.task.poll(),
            None => return Ok(Some(vk::Result::ERROR_DEVICE_LOST.as_raw() as i64 as u64)),
        };
        if matches!(result, Ok(None)) {
            return Ok(None);
        }
        let c = self.compiles.remove(&job).expect("polled compile");
        let mut pipeline = match result {
            Ok(Some(Ok(p))) => p,
            Ok(Some(Err(e))) => return Ok(Some(e.as_raw() as i64 as u64)),
            Err(()) => return Ok(Some(vk::Result::ERROR_DEVICE_LOST.as_raw() as i64 as u64)),
            Ok(None) => unreachable!(),
        };
        // Mappings may have changed while another CLONE_VM thread ran. Check
        // the live output before installing an ID; failure drops native output.
        output(m, c.output, 8).map_err(|e| match e {
            Failure::Memory(e) => e,
            _ => unreachable!(),
        })?;
        let id = self.put(
            Kind::Pipeline,
            pipeline.raw.as_raw(),
            // Shaders are needed only until compilation finishes. Keep the
            // layout and graphics compatibility pass, without pinning deleted
            // shader modules against the context's retained-object budget.
            c.dependencies
                .iter()
                .take(if c.bind_point == vk::PipelineBindPoint::GRAPHICS {
                    2
                } else {
                    1
                })
                .cloned()
                .collect(),
            0,
            c.bind_point.as_raw() as u32,
        );
        *self.objects[&id].vertex_inputs.borrow_mut() = c.vertex_inputs;
        self.objects[&id].static_states.set(c.static_states);
        pipeline.raw = vk::Pipeline::null();
        if let Err(error) = m.write(c.output, &id.to_le_bytes()) {
            // A live backing provider can still fail after permission preflight.
            // Remove the unpublished object, releasing its native pipeline and
            // dependencies; a consumed opaque ID is never reused.
            self.objects.remove(&id);
            return Err(error);
        }
        Ok(Some(0))
    }
    fn call(&mut self, m: &mut impl CpuMemory, op: u64, a: [u64; 16]) -> Result<()> {
        if (109..=111).contains(&op) {
            return self.wayland_entry(m, op, a);
        }
        if (82..=86).contains(&op) && self.wayland.surfaces.contains_key(&a[1]) {
            return self.wayland_query(m, op, a);
        }
        if op == 79 {
            let (w, h, _) = self.display.info();
            return write_words(m, a[0], &[u64::from(w != 0), w as u64, h as u64], 24);
        }
        if (80..=86).contains(&op) {
            return self.wsi_query(m, op, a);
        }
        if op == 1 {
            output(m, a[0], 8)?;
            if self.instance.is_some() {
                return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
            }
            let entry =
                load_entry().map_err(|_| Failure::Vk(vk::Result::ERROR_INITIALIZATION_FAILED))?;
            let extensions = unsafe { entry.enumerate_instance_extension_properties(None) }?;
            let portability=extensions.iter().any(|e| unsafe { std::ffi::CStr::from_ptr(e.extension_name.as_ptr()) }==ash::khr::portability_enumeration::NAME);
            let mut names = if portability {
                vec![ash::khr::portability_enumeration::NAME.as_ptr()]
            } else {
                Vec::new()
            };
            let queries2 = extensions.iter().any(|e| unsafe { std::ffi::CStr::from_ptr(e.extension_name.as_ptr()) } == ash::khr::get_physical_device_properties2::NAME);
            if queries2 {
                names.push(ash::khr::get_physical_device_properties2::NAME.as_ptr());
            }
            if a[1] > 2 {
                return unsupported();
            }
            self.virtual_wsi = a[1] == 2;
            if a[1] == 2 && self.wayland.server.is_none() {
                return unsupported();
            }
            if a[1] == 1 {
                if self.display.target().is_none() {
                    return Err(vk::Result::ERROR_INITIALIZATION_FAILED.into());
                }
                names.extend([
                    ash::khr::surface::NAME.as_ptr(),
                    ash::ext::metal_surface::NAME.as_ptr(),
                ]);
            }
            let simulator = cfg!(all(target_os = "ios", target_abi = "sim"));
            if simulator {
                if !extensions.iter().any(|e| unsafe { std::ffi::CStr::from_ptr(e.extension_name.as_ptr()) } == ash::ext::layer_settings::NAME) {
                    return Err(vk::Result::ERROR_INITIALIZATION_FAILED.into());
                }
                names.push(ash::ext::layer_settings::NAME.as_ptr());
            }
            // The iOS 18.5 simulator's SimMetalHost aborts while deserializing
            // argument-encoder buffer slots. Select MoltenVK's original direct
            // resource-binding path per instance, without global env mutation.
            let argument_buffers = vk::FALSE;
            let settings = [vk::LayerSettingEXT {
                value_count: 1,
                p_values: (&argument_buffers as *const vk::Bool32).cast(),
                ..vk::LayerSettingEXT::default()
                    .layer_name(c"MoltenVK")
                    .setting_name(c"MVK_CONFIG_USE_METAL_ARGUMENT_BUFFERS")
                    .ty(vk::LayerSettingTypeEXT::BOOL32)
            }];
            let mut layer_settings = vk::LayerSettingsCreateInfoEXT::default().settings(&settings);
            let app = vk::ApplicationInfo::default().api_version(vk::API_VERSION_1_0);
            let mut info = vk::InstanceCreateInfo::default()
                .application_info(&app)
                .enabled_extension_names(&names)
                .flags(if portability {
                    vk::InstanceCreateFlags::ENUMERATE_PORTABILITY_KHR
                } else {
                    vk::InstanceCreateFlags::empty()
                });
            if simulator {
                info = info.push_next(&mut layer_settings);
            }
            let native = unsafe { entry.create_instance(&info, None) }?;
            let instance = Arc::new(Instance {
                native,
                _entry: entry,
                queries2,
            });
            let devices = unsafe { instance.native.enumerate_physical_devices() }?;
            self.physical = devices
                .into_iter()
                .find(|&p| {
                    unsafe {
                        instance
                            .native
                            .get_physical_device_queue_family_properties(p)
                    }
                    .iter()
                    .any(|q| q.queue_flags.contains(vk::QueueFlags::COMPUTE))
                })
                .ok_or(Failure::Vk(vk::Result::ERROR_INITIALIZATION_FAILED))?;
            self.capabilities = zink::Capabilities::query(&instance, self.physical)?;
            self.wsi_enabled = a[1] != 0;
            self.instance = Some(instance);
            self.instance_id = self.id();
            self.physical_id = self.id();
            write(m, a[0], &self.instance_id.to_le_bytes())?;
            return Ok(());
        }
        if op == 2 {
            if a[0] != self.instance_id {
                return invalid();
            }
            self.clear_device();
            self.wsi.surfaces.clear();
            self.wayland.surfaces.clear();
            self.instance = None;
            self.wsi_enabled = false;
            self.instance_id = 0;
            self.physical_id = 0;
            self.capabilities = Default::default();
            return Ok(());
        }
        let instance = self
            .instance
            .clone()
            .ok_or(Failure::Vk(vk::Result::ERROR_INITIALIZATION_FAILED))?;
        if ((3..=8).contains(&op)
            || (58..=59).contains(&op)
            || op == 115
            || op == 121
            || op == 126
            || op == 133
            || op == 137
            || op == 150)
            && a[0]
                != if op == 3 {
                    self.instance_id
                } else {
                    self.physical_id
                }
        {
            return invalid();
        }
        match op {
            115 => {
                write_words(
                    m,
                    a[1],
                    &[
                        self.capabilities.bits,
                        self.capabilities.max_timeline_difference,
                    ],
                    16,
                )?;
            }
            133 => self.capabilities.write_portability(m, a[1])?,
            137 => self.capabilities.write_feedback(m, a[1])?,
            150 => write(
                m,
                a[1],
                &self
                    .capabilities
                    .divisor
                    .map_or(0, |p| p.maximum)
                    .to_le_bytes(),
            )?,
            126 => {
                self.capabilities.write_clipping(m, a[1])?;
            }
            121 => {
                self.capabilities.write_driver(m, a[1])?;
            }
            3 => {
                output(m, a[1], 4)?;
                if a[2] != 0 {
                    output(m, a[2], 8)?;
                    write(m, a[2], &self.physical_id.to_le_bytes())?;
                }
                write(m, a[1], &1u32.to_le_bytes())?;
            }
            4 => {
                let mut b =
                    vec![0u64; std::mem::size_of::<vk::PhysicalDeviceProperties>().div_ceil(8)];
                output(m, a[1], std::mem::size_of::<vk::PhysicalDeviceProperties>())?;
                unsafe {
                    (instance.native.fp_v1_0().get_physical_device_properties)(
                        self.physical,
                        b.as_mut_ptr().cast(),
                    );
                }
                // This is an experimental 1.0 compute profile, not a complete
                // Vulkan conformance claim or the host driver's extension set.
                b[0] = (b[0] & 0xffffffff00000000) | vk::API_VERSION_1_0 as u64;
                // Bound the implemented MRT profile by the real native limit.
                let properties =
                    unsafe { &mut *b.as_mut_ptr().cast::<vk::PhysicalDeviceProperties>() };
                properties.limits.max_color_attachments = properties
                    .limits
                    .max_color_attachments
                    .min(graphics::MAX_COLORS as u32);
                properties.limits.max_fragment_output_attachments = properties
                    .limits
                    .max_fragment_output_attachments
                    .min(properties.limits.max_color_attachments);
                properties.limits.max_viewports = 1;
                properties.limits.max_image_dimension1_d = properties
                    .limits
                    .max_image_dimension1_d
                    .min(graphics::DIMENSION);
                properties.limits.max_image_dimension2_d = properties
                    .limits
                    .max_image_dimension2_d
                    .min(graphics::DIMENSION);
                properties.limits.max_image_dimension3_d = properties
                    .limits
                    .max_image_dimension3_d
                    .min(graphics::DIMENSION);
                properties.limits.max_image_dimension_cube = properties
                    .limits
                    .max_image_dimension_cube
                    .min(graphics::DIMENSION);
                properties.limits.max_image_array_layers = properties
                    .limits
                    .max_image_array_layers
                    .min(graphics::LAYERS);
                write_words(
                    m,
                    a[1],
                    &b,
                    std::mem::size_of::<vk::PhysicalDeviceProperties>(),
                )?;
            }
            5 => {
                let mut b = vec![
                    0u64;
                    std::mem::size_of::<vk::PhysicalDeviceMemoryProperties>()
                        .div_ceil(8)
                ];
                output(
                    m,
                    a[1],
                    std::mem::size_of::<vk::PhysicalDeviceMemoryProperties>(),
                )?;
                unsafe {
                    (instance
                        .native
                        .fp_v1_0()
                        .get_physical_device_memory_properties)(
                        self.physical,
                        b.as_mut_ptr().cast(),
                    );
                }
                // Explicitly capped sessions expose their native quota. Host-
                // managed sessions retain the original driver's heap sizes.
                // Contexts and coherent baselines share live accounting.
                // SAFETY: u64 storage provides the native struct's alignment;
                // the original Vulkan driver initialized this complete value.
                let properties =
                    unsafe { &mut *b.as_mut_ptr().cast::<vk::PhysicalDeviceMemoryProperties>() };
                for heap in properties
                    .memory_heaps
                    .iter_mut()
                    .take(properties.memory_heap_count as usize)
                {
                    heap.size = heap.size.min(self.budget.limit());
                }
                // Native coherent types are mirrored at queue submission and
                // exposed host completion boundaries, with per-byte ownership.
                write_words(
                    m,
                    a[1],
                    &b,
                    std::mem::size_of::<vk::PhysicalDeviceMemoryProperties>(),
                )?;
            }
            6 => {
                let props = unsafe {
                    instance
                        .native
                        .get_physical_device_queue_family_properties(self.physical)
                };
                let capacity = read32(m, a[1])? as usize;
                output(m, a[1], 4)?;
                if a[2] != 0 {
                    output(m, a[2], capacity.min(props.len()) * 24)?;
                    for (i, q) in props.iter().take(capacity).enumerate() {
                        let mut v = Vec::new();
                        for n in [
                            q.queue_flags.as_raw()
                                & (vk::QueueFlags::GRAPHICS
                                    | vk::QueueFlags::COMPUTE
                                    | vk::QueueFlags::TRANSFER)
                                    .as_raw(),
                            q.queue_count.min(1),
                            q.timestamp_valid_bits,
                            q.min_image_transfer_granularity.width,
                            q.min_image_transfer_granularity.height,
                            q.min_image_transfer_granularity.depth,
                        ] {
                            v.extend(n.to_le_bytes());
                        }
                        write(m, a[2] + i as u64 * 24, &v)?;
                    }
                }
                write(
                    m,
                    a[1],
                    &(if a[2] == 0 {
                        props.len()
                    } else {
                        capacity.min(props.len())
                    } as u32)
                        .to_le_bytes(),
                )?;
            }
            7 => {
                let native = unsafe { instance.native.get_physical_device_features(self.physical) };
                let mut features = vec![0; std::mem::size_of::<vk::PhysicalDeviceFeatures>()];
                for (at, value) in [
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, sampler_anisotropy),
                        native.sampler_anisotropy,
                    ),
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, logic_op),
                        native.logic_op,
                    ),
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, fill_mode_non_solid),
                        native.fill_mode_non_solid,
                    ),
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, shader_clip_distance),
                        native.shader_clip_distance,
                    ),
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, independent_blend),
                        native.independent_blend,
                    ),
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, image_cube_array),
                        native.image_cube_array,
                    ),
                    (
                        std::mem::offset_of!(vk::PhysicalDeviceFeatures, sample_rate_shading),
                        native.sample_rate_shading,
                    ),
                ] {
                    features[at..at + 4].copy_from_slice(&value.to_le_bytes());
                }
                write(m, a[1], &features)?;
            }
            8 => {
                output(m, a[2], 8)?;
                if self.device.is_some() {
                    return Err(vk::Result::ERROR_TOO_MANY_OBJECTS.into());
                }
                let queues = unsafe {
                    instance
                        .native
                        .get_physical_device_queue_family_properties(self.physical)
                };
                if !queues
                    .get(a[1] as usize)
                    .is_some_and(|q| q.queue_flags.contains(vk::QueueFlags::COMPUTE))
                {
                    return unsupported();
                }
                let priorities = [1.0];
                let queue = [vk::DeviceQueueCreateInfo::default()
                    .queue_family_index(a[1] as u32)
                    .queue_priorities(&priorities)];
                let ext = unsafe {
                    instance
                        .native
                        .enumerate_device_extension_properties(self.physical)
                }?;
                let subset=ext.iter().any(|e| unsafe { std::ffi::CStr::from_ptr(e.extension_name.as_ptr()) }==ash::khr::portability_subset::NAME);
                let mut names = if subset {
                    vec![ash::khr::portability_subset::NAME.as_ptr()]
                } else {
                    Vec::new()
                };
                if a[3] > 1 || a[3] != 0 && !self.wsi_enabled {
                    return unsupported();
                }
                if a[3] != 0 && !self.virtual_wsi {
                    names.push(ash::khr::swapchain::NAME.as_ptr());
                }
                if self.virtual_wsi && cfg!(target_vendor = "apple") {
                    if !ext.iter().any(|e|unsafe {std::ffi::CStr::from_ptr(e.extension_name.as_ptr())}==ash::ext::metal_objects::NAME){return unsupported();}
                    names.push(ash::ext::metal_objects::NAME.as_ptr());
                }
                let native_features =
                    unsafe { instance.native.get_physical_device_features(self.physical) };
                if a[4] & !127 != 0
                    || [
                        native_features.sampler_anisotropy,
                        native_features.logic_op,
                        native_features.fill_mode_non_solid,
                        native_features.shader_clip_distance,
                        native_features.independent_blend,
                        native_features.image_cube_array,
                        native_features.sample_rate_shading,
                    ]
                    .iter()
                    .enumerate()
                    .any(|(i, &v)| a[4] & (1 << i) != 0 && v == 0)
                {
                    return unsupported();
                }
                let features = vk::PhysicalDeviceFeatures::default()
                    .sampler_anisotropy(a[4] & 1 != 0)
                    .logic_op(a[4] & 2 != 0)
                    .fill_mode_non_solid(a[4] & 4 != 0)
                    .shader_clip_distance(a[4] & 8 != 0)
                    .independent_blend(a[4] & 16 != 0)
                    .image_cube_array(a[4] & 32 != 0)
                    .sample_rate_shading(a[4] & 64 != 0);
                self.wsi.device_enabled = a[3] != 0;
                zink::device_extensions(a[5], &self.capabilities, &mut names)?;
                let mut timeline = vk::PhysicalDeviceTimelineSemaphoreFeatures::default()
                    .timeline_semaphore(a[5] & 2 != 0);
                let mut imageless = vk::PhysicalDeviceImagelessFramebufferFeatures::default()
                    .imageless_framebuffer(a[5] & 512 != 0);
                let mut portability = self.capabilities.portability;
                let mut scalar = vk::PhysicalDeviceScalarBlockLayoutFeatures::default()
                    .scalar_block_layout(a[5] & 2048 != 0);
                let mut feedback = vk::PhysicalDeviceTransformFeedbackFeaturesEXT::default()
                    .transform_feedback(a[5] & 16384 != 0);
                let mut divisor = vk::PhysicalDeviceVertexAttributeDivisorFeaturesEXT::default()
                    .vertex_attribute_instance_rate_divisor(a[5] & 65536 != 0)
                    .vertex_attribute_instance_rate_zero_divisor(a[5] & 131072 != 0);
                let mut info = vk::DeviceCreateInfo::default()
                    .queue_create_infos(&queue)
                    .enabled_features(&features)
                    .enabled_extension_names(&names);
                if a[5] & 2 != 0 {
                    info = info.push_next(&mut timeline);
                }
                if a[5] & 512 != 0 {
                    info = info.push_next(&mut imageless);
                }
                if a[5] & 2048 != 0 {
                    info = info.push_next(&mut scalar);
                }
                if a[5] & 8192 != 0 {
                    info = info.push_next(&mut feedback);
                }
                if a[5] & 32768 != 0 {
                    info = info.push_next(&mut divisor);
                }
                if let Some(ref mut subset) = portability {
                    info = info.push_next(subset);
                }
                let native = unsafe { instance.native.create_device(self.physical, &info, None) }?;
                self.queue = unsafe { native.get_device_queue(a[1] as u32, 0) };
                self.family = a[1] as u32;
                let limits = unsafe {
                    instance
                        .native
                        .get_physical_device_properties(self.physical)
                }
                .limits;
                self.device = Some(Arc::new(Device {
                    anisotropy: a[4] & 1 != 0,
                    features,
                    maintenance1: a[5] & 1 != 0,
                    timeline: a[5] & 2 != 0,
                    renderpass2: a[5] & 128 != 0,
                    imageless: a[5] & 512 != 0,
                    format_list: a[5] & 64 != 0,
                    maintenance2: a[5] & 16 != 0,
                    feedback: self.capabilities.feedback.filter(|_| a[5] & 16384 != 0),
                    feedback_extension: a[5] & 8192 != 0,
                    divisor: self
                        .capabilities
                        .divisor
                        .filter(|_| a[5] & 65536 != 0)
                        .map(|p| zink::Divisor {
                            zero: p.zero && a[5] & 131072 != 0,
                            ..p
                        }),
                    portability: self.capabilities.portability,
                    native,
                    instance,
                    atom: limits.non_coherent_atom_size,
                    map_alignment: limits.min_memory_map_alignment as u64,
                    viewport_dimensions: limits.max_viewport_dimensions,
                    viewport_bounds: limits.viewport_bounds_range,
                }));
                self.device_id = self.id();
                self.queue_id = self.id();
                write(m, a[2], &self.device_id.to_le_bytes())?;
            }
            9 => {
                self.device(a[0])?;
                self.clear_device();
            }
            10 => {
                self.device(a[0])?;
                if a[1] != self.family as u64 || a[2] != 0 {
                    return invalid();
                }
                write(m, a[3], &self.queue_id.to_le_bytes())?;
            }
            58..=59 => self.format_query(m, op, a)?,
            _ => {
                self.device(a[0])?;
                self.device_call(m, op, a)?;
            }
        }
        Ok(())
    }
    fn clear_device(&mut self) {
        self.compiles.clear();
        if let Some(d) = &self.device {
            unsafe {
                let _ = d.native.device_wait_idle();
            }
        }
        self.submissions.clear();
        self.wayland.clear_device();
        self.wsi.clear_device();
        self.mappings.clear();
        self.objects.clear();
        self.device = None;
        self.device_id = 0;
        self.queue_id = 0;
    }
    fn device_call(&mut self, m: &mut impl CpuMemory, op: u64, a: [u64; 16]) -> Result<()> {
        let dev = self.device.as_ref().unwrap().clone();
        let d = &dev.native;
        match op {
            112 => {
                self.room(1)?;
                output(m, a[1], 8)?;
                let size = bounded(a[3], MAX_ALLOCATION as usize)?;
                let mut data = vec![0; size];
                if size != 0 {
                    m.read(a[2], &mut data)?;
                }
                let info = vk::PipelineCacheCreateInfo::default().initial_data(&data);
                let raw = unsafe { d.create_pipeline_cache(&info, None) }?;
                let id = self.put(Kind::PipelineCache, raw.as_raw(), vec![], 0, 0);
                self.publish(m, a[1], id)?;
            }
            113 => self.remove(a[1], Kind::PipelineCache)?,
            130 => {
                output(m, a[2], 8)?;
                let cache = self.object(a[1], Kind::PipelineCache)?;
                let native = vk::PipelineCache::from_raw(cache.raw);
                if a[3] == 0 {
                    let mut size = 0usize;
                    unsafe {
                        (d.fp_v1_0().get_pipeline_cache_data)(
                            d.handle(),
                            native,
                            &mut size,
                            std::ptr::null_mut(),
                        )
                    }
                    .result()?;
                    write(m, a[2], &(size as u64).to_le_bytes())?;
                } else {
                    let capacity = bounded(
                        u64::from_le_bytes(m.read_array::<8>(a[2])?),
                        MAX_ALLOCATION as usize,
                    )?;
                    let mut size = capacity;
                    let mut data = vec![0; capacity];
                    let result = unsafe {
                        (d.fp_v1_0().get_pipeline_cache_data)(
                            d.handle(),
                            native,
                            &mut size,
                            data.as_mut_ptr().cast(),
                        )
                    };
                    if !matches!(result, vk::Result::SUCCESS | vk::Result::INCOMPLETE) {
                        return Err(result.into());
                    }
                    if size > capacity {
                        return invalid();
                    }
                    write(m, a[3], &data[..size])?;
                    write(m, a[2], &(size as u64).to_le_bytes())?;
                    result.result()?;
                }
            }
            131 => {
                let dest = self.object(a[1], Kind::PipelineCache)?;
                let source = words64(m, a[3], bounded(a[2], 64)?)?;
                let mut native = Vec::new();
                for id in source {
                    if id == a[1] {
                        return invalid();
                    }
                    native.push(vk::PipelineCache::from_raw(
                        self.object(id, Kind::PipelineCache)?.raw,
                    ));
                }
                unsafe { d.merge_pipeline_caches(vk::PipelineCache::from_raw(dest.raw), &native) }?;
            }
            11 => {
                self.room(1)?;
                output(m, a[3], 8)?;
                if a[1] == 0 || a[1] > self.budget.max_allocation() {
                    return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
                }
                let mut allowed = vk::BufferUsageFlags::UNIFORM_TEXEL_BUFFER
                    | vk::BufferUsageFlags::STORAGE_TEXEL_BUFFER
                    | vk::BufferUsageFlags::INDIRECT_BUFFER
                    | vk::BufferUsageFlags::STORAGE_BUFFER
                    | vk::BufferUsageFlags::UNIFORM_BUFFER
                    | vk::BufferUsageFlags::VERTEX_BUFFER
                    | vk::BufferUsageFlags::INDEX_BUFFER
                    | vk::BufferUsageFlags::TRANSFER_SRC
                    | vk::BufferUsageFlags::TRANSFER_DST;
                if dev.feedback.is_some() {
                    allowed |= vk::BufferUsageFlags::TRANSFORM_FEEDBACK_BUFFER_EXT
                        | vk::BufferUsageFlags::TRANSFORM_FEEDBACK_COUNTER_BUFFER_EXT;
                }
                if a[2] == 0 || a[2] & !(allowed.as_raw() as u64) != 0 {
                    return unsupported();
                }
                let info = vk::BufferCreateInfo::default()
                    .size(a[1])
                    .usage(vk::BufferUsageFlags::from_raw(a[2] as u32));
                let raw = unsafe { d.create_buffer(&info, None) }?;
                let id = self.put(Kind::Buffer, raw.as_raw(), vec![], a[1], a[2] as u32);
                write(m, a[3], &id.to_le_bytes())?;
            }
            12 => self.remove(a[1], Kind::Buffer)?,
            13 => {
                let b = self.object(a[1], Kind::Buffer)?;
                let r = unsafe { d.get_buffer_memory_requirements(vk::Buffer::from_raw(b.raw)) };
                let mut bytes = Vec::new();
                bytes.extend(r.size.to_le_bytes());
                bytes.extend(r.alignment.to_le_bytes());
                bytes.extend(r.memory_type_bits.to_le_bytes());
                bytes.extend([0; 4]);
                write(m, a[2], &bytes)?;
            }
            14 => {
                self.room(1)?;
                output(m, a[3], 8)?;
                if a[1] == 0 || a[1] > self.budget.max_allocation() {
                    return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
                }
                let props = unsafe {
                    dev.instance
                        .native
                        .get_physical_device_memory_properties(self.physical)
                };
                if a[2] >= props.memory_type_count as u64 {
                    return invalid();
                }
                let info = vk::MemoryAllocateInfo::default()
                    .allocation_size(a[1])
                    .memory_type_index(a[2] as u32);
                if !self.budget.reserve(a[1]) {
                    return Err(vk::Result::ERROR_OUT_OF_DEVICE_MEMORY.into());
                }
                let raw = match unsafe { d.allocate_memory(&info, None) } {
                    Ok(raw) => raw,
                    Err(e) => {
                        self.budget.release(a[1]);
                        return Err(e.into());
                    }
                };
                let id = self.put(
                    Kind::Memory,
                    raw.as_raw(),
                    vec![],
                    a[1],
                    props.memory_types[a[2] as usize].property_flags.as_raw(),
                );
                self.objects[&id].state.set(a[2] as u8);
                write(m, a[3], &id.to_le_bytes())?;
            }
            15 => {
                if let Some(map) = self.mappings.remove(&a[1]) {
                    unsafe {
                        d.unmap_memory(vk::DeviceMemory::from_raw(map.memory.raw));
                    }
                    map.memory.mapped.set(0);
                }
                self.remove(a[1], Kind::Memory)?;
            }
            16 => {
                let b = self.object(a[1], Kind::Buffer)?;
                let mem = self.object(a[2], Kind::Memory)?;
                let r = unsafe { d.get_buffer_memory_requirements(vk::Buffer::from_raw(b.raw)) };
                if !a[3].is_multiple_of(r.alignment)
                    || r.memory_type_bits & (1u32 << mem.state.get()) == 0
                    || a[3].checked_add(r.size).is_none_or(|n| n > mem.size)
                    || !b.deps.borrow().is_empty()
                {
                    return invalid();
                }
                unsafe {
                    d.bind_buffer_memory(
                        vk::Buffer::from_raw(b.raw),
                        vk::DeviceMemory::from_raw(mem.raw),
                        a[3],
                    )
                }?;
                b.retain(mem);
            }
            17 => {
                let mem = self.object(a[1], Kind::Memory)?;
                if mem.mapped.get() != 0
                    || mem.flags & vk::MemoryPropertyFlags::HOST_VISIBLE.as_raw() == 0
                {
                    return invalid();
                }
                let len = if a[3] == u64::MAX {
                    mem.size.saturating_sub(a[2])
                } else {
                    a[3]
                };
                if len == 0 || a[2].checked_add(len).is_none_or(|n| n > mem.size) {
                    return invalid();
                }
                output(m, a[4], len as usize)?;
                let ptr = unsafe {
                    d.map_memory(
                        vk::DeviceMemory::from_raw(mem.raw),
                        0,
                        vk::WHOLE_SIZE,
                        vk::MemoryMapFlags::empty(),
                    )
                }?;
                mem.mapped.set(ptr as usize);
                let initialized = (|| -> Result<Option<coherent::CoherentBytes>> {
                    if mem.flags & vk::MemoryPropertyFlags::HOST_COHERENT.as_raw() == 0 {
                        return Ok(None);
                    }
                    let mut baseline =
                        coherent::CoherentBytes::new(len as usize, self.budget.clone())?;
                    let mut t = unsafe {
                        transfer_pages(
                            m,
                            a[4],
                            (ptr as *mut u8).add(a[2] as usize),
                            len as usize,
                            false,
                        )
                    }?;
                    t.download_bytes = len;
                    self.record_transfer(t);
                    baseline.initialize(m, a[4])?;
                    Ok(Some(baseline))
                })();
                let coherent = match initialized {
                    Ok(v) => v,
                    Err(e) => {
                        unsafe {
                            d.unmap_memory(vk::DeviceMemory::from_raw(mem.raw));
                        }
                        mem.mapped.set(0);
                        return Err(e);
                    }
                };
                self.mappings.insert(
                    a[1],
                    Mapping {
                        memory: mem,
                        guest: a[4],
                        offset: a[2],
                        size: len,
                        coherent,
                    },
                );
            }
            18 => {
                let map = self
                    .mappings
                    .get_mut(&a[1])
                    .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                let t = coherent::synchronize(map, m, map.offset, map.size, true)?;
                self.record_transfer(t);
                let map = self.mappings.remove(&a[1]).unwrap();
                unsafe {
                    d.unmap_memory(vk::DeviceMemory::from_raw(map.memory.raw));
                }
                map.memory.mapped.set(0);
            }
            19 | 20 => {
                let map = self
                    .mappings
                    .get_mut(&a[1])
                    .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                let len = if a[3] == u64::MAX {
                    map.memory.size.saturating_sub(a[2])
                } else {
                    a[3]
                };
                let atom = dev.atom;
                if !a[2].is_multiple_of(atom)
                    || a[3] != u64::MAX
                        && !len.is_multiple_of(atom)
                        && a[2].checked_add(len) != Some(map.memory.size)
                {
                    return invalid();
                }
                if a[2] < map.offset
                    || a[2]
                        .checked_add(len)
                        .is_none_or(|n| n > map.offset + map.size)
                {
                    return invalid();
                }
                if map.coherent.is_some() {
                    let t = coherent::synchronize(map, m, a[2], len, true)?;
                    let down = if op == 20 {
                        coherent::synchronize(map, m, a[2], len, false)?
                    } else {
                        TransferMetrics::default()
                    };
                    self.record_transfer(t);
                    self.record_transfer(down);
                    return Ok(());
                }
                let guest = map.guest + (a[2] - map.offset);
                let ptr = (map.memory.mapped.get() as *mut u8).wrapping_add(a[2] as usize);
                // Native mapped storage is retained by Mapping. No Rust slice
                // or guest-memory guard is kept while the GPU runs.
                let range = [vk::MappedMemoryRange::default()
                    .memory(vk::DeviceMemory::from_raw(map.memory.raw))
                    .offset(a[2])
                    .size(a[3])];
                if op == 19 {
                    // One guest-to-native copy per page, with no full-range Vec.
                    let transfer = unsafe { transfer_pages(m, guest, ptr, len as usize, true) }?;
                    self.transfers.upload_bytes += len;
                    self.transfers.direct_bytes += transfer.direct_bytes;
                    self.transfers.buffered_bytes += transfer.buffered_bytes;
                    unsafe {
                        d.flush_mapped_memory_ranges(&range)?;
                    }
                } else {
                    output(m, guest, len as usize)?;
                    unsafe {
                        d.invalidate_mapped_memory_ranges(&range)?;
                    }
                    let transfer = unsafe { transfer_pages(m, guest, ptr, len as usize, false) }?;
                    self.transfers.download_bytes += len;
                    self.transfers.direct_bytes += transfer.direct_bytes;
                    self.transfers.buffered_bytes += transfer.buffered_bytes;
                }
            }
            21 => {
                self.room(1)?;
                output(m, a[3], 8)?;
                if a[2] == 0 || a[2] > 1 << 20 || !a[2].is_multiple_of(4) {
                    return invalid();
                }
                let mut code = words32(m, a[1], a[2] as usize / 4)?;
                if code.first() != Some(&0x07230203) {
                    return invalid();
                }
                strip_debug_names(&mut code)?;
                let info = vk::ShaderModuleCreateInfo::default().code(&code);
                let raw = unsafe { d.create_shader_module(&info, None) }?;
                let id = self.put(Kind::Shader, raw.as_raw(), vec![], 0, 0);
                write(m, a[3], &id.to_le_bytes())?;
            }
            22 => self.remove(a[1], Kind::Shader)?,
            23 => {
                self.room(1)?;
                output(m, a[3], 8)?;
                let wire = words64(m, a[1], bounded(a[2], 64)? * 4)?;
                let mut bindings = Vec::new();
                let mut metadata = BTreeMap::new();
                for b in wire.chunks_exact(4) {
                    if b[1] > 9 || b[2] == 0 || b[2] > 64 || visibility_stages(b[3]).is_err() {
                        return unsupported();
                    }
                    if b[0] > u32::MAX as u64
                        || metadata
                            .insert(b[0] as u32, (b[1] as u32, b[2] as u32, b[3] as u32))
                            .is_some()
                    {
                        return invalid();
                    }
                    bindings.push(
                        vk::DescriptorSetLayoutBinding::default()
                            .binding(b[0] as u32)
                            .descriptor_type(vk::DescriptorType::from_raw(b[1] as i32))
                            .descriptor_count(b[2] as u32)
                            .stage_flags(visibility_stages(b[3])?),
                    );
                }
                let info = vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
                let raw = unsafe { d.create_descriptor_set_layout(&info, None) }?;
                let id = self.put(Kind::DescriptorLayout, raw.as_raw(), vec![], 0, 0);
                *self.objects[&id].bindings.borrow_mut() = metadata;
                write(m, a[3], &id.to_le_bytes())?;
            }
            24 => self.remove(a[1], Kind::DescriptorLayout)?,
            25 => {
                self.room(1)?;
                output(m, a[5], 8)?;
                let ids = words64(m, a[1], bounded(a[2], 8)?)?;
                let mut deps = Vec::new();
                let mut layouts = Vec::new();
                for id in ids {
                    let obj = self.object(id, Kind::DescriptorLayout)?;
                    layouts.push(vk::DescriptorSetLayout::from_raw(obj.raw));
                    deps.push(obj);
                }
                let wire = words64(m, a[3], bounded(a[4], 8)? * 3)?;
                let mut ranges = Vec::new();
                for r in wire.chunks_exact(3) {
                    if visibility_stages(r[0]).is_err()
                        || r[1] % 4 != 0
                        || r[2] == 0
                        || r[2] % 4 != 0
                        || r[1].checked_add(r[2]).is_none_or(|n| n > 128)
                        || ranges.iter().any(|p: &vk::PushConstantRange| {
                            p.stage_flags.as_raw() as u64 & r[0] != 0
                        })
                    {
                        return unsupported();
                    }
                    ranges.push(
                        vk::PushConstantRange::default()
                            .stage_flags(visibility_stages(r[0])?)
                            .offset(r[1] as u32)
                            .size(r[2] as u32),
                    );
                }
                let info = vk::PipelineLayoutCreateInfo::default()
                    .set_layouts(&layouts)
                    .push_constant_ranges(&ranges);
                let raw = unsafe { d.create_pipeline_layout(&info, None) }?;
                let id = self.put(Kind::PipelineLayout, raw.as_raw(), deps, 0, 0);
                *self.objects[&id].push_ranges.borrow_mut() = ranges
                    .iter()
                    .map(|r| (r.offset, r.size, r.stage_flags.as_raw()))
                    .collect();
                write(m, a[5], &id.to_le_bytes())?;
            }
            26 => self.remove(a[1], Kind::PipelineLayout)?,
            28 => self.remove(a[1], Kind::Pipeline)?,
            29 => {
                self.room(1)?;
                output(m, a[5], 8)?;
                let wire = words64(m, a[1], bounded(a[2], 64)? * 2)?;
                let mut sizes = Vec::new();
                for x in wire.chunks_exact(2) {
                    if x[0] > 9 || x[1] == 0 || x[1] > 65536 {
                        return unsupported();
                    }
                    sizes.push(
                        vk::DescriptorPoolSize::default()
                            .ty(vk::DescriptorType::from_raw(x[0] as i32))
                            .descriptor_count(x[1] as u32),
                    );
                }
                if a[3] == 0 || a[3] > MAX_DESCRIPTOR_SETS as u64 || a[4] & !1 != 0 {
                    return unsupported();
                }
                let info = vk::DescriptorPoolCreateInfo::default()
                    .pool_sizes(&sizes)
                    .max_sets(a[3] as u32)
                    .flags(vk::DescriptorPoolCreateFlags::FREE_DESCRIPTOR_SET);
                let raw = unsafe { d.create_descriptor_pool(&info, None) }?;
                let id = self.put(Kind::DescriptorPool, raw.as_raw(), vec![], 0, a[4] as u32);
                write(m, a[5], &id.to_le_bytes())?;
            }
            129 => {
                let pool = self.object(a[1], Kind::DescriptorPool)?;
                if a[2] != 0 {
                    return unsupported();
                }
                let next = pool
                    .descriptor_epoch
                    .get()
                    .checked_add(1)
                    .ok_or(Failure::Vk(vk::Result::ERROR_TOO_MANY_OBJECTS))?;
                let commands: Vec<_> = self
                    .objects
                    .values()
                    .filter(|c| {
                        c.kind == Kind::CommandBuffer
                            && c.deps.borrow().iter().any(|s| {
                                s.kind == Kind::DescriptorSet
                                    && Rc::ptr_eq(&s.deps.borrow()[0], &pool)
                            })
                    })
                    .cloned()
                    .collect();
                if commands.iter().any(|c| c.state.get() == 3) {
                    return invalid();
                }
                unsafe {
                    d.reset_descriptor_pool(
                        vk::DescriptorPool::from_raw(pool.raw),
                        vk::DescriptorPoolResetFlags::empty(),
                    )
                }?;
                pool.descriptor_epoch.set(next);
                for c in commands {
                    c.state.set(4);
                    c.deps.borrow_mut().truncate(1);
                    *c.recording.borrow_mut() = Recording::default();
                }
                self.objects.retain(|_, s| {
                    s.kind != Kind::DescriptorSet || !Rc::ptr_eq(&s.deps.borrow()[0], &pool)
                });
            }
            30 => self.remove(a[1], Kind::DescriptorPool)?,
            31 => {
                let count = bounded(a[3], MAX_DESCRIPTOR_SETS)?;
                self.room(count)?;
                output(m, a[4], count * 8)?;
                let pool = self.object(a[1], Kind::DescriptorPool)?;
                let ids = words64(m, a[2], count)?;
                let mut deps = Vec::new();
                let mut layouts = Vec::new();
                for id in ids {
                    let obj = self.object(id, Kind::DescriptorLayout)?;
                    layouts.push(vk::DescriptorSetLayout::from_raw(obj.raw));
                    deps.push(obj);
                }
                let info = vk::DescriptorSetAllocateInfo::default()
                    .descriptor_pool(vk::DescriptorPool::from_raw(pool.raw))
                    .set_layouts(&layouts);
                let raw = unsafe { d.allocate_descriptor_sets(&info) }?;
                for (i, (set, layout)) in raw.into_iter().zip(deps).enumerate() {
                    let id = self.put(
                        Kind::DescriptorSet,
                        set.as_raw(),
                        vec![pool.clone(), layout],
                        0,
                        0,
                    );
                    self.objects[&id]
                        .descriptor_epoch
                        .set(pool.descriptor_epoch.get());
                    write(m, a[4] + i as u64 * 8, &id.to_le_bytes())?;
                }
            }
            32 => {
                let pool = self.object(a[1], Kind::DescriptorPool)?;
                if pool.flags & 1 == 0 {
                    return invalid();
                }
                let ids = words64(m, a[2], bounded(a[3], MAX_DESCRIPTOR_SETS)?)?;
                for id in &ids {
                    let set = self.object(*id, Kind::DescriptorSet)?;
                    if !Rc::ptr_eq(&set.deps.borrow()[0], &pool) {
                        return invalid();
                    }
                }
                for id in ids {
                    self.remove(id, Kind::DescriptorSet)?;
                }
            }
            33 => self.write_descriptors(m, a)?,
            34 => {
                self.room(1)?;
                output(m, a[3], 8)?;
                if a[1] != self.family as u64 || a[2] & !3 != 0 {
                    return unsupported();
                }
                let info = vk::CommandPoolCreateInfo::default()
                    .queue_family_index(self.family)
                    .flags(vk::CommandPoolCreateFlags::from_raw(a[2] as u32));
                let raw = unsafe { d.create_command_pool(&info, None) }?;
                let id = self.put(Kind::CommandPool, raw.as_raw(), vec![], 0, a[2] as u32);
                write(m, a[3], &id.to_le_bytes())?;
            }
            35 => self.remove(a[1], Kind::CommandPool)?,
            36 => {
                self.room(1)?;
                output(m, a[2], 8)?;
                let pool = self.object(a[1], Kind::CommandPool)?;
                let info = vk::CommandBufferAllocateInfo::default()
                    .command_pool(vk::CommandPool::from_raw(pool.raw))
                    .level(vk::CommandBufferLevel::PRIMARY)
                    .command_buffer_count(1);
                let raw = unsafe { d.allocate_command_buffers(&info) }?[0];
                let id = self.put(Kind::CommandBuffer, raw.as_raw(), vec![pool], 0, 0);
                write(m, a[2], &id.to_le_bytes())?;
            }
            37 => {
                let c = self.object(a[2], Kind::CommandBuffer)?;
                let pool = self.object(a[1], Kind::CommandPool)?;
                if !Rc::ptr_eq(&c.deps.borrow()[0], &pool) {
                    return invalid();
                }
                self.remove(a[2], Kind::CommandBuffer)?;
            }
            38..=40 => {
                let c = self.object(a[1], Kind::CommandBuffer)?;
                if c.state.get() == 3 {
                    return invalid();
                }
                let raw = vk::CommandBuffer::from_raw(c.raw);
                unsafe {
                    if op == 38 {
                        if a[2] & !5 != 0 || a[2] == 5 {
                            return unsupported();
                        }
                        let info = vk::CommandBufferBeginInfo::default()
                            .flags(vk::CommandBufferUsageFlags::from_raw(a[2] as u32));
                        d.begin_command_buffer(raw, &info)?;
                        c.command_usage.set(a[2] as u32);
                        c.deps.borrow_mut().truncate(1);
                        *c.recording.borrow_mut() = Recording::default();
                        c.state.set(1);
                    } else if op == 39 {
                        if c.state.get() != 1
                            || c.recording.borrow().pass.is_some()
                            || c.recording.borrow().feedback_active
                            || !c.recording.borrow().queries.is_empty()
                        {
                            return invalid();
                        }
                        d.end_command_buffer(raw)?;
                        c.state.set(2);
                    } else {
                        if c.deps.borrow()[0].flags & 2 == 0 || a[2] & !1 != 0 {
                            return invalid();
                        }
                        d.reset_command_buffer(
                            raw,
                            vk::CommandBufferResetFlags::from_raw(a[2] as u32),
                        )?;
                        c.deps.borrow_mut().truncate(1);
                        *c.recording.borrow_mut() = Recording::default();
                        c.state.set(0);
                    }
                }
            }
            41..=47 => {
                let c = self.object(a[1], Kind::CommandBuffer)?;
                if c.state.get() != 1 {
                    return invalid();
                }
                let raw = vk::CommandBuffer::from_raw(c.raw);
                match op {
                    41 => {
                        let p = self.object(a[2], Kind::Pipeline)?;
                        if a[3] != p.flags as u64 || a[3] > 1 {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_bind_pipeline(
                                raw,
                                vk::PipelineBindPoint::from_raw(p.flags as i32),
                                vk::Pipeline::from_raw(p.raw),
                            );
                        }
                        if p.flags == vk::PipelineBindPoint::GRAPHICS.as_raw() as u32 {
                            c.recording.borrow_mut().pipeline = Some(p.clone());
                        } else {
                            c.recording.borrow_mut().compute_pipeline = Some(p.clone());
                        }
                        c.retain(p);
                    }
                    42 => {
                        let layout = self.object(a[2], Kind::PipelineLayout)?;
                        if a[6] > 1 {
                            return unsupported();
                        }
                        if a[3]
                            .checked_add(a[5])
                            .is_none_or(|n| n > layout.deps.borrow().len() as u64)
                        {
                            return invalid();
                        }
                        let ids = words64(m, a[4], bounded(a[5], 8)?)?;
                        let offsets = words32(m, a[7], bounded(a[8], 64)?)?;
                        let mut used_offsets = 0;
                        let mut sets = Vec::new();
                        let mut retained = Vec::new();
                        for (i, id) in ids.into_iter().enumerate() {
                            let s = self.object(id, Kind::DescriptorSet)?;
                            let expected = layout.deps.borrow()[a[3] as usize + i].clone();
                            let actual = s.deps.borrow()[1].clone();
                            if *expected.bindings.borrow() != *actual.bindings.borrow() {
                                return invalid();
                            }
                            let limits = unsafe {
                                dev.instance
                                    .native
                                    .get_physical_device_properties(self.physical)
                            }
                            .limits;
                            for (&binding, &(ty, count, _)) in actual.bindings.borrow().iter() {
                                if !matches!(ty, 8 | 9) {
                                    continue;
                                }
                                let alignment = if ty == 8 {
                                    limits.min_uniform_buffer_offset_alignment
                                } else {
                                    limits.min_storage_buffer_offset_alignment
                                };
                                for index in 0..count {
                                    let dynamic = *offsets
                                        .get(used_offsets)
                                        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?
                                        as u64;
                                    used_offsets += 1;
                                    let ranges = s.dynamic_ranges.borrow();
                                    let &(base, range) = ranges
                                        .get(&(binding, index))
                                        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?;
                                    let resources = s.bound_resources.borrow();
                                    let buffer = &resources
                                        .get(&(binding, index))
                                        .ok_or(Failure::Vk(vk::Result::ERROR_UNKNOWN))?[0];
                                    if !dynamic.is_multiple_of(alignment.max(1))
                                        || base
                                            .checked_add(dynamic)
                                            .and_then(|n| n.checked_add(range))
                                            .is_none_or(|end| end > buffer.size)
                                    {
                                        return invalid();
                                    }
                                }
                            }
                            sets.push(vk::DescriptorSet::from_raw(s.raw));
                            retained.push(s);
                        }
                        if used_offsets != offsets.len() {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_bind_descriptor_sets(
                                raw,
                                if a[6] == 1 {
                                    vk::PipelineBindPoint::GRAPHICS
                                } else {
                                    vk::PipelineBindPoint::COMPUTE
                                },
                                vk::PipelineLayout::from_raw(layout.raw),
                                a[3] as u32,
                                &sets,
                                &offsets,
                            );
                        }
                        for set in retained {
                            c.retain(set);
                        }
                        c.retain(layout);
                    }
                    43 => {
                        if c.recording.borrow().pass.is_some()
                            || c.recording.borrow().compute_pipeline.is_none()
                        {
                            return invalid();
                        }
                        let lim = unsafe {
                            dev.instance
                                .native
                                .get_physical_device_properties(self.physical)
                        }
                        .limits
                        .max_compute_work_group_count;
                        if (0..3).any(|i| a[2 + i] > lim[i] as u64) {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_dispatch(raw, a[2] as u32, a[3] as u32, a[4] as u32);
                        }
                    }
                    44 => {
                        if c.recording.borrow().pass.is_some() {
                            return invalid();
                        }
                        if a[9] & !1 != 0 {
                            return unsupported();
                        }
                        let images = self.image_barriers(m, &c, a[6], a[7], a[8])?;
                        let barriers = [vk::MemoryBarrier::default()
                            .src_access_mask(vk::AccessFlags::from_raw(a[4] as u32))
                            .dst_access_mask(vk::AccessFlags::from_raw(a[5] as u32))];
                        unsafe {
                            d.cmd_pipeline_barrier(
                                raw,
                                dev.stage(a[2] as u32)?,
                                dev.stage(a[3] as u32)?,
                                vk::DependencyFlags::from_raw(a[9] as u32),
                                &barriers,
                                &[],
                                &images,
                            );
                        }
                    }
                    45 => {
                        if c.recording.borrow().pass.is_some() {
                            return invalid();
                        }
                        let src = self.object(a[2], Kind::Buffer)?;
                        let dst = self.object(a[3], Kind::Buffer)?;
                        if src.deps.borrow().is_empty()
                            || dst.deps.borrow().is_empty()
                            || src.flags & vk::BufferUsageFlags::TRANSFER_SRC.as_raw() == 0
                            || dst.flags & vk::BufferUsageFlags::TRANSFER_DST.as_raw() == 0
                        {
                            return invalid();
                        }
                        let wire = words64(m, a[4], bounded(a[5], 64)? * 3)?;
                        let mut regions = Vec::new();
                        for x in wire.chunks_exact(3) {
                            if x[2] == 0
                                || x[0].checked_add(x[2]).is_none_or(|n| n > src.size)
                                || x[1].checked_add(x[2]).is_none_or(|n| n > dst.size)
                            {
                                return invalid();
                            }
                            regions.push(
                                vk::BufferCopy::default()
                                    .src_offset(x[0])
                                    .dst_offset(x[1])
                                    .size(x[2]),
                            );
                        }
                        unsafe {
                            d.cmd_copy_buffer(
                                raw,
                                vk::Buffer::from_raw(src.raw),
                                vk::Buffer::from_raw(dst.raw),
                                &regions,
                            );
                        }
                        c.retain(src);
                        c.retain(dst);
                    }
                    46 => {
                        if c.recording.borrow().pass.is_some() {
                            return invalid();
                        }
                        let b = self.object(a[2], Kind::Buffer)?;
                        if b.deps.borrow().is_empty()
                            || b.flags & vk::BufferUsageFlags::TRANSFER_DST.as_raw() == 0
                        {
                            return invalid();
                        }
                        let len = if a[4] == u64::MAX {
                            b.size.saturating_sub(a[3])
                        } else {
                            a[4]
                        };
                        if !a[3].is_multiple_of(4)
                            || len % 4 != 0
                            || a[3].checked_add(len).is_none_or(|n| n > b.size)
                        {
                            return invalid();
                        }
                        unsafe {
                            d.cmd_fill_buffer(
                                raw,
                                vk::Buffer::from_raw(b.raw),
                                a[3],
                                a[4],
                                a[5] as u32,
                            );
                        }
                        c.retain(b);
                    }
                    47 => {
                        let layout = self.object(a[2], Kind::PipelineLayout)?;
                        let stages = visibility_stages(if a[6] == 0 { 32 } else { a[6] })?;
                        let mut covered = 0;
                        for &(offset, size, flags) in layout.push_ranges.borrow().iter() {
                            if a[3] >= offset as u64
                                && a[3]
                                    .checked_add(a[4])
                                    .is_some_and(|end| end <= (offset as u64 + size as u64))
                            {
                                covered |= flags;
                            }
                        }
                        if covered & stages.as_raw() != stages.as_raw() {
                            return invalid();
                        }
                        if !a[3].is_multiple_of(4)
                            || a[4] == 0
                            || !a[4].is_multiple_of(4)
                            || a[3].checked_add(a[4]).is_none_or(|n| n > 128)
                        {
                            return invalid();
                        }
                        let mut bytes = vec![0; a[4] as usize];
                        m.read(a[5], &mut bytes)?;
                        unsafe {
                            d.cmd_push_constants(
                                raw,
                                vk::PipelineLayout::from_raw(layout.raw),
                                stages,
                                a[3] as u32,
                                &bytes,
                            );
                        }
                        c.retain(layout);
                    }
                    _ => unreachable!(),
                }
            }
            48 => {
                self.room(1)?;
                output(m, a[2], 8)?;
                if a[1] & !1 != 0 {
                    return invalid();
                }
                let info = vk::FenceCreateInfo::default()
                    .flags(vk::FenceCreateFlags::from_raw(a[1] as u32));
                let raw = unsafe { d.create_fence(&info, None) }?;
                let id = self.put(Kind::Fence, raw.as_raw(), vec![], 0, 0);
                write(m, a[2], &id.to_le_bytes())?;
            }
            49 => self.remove(a[1], Kind::Fence)?,
            50 => {
                let f = self.object(a[1], Kind::Fence)?;
                if self.submissions.iter().any(|s| Rc::ptr_eq(&s.fence, &f)) {
                    return invalid();
                }
                if f.acquisition.borrow().is_some() && !Self::fence_ready(&f)? {
                    return invalid();
                }
                unsafe { d.reset_fences(&[vk::Fence::from_raw(f.raw)]) }?;
                *f.acquisition.borrow_mut() = None;
            }
            51 => {
                let f = self.object(a[1], Kind::Fence)?;
                if !Self::fence_ready(&f)? {
                    return Err(vk::Result::NOT_READY.into());
                }
                self.coherent_sync(m, false)?;
            }
            52 | 56 | 120 => self.submit(m, op, a, dev.clone())?,
            54 => {
                self.room(1)?;
                output(m, a[1], 8)?;
                if a[2] > 1 || a[2] == 1 && !dev.timeline || a[2] == 0 && a[3] != 0 {
                    return unsupported();
                }
                let mut ty = vk::SemaphoreTypeCreateInfo::default()
                    .semaphore_type(vk::SemaphoreType::TIMELINE)
                    .initial_value(a[3]);
                let mut info = vk::SemaphoreCreateInfo::default();
                if a[2] != 0 {
                    info = info.push_next(&mut ty);
                }
                let raw = unsafe { d.create_semaphore(&info, None) }?;
                let id = self.put(Kind::Semaphore, raw.as_raw(), vec![], 0, a[2] as u32);
                write(m, a[1], &id.to_le_bytes())?;
            }
            55 => self.remove(a[1], Kind::Semaphore)?,
            57 => {
                let alignment = dev.map_alignment;
                write(m, a[1], &alignment.to_le_bytes())?;
            }
            53 => {
                let pool = self.object(a[1], Kind::CommandPool)?;
                let children: Vec<_> = self
                    .objects
                    .values()
                    .filter(|x| {
                        x.kind == Kind::CommandBuffer
                            && x.deps
                                .borrow()
                                .first()
                                .is_some_and(|p| Rc::ptr_eq(p, &pool))
                    })
                    .cloned()
                    .collect();
                if children.iter().any(|c| c.state.get() == 3) || a[2] & !1 != 0 {
                    return invalid();
                }
                unsafe {
                    d.reset_command_pool(
                        vk::CommandPool::from_raw(pool.raw),
                        vk::CommandPoolResetFlags::from_raw(a[2] as u32),
                    )
                }?;
                for c in children {
                    c.state.set(0);
                    c.deps.borrow_mut().truncate(1);
                    *c.recording.borrow_mut() = Recording::default();
                }
            }
            60..=76 | 94..=97 | 114 | 122..=125 | 134..=136 | 151 => {
                self.graphics_call(m, op, a)?
            }
            132 => self.dynamic_call(m, a)?,
            127..=128 => self.texel_view_call(m, op, a)?,
            92..=93 => self.sampler_call(m, op, a)?,
            87..=91 => self.wsi_device(m, op, a)?,
            116..=119 => self.zink_device(m, op, a, &dev)?,
            138..=149 => self.feedback_call(m, op, a, &dev)?,
            _ => return unsupported(),
        }
        Ok(())
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.clear_device();
    }
}
#[cfg(trames_moltenvk)]
fn load_entry() -> std::result::Result<Entry, ash::LoadingError> {
    unsafe extern "system" {
        fn vkGetInstanceProcAddr(
            instance: vk::Instance,
            name: *const std::ffi::c_char,
        ) -> vk::PFN_vkVoidFunction;
    }
    Ok(unsafe {
        Entry::from_static_fn(ash::StaticFn {
            get_instance_proc_addr: vkGetInstanceProcAddr,
        })
    })
}
#[cfg(not(trames_moltenvk))]
fn load_entry() -> std::result::Result<Entry, ash::LoadingError> {
    if let Some(path) = std::env::var_os("TRAMES_VULKAN_LIBRARY") {
        unsafe { Entry::load_from(path) }
    } else {
        unsafe { Entry::load() }
    }
}
fn bounded(n: u64, limit: usize) -> Result<usize> {
    if n > limit as u64 {
        unsupported()
    } else {
        Ok(n as usize)
    }
}
/// Native pointer covers a retained, mapped driver allocation disjoint from
/// guest backing. Only this callback borrows guest pages; nothing escapes it.
unsafe fn transfer_pages(
    m: &mut impl CpuMemory,
    guest: u64,
    native: *mut u8,
    len: usize,
    upload: bool,
) -> std::result::Result<TransferMetrics, MemoryError> {
    m.check(
        guest,
        len,
        if upload { Access::Read } else { Access::Write },
    )?;
    let mut transferred = TransferMetrics::default();
    let mut offset = 0;
    while offset < len {
        let address = guest + offset as u64;
        let n = (len - offset)
            .min((trames_memory::PAGE_SIZE - address % trames_memory::PAGE_SIZE) as usize);
        let direct = if upload {
            m.cpu_read_chunk(address, n, |bytes| unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), native.add(offset), n);
            })?
            .1
        } else {
            m.cpu_write_chunk(address, n, |bytes| unsafe {
                std::ptr::copy_nonoverlapping(native.add(offset), bytes.as_mut_ptr(), n);
            })?
            .1
        };
        if direct {
            transferred.direct_bytes += n as u64;
        } else {
            transferred.buffered_bytes += n as u64;
        }
        offset += n;
    }
    Ok(transferred)
}
fn visibility_stages(raw: u64) -> Result<vk::ShaderStageFlags> {
    // Visibility may name disabled stages (ALL_GRAPHICS/ALL); it does not
    // enable tessellation/geometry execution or any new pipeline feature.
    if raw != vk::ShaderStageFlags::ALL.as_raw() as u64 && (raw == 0 || raw & !0x3f != 0) {
        return unsupported();
    }
    Ok(vk::ShaderStageFlags::from_raw(raw as u32))
}
fn compute_stage(stage: u32) -> Result<vk::PipelineStageFlags> {
    let allowed = vk::PipelineStageFlags::TOP_OF_PIPE
        | vk::PipelineStageFlags::DRAW_INDIRECT
        | vk::PipelineStageFlags::VERTEX_INPUT
        | vk::PipelineStageFlags::COMPUTE_SHADER
        | vk::PipelineStageFlags::VERTEX_SHADER
        | vk::PipelineStageFlags::EARLY_FRAGMENT_TESTS
        | vk::PipelineStageFlags::LATE_FRAGMENT_TESTS
        | vk::PipelineStageFlags::FRAGMENT_SHADER
        | vk::PipelineStageFlags::COLOR_ATTACHMENT_OUTPUT
        | vk::PipelineStageFlags::ALL_GRAPHICS
        | vk::PipelineStageFlags::TRANSFER
        | vk::PipelineStageFlags::BOTTOM_OF_PIPE
        | vk::PipelineStageFlags::HOST
        | vk::PipelineStageFlags::ALL_COMMANDS
        | vk::PipelineStageFlags::TRANSFORM_FEEDBACK_EXT;
    if stage == 0 || stage & !allowed.as_raw() != 0 {
        return unsupported();
    }
    Ok(vk::PipelineStageFlags::from_raw(stage))
}
fn strip_debug_names(code: &mut Vec<u32>) -> Result<()> {
    // OpName/OpMemberName are nonsemantic debug annotations. MoltenVK 1.4.2's
    // bundled SPIRV-Cross can preserve a valid GLSL name such as `bias`, then
    // collide with metal::bias in generated MSL. Let it generate ID-based names;
    // keep OpEntryPoint strings, IDs, decorations and executable words unchanged.
    if code.len() < 5 {
        return invalid();
    }
    let (mut read, mut write) = (5, 5);
    while read < code.len() {
        let count = (code[read] >> 16) as usize;
        if count == 0 || count > code.len() - read {
            return invalid();
        }
        let opcode = code[read] & 0xffff;
        if opcode != 5 && opcode != 6 {
            if read != write {
                code.copy_within(read..read + count, write);
            }
            write += count;
        }
        read += count;
    }
    code.truncate(write);
    Ok(())
}
fn specialization_entries(wire: &[u64], size: usize) -> Result<Vec<vk::SpecializationMapEntry>> {
    let mut entries = Vec::new();
    for e in wire.chunks_exact(3) {
        if e[0] > u32::MAX as u64
            || e[1] > u32::MAX as u64
            || e[2] == 0
            || e[1].checked_add(e[2]).is_none_or(|end| end > size as u64)
            || entries
                .iter()
                .any(|entry: &vk::SpecializationMapEntry| entry.constant_id == e[0] as u32)
        {
            return invalid();
        }
        entries.push(vk::SpecializationMapEntry {
            constant_id: e[0] as u32,
            offset: e[1] as u32,
            size: e[2] as usize,
        });
    }
    Ok(entries)
}
fn output(m: &impl CpuMemory, p: u64, n: usize) -> Result<()> {
    m.check(p, n, Access::Write)?;
    Ok(())
}
fn guest_string(m: &impl CpuMemory, address: u64, limit: usize) -> Result<Vec<u8>> {
    let address = address & 0x00ffffffffffffff;
    let mut bytes = Vec::new();
    while bytes.len() < limit {
        let at = address
            .checked_add(bytes.len() as u64)
            .ok_or(MemoryError::InvalidRange)?;
        let len = (limit - bytes.len())
            .min((trames_memory::PAGE_SIZE - at % trames_memory::PAGE_SIZE) as usize);
        let (terminated, _) = m.cpu_read_chunk(at, len, |part| {
            let end = part.iter().position(|&b| b == 0);
            bytes.extend_from_slice(&part[..end.unwrap_or(part.len())]);
            end.is_some()
        })?;
        if terminated {
            return Ok(bytes);
        }
    }
    Err(MemoryError::Limit.into())
}
fn write(m: &mut impl CpuMemory, p: u64, b: &[u8]) -> Result<()> {
    m.write(p, b)?;
    Ok(())
}
fn read32(m: &impl CpuMemory, p: u64) -> Result<u32> {
    let mut b = [0; 4];
    m.read(p, &mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn words64(m: &impl CpuMemory, p: u64, n: usize) -> Result<Vec<u64>> {
    let mut b = vec![0; n * 8];
    m.read(p, &mut b)?;
    Ok(b.chunks_exact(8)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .collect())
}
fn words32(m: &impl CpuMemory, p: u64, n: usize) -> Result<Vec<u32>> {
    let mut b = vec![0; n * 4];
    m.read(p, &mut b)?;
    Ok(b.chunks_exact(4)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
        .collect())
}
fn write_words(m: &mut impl CpuMemory, p: u64, b: &[u64], n: usize) -> Result<()> {
    let bytes: Vec<_> = b.iter().flat_map(|x| x.to_le_bytes()).collect();
    write(m, p, &bytes[..n])
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn worker_transfers_use_cpu_pages_and_preflight_before_external_effects() {
        let base = 0x10000;
        let mut memory = Memory::default();
        memory.map(base, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        let data: Vec<_> = (0..5000).map(|i| i as u8).collect();
        let at = base + PAGE_SIZE - 13;
        memory.write(at, &data).unwrap();
        let parent = memory.clone();
        memory
            .protect(base + 2 * PAGE_SIZE, PAGE_SIZE, Permissions::R)
            .unwrap();
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let mut native = vec![0; data.len()];
        let metrics =
            unsafe { transfer_pages(&mut view, at, native.as_mut_ptr(), native.len(), true) }
                .unwrap();
        assert_eq!(native, data);
        assert_eq!(metrics.direct_bytes, data.len() as u64);
        native.fill(42);
        // Last page is read-only. Failure must not touch the writable prefix.
        assert!(
            unsafe { transfer_pages(&mut view, at, native.as_mut_ptr(), native.len(), false) }
                .is_err()
        );
        let mut current = vec![0; data.len()];
        view.read(at, &mut current).unwrap();
        assert_eq!(current, data);
        let metrics =
            unsafe { transfer_pages(&mut view, at, native.as_mut_ptr(), 4096, false) }.unwrap();
        assert_eq!(metrics.direct_bytes, 4096);
        assert_eq!(metrics.buffered_bytes, 0);
        view.read(at, &mut current[..4096]).unwrap();
        assert_eq!(&current[..4096], &[42; 4096]);
        drop(view);
        memory.commit_parallel().unwrap();
        memory.read(at, &mut current[..4096]).unwrap();
        assert_eq!(&current[..4096], &[42; 4096]);
        parent.read(at, &mut current).unwrap();
        assert_eq!(current, data);
    }
    #[test]
    fn spirv_debug_names_do_not_change_entrypoints_or_specialization_decorations() {
        let header = [0x07230203, 0x10000, 0, 10, 0];
        let entry = [5 << 16 | 15, 5, 1, 0x6e69616d, 0];
        let decoration = [4 << 16 | 71, 3, 1, 0];
        let mut code = [
            header.as_slice(),
            &entry,
            &[4 << 16 | 5, 2, 0x73616962, 0],
            &[5 << 16 | 6, 4, 0, 0x6c616373, 0x65],
            &decoration,
        ]
        .concat();
        strip_debug_names(&mut code).unwrap();
        assert_eq!(code, [header.as_slice(), &entry, &decoration].concat());
        for mut malformed in [vec![0; 4], vec![0; 6], vec![0, 0, 0, 0, 0, 3 << 16 | 15]] {
            assert!(strip_debug_names(&mut malformed).is_err());
        }
    }
    #[test]
    fn native_transfers_cross_pages_keep_cow_and_preflight_permissions() {
        let mut memory = Memory::new(3 * PAGE_SIZE as usize);
        memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        let mut source: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        memory.write(0x1ff3, &source).unwrap();
        let parent = memory.clone();
        let mut native = vec![0; source.len()];
        let upload =
            unsafe { transfer_pages(&mut memory, 0x1ff3, native.as_mut_ptr(), native.len(), true) }
                .unwrap();
        assert_eq!(native, source);
        assert_eq!(upload.direct_bytes, source.len() as u64);
        source.fill(42);
        native.copy_from_slice(&source);
        let download = unsafe {
            transfer_pages(
                &mut memory,
                0x1ff3,
                native.as_mut_ptr(),
                native.len(),
                false,
            )
        }
        .unwrap();
        let mut current = vec![0; source.len()];
        memory.read(0x1ff3, &mut current).unwrap();
        assert_eq!(current, source);
        parent.read(0x1ff3, &mut current).unwrap();
        assert_ne!(current, source);
        assert_eq!(download.direct_bytes, source.len() as u64);
        memory.protect(0x3000, PAGE_SIZE, Permissions::RX).unwrap();
        native.fill(7);
        assert!(unsafe {
            transfer_pages(
                &mut memory,
                0x1ff3,
                native.as_mut_ptr(),
                native.len(),
                false,
            )
        }
        .is_err());
        memory.read(0x1ff3, &mut current).unwrap();
        assert_eq!(current, source);
    }
    #[test]
    fn specialization_records_keep_offsets_and_reject_overflow_or_duplicate_ids() {
        let entries = specialization_entries(&[1, 4, 4, 0, 8, 4], 16).unwrap();
        assert_eq!(
            (entries[0].constant_id, entries[0].offset, entries[0].size),
            (1, 4, 4)
        );
        assert_eq!((entries[1].constant_id, entries[1].offset), (0, 8));
        for invalid in [
            vec![0, 12, 8],
            vec![0, 0, 0],
            vec![0, 1, u64::MAX],
            vec![u64::MAX, 0, 4],
            vec![0, 0, 4, 0, 4, 4],
        ] {
            assert!(specialization_entries(&invalid, 16).is_err());
        }
    }
    #[test]
    fn wait_stages_support_selected_graphics_but_reject_unknown_extension_bits() {
        assert!(compute_stage(vk::PipelineStageFlags::COMPUTE_SHADER.as_raw()).is_ok());
        assert!(compute_stage(vk::PipelineStageFlags::VERTEX_INPUT.as_raw()).is_ok());
        assert!(compute_stage(vk::PipelineStageFlags::ALL_COMMANDS.as_raw()).is_ok());
        for stage in [
            0,
            vk::PipelineStageFlags::GEOMETRY_SHADER.as_raw(),
            u32::MAX,
        ] {
            assert!(compute_stage(stage).is_err());
        }
    }
    #[test]
    fn malformed_transport_cannot_read_guest_memory_or_create_driver_objects() {
        let mut b = Backend::new();
        let mut memory = Memory::new(PAGE_SIZE as usize);
        assert_eq!(
            b.invoke(&mut memory, 1, 0, 127).unwrap(),
            Invocation::Complete(vk::Result::ERROR_UNKNOWN.as_raw() as i64 as u64)
        );
        assert!(b.instance.is_none());
        assert!(b.objects.is_empty());
        assert!(b.invoke(&mut memory, 1, 0, 128).is_err());
        assert!(b.instance.is_none());
        assert!(b.objects.is_empty());
    }
    #[test]
    fn unknown_object_domains_and_uninitialized_driver_never_become_host_handles() {
        let mut left = Backend::new();
        let right = Backend::new();
        assert_ne!(left.domain, right.domain);
        assert!(left.object((right.domain << 32) | 1, Kind::Memory).is_err());
        let mut memory = Memory::new(PAGE_SIZE as usize);
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let result = left.invoke(&mut memory, 13, 0x1000, 128).unwrap();
        assert_eq!(
            result,
            Invocation::Complete(vk::Result::ERROR_INITIALIZATION_FAILED.as_raw() as i64 as u64)
        );
        assert!(left.objects.is_empty());
    }
}
