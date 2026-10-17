// SPDX-License-Identifier: GPL-3.0-or-later
//! Native image capabilities: no guest pointer, Vk handle, coordinator Rc, byte
//! borrow or pixel readback crosses into the compositor/UI.
use crate::State;
use std::{io, sync::Arc};

/// # Safety
/// Implementors own the native image, memory and completion primitive through
/// final GPU/UI use. A nonzero Metal pointer is a live MTLTexture until the last
/// Arc is released. ready() is nonblocking and safe on the compositor thread;
/// it proves producer writes complete before the UI submits any texture reads.
/// Dropping a queued capability must not destroy in-flight native resources.
pub unsafe trait GpuImage: Send + Sync {
    fn dimensions(&self) -> (u32, u32);
    fn metal_texture(&self) -> usize;
    fn ready(&self) -> io::Result<bool>;
    /// Mailbox replaces queued frames; producer/UI leases still retain their
    /// resources until native writes/reads complete. FIFO remains the default.
    fn mailbox(&self) -> bool {
        false
    }
}
impl State {
    pub(crate) fn enqueue_gpu(&mut self, id: u64, image: Arc<dyn GpuImage>) {
        let (w, h) = image.dimensions();
        if w == 0 || h == 0 || w > 4096 || h > 4096 {
            return;
        }
        if let Some(s) = self.surfaces.get_mut(&id) {
            // Cancellation drops only the queue lease, never a producer/UI
            // lease. Retain FIFO entries from a preceding swapchain generation.
            if image.mailbox() {
                s.gpu_pending.retain(|old| !old.mailbox());
            }
            if s.gpu_pending.len() < 64 {
                s.gpu_pending.push_back(image);
            }
        }
    }
    /// True only while an eligible producer fence is still pending. FIFO
    /// backpressure waits for the UI wakeup and must not spin on a timer.
    pub(crate) fn poll_gpu(&mut self) -> bool {
        let mut waiting_for_gpu = false;
        for s in self.surfaces.values_mut() {
            if s.xdg.is_some() && !s.acknowledged {
                continue;
            }
            let Some(image) = s.gpu_pending.front() else {
                continue;
            };
            if matches!(s.current, Some(crate::scene::ImageBuffer::Gpu(_)))
                && !s.gpu_presented
                && !image.mailbox()
            {
                continue;
            }
            match image.ready() {
                Ok(false) => {
                    waiting_for_gpu = true;
                    continue;
                }
                Err(_) => {
                    s.gpu_pending.pop_front();
                    continue;
                }
                Ok(true) => {}
            }
            let image = s.gpu_pending.pop_front().unwrap();
            let (w, h) = image.dimensions();
            let (w, h) = if s.transform & 1 != 0 { (h, w) } else { (w, h) };
            if !w.is_multiple_of(s.scale as u32) || !h.is_multiple_of(s.scale as u32) {
                continue;
            }
            s.size = s
                .geometry
                .map(|(_, _, w, h)| (w, h))
                .unwrap_or((w / s.scale as u32, h / s.scale as u32));
            s.current = Some(crate::scene::ImageBuffer::Gpu(image));
            s.gpu_presented = false;
            self.revision = self.revision.wrapping_add(1);
            s.revision = self.revision;
        }
        waiting_for_gpu
    }
}

/// Queue/current/UI leases share this per-surface bound across swapchain
/// replacement. The producer reserves before consuming Vulkan wait semaphores.
#[derive(Clone, Default, Debug)]
pub struct GpuBudget(std::sync::Arc<std::sync::atomic::AtomicUsize>);
pub struct GpuPermit(GpuBudget);
impl GpuBudget {
    pub fn reserve(&self) -> Option<GpuPermit> {
        self.0
            .try_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |n| (n < 64).then_some(n + 1),
            )
            .ok()?;
        Some(GpuPermit(self.clone()))
    }
}
impl Drop for GpuPermit {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
