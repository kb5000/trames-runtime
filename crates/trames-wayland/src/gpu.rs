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
            if !s.update_size(image.dimensions()) {
                continue;
            }
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
#[derive(Default)]
struct BudgetState {
    count: std::sync::atomic::AtomicUsize,
    closed: std::sync::atomic::AtomicBool,
    changed: std::sync::Arc<trames_shared::Readiness>,
}
#[derive(Clone, Default)]
pub struct GpuBudget(std::sync::Arc<BudgetState>);
impl std::fmt::Debug for GpuBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuBudget").finish_non_exhaustive()
    }
}
pub struct GpuPermit(GpuBudget);
impl GpuBudget {
    pub fn is_live(&self) -> bool {
        !self.0.closed.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(crate) fn close(&self) {
        self.0
            .closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.notify();
    }
    pub fn notify(&self) {
        self.0.changed.notify_atomic();
    }
    pub fn subscribe(
        &self,
        signal: &std::sync::Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.0.changed.subscribe(signal)
    }
    pub fn reserve(&self) -> Option<GpuPermit> {
        self.0
            .count
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
        self.0
             .0
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        self.0.notify();
    }
}

#[cfg(test)]
mod acquisition_tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    struct Wake(mpsc::Sender<()>);
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            self.0.send(()).unwrap();
        }
    }
    #[test]
    fn original_surface_release_and_destruction_wake_acquisition_waiters() {
        let budget = GpuBudget::default();
        let other = GpuBudget::default();
        let permit = budget.reserve().unwrap();
        let (send, recv) = mpsc::channel();
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(send));
        let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        let subscription = budget.subscribe(&signal);
        drop(other.reserve());
        assert!(recv.try_recv().is_err());
        drop(permit);
        recv.recv().unwrap();
        signal.reset();
        assert!(budget.is_live());
        budget.close();
        recv.recv().unwrap();
        assert!(!budget.is_live());
        assert!(other.is_live());
        drop(subscription);
        signal.reset();
        budget.notify();
        assert!(recv.try_recv().is_err());
    }
}
