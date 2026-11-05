// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual per-mm native ownership. A capability clone retains one task; only
//! creating another real CLONE_VM task increments the live-task count.
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};

#[derive(Default)]
pub(super) struct Devices {
    pub gpu: Option<trames_vulkan::Context>,
    pub video: Option<trames_video::Context>,
    pub audio: Option<trames_audio::Context>,
}
impl Drop for Devices {
    fn drop(&mut self) {
        if let Some(gpu) = &self.gpu {
            gpu.retire();
        }
    }
}
#[derive(Default)]
struct Cache {
    gpu: OnceLock<trames_vulkan::WeakContext>,
    video: OnceLock<trames_video::WeakContext>,
    audio: OnceLock<trames_audio::WeakContext>,
}
#[derive(Clone, Default)]
pub(super) struct Native {
    owner: Owner<Devices>,
    cache: Arc<Cache>,
}
impl Native {
    pub fn share(&self) -> Self {
        Self {
            owner: self.owner.share(),
            cache: self.cache.clone(),
        }
    }
    pub fn retire(&self) {
        self.owner.retire();
    }
    pub fn gpu(
        &self,
        create: impl FnOnce() -> trames_vulkan::Context,
    ) -> Option<trames_vulkan::Context> {
        if let Some(context) = self.existing_gpu() {
            return Some(context);
        }
        let context = self
            .owner
            .with(|r| r.gpu.get_or_insert_with(create).clone())?;
        self.cache.gpu.get_or_init(|| context.downgrade());
        Some(context)
    }
    pub fn existing_gpu(&self) -> Option<trames_vulkan::Context> {
        self.cache.gpu.get()?.upgrade()
    }
    pub fn video(&self) -> Option<trames_video::Context> {
        if let Some(context) = self.cache.video.get().and_then(|c| c.upgrade()) {
            return Some(context);
        }
        let context = self
            .owner
            .with(|r| r.video.get_or_insert_with(Default::default).clone())?;
        self.cache.video.get_or_init(|| context.downgrade());
        Some(context)
    }
    pub fn audio(
        &self,
        create: impl FnOnce() -> trames_audio::Context,
    ) -> Option<trames_audio::Context> {
        if let Some(context) = self.cache.audio.get().and_then(|c| c.upgrade()) {
            return Some(context);
        }
        let context = self
            .owner
            .with(|r| r.audio.get_or_insert_with(create).clone())?;
        self.cache.audio.get_or_init(|| context.downgrade());
        Some(context)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn with<T>(&self, f: impl FnOnce(&mut Devices) -> T) -> Option<T> {
        self.owner.with(f)
    }
}
pub(super) struct Owner<R>(Arc<Task<R>>);
struct Task<R> {
    live: AtomicBool,
    space: Arc<Space<R>>,
}
struct Space<R> {
    tasks: AtomicUsize,
    resources: Mutex<Option<R>>,
}
impl<R: Default> Default for Owner<R> {
    fn default() -> Self {
        Self(Arc::new(Task {
            live: AtomicBool::new(true),
            space: Arc::new(Space {
                tasks: AtomicUsize::new(1),
                resources: Mutex::new(Some(R::default())),
            }),
        }))
    }
}
impl<R> Clone for Owner<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<R> Task<R> {
    fn retire(&self) {
        if !self.live.swap(false, Ordering::Relaxed) {
            return;
        }
        if self.space.tasks.fetch_sub(1, Ordering::Relaxed) != 1 {
            return;
        }
        // Native leases and accepted jobs retain their own original objects.
        // Destruction/callbacks must run outside the mm membership mutex.
        let resources = self.space.resources.lock().unwrap().take();
        drop(resources);
    }
}
impl<R> Drop for Task<R> {
    fn drop(&mut self) {
        self.retire();
    }
}
impl<R> Owner<R> {
    /// Structural fork/clone custody holds this actual parent task alive.
    pub fn share(&self) -> Self {
        debug_assert!(self.0.live.load(Ordering::Relaxed));
        let previous = self.0.space.tasks.fetch_add(1, Ordering::Relaxed);
        debug_assert!(previous != 0);
        Self(Arc::new(Task {
            live: AtomicBool::new(true),
            space: self.0.space.clone(),
        }))
    }
    pub fn retire(&self) {
        self.0.retire();
    }
    /// Only cache lookup/creation runs here, never a native invocation or wait.
    pub fn with<T>(&self, f: impl FnOnce(&mut R) -> T) -> Option<T> {
        self.0.space.resources.lock().unwrap().as_mut().map(f)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    #[derive(Default)]
    struct Resources {
        item: Option<Arc<Item>>,
    }
    struct Item {
        drops: Arc<AtomicU32>,
        on_drop: Option<Box<dyn Fn() + Send + Sync>>,
    }
    impl Drop for Item {
        fn drop(&mut self) {
            if let Some(f) = &self.on_drop {
                f();
            }
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn ordinary_native_cache_hits_do_not_acquire_mm_membership_mutex() {
        let native = Native::default();
        let context = native
            .gpu(|| trames_vulkan::Context::new(Default::default()))
            .unwrap();
        let metadata = native.owner.0.space.resources.lock().unwrap();
        let peer = native.clone();
        let (sent, got) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let context = peer
                .gpu(|| panic!("cache hit must keep its original context"))
                .unwrap();
            sent.send(context).unwrap();
        });
        let result = got.recv_timeout(std::time::Duration::from_secs(1));
        drop(metadata);
        worker.join().unwrap();
        assert!(
            result.is_ok(),
            "ordinary native calls must bypass mm metadata locking"
        );
        drop(result);
        drop(context);
    }
    #[test]
    fn task_references_not_capability_clones_decide_mm_retirement() {
        let owner = Owner::<Resources>::default();
        let peer = owner.share();
        let saved = owner.clone();
        let drops = Arc::new(AtomicU32::new(0));
        owner.with(|r| {
            r.item = Some(Arc::new(Item {
                drops: drops.clone(),
                on_drop: None,
            }))
        });
        let accepted = peer.with(|r| r.item.clone()).flatten().unwrap();
        std::thread::spawn(move || {
            owner.retire();
            owner.retire();
        })
        .join()
        .unwrap();
        assert!(peer.with(|r| r.item.is_some()).unwrap());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        peer.retire();
        assert!(saved
            .with(|_| panic!("retired mm cannot reinitialize native resources"))
            .is_none());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(accepted);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        saved.retire();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn final_original_resource_drop_can_reenter_without_holding_mm_membership() {
        let owner = Owner::<Resources>::default();
        let weak = Arc::downgrade(&owner.0.space);
        let drops = Arc::new(AtomicU32::new(0));
        owner.with(|r| {
            r.item = Some(Arc::new(Item {
                drops: drops.clone(),
                on_drop: Some(Box::new(move || {
                    let space = weak.upgrade().unwrap();
                    assert!(space.resources.try_lock().unwrap().is_none());
                })),
            }))
        });
        owner.retire();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn concurrent_original_mm_members_release_once_despite_late_capabilities() {
        let owner = Owner::<Resources>::default();
        let drops = Arc::new(AtomicU32::new(0));
        owner.with(|r| {
            r.item = Some(Arc::new(Item {
                drops: drops.clone(),
                on_drop: None,
            }))
        });
        let peers: Vec<_> = (0..16).map(|_| owner.share()).collect();
        let saved: Vec<_> = peers.to_vec();
        owner.retire();
        let gate = Arc::new(std::sync::Barrier::new(peers.len()));
        std::thread::scope(|s| {
            for peer in peers {
                let gate = gate.clone();
                s.spawn(move || {
                    gate.wait();
                    peer.retire();
                });
            }
        });
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(saved.iter().all(|p| p.with(|_| ()).is_none()));
    }
    #[test]
    fn distinct_address_spaces_never_share_their_original_device_objects() {
        let first = Owner::<Resources>::default();
        let fork = Owner::<Resources>::default();
        let drops = Arc::new(AtomicU32::new(0));
        first.with(|r| {
            r.item = Some(Arc::new(Item {
                drops: drops.clone(),
                on_drop: None,
            }))
        });
        assert!(!fork.with(|r| r.item.is_some()).unwrap());
        first.retire();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(fork.with(|r| r.item.is_none()).unwrap());
    }
}
