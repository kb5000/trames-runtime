// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-owned display capability. Guest code never supplies a native pointer.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

#[derive(Clone, Default)]
pub struct Display(Arc<Mutex<Option<Arc<Target>>>>);
pub(crate) struct Target {
    pub layer: usize,
    pub width: u32,
    pub height: u32,
    pub owner: AtomicU64,
    pub presented: AtomicU64,
}
#[cfg(target_vendor = "apple")]
#[link(name = "objc")]
unsafe extern "C" {
    fn objc_retain(object: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn objc_release(object: *mut std::ffi::c_void);
}
impl Drop for Target {
    fn drop(&mut self) {
        #[cfg(target_vendor = "apple")]
        unsafe {
            objc_release(self.layer as *mut std::ffi::c_void);
        }
    }
}
impl Display {
    /// # Safety
    /// On Apple, `layer` is a live CAMetalLayer created/configured by the native
    /// main thread. Its fixed bounds/drawable size must not change while attached.
    /// Retain here; native surfaces keep this lease until their driver work ends.
    pub unsafe fn attach(
        &self,
        layer: *mut std::ffi::c_void,
        width: u32,
        height: u32,
    ) -> Result<(), &'static str> {
        if layer.is_null() || width == 0 || height == 0 || width > 4096 || height > 4096 {
            return Err("invalid display target");
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            Err("native Metal display is Apple-only")
        }
        #[cfg(target_vendor = "apple")]
        {
            let mut slot = self.0.lock().map_err(|_| "display lock failed")?;
            unsafe {
                objc_retain(layer);
            }
            *slot = Some(Arc::new(Target {
                layer: layer as usize,
                width,
                height,
                owner: AtomicU64::new(0),
                presented: AtomicU64::new(0),
            }));
            Ok(())
        }
    }
    pub fn detach(&self) {
        if let Ok(mut target) = self.0.lock() {
            *target = None;
        }
    }
    pub fn info(&self) -> (u32, u32, u64) {
        self.target().map_or((0, 0, 0), |t| {
            (t.width, t.height, t.presented.load(Ordering::Relaxed))
        })
    }
    pub(crate) fn target(&self) -> Option<Arc<Target>> {
        self.0.lock().ok()?.clone()
    }
    pub(crate) fn current(&self, target: &Arc<Target>) -> bool {
        self.target().is_some_and(|t| Arc::ptr_eq(&t, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detach_invalidates_generation_but_preserves_in_flight_lease() {
        let display = Display::default();
        assert_eq!(display.info(), (0, 0, 0));
        let target = Arc::new(Target {
            layer: 0,
            width: 1024,
            height: 768,
            owner: AtomicU64::new(0),
            presented: AtomicU64::new(3),
        });
        *display.0.lock().unwrap() = Some(target.clone());
        assert_eq!(display.info(), (1024, 768, 3));
        assert!(display.current(&target));
        assert!(target
            .owner
            .compare_exchange(0, 7, Ordering::AcqRel, Ordering::Acquire)
            .is_ok());
        assert!(target
            .owner
            .compare_exchange(0, 8, Ordering::AcqRel, Ordering::Acquire)
            .is_err());
        display.detach();
        assert_eq!(display.info(), (0, 0, 0));
        assert!(!display.current(&target));
        assert_eq!(Arc::strong_count(&target), 1);
        assert_eq!(target.owner.load(Ordering::Acquire), 7);
    }
    #[test]
    fn invalid_native_targets_fail_before_objc_access() {
        let display = Display::default();
        assert!(unsafe { display.attach(std::ptr::null_mut(), 1024, 768) }.is_err());
        let pointer = std::ptr::dangling_mut::<std::ffi::c_void>();
        for (width, height) in [(0, 768), (1024, 0), (4097, 768), (1024, 4097)] {
            assert!(unsafe { display.attach(pointer, width, height) }.is_err());
        }
    }
}
