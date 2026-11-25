// SPDX-License-Identifier: GPL-3.0-or-later
//! Host-owned display capability. Guest code never supplies a native pointer.
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, Weak,
};

#[derive(Clone, Default)]
pub struct Display(Arc<Mutex<Option<Arc<Target>>>>, Arc<Activity>);
#[derive(Default)]
struct Activity {
    suspended: AtomicBool,
    contexts: Mutex<Vec<Weak<dyn SuspensionFence>>>,
}
pub(crate) trait SuspensionFence: Send + Sync {
    fn quiesce(&self);
    fn resume(&self);
}
pub(crate) struct Target {
    pub window: Window,
    pub width: u32,
    pub height: u32,
    pub owner: Arc<AtomicU64>,
    pub presented: AtomicU64,
    // Native surfaces/swapchains retain this capability after host detach.
    _lease: Option<Arc<dyn Send + Sync>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Window {
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    Metal(usize),
    #[cfg(target_os = "linux")]
    Xcb { connection: usize, window: u32 },
    #[cfg(target_os = "linux")]
    Wayland { display: usize, surface: usize },
}
impl Target {
    pub fn extension(&self) -> &'static std::ffi::CStr {
        match self.window {
            Window::Metal(_) => ash::ext::metal_surface::NAME,
            #[cfg(target_os = "linux")]
            Window::Xcb { .. } => ash::khr::xcb_surface::NAME,
            #[cfg(target_os = "linux")]
            Window::Wayland { .. } => ash::khr::wayland_surface::NAME,
        }
    }
    /// # Safety
    /// The caller enabled extension() on this live instance. The target retains
    /// its original host window/connection until every surface lease is gone.
    pub unsafe fn surface(
        &self,
        entry: &ash::Entry,
        instance: &ash::Instance,
    ) -> Result<ash::vk::SurfaceKHR, ash::vk::Result> {
        use ash::vk;
        match self.window {
            #[cfg(target_vendor = "apple")]
            Window::Metal(layer) => unsafe {
                ash::ext::metal_surface::Instance::new(entry, instance).create_metal_surface(
                    &vk::MetalSurfaceCreateInfoEXT::default().layer(layer as *const _),
                    None,
                )
            },
            #[cfg(not(target_vendor = "apple"))]
            Window::Metal(_) => Err(vk::Result::ERROR_EXTENSION_NOT_PRESENT),
            #[cfg(target_os = "linux")]
            Window::Xcb { connection, window } => unsafe {
                ash::khr::xcb_surface::Instance::new(entry, instance).create_xcb_surface(
                    &vk::XcbSurfaceCreateInfoKHR::default()
                        .connection(connection as *mut _)
                        .window(window),
                    None,
                )
            },
            #[cfg(target_os = "linux")]
            Window::Wayland { display, surface } => unsafe {
                ash::khr::wayland_surface::Instance::new(entry, instance).create_wayland_surface(
                    &vk::WaylandSurfaceCreateInfoKHR::default()
                        .display(display as *mut _)
                        .surface(surface as *mut _),
                    None,
                )
            },
        }
    }
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
        match self.window {
            Window::Metal(layer) => unsafe { objc_release(layer as *mut std::ffi::c_void) },
        }
    }
}
impl Display {
    pub fn suspended(&self) -> bool {
        self.1.suspended.load(Ordering::Acquire)
    }
    /// Called at host lifecycle transitions, never on ordinary CPU/memory access.
    /// Existing native entries finish before the host returns to its background.
    pub fn set_suspended(&self, suspended: bool) {
        self.1.suspended.store(suspended, Ordering::Release);
        let contexts = {
            let mut entries = self.1.contexts.lock().unwrap();
            let live: Vec<_> = entries.iter().filter_map(Weak::upgrade).collect();
            entries.retain(|entry| entry.strong_count() != 0);
            live
        };
        for context in contexts {
            if suspended {
                context.quiesce();
            } else {
                context.resume();
            }
        }
    }
    pub(crate) fn register_context(&self, context: &Arc<dyn SuspensionFence>) {
        let mut contexts = self.1.contexts.lock().unwrap();
        contexts.retain(|entry| entry.strong_count() != 0);
        contexts.push(Arc::downgrade(context));
    }

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
                window: Window::Metal(layer as usize),
                width,
                height,
                owner: Arc::default(),
                presented: AtomicU64::new(0),
                _lease: None,
            }));
            Ok(())
        }
    }
    #[cfg(target_os = "linux")]
    fn attach_linux(
        &self,
        window: Window,
        width: u32,
        height: u32,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<(), &'static str> {
        if width == 0 || height == 0 || width > 4096 || height > 4096 {
            return Err("invalid display dimensions");
        }
        let mut slot = self.0.lock().map_err(|_| "display lock failed")?;
        let owner = slot
            .as_ref()
            .filter(|old| {
                old.window == window
                    && old
                        ._lease
                        .as_ref()
                        .is_some_and(|previous| Arc::ptr_eq(previous, &lease))
            })
            .map(|old| old.owner.clone())
            .unwrap_or_default();
        *slot = Some(Arc::new(Target {
            window,
            width,
            height,
            owner,
            presented: AtomicU64::new(0),
            _lease: Some(lease),
        }));
        Ok(())
    }
    /// Attach an original host X11 capability; no guest handle is accepted.
    /// # Safety
    /// The nonnull libxcb connection and nonzero window belong to the same X
    /// server. lease keeps both valid through its last drop, including after
    /// detach. Their native API permits use by Vulkan on execution workers.
    #[cfg(target_os = "linux")]
    pub unsafe fn attach_xcb(
        &self,
        connection: *mut std::ffi::c_void,
        window: u32,
        width: u32,
        height: u32,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<(), &'static str> {
        if connection.is_null() || window == 0 {
            return Err("invalid XCB display target");
        }
        self.attach_linux(
            Window::Xcb {
                connection: connection as usize,
                window,
            },
            width,
            height,
            lease,
        )
    }
    /// Attach an already configured original host Wayland capability.
    /// # Safety
    /// display and surface are live libwayland objects on the same connection;
    /// lease owns both until its final drop. The host observes the WSI protocol
    /// ordering rules and never attaches another producer's buffer to surface.
    #[cfg(target_os = "linux")]
    pub unsafe fn attach_wayland(
        &self,
        display: *mut std::ffi::c_void,
        surface: *mut std::ffi::c_void,
        width: u32,
        height: u32,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<(), &'static str> {
        if display.is_null() || surface.is_null() {
            return Err("invalid Wayland display target");
        }
        self.attach_linux(
            Window::Wayland {
                display: display as usize,
                surface: surface as usize,
            },
            width,
            height,
            lease,
        )
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
            window: Window::Metal(0),
            width: 1024,
            height: 768,
            owner: Arc::default(),
            presented: AtomicU64::new(3),
            _lease: None,
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
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_detach_retains_native_lease_and_resize_cannot_steal_surface_claim() {
        let display = Display::default();
        let lease: Arc<dyn Send + Sync> = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let window = Window::Xcb {
            connection: 1,
            window: 2,
        };
        // Metadata-only test; these sentinels are never submitted to a driver.
        display
            .attach_linux(window, 640, 480, lease.clone())
            .unwrap();
        let old = display.target().unwrap();
        assert_eq!(old.extension(), ash::khr::xcb_surface::NAME);
        old.owner.store(17, Ordering::Relaxed);
        display.attach_linux(window, 800, 600, lease).unwrap();
        let resized = display.target().unwrap();
        assert!(!display.current(&old));
        assert!(display.current(&resized));
        assert!(Arc::ptr_eq(&old.owner, &resized.owner));
        assert_eq!(resized.owner.load(Ordering::Relaxed), 17);
        display.detach();
        drop(resized);
        assert!(weak.upgrade().is_some());
        drop(old);
        assert!(weak.upgrade().is_none());
    }
}
