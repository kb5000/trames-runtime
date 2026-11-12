// SPDX-License-Identifier: GPL-3.0-or-later
//! Cancelable scheduling notification for an original Metal shared event.
use std::ffi::c_void;
unsafe extern "C" {
    fn trames_graphics_observe_event(
        event: *mut c_void,
        value: u64,
        notify: unsafe extern "C" fn(*mut c_void),
        data: *mut c_void,
        dispose: unsafe extern "C" fn(*mut c_void),
    ) -> *mut c_void;
    fn trames_graphics_cancel_event(observation: *mut c_void);
}
pub struct EventObservation(*mut c_void);
impl EventObservation {
    /// # Safety
    /// `event` is a live MTLSharedEvent during registration. `data` transfers
    /// uniquely to `dispose`, and must support a concurrent `notify` callback.
    /// Neither callback may unwind or access guest memory or backend borrows.
    pub unsafe fn register(
        event: *mut c_void,
        value: u64,
        notify: unsafe extern "C" fn(*mut c_void),
        data: *mut c_void,
        dispose: unsafe extern "C" fn(*mut c_void),
    ) -> Option<Self> {
        let raw = unsafe { trames_graphics_observe_event(event, value, notify, data, dispose) };
        (!raw.is_null()).then_some(Self(raw))
    }
}
impl Drop for EventObservation {
    fn drop(&mut self) {
        // A racing callback retains its own shared owner until it returns.
        // Canceled, never-signaled notifications keep only a native weak owner.
        unsafe { trames_graphics_cancel_event(self.0) };
    }
}
