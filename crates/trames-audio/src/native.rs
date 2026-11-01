// SPDX-License-Identifier: GPL-3.0-or-later
use super::Notify;
#[cfg(target_vendor = "apple")]
mod apple {
    use super::*;
    use std::ffi::c_void;
    unsafe extern "C" {
        fn trames_audio_new(
            args: *const u64,
            notify: unsafe extern "C" fn(*mut c_void),
            release: unsafe extern "C" fn(*mut c_void),
            data: *mut c_void,
            error: *mut i64,
        ) -> *mut c_void;
        fn trames_audio_free(stream: *mut c_void);
        fn trames_audio_control(stream: *mut c_void, operation: u64) -> i64;
        fn trames_audio_transfer(stream: *mut c_void, bytes: *mut u8, len: usize) -> i64;
        fn trames_audio_status(stream: *mut c_void, stats: *mut u64);
    }
    unsafe extern "C" fn wake(data: *mut c_void) {
        // SAFETY: the native lease retains this box through the final callback.
        unsafe { (&*data.cast::<Notify>())() };
    }
    unsafe extern "C" fn release(data: *mut c_void) {
        // SAFETY: the final native callback lease releases this box exactly once.
        drop(unsafe { Box::from_raw(data.cast::<Notify>()) });
    }
    pub struct Stream {
        pointer: *mut c_void,
        capture: bool,
    }
    // SAFETY: guest operations use the per-stream mutex. Native callbacks touch
    // only their owned SPSC state and the retained notification, never guest data.
    unsafe impl Send for Stream {}
    impl Stream {
        pub fn new(a: &[u64; 16], notify: Notify) -> Result<Self, i64> {
            let notify = Box::new(notify);
            let mut error = -5;
            let pointer = unsafe {
                trames_audio_new(
                    a.as_ptr(),
                    wake,
                    release,
                    (&*notify as *const Notify).cast_mut().cast(),
                    &mut error,
                )
            };
            if pointer.is_null() {
                Err(error)
            } else {
                let _ = Box::into_raw(notify);
                Ok(Self {
                    pointer,
                    capture: a[1] != 0,
                })
            }
        }
        pub fn capture(&self) -> bool {
            self.capture
        }
        pub fn transfer(&mut self, bytes: &mut [u8]) -> i64 {
            unsafe { trames_audio_transfer(self.pointer, bytes.as_mut_ptr(), bytes.len()) }
        }
        pub fn control(&mut self, op: u64) -> i64 {
            unsafe { trames_audio_control(self.pointer, op) }
        }
        pub fn status(&self) -> [u64; 8] {
            let mut a = [0; 8];
            unsafe { trames_audio_status(self.pointer, a.as_mut_ptr()) };
            a
        }
    }
    impl Drop for Stream {
        fn drop(&mut self) {
            // This diagnostic runs only at stream teardown, never per sample.
            if std::env::var_os("TRAMES_AUDIO_STATS").is_some() {
                eprintln!(
                    "trames audio: capture={} status={:?}",
                    self.capture,
                    self.status()
                );
            }
            // Native render closures retain their own data and notification lease.
            unsafe { trames_audio_free(self.pointer) };
        }
    }
}
#[cfg(target_vendor = "apple")]
pub use apple::*;
#[cfg(not(target_vendor = "apple"))]
pub struct Stream;
#[cfg(not(target_vendor = "apple"))]
impl Stream {
    pub fn new(_: &[u64; 16], _: Notify) -> Result<Self, i64> {
        Err(-95)
    }
    pub fn capture(&self) -> bool {
        false
    }
    pub fn transfer(&mut self, _: &mut [u8]) -> i64 {
        -95
    }
    pub fn control(&mut self, _: u64) -> i64 {
        -95
    }
    pub fn status(&self) -> [u64; 8] {
        [0; 8]
    }
}
