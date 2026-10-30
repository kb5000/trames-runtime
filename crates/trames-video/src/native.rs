// SPDX-License-Identifier: GPL-3.0-or-later
use super::Job;
#[cfg(target_vendor = "apple")]
use super::{INVALID, IO_ERROR};
use std::sync::Arc;
#[cfg(target_vendor = "apple")]
mod apple {
    use super::*;
    use std::ffi::c_void;
    unsafe extern "C" {
        fn trames_video_caps() -> u64;
        fn trames_video_decoder_new(width: u32, height: u32) -> *mut c_void;
        fn trames_video_decoder_free(decoder: *mut c_void);
        fn trames_video_submit(
            decoder: *mut c_void,
            sps: *const u8,
            sps_len: usize,
            pps: *const u8,
            pps_len: usize,
            bytes: *const u8,
            len: usize,
            data: *mut c_void,
            job: *mut c_void,
        );
        fn trames_video_frame_free(frame: *mut c_void);
        fn trames_video_frame_buffer(frame: *mut c_void) -> *mut c_void;
        fn trames_video_frame_size(frame: *mut c_void, size: *mut u32);
        fn trames_video_frame_copy(frame: *mut c_void, bytes: *mut u8, size: usize) -> i32;
    }
    pub struct Decoder(*mut c_void);
    // SAFETY: the owning Rust Decoder is accessed only under its per-decoder
    // mutex. VT callbacks own Jobs and CVPixelBuffers, never this Decoder.
    unsafe impl Send for Decoder {}
    impl Decoder {
        pub fn new(w: u32, h: u32) -> Result<Self, i64> {
            // SAFETY: scalar dimensions; native allocation is uniquely owned.
            let p = unsafe { trames_video_decoder_new(w, h) };
            if p.is_null() {
                Err(-12)
            } else {
                Ok(Self(p))
            }
        }
        pub(crate) fn submit(&mut self, sps: &[u8], pps: &[u8], bytes: Vec<u8>, job: Arc<Job>) {
            let data = Box::new(bytes);
            let pointer = data.as_ptr();
            let len = data.len();
            // SAFETY: native code takes both boxed allocations on every path.
            // CMBlockBuffer's custom destructor frees the compressed Vec only
            // after its final consumer releases it. No guest pointer escapes.
            unsafe {
                trames_video_submit(
                    self.0,
                    sps.as_ptr(),
                    sps.len(),
                    pps.as_ptr(),
                    pps.len(),
                    pointer,
                    len,
                    Box::into_raw(data).cast(),
                    Box::into_raw(Box::new(job)).cast(),
                )
            };
        }
    }
    impl Drop for Decoder {
        fn drop(&mut self) {
            unsafe { trames_video_decoder_free(self.0) }
        }
    }
    pub struct Frame(*mut c_void);
    // SAFETY: each frame owns one retained, immutable output CVPixelBuffer.
    // Shared reads lock CoreVideo's CPU mapping; destruction requires final Arc.
    unsafe impl Send for Frame {}
    unsafe impl Sync for Frame {}
    impl Frame {
        pub fn pixel_buffer(&self) -> usize {
            unsafe { trames_video_frame_buffer(self.0) as usize }
        }
        pub fn dimensions(&self) -> (u32, u32) {
            let mut size = [0; 2];
            unsafe { trames_video_frame_size(self.0, size.as_mut_ptr()) };
            (size[0], size[1])
        }
        pub fn readback(&self) -> Result<Vec<u8>, i64> {
            let (w, h) = self.dimensions();
            let length = (w as usize)
                .checked_mul(h as usize)
                .and_then(|n| n.checked_mul(3))
                .map(|n| n / 2)
                .ok_or(INVALID)?;
            let mut data = vec![0; length];
            if unsafe { trames_video_frame_copy(self.0, data.as_mut_ptr(), data.len()) } == 0 {
                Ok(data)
            } else {
                Err(IO_ERROR)
            }
        }
    }
    impl Drop for Frame {
        fn drop(&mut self) {
            unsafe { trames_video_frame_free(self.0) }
        }
    }
    pub fn capabilities() -> u64 {
        unsafe { trames_video_caps() }
    }
    #[no_mangle]
    unsafe extern "C" fn trames_video_free_bytes(data: *mut c_void) {
        // SAFETY: exactly one C owner returned by Box::into_raw in submit.
        drop(unsafe { Box::from_raw(data.cast::<Vec<u8>>()) });
    }
    #[no_mangle]
    unsafe extern "C" fn trames_video_complete(job: *mut c_void, status: i32, frame: *mut c_void) {
        // SAFETY: native submit completes this opaque job exactly once,
        // including synchronous failures. The frame reference is transferred.
        let job = unsafe { Box::from_raw(job.cast::<Arc<Job>>()) };
        let result = if !frame.is_null() {
            Ok(Arc::new(super::super::Frame {
                native: Frame(frame),
                graphics: job.graphics.clone(),
                planes: Default::default(),
            }))
        } else {
            Err(if status == 0 { -5 } else { status as i64 })
        };
        job.finish(result);
    }
}
#[cfg(target_vendor = "apple")]
pub use apple::*;
#[cfg(not(target_vendor = "apple"))]
mod unavailable {
    use super::*;
    pub struct Decoder;
    impl Decoder {
        pub fn new(_: u32, _: u32) -> Result<Self, i64> {
            Err(-95)
        }
        pub(crate) fn submit(&mut self, _: &[u8], _: &[u8], _: Vec<u8>, job: Arc<Job>) {
            job.finish(Err(-95));
        }
    }
    pub struct Frame;
    impl Frame {
        pub fn pixel_buffer(&self) -> usize {
            0
        }
        pub fn dimensions(&self) -> (u32, u32) {
            (0, 0)
        }
        pub fn readback(&self) -> Result<Vec<u8>, i64> {
            Err(-95)
        }
    }
    pub fn capabilities() -> u64 {
        0
    }
}
#[cfg(not(target_vendor = "apple"))]
pub use unavailable::*;
