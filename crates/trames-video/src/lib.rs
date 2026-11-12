// SPDX-License-Identifier: GPL-3.0-or-later
//! Asynchronous native video resources. Guest waits use ordinary event descriptors.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use trames_memory::{CpuMemory, MemoryError};
mod native;
pub const PROFILE: u64 = 0x0001_0007;
pub const AUXV_KEY: u64 = 0x5452_0009;
pub const CREATE_SURFACE: u64 = 3;
pub const EXPORT_FRAME: u64 = 8;
pub const ALLOCATE_IMAGE: u64 = 10;
pub type Notify = Arc<dyn Fn() + Send + Sync>;
const INVALID: i64 = -22;
const MISSING: i64 = -2;
const PENDING: i64 = -11;
const IO_ERROR: i64 = -5;
pub struct Frame {
    native: native::Frame,
    graphics: trames_graphics::Context,
    planes: std::sync::OnceLock<Result<[Arc<dyn trames_graphics::Image>; 2], i64>>,
}
impl Frame {
    pub fn plane(&self, plane: u32) -> Result<Arc<dyn trames_graphics::Image>, i64> {
        let planes = self.planes.get_or_init(|| {
            let buffer = self.native.pixel_buffer();
            // SAFETY: this frame owns a retained CVPixelBuffer throughout both
            // calls; each Image takes its own reference before returning.
            unsafe {
                Ok([
                    self.graphics
                        .pixel_buffer_plane(buffer, 0)
                        .map_err(|_| IO_ERROR)?,
                    self.graphics
                        .pixel_buffer_plane(buffer, 1)
                        .map_err(|_| IO_ERROR)?,
                ])
            }
        });
        planes
            .as_ref()
            .map_err(|e| *e)?
            .get(plane as usize)
            .cloned()
            .ok_or(INVALID)
    }
    pub fn dimensions(&self) -> (u32, u32) {
        self.native.dimensions()
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};
    // Generated from a single 32x32 gray frame with the stock libx264 encoder.
    const SPS: &[u8] = &[
        103, 66, 192, 10, 217, 9, 108, 4, 64, 0, 0, 3, 0, 64, 0, 0, 15, 3, 196, 137, 146,
    ];
    const PPS: &[u8] = &[104, 203, 131, 203, 32];
    const SAMPLE: &[u8] = &[
        0, 0, 0, 12, 101, 136, 132, 9, 242, 98, 128, 1, 57, 58, 235, 192,
    ];
    struct Dropped(mpsc::Sender<()>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.send(()).unwrap();
        }
    }
    #[test]
    #[ignore = "requires an authorized hardware VideoToolbox decoder"]
    fn native_callbacks_and_teardown_release_every_owned_job() {
        assert_eq!(native::capabilities() & 1, 1);
        for cancel in [false, true] {
            let (sender, receiver) = mpsc::channel();
            let mut decoder = native::Decoder::with_codec(32, 32, 0).unwrap();
            for i in 0..17 {
                let dropped = Dropped(sender.clone());
                let notify: Notify = Arc::new(move || {
                    let _ = &dropped;
                });
                let job = Arc::new(Job {
                    result: Mutex::new(None),
                    notify,
                    graphics: Default::default(),
                });
                decoder.submit(if i == 16 { &[0] } else { SPS }, PPS, SAMPLE.to_vec(), job);
            }
            if cancel {
                drop(decoder);
                for _ in 0..17 {
                    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                }
            } else {
                for _ in 0..17 {
                    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                drop(decoder);
            }
        }
    }
    #[test]
    #[ignore = "requires an authorized hardware VideoToolbox decoder"]
    fn valid_codec_configuration_with_corrupt_packet_completes_and_drains() {
        // Parameter sets from synthetic 1920x1080 libx265 / SVT-AV1 fixtures.
        const HEVC: &[u8] = &[
            0, 0, 0, 24, 64, 1, 12, 1, 255, 255, 1, 96, 0, 0, 3, 0, 144, 0, 0, 3, 0, 0, 3, 0, 120,
            149, 148, 9, 0, 0, 0, 44, 66, 1, 1, 1, 96, 0, 0, 3, 0, 144, 0, 0, 3, 0, 0, 3, 0, 120,
            160, 3, 192, 128, 17, 7, 203, 150, 86, 84, 164, 194, 240, 22, 156, 32, 0, 0, 3, 0, 32,
            0, 0, 3, 3, 193, 0, 0, 0, 6, 68, 1, 192, 115, 193, 137,
        ];
        const AV1: &[u8] = &[
            129, 8, 13, 0, 10, 11, 0, 0, 0, 66, 171, 191, 195, 112, 11, 224, 9,
        ];
        for (codec, height, configuration) in [(1, 1088, HEVC), (2, 1080, AV1)] {
            if native::capabilities() & (1 << codec) == 0 {
                continue;
            }
            let (sender, receiver) = mpsc::channel();
            let mut decoder = native::Decoder::with_codec(1920, height, codec).unwrap();
            let mut jobs = Vec::new();
            for _ in 0..4 {
                let sender = sender.clone();
                let job = Arc::new(Job {
                    result: Mutex::new(None),
                    notify: Arc::new(move || {
                        sender.send(()).unwrap();
                    }),
                    graphics: Default::default(),
                });
                decoder.submit_bitstream(configuration, vec![0], job.clone());
                jobs.push(job);
            }
            drop(decoder);
            for job in jobs {
                receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(job.result.lock().unwrap().as_ref().unwrap().is_err());
            }
            assert!(receiver.try_recv().is_err());
        }
    }
    #[test]
    #[ignore = "requires an authorized hardware VideoToolbox decoder"]
    fn invalid_complete_bitstreams_release_every_owned_job() {
        for codec in [1, 2] {
            if native::capabilities() & (1 << codec) == 0 {
                continue;
            }
            let (sender, receiver) = mpsc::channel();
            let mut decoder = native::Decoder::with_codec(32, 32, codec).unwrap();
            for _ in 0..17 {
                let dropped = Dropped(sender.clone());
                let job = Arc::new(Job {
                    result: Mutex::new(None),
                    notify: Arc::new(move || {
                        let _ = &dropped;
                    }),
                    graphics: Default::default(),
                });
                decoder.submit_bitstream(&[0], vec![0], job);
            }
            drop(decoder);
            for _ in 0..17 {
                receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            }
        }
    }
}
struct Job {
    result: Mutex<Option<Result<Arc<Frame>, i64>>>,
    notify: Notify,
    #[cfg_attr(not(target_vendor = "apple"), allow(dead_code))]
    graphics: trames_graphics::Context,
}
impl Job {
    fn finish(&self, result: Result<Arc<Frame>, i64>) {
        let mut completed = self.result.lock().unwrap();
        *completed = Some(result);
        // A ready observation must follow publication of the event. Otherwise
        // surface reuse could drain before this notification and leave a stale
        // readable event attached to the next pending frame.
        (self.notify)();
    }
}
struct Surface {
    width: u32,
    height: u32,
    notify: Notify,
    job: Mutex<Option<Arc<Job>>>,
}
#[derive(Default)]
struct Objects {
    decoders: BTreeMap<u64, Arc<Mutex<native::Decoder>>>,
    surfaces: BTreeMap<u64, Arc<Surface>>,
}
#[derive(Default)]
struct Inner {
    graphics: trames_graphics::Context,
    ids: AtomicU64,
    objects: Mutex<Objects>,
}
#[derive(Clone, Default)]
pub struct Context(Arc<Inner>);
pub struct WeakContext(std::sync::Weak<Inner>);
impl WeakContext {
    pub fn upgrade(&self) -> Option<Context> {
        self.0.upgrade().map(Context)
    }
}
impl Context {
    pub fn downgrade(&self) -> WeakContext {
        WeakContext(Arc::downgrade(&self.0))
    }
    pub fn allocate_image(
        &self,
        format: trames_graphics::Format,
        width: u32,
        height: u32,
    ) -> std::io::Result<Arc<dyn trames_graphics::Image>> {
        self.0.graphics.allocate(format, width, height)
    }
    fn id(&self) -> u64 {
        self.0.ids.fetch_add(1, Ordering::Relaxed) + 1
    }
    pub fn frame(&self, surface: u64) -> Result<Arc<Frame>, i64> {
        let surface = self
            .0
            .objects
            .lock()
            .unwrap()
            .surfaces
            .get(&surface)
            .cloned()
            .ok_or(MISSING)?;
        let job = surface.job.lock().unwrap().clone().ok_or(INVALID)?;
        let result = job.result.lock().unwrap().clone().ok_or(PENDING)?;
        if let Ok(frame) = &result {
            let (width, height) = frame.dimensions();
            if width > surface.width || height > surface.height {
                return Err(IO_ERROR);
            }
        }
        result
    }
    /// The caller supplies the accepted notification resource; surface creation,
    /// submissions and result access run on the executing guest thread.
    pub fn invoke(
        &self,
        memory: &mut impl CpuMemory,
        op: u64,
        at: u64,
        size: u64,
        notify: Option<Notify>,
    ) -> Result<u64, MemoryError> {
        if size != 128 {
            return Ok(INVALID as u64);
        }
        let record = memory.read_array::<128>(at)?;
        let a: [u64; 16] = std::array::from_fn(|i| {
            u64::from_le_bytes(record[i * 8..i * 8 + 8].try_into().unwrap())
        });
        let value = match op {
            0 => native::capabilities() as i64,
            1 => {
                if a[0] == 0 || a[1] == 0 || a[0] > u32::MAX as u64 || a[1] > u32::MAX as u64 {
                    return Ok(INVALID as u64);
                }
                if a[2] > 2 {
                    return Ok(INVALID as u64);
                }
                match native::Decoder::with_codec(a[0] as u32, a[1] as u32, a[2] as u32) {
                    Ok(decoder) => {
                        let id = self.id();
                        self.0
                            .objects
                            .lock()
                            .unwrap()
                            .decoders
                            .insert(id, Arc::new(Mutex::new(decoder)));
                        id as i64
                    }
                    Err(e) => e,
                }
            }
            2 => {
                let decoder = self.0.objects.lock().unwrap().decoders.remove(&a[0]);
                if decoder.is_some() {
                    drop(decoder);
                    0
                } else {
                    MISSING
                }
            }
            CREATE_SURFACE => {
                let Some(notify) = notify else {
                    return Ok(INVALID as u64);
                };
                if a[1] == 0 || a[2] == 0 || a[1] > u32::MAX as u64 || a[2] > u32::MAX as u64 {
                    return Ok(INVALID as u64);
                }
                let id = self.id();
                self.0.objects.lock().unwrap().surfaces.insert(
                    id,
                    Arc::new(Surface {
                        width: a[1] as u32,
                        height: a[2] as u32,
                        notify,
                        job: Mutex::new(None),
                    }),
                );
                id as i64
            }
            4 => {
                if self
                    .0
                    .objects
                    .lock()
                    .unwrap()
                    .surfaces
                    .remove(&a[0])
                    .is_some()
                {
                    0
                } else {
                    MISSING
                }
            }
            5 | 9 => {
                let (decoder, surface) = {
                    let objects = self.0.objects.lock().unwrap();
                    (
                        objects.decoders.get(&a[0]).cloned(),
                        objects.surfaces.get(&a[1]).cloned(),
                    )
                };
                let (Some(decoder), Some(surface)) = (decoder, surface) else {
                    return Ok(MISSING as u64);
                };
                let read = |address, size: u64| -> Result<Vec<u8>, MemoryError> {
                    let mut data = Vec::new();
                    data.try_reserve_exact(size as usize)
                        .map_err(|_| MemoryError::BackingIo(12))?;
                    data.resize(size as usize, 0);
                    memory.read(address, &mut data)?;
                    Ok(data)
                };
                // Parameter-set NAL units have bounded H.264 syntax. Compressed
                // frame size itself follows guest address-space/usize limits.
                let (configuration, pps, data) = if op == 5 {
                    if a[3] == 0
                        || a[3] > 65536
                        || a[5] == 0
                        || a[5] > 65536
                        || a[7] == 0
                        || a[7] > isize::MAX as u64
                    {
                        return Ok(INVALID as u64);
                    }
                    (read(a[2], a[3])?, read(a[4], a[5])?, read(a[6], a[7])?)
                } else if a[3] == 0 || a[3] > 65536 || a[5] == 0 || a[5] > isize::MAX as u64 {
                    return Ok(INVALID as u64);
                } else {
                    (read(a[2], a[3])?, Vec::new(), read(a[4], a[5])?)
                };
                let job = Arc::new(Job {
                    result: Mutex::new(None),
                    notify: surface.notify.clone(),
                    graphics: self.0.graphics.clone(),
                });
                {
                    let mut slot = surface.job.lock().unwrap();
                    if slot
                        .as_ref()
                        .is_some_and(|old| old.result.lock().unwrap().is_none())
                    {
                        return Ok(PENDING as u64);
                    }
                    *slot = Some(job.clone());
                }
                if op == 5 {
                    decoder
                        .lock()
                        .unwrap()
                        .submit(&configuration, &pps, data, job);
                } else {
                    decoder
                        .lock()
                        .unwrap()
                        .submit_bitstream(&configuration, data, job);
                }
                0
            }
            6 => {
                let surface = self.0.objects.lock().unwrap().surfaces.get(&a[0]).cloned();
                match surface {
                    None => MISSING,
                    Some(surface) => {
                        let job = surface.job.lock().unwrap().clone();
                        match job {
                            None => 0,
                            Some(job) => match &*job.result.lock().unwrap() {
                                None => PENDING,
                                Some(Ok(_)) => 0,
                                Some(Err(e)) => *e,
                            },
                        }
                    }
                }
            }
            7 => match self.frame(a[0]) {
                Err(e) => e,
                Ok(frame) => {
                    let (w, h) = frame.dimensions();
                    let data = frame.native.readback();
                    match data {
                        Err(e) => e,
                        Ok(data) => {
                            if data.len() as u64 > a[2] {
                                INVALID
                            } else {
                                memory.write(a[1], &data)?;
                                let mut dimensions = [0; 16];
                                dimensions[..8].copy_from_slice(&u64::from(w).to_le_bytes());
                                dimensions[8..].copy_from_slice(&u64::from(h).to_le_bytes());
                                memory.write(a[3], &dimensions)?;
                                0
                            }
                        }
                    }
                }
            },
            _ => -38,
        };
        Ok(value as u64)
    }
}
