// SPDX-License-Identifier: GPL-3.0-or-later
//! Native PCM streams. Guest eventfd/poll waits release the calling CPU slot.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use trames_memory::{Access, CpuMemory, MemoryError};
mod native;
pub const PROFILE: u64 = 0x0001_0008;
pub const AUXV_KEY: u64 = 0x5452_000a;
pub const CAPS_KEY: u64 = 0x5452_000b;
pub const OPEN: u64 = 1;
pub type Notify = Arc<dyn Fn() + Send + Sync>;
struct Stream {
    native: native::Stream,
    scratch: Vec<u8>,
    frame_bytes: usize,
}
struct Inner {
    capabilities: u64,
    ids: AtomicU64,
    streams: Mutex<BTreeMap<u64, Arc<Mutex<Stream>>>>,
}

#[derive(Clone)]
pub struct Context(Arc<Inner>);
impl Default for Context {
    fn default() -> Self {
        Self::new(0)
    }
}
impl Context {
    pub fn new(capabilities: u64) -> Self {
        Self(Arc::new(Inner {
            capabilities,
            ids: AtomicU64::new(0),
            streams: Mutex::default(),
        }))
    }
    /// OPEN resolves the notification FD on the namespace owner. Transfers,
    /// positions and controls are dispatched on the existing CPU worker.
    pub fn invoke(
        &self,
        memory: &mut impl CpuMemory,
        op: u64,
        at: u64,
        size: u64,
        notify: Option<Notify>,
    ) -> Result<u64, MemoryError> {
        if size != 128 {
            return Ok((-22i64) as u64);
        }
        let record = memory.read_array::<128>(at)?;
        let a: [u64; 16] = std::array::from_fn(|i| {
            u64::from_le_bytes(record[i * 8..i * 8 + 8].try_into().unwrap())
        });
        if op == 0 {
            return Ok(self.0.capabilities);
        }
        if op == OPEN {
            // fd, direction (0=output,1=input), rate, channels, format
            // (0=s16le,1=f32le), period frames, buffer frames.
            if a[1] > 1 || self.0.capabilities & (1 << a[1]) == 0 {
                return Ok((-13i64) as u64);
            }
            if !(8000..=192000).contains(&a[2])
                || !(1..=2).contains(&a[3])
                || a[4] > 1
                || a[5] == 0
                || a[5] > a[6]
                || a[6] > u32::MAX as u64
                || a[5] > u32::MAX as u64 / 8
            {
                return Ok((-22i64) as u64);
            }
            let Some(notify) = notify else {
                return Ok((-22i64) as u64);
            };
            let native = match native::Stream::new(&a, notify) {
                Ok(s) => s,
                Err(e) => return Ok(e as u64),
            };
            let id = self.0.ids.fetch_add(1, Ordering::Relaxed) + 1;
            let stream = Stream {
                native,
                scratch: vec![0; 65536],
                frame_bytes: a[3] as usize * if a[4] == 0 { 2 } else { 4 },
            };
            self.0
                .streams
                .lock()
                .unwrap()
                .insert(id, Arc::new(Mutex::new(stream)));
            return Ok(id);
        }
        if op == 2 {
            let stream = self.0.streams.lock().unwrap().remove(&a[0]);
            return Ok(if stream.is_some() { 0 } else { (-2i64) as u64 });
        }
        let stream = self.0.streams.lock().unwrap().get(&a[0]).cloned();
        let Some(stream) = stream else {
            return Ok((-2i64) as u64);
        };
        let mut stream = stream.lock().unwrap();
        let value = match op {
            3..=5 => stream.native.control(op), // start, stop, prepare
            6 => {
                // interleaved transfer, returns frames, never waits
                let frames = a[2].min((stream.scratch.len() / stream.frame_bytes) as u64) as usize;
                let bytes = frames * stream.frame_bytes;
                let Stream {
                    native, scratch, ..
                } = &mut *stream;
                if native.capture() {
                    memory.check(a[1], bytes, Access::Write)?;
                    let done = native.transfer(&mut scratch[..bytes]);
                    if done > 0 {
                        memory.write(a[1], &scratch[..done as usize])?;
                    }
                    if done < 0 {
                        done
                    } else {
                        done / stream.frame_bytes as i64
                    }
                } else {
                    memory.read(a[1], &mut scratch[..bytes])?;
                    let done = native.transfer(&mut scratch[..bytes]);
                    if done < 0 {
                        done
                    } else {
                        done / stream.frame_bytes as i64
                    }
                }
            }
            7 => {
                let stats = stream.native.status();
                let mut bytes = [0; 64];
                for (dst, n) in bytes.chunks_exact_mut(8).zip(stats) {
                    dst.copy_from_slice(&n.to_le_bytes());
                }
                memory.write(a[1], &bytes)?;
                0
            }
            8 => stream.native.control(if a[1] != 0 { 8 } else { 3 }), // pause/resume
            _ => -38,
        };
        Ok(value as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn capability_and_wire_failures_do_not_open_a_host_device() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let context = Context::new(1);
        assert_eq!(
            context.invoke(&mut memory, 0, 0x1000, 128, None).unwrap(),
            1
        );
        assert_eq!(
            context
                .invoke(&mut memory, OPEN, 0x1000, 127, None)
                .unwrap() as i64,
            -22
        );
        let mut record = [0; 128];
        record[8..16].copy_from_slice(&1u64.to_le_bytes());
        memory.write(0x1000, &record).unwrap();
        assert_eq!(
            context
                .invoke(&mut memory, OPEN, 0x1000, 128, None)
                .unwrap() as i64,
            -13
        );
        assert_eq!(
            context.invoke(&mut memory, 2, 0x1000, 128, None).unwrap() as i64,
            -2
        );
        assert!(context.invoke(&mut memory, 0, 0x9000, 128, None).is_err());
    }
}
