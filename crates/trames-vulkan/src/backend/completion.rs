// SPDX-License-Identifier: GPL-3.0-or-later
//! Driver completion callbacks publish scheduling readiness, never guest bytes.
use super::*;
use std::time::{Duration, Instant};

pub(super) fn available() -> bool {
    cfg!(trames_moltenvk)
}

#[cfg(trames_moltenvk)]
unsafe extern "C" {
    fn trames_mvk_observe_fence(
        fence: u64,
        notify: unsafe extern "C" fn(*mut std::ffi::c_void),
        data: *mut std::ffi::c_void,
        dispose: unsafe extern "C" fn(*mut std::ffi::c_void),
    );
}
#[cfg(trames_moltenvk)]
unsafe extern "C" fn notify(data: *mut std::ffi::c_void) {
    // SAFETY: native owns this weak capability until its one-shot callback has
    // returned; dispose runs only after that callback or canceled fence teardown.
    let weak = unsafe { &*data.cast::<std::sync::Weak<trames_shared::Readiness>>() };
    if let Some(readiness) = weak.upgrade() {
        readiness.notify_atomic();
    }
}
#[cfg(trames_moltenvk)]
unsafe extern "C" fn dispose(data: *mut std::ffi::c_void) {
    // SAFETY: exactly one native shared owner consumes the original Box.
    drop(unsafe { Box::from_raw(data.cast::<std::sync::Weak<trames_shared::Readiness>>()) });
}

pub(super) struct Wait {
    pub deadline: Option<Instant>,
    objects: Vec<Rc<Object>>,
    values: Option<Vec<u64>>,
    any: bool,
}
impl Wait {
    fn ready(&self) -> Result<bool> {
        let mut ready = !self.any;
        for (i, object) in self.objects.iter().enumerate() {
            let signaled = if let Some(values) = &self.values {
                let dev = &object.device;
                let api =
                    ash::khr::timeline_semaphore::Device::new(&dev.instance.native, &dev.native);
                unsafe { api.get_semaphore_counter_value(vk::Semaphore::from_raw(object.raw)) }?
                    >= values[i]
            } else {
                Backend::fence_ready(object)?
            };
            if self.any {
                ready |= signaled;
            } else {
                ready &= signaled;
            }
        }
        Ok(ready)
    }
}
impl Backend {
    pub(super) fn observe_fence(&self, fence: &Object) {
        #[cfg(trames_moltenvk)]
        {
            let data = Box::into_raw(Box::new(Arc::downgrade(&self.completion)));
            // SAFETY: only validated retained native fence handles reach here.
            // MoltenVK consumes the weak capability, calls it after its mutex
            // releases, and destroys it once even if the fence never signals.
            unsafe { trames_mvk_observe_fence(fence.raw, notify, data.cast(), dispose) };
        }
        #[cfg(not(trames_moltenvk))]
        let _ = fence;
    }
    pub(super) fn start_wait(
        &mut self,
        m: &mut impl CpuMemory,
        op: u64,
        a: [u64; 16],
    ) -> Result<Invocation> {
        if !available() {
            return unsupported();
        }
        let dev = self.device(a[0])?;
        let (count, any, timeout, kind) = if op == 201 {
            if a[3] > 1 {
                return invalid();
            }
            (a[2], a[3] == 0, a[4], Kind::Fence)
        } else {
            if !dev.timeline || a[4] & !1 != 0 {
                return unsupported();
            }
            (a[3], a[4] & 1 != 0, a[5], Kind::Semaphore)
        };
        let count = bounded(count, 64)?;
        if count == 0 || self.waits.len() >= LIMIT {
            return invalid();
        }
        let objects = words64(m, a[1], count)?
            .into_iter()
            .map(|id| self.object(id, kind))
            .collect::<Result<Vec<_>>>()?;
        if kind == Kind::Semaphore && objects.iter().any(|s| s.flags != 1) {
            return invalid();
        }
        let wait = Wait {
            deadline: if timeout == u64::MAX {
                None
            } else {
                Instant::now().checked_add(Duration::from_nanos(timeout))
            },
            objects,
            any,
            values: if op == 202 {
                Some(words64(m, a[2], count)?)
            } else {
                None
            },
        };
        if wait.ready()? {
            self.collect();
            self.coherent_download(m)?;
            return Ok(Invocation::Complete(0));
        }
        if timeout == 0 {
            return Ok(Invocation::Complete(
                vk::Result::TIMEOUT.as_raw() as i64 as u64
            ));
        }
        let id = self.id();
        self.waits.insert(id, wait);
        Ok(Invocation::Pending(id))
    }
    pub(super) fn poll_wait(&mut self, m: &mut impl CpuMemory, job: u64) -> Result<Option<u64>> {
        let wait = &self.waits[&job];
        let result = match wait.ready() {
            Ok(true) => Ok(0),
            Ok(false)
                if wait
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline) =>
            {
                Ok(vk::Result::TIMEOUT.as_raw() as i64 as u64)
            }
            Ok(false) => return Ok(None),
            Err(error) => Err(error),
        };
        self.waits.remove(&job);
        if result.as_ref().is_ok_and(|&value| value == 0) {
            self.collect();
            self.coherent_download(m)?;
        }
        result.map(Some)
    }
}
