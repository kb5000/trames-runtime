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
    fn needs_download(&self) -> bool {
        self.values.is_some()
            || self
                .objects
                .iter()
                .any(|object| object.state.get() != HOST_SIGNALED)
    }
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
        self.observe_raw_fence(fence.raw);
    }
    pub(super) fn observe_raw_fence(&self, fence: u64) {
        #[cfg(trames_moltenvk)]
        {
            let data = Box::into_raw(Box::new(Arc::downgrade(&self.completion)));
            // SAFETY: only validated retained native fence handles reach here.
            // MoltenVK consumes the weak capability, calls it after its mutex
            // releases, and destroys it once even if the fence never signals.
            unsafe { trames_mvk_observe_fence(fence, notify, data.cast(), dispose) };
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
            if wait.needs_download() {
                self.coherent_download(m)?;
            }
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
        let needs_download = wait.needs_download();
        self.waits.remove(&job);
        if result.as_ref().is_ok_and(|&value| value == 0) {
            self.collect();
            if needs_download {
                self.coherent_download(m)?;
            }
        }
        result.map(Some)
    }
}

pub(super) struct Teardown {
    pub operation: u64,
    pub target: u64,
    pub abandoned: bool,
}
impl Backend {
    fn validate_teardown(&self, operation: u64, target: u64) -> Result<()> {
        if operation == 2 {
            if target != self.instance_id {
                return invalid();
            }
        } else {
            if self.instance.is_none() {
                return Err(vk::Result::ERROR_INITIALIZATION_FAILED.into());
            }
            self.device(target)?;
        }
        Ok(())
    }
    pub(super) fn teardown_ready(&self) -> bool {
        self.compiles.values().all(|c| c.task.completed())
            && (!available()
                || self
                    .submissions
                    .iter()
                    .all(|s| !matches!(Self::fence_ready(&s.fence), Ok(false)))
                    && self.wayland.idle())
    }
    pub(super) fn start_teardown(&mut self, operation: u64, target: u64) -> Result<Invocation> {
        self.validate_teardown(operation, target)?;
        if self.teardown_ready() {
            self.finish_teardown(operation, target)?;
            return Ok(Invocation::Complete(0));
        }
        let id = self.id();
        self.teardowns.insert(
            id,
            Teardown {
                operation,
                target,
                abandoned: false,
            },
        );
        Ok(Invocation::Pending(id))
    }
    pub(super) fn poll_teardown(&mut self, job: u64) -> Result<Option<u64>> {
        self.collect();
        if !self.teardown_ready() {
            return Ok(None);
        }
        let Some(job) = self.teardowns.remove(&job) else {
            return Err(vk::Result::ERROR_DEVICE_LOST.into());
        };
        self.finish_teardown(job.operation, job.target)?;
        Ok(Some(0))
    }
    pub(super) fn finish_teardown(&mut self, operation: u64, target: u64) -> Result<()> {
        self.validate_teardown(operation, target)?;
        // Keep the original final native idle/destruction algorithm. Pending
        // compilation and observed GPU submissions have already released the
        // execution slot; races with later calls retain original device safety.
        self.clear_device();
        if operation == 2 {
            self.wsi.surfaces.clear();
            self.wayland.surfaces.clear();
            self.instance = None;
            self.wsi_enabled = false;
            self.instance_id = 0;
            self.physical_id = 0;
            self.capabilities = Default::default();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    struct Wake(mpsc::Sender<()>);
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            let _ = self.0.send(());
        }
    }
    #[test]
    fn device_teardown_defers_for_native_compilation_and_uses_the_accepted_target() {
        let mut backend = Backend::new();
        let (release, gate) = mpsc::channel();
        let completion = Some(backend.completion.clone());
        let task = crate::task::Task::spawn_notifying(completion, move || {
            gate.recv().unwrap();
            Err(vk::Result::ERROR_INITIALIZATION_FAILED)
        })
        .unwrap();
        backend.compiles.insert(
            37,
            Compile {
                task,
                dependencies: Vec::new(),
                rendering: None,
                bind_point: vk::PipelineBindPoint::COMPUTE,
                creation_flags: 0,
                subpass: 0,
                vertex_inputs: Vec::new(),
                static_states: 0,
                output: 0,
                abandoned: false,
            },
        );
        let context = crate::Context::new(backend);
        let mut memory = Memory::default();
        memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        let Invocation::Pending(job) = context.invoke(&mut memory, 2, 0x1000, 128, None).0.unwrap()
        else {
            panic!("native compile must not join on this caller")
        };
        assert_eq!(context.poll(&mut memory, job).unwrap(), None);
        let (send, receive) = mpsc::channel();
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(send));
        let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
        let _subscription = context
            .try_lock()
            .unwrap()
            .subscribe_compile(job, &signal)
            .unwrap();
        // Native work on another context remains runnable. The record can change
        // while waiting; destruction still targets the original accepted ID.
        let other = crate::Context::new(Backend::new());
        memory.write_array(0x1000, 0x2000u64.to_le_bytes()).unwrap();
        assert_eq!(
            other.invoke(&mut memory, 79, 0x1000, 128, None).0,
            Ok(Invocation::Complete(0))
        );
        release.send(()).unwrap();
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(context.poll(&mut memory, job).unwrap(), Some(0));
        assert!(!context.try_lock().unwrap().is_compile(37));
        assert_eq!(
            context.poll(&mut memory, job).unwrap(),
            Some(vk::Result::ERROR_DEVICE_LOST.as_raw() as i64 as u64)
        );
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };
    fn pending(backend: &mut Backend, id: u64) -> mpsc::Sender<()> {
        let (release, gate) = mpsc::channel();
        let task =
            crate::task::Task::spawn_notifying(Some(backend.completion.clone()), move || {
                gate.recv().unwrap();
                Err(vk::Result::ERROR_INITIALIZATION_FAILED)
            })
            .unwrap();
        backend.compiles.insert(
            id,
            Compile {
                task,
                dependencies: Vec::new(),
                rendering: None,
                bind_point: vk::PipelineBindPoint::COMPUTE,
                creation_flags: 0,
                subpass: 0,
                vertex_inputs: Vec::new(),
                static_states: 0,
                output: 0,
                abandoned: false,
            },
        );
        release
    }
    fn gone(context: &crate::WeakContext) {
        let until = Instant::now() + Duration::from_secs(5);
        while context.upgrade().is_some() {
            assert!(
                Instant::now() < until,
                "native completion must release its graph without owner polling"
            );
            std::thread::yield_now();
        }
    }
    #[test]
    fn final_mm_release_returns_before_two_native_jobs_and_each_completion_releases_its_graph() {
        let mut backend = Backend::new();
        let first = pending(&mut backend, 37);
        let second = pending(&mut backend, 38);
        let context = crate::Context::new(backend);
        let weak = context.downgrade();
        let (sent, returned) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            context.retire();
            drop(context);
            sent.send(()).unwrap();
        });
        let early = returned.recv_timeout(Duration::from_secs(1));
        if early.is_err() {
            first.send(()).unwrap();
            second.send(()).unwrap();
            worker.join().unwrap();
            panic!("guest task slot waited for unfinished native work");
        }
        worker.join().unwrap();
        assert!(weak.upgrade().is_some());
        first.send(()).unwrap();
        assert!(weak.upgrade().is_some());
        second.send(()).unwrap();
        gone(&weak);
    }
    #[test]
    fn a_busy_context_defers_driver_callback_cleanup_to_unlock_without_losing_completion() {
        for _ in 0..30 {
            let mut backend = Backend::new();
            let release = pending(&mut backend, 37);
            let completion = backend.completion.clone();
            let context = crate::Context::new(backend);
            let weak = context.downgrade();
            context.abandon(37);
            let lease = context.try_lock().unwrap();
            let (sent, notified) = mpsc::channel();
            let notify = std::thread::spawn(move || {
                completion.notify_atomic();
                sent.send(()).unwrap();
            });
            let early = notified.recv_timeout(Duration::from_secs(1));
            if early.is_err() {
                drop(lease);
                release.send(()).unwrap();
                notify.join().unwrap();
                panic!("driver callback blocked behind native context lease");
            }
            notify.join().unwrap();
            release.send(()).unwrap();
            drop(lease);
            drop(context);
            gone(&weak);
        }
    }
}

#[cfg(test)]
mod retirement_unlock_tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };
    struct Wake(mpsc::Sender<()>);
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            let _ = self.0.send(());
        }
    }
    #[test]
    fn unlock_collects_finished_work_even_if_another_native_caller_consumed_the_completion() {
        let mut backend = Backend::new();
        let (release, gate) = mpsc::channel();
        // No aggregate delivery: completion was observed through its original
        // task readiness, as another native caller can do before context unlock.
        let task = crate::task::Task::spawn_notifying(None, move || {
            gate.recv().unwrap();
            Err(vk::Result::ERROR_INITIALIZATION_FAILED)
        })
        .unwrap();
        let (sent, finished) = mpsc::channel();
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(sent));
        let signal = trames_shared::IoSignal::new(0, Arc::downgrade(&wake));
        let _subscription = task.subscribe(&signal);
        backend.compiles.insert(
            37,
            Compile {
                task,
                dependencies: Vec::new(),
                rendering: None,
                bind_point: vk::PipelineBindPoint::COMPUTE,
                creation_flags: 0,
                subpass: 0,
                vertex_inputs: Vec::new(),
                static_states: 0,
                output: 0,
                abandoned: false,
            },
        );
        let context = crate::Context::new(backend);
        let weak = context.downgrade();
        context.abandon(37);
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(context.try_lock().unwrap());
        drop(context);
        let until = Instant::now() + Duration::from_secs(5);
        while weak.upgrade().is_some() {
            assert!(
                Instant::now() < until,
                "a native unlock must retire the completed original graph without an owner poll"
            );
            std::thread::yield_now();
        }
    }
}
