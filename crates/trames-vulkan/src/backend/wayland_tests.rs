// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual native image/fence tests. UI leases are held explicitly, so blocked
//! acquisition, producer completion and cancellation are deterministic.
use super::*;
use std::{sync::mpsc, time::Duration};
use trames_memory::Memory;
const AT: u64 = 0x1000;
const OUT: u64 = 0x2000;
fn invoke(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> Invocation {
    let mut packet = [0; 128];
    for (i, a) in args.iter().enumerate() {
        packet[i * 8..i * 8 + 8].copy_from_slice(&a.to_le_bytes());
    }
    m.write(AT, &packet).unwrap();
    b.invoke(m, op, AT, 128).unwrap()
}
fn ok(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) {
    assert_eq!(invoke(b, m, op, args), Invocation::Complete(0));
}
fn word(m: &Memory) -> u64 {
    m.read_u64(OUT).unwrap()
}
fn sync(b: &mut Backend, m: &mut Memory, kind: u64) -> u64 {
    let dev = b.device_id;
    ok(b, m, kind, &[dev, 0, OUT]);
    word(m)
}
fn sem(b: &mut Backend, m: &mut Memory) -> u64 {
    let dev = b.device_id;
    ok(b, m, 54, &[dev, OUT]);
    word(m)
}
fn setup() -> (Backend, Memory, u64) {
    let server = Server::new().unwrap();
    let mut b = Backend::new().with_wayland(Some(server.clone()));
    let mut m = Memory::default();
    m.map(AT, 0x4000, trames_memory::Permissions::RW).unwrap();
    ok(&mut b, &mut m, 1, &[OUT, 2]);
    let instance = word(&m);
    m.write_array(0x2100, 1u32.to_le_bytes()).unwrap();
    ok(&mut b, &mut m, 3, &[instance, 0x2100, OUT]);
    let physical = word(&m);
    ok(&mut b, &mut m, 6, &[physical, 0x2100, 0]);
    ok(&mut b, &mut m, 6, &[physical, 0x2100, 0x2200]);
    let family = (0..read32(&m, 0x2100).unwrap())
        .find(|i| read32(&m, 0x2200 + u64::from(*i) * 24).unwrap() & 1 != 0)
        .unwrap();
    ok(
        &mut b,
        &mut m,
        8,
        &[physical, u64::from(family), OUT, 1, 0, 10],
    );
    let device = b.device.as_ref().unwrap().clone();
    let surface = Rc::new(Surface {
        server,
        connection: 1,
        protocol: 1,
        id: 1,
        owner: Arc::default(),
        gpu_budget: Default::default(),
    });
    let images = (0..2)
        .map(|_| NativeImage::allocate(&b, device.clone(), 16, 16, 19).unwrap())
        .collect();
    let pool = Rc::new(Pool {
        device,
        surface: surface.clone(),
        claim: Claim {
            owner: surface.owner.clone(),
            token: 1,
        },
        images,
    });
    let chain = 999;
    b.wayland.chains.insert(
        chain,
        Chain {
            pool,
            images: vec![0, 0],
            acquired: vec![false; 2],
            retired: false,
            mailbox: false,
        },
    );
    (b, m, chain)
}
fn acquire(
    b: &mut Backend,
    m: &mut Memory,
    chain: u64,
    semaphore: u64,
    fence: u64,
    timeout: u64,
) -> Invocation {
    invoke(
        b,
        m,
        251,
        &[b.device_id, chain, semaphore, fence, OUT, timeout],
    )
}
fn hold(b: &mut Backend, chain: u64, index: usize, ready: bool) -> Arc<Frame> {
    let pool = &b.wayland.chains[&chain].pool;
    let fence = unsafe {
        pool.device.native.create_fence(
            &vk::FenceCreateInfo::default().flags(if ready {
                vk::FenceCreateFlags::SIGNALED
            } else {
                vk::FenceCreateFlags::empty()
            }),
            None,
        )
    }
    .unwrap();
    b.observe_raw_fence(fence.as_raw());
    pool.images[index].state.store(2, Ordering::Release);
    Arc::new(Frame {
        image: pool.images[index].clone(),
        completion: Arc::new(Completion {
            device: pool.device.clone(),
            fence,
        }),
        mailbox: false,
        _permit: pool.surface.gpu_budget.reserve().unwrap(),
    })
}
struct Wake(mpsc::Sender<()>);
impl trames_shared::IoWake for Wake {
    fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
        self.0.send(()).unwrap();
    }
}
fn listener() -> (
    Arc<dyn trames_shared::IoWake>,
    Arc<trames_shared::IoSignal>,
    mpsc::Receiver<()>,
) {
    let (send, recv) = mpsc::channel();
    let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake(send));
    let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
    (target, signal, recv)
}
#[test]
#[ignore = "requires the original native MoltenVK image/fence adapter"]
fn hardware_acquisition_has_no_dummy_submit_and_consumes_host_signal_once() {
    let (mut b, mut m, chain) = setup();
    let a = sem(&mut b, &mut m);
    let f = sync(&mut b, &mut m, 48);
    let dev = b.device_id;
    assert_eq!(
        acquire(&mut b, &mut m, chain, a, f, 0),
        Invocation::Complete(0)
    );
    assert!(b.submissions.is_empty());
    let fence = b.objects[&f].clone();
    assert!(Backend::fence_ready(&fence).unwrap());
    assert!(!unsafe {
        fence
            .device
            .native
            .get_fence_status(vk::Fence::from_raw(fence.raw))
    }
    .unwrap());
    ok(&mut b, &mut m, 50, &[dev, f]);
    assert!(!Backend::fence_ready(&fence).unwrap());
    // One submit consumes a host-ready signal, then signals/waits that same
    // binary semaphore natively in later batches. No native wait may survive
    // for the elided CPU acquisition, and batch state is committed once.
    m.write_array(0x3000, a.to_le_bytes()).unwrap();
    m.write_array(0x3100, 0x10000u32.to_le_bytes()).unwrap();
    let records = [
        0x3000, 1, 0x3100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3000, 1, 0x3000, 1, 0x3100, 0, 0, 0, 0,
    ];
    m.write(
        0x3200,
        &records
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let queue = b.queue_id;
    ok(&mut b, &mut m, 56, &[dev, queue, 0x3200, 3, f]);
    assert_eq!(b.objects[&a].state.get(), 0);
    unsafe { b.device.as_ref().unwrap().native.device_wait_idle() }.unwrap();
    b.collect();
    assert!(Backend::fence_ready(&fence).unwrap());
    ok(&mut b, &mut m, 50, &[dev, f]);
    assert_eq!(
        acquire(&mut b, &mut m, chain, a, f, 0),
        Invocation::Complete(0)
    );
    assert!(b.submissions.is_empty());
    // Eliding a host binary wait must keep native timeline values aligned with
    // their remaining handles, including a wait/signal of the same timeline.
    ok(&mut b, &mut m, 50, &[dev, f]);
    ok(&mut b, &mut m, 54, &[dev, OUT, 1, 7]);
    let timeline = word(&m);
    m.write_array(0x3300, a.to_le_bytes()).unwrap();
    m.write_array(0x3308, timeline.to_le_bytes()).unwrap();
    m.write_array(0x3400, 0x10000u32.to_le_bytes()).unwrap();
    m.write_array(0x3404, 0x10000u32.to_le_bytes()).unwrap();
    m.write_array(0x3500, 0u64.to_le_bytes()).unwrap();
    m.write_array(0x3508, 7u64.to_le_bytes()).unwrap();
    m.write_array(0x3600, timeline.to_le_bytes()).unwrap();
    m.write_array(0x3700, 8u64.to_le_bytes()).unwrap();
    let record = [0x3300, 2, 0x3400, 0, 0, 0x3600, 1, 0x3500, 0x3700];
    m.write(
        0x3800,
        &record
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    ok(&mut b, &mut m, 120, &[dev, queue, 0x3800, 1, f]);
    unsafe { b.device.as_ref().unwrap().native.device_wait_idle() }.unwrap();
    let device = b.device.as_ref().unwrap();
    let api = ash::khr::timeline_semaphore::Device::new(&device.instance.native, &device.native);
    assert_eq!(
        unsafe {
            api.get_semaphore_counter_value(vk::Semaphore::from_raw(b.objects[&timeline].raw))
        }
        .unwrap(),
        8
    );
    assert_eq!(b.objects[&a].state.get(), 0);
}
#[test]
#[ignore = "requires the original native MoltenVK image/fence adapter"]
fn hardware_wait_uses_original_pool_and_sync_objects_and_cancels_without_effects() {
    let (mut b, mut m, chain) = setup();
    for image in &b.wayland.chains[&chain].pool.images {
        image.state.store(2, Ordering::Release);
    }
    let a = sem(&mut b, &mut m);
    let f = sync(&mut b, &mut m, 48);
    let dev = b.device_id;
    let original = b.objects[&a].clone();
    assert_eq!(
        acquire(&mut b, &mut m, chain, a, f, 0),
        Invocation::Complete(vk::Result::NOT_READY.as_raw() as i64 as u64)
    );
    let Invocation::Pending(job) = acquire(&mut b, &mut m, chain, a, f, 1_000_000) else {
        panic!()
    };
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(
        b.poll(&mut m, job).unwrap(),
        Some(vk::Result::TIMEOUT.as_raw() as i64 as u64)
    );
    assert_eq!(original.state.get(), 0);
    let Invocation::Pending(job) = acquire(&mut b, &mut m, chain, a, f, u64::MAX) else {
        panic!()
    };
    b.abandon(job);
    assert!(b.acquires.is_empty());
    assert_eq!(original.state.get(), 0);
    assert!(!Backend::fence_ready(&b.objects[&f]).unwrap());
    let held = hold(&mut b, chain, 0, true);
    let Invocation::Pending(job) = acquire(&mut b, &mut m, chain, a, f, u64::MAX) else {
        panic!()
    };
    let (_target, signal, recv) = listener();
    let _sub = b.subscribe_job(job, &signal).unwrap();
    ok(&mut b, &mut m, 55, &[dev, a]);
    let replacement = sem(&mut b, &mut m);
    assert_ne!(a, replacement);
    drop(held);
    recv.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(b.poll(&mut m, job).unwrap(), Some(0));
    assert_eq!(original.state.get(), HOST_SIGNALED);
    assert_eq!(b.objects[&replacement].state.get(), 0);
    let other_f = sync(&mut b, &mut m, 48);
    let Invocation::Pending(job) = acquire(&mut b, &mut m, chain, replacement, other_f, u64::MAX)
    else {
        panic!()
    };
    let (_target, signal, recv) = listener();
    let _sub = b.subscribe_job(job, &signal).unwrap();
    b.wayland.retire(chain);
    recv.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        b.poll(&mut m, job).unwrap(),
        Some(vk::Result::ERROR_OUT_OF_DATE_KHR.as_raw() as i64 as u64)
    );
}
#[test]
#[ignore = "requires the original native MoltenVK image/fence adapter"]
fn hardware_producer_completion_releases_its_last_lease_without_polling() {
    let (mut b, mut m, chain) = setup();
    for image in &b.wayland.chains[&chain].pool.images {
        image.state.store(2, Ordering::Release);
    }
    let frame = hold(&mut b, chain, 0, false);
    let completion = frame.completion.clone();
    b.wayland.pending.push(Pending {
        frame,
        _resources: vec![],
    });
    let a = sem(&mut b, &mut m);
    let f = sync(&mut b, &mut m, 48);
    let Invocation::Pending(job) = acquire(&mut b, &mut m, chain, a, f, u64::MAX) else {
        panic!()
    };
    let (_target, signal, recv) = listener();
    let _sub = b.subscribe_job(job, &signal).unwrap();
    unsafe {
        completion.device.native.queue_submit(
            b.queue,
            &[vk::SubmitInfo::default()],
            completion.fence,
        )
    }
    .unwrap();
    recv.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(b.poll(&mut m, job).unwrap(), Some(0));
    assert!(b.wayland.pending.is_empty());
    assert!(b.submissions.is_empty());
}

#[test]
#[ignore = "requires the original native MoltenVK image/fence adapter"]
fn hardware_waited_acquisition_output_fault_retires_without_retargeting() {
    let (mut b, mut m, chain) = setup();
    for image in &b.wayland.chains[&chain].pool.images {
        image.state.store(2, Ordering::Release);
    }
    let held = hold(&mut b, chain, 0, true);
    let a = sem(&mut b, &mut m);
    let f = sync(&mut b, &mut m, 48);
    let Invocation::Pending(job) = acquire(&mut b, &mut m, chain, a, f, u64::MAX) else {
        panic!()
    };
    m.protect(OUT, 4096, trames_memory::Permissions::R).unwrap();
    drop(held);
    assert!(b.poll(&mut m, job).is_err());
    assert!(b.wayland.chains[&chain].retired);
    assert!(b.acquires.is_empty());
    assert!(b.submissions.is_empty());
}
#[test]
#[ignore = "requires the original native MoltenVK image/fence adapter"]
fn hardware_host_fence_completion_wakes_only_after_context_unlock() {
    struct Unlocked(crate::Context, mpsc::Sender<()>);
    impl trames_shared::IoWake for Unlocked {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            assert!(self.0.try_lock().is_some());
            self.1.send(()).unwrap();
        }
    }
    let (mut b, mut m, chain) = setup();
    let f = sync(&mut b, &mut m, 48);
    let dev = b.device_id;
    m.write_array(0x3000, f.to_le_bytes()).unwrap();
    let Invocation::Pending(wait) = invoke(&mut b, &mut m, 201, &[dev, 0x3000, 1, 1, u64::MAX])
    else {
        panic!()
    };
    let context = crate::Context::new(b);
    let (send, recv) = mpsc::channel();
    let target: Arc<dyn trames_shared::IoWake> = Arc::new(Unlocked(context.clone(), send));
    let signal = trames_shared::IoSignal::new(2, Arc::downgrade(&target));
    let mut lease = context.try_lock().unwrap();
    let _subscription = lease.subscribe_compile(wait, &signal).unwrap();
    let mut packet = [0; 128];
    for (i, v) in [dev, chain, 0, f, OUT, u64::MAX].into_iter().enumerate() {
        packet[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    m.write(AT, &packet).unwrap();
    assert_eq!(
        lease.invoke(&mut m, 251, AT, 128, None).0.unwrap(),
        Invocation::Complete(0)
    );
    assert!(recv.try_recv().is_err());
    drop(lease);
    recv.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(context.poll(&mut m, wait).unwrap(), Some(0));
}
