// SPDX-License-Identifier: GPL-3.0-or-later
//! Manual transport experiment, not an alternative runtime backend.
//!
//! The coordinator case uses the production Request/Reply/Event/Pool transport.
//! Its body is deliberately the SAME counter operation as peer-worker messages
//! and direct cases. It excludes Linux/VFS work, interpreter execution and
//! stop/join/commit/redispatch, so it is a lower bound for coordinator services.
use super::*;
use trames_cpu::Cpu;
type Pool = super::Pool<Cpu>;
type Request = super::Request<Cpu>;
use std::{hint::black_box, sync::Barrier};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

#[derive(Clone, Copy, Debug)]
enum Mode {
    SharedMutex,
    SharedAtomic,
    WorkerQueue,
    WorkerMailbox,
    CoordinatorRpc,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::SharedMutex => "shared_mutex",
            Self::SharedAtomic => "shared_atomic",
            Self::WorkerQueue => "worker_queue",
            Self::WorkerMailbox => "worker_mailbox_busy_poll",
            Self::CoordinatorRpc => "coordinator_rpc_lower_bound",
        }
    }
}

// Avoid false sharing between logically independent resources. Contended cases
// intentionally share ONE object. The atomic variant models only a counter;
// it does not purport to replace a lock for multi-field invariants or futexes.
#[repr(align(128))]
struct Resource {
    locked: std::sync::Mutex<u64>,
    atomic: AtomicU64,
}
impl Resource {
    fn new() -> Self {
        Self {
            locked: std::sync::Mutex::new(0),
            atomic: AtomicU64::new(0),
        }
    }
    fn increment(&self, delta: u64) -> u64 {
        let mut n = self.locked.lock().unwrap();
        *n += delta;
        *n
    }
    fn atomic_increment(&self, delta: u64) -> u64 {
        // The value is the entire shared state; no associated bytes need to be
        // published. Acquire/release would promise an unneeded ordering here.
        self.atomic.fetch_add(delta, Ordering::Relaxed) + delta
    }
}
enum BusMessage {
    Request {
        caller: usize,
        resource: usize,
        delta: u64,
    },
    Reply(u64),
    Shutdown,
}
fn owner(caller: usize, workers: usize, shared: bool) -> usize {
    if shared {
        0
    } else {
        (caller + 1) % workers
    }
}
fn serve_queue(
    message: BusMessage,
    resources: &[Arc<Resource>],
    peers: &[mpsc::Sender<BusMessage>],
) -> Option<u64> {
    match message {
        BusMessage::Request {
            caller,
            resource,
            delta,
        } => {
            let value = resources[resource].increment(delta);
            peers[caller].send(BusMessage::Reply(value)).unwrap();
            None
        }
        BusMessage::Reply(value) => Some(value),
        BusMessage::Shutdown => panic!("shutdown before all callers completed"),
    }
}
#[repr(align(128))]
struct Mailbox {
    request: AtomicU64,
    complete: AtomicU64,
    value: AtomicU64,
    delta: AtomicU64,
}
impl Mailbox {
    fn new() -> Self {
        Self {
            request: AtomicU64::new(0),
            complete: AtomicU64::new(0),
            value: AtomicU64::new(0),
            delta: AtomicU64::new(0),
        }
    }
}

fn serve_mailboxes(
    owned: &[usize],
    seen: &mut [u64],
    mailboxes: &[Mailbox],
    resources: &[Arc<Resource>],
    shared: bool,
) {
    for &caller in owned {
        let mailbox = &mailboxes[caller];
        let sequence = mailbox.request.load(Ordering::Acquire);
        if sequence != seen[caller] {
            let resource = if shared { 0 } else { caller };
            let delta = mailbox.delta.load(Ordering::Relaxed);
            let value = resources[resource].increment(delta);
            mailbox.value.store(value, Ordering::Relaxed);
            seen[caller] = sequence;
            mailbox.complete.store(sequence, Ordering::Release);
        }
    }
}

// Both supported Unix ABIs use 64-bit time_t/long here. These declarations are
// confined to this manual test; no guest byte or runtime FFI boundary is added.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
fn thread_cpu_seconds() -> f64 {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanos: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
    }
    let mut value = Timespec {
        seconds: 0,
        nanos: 0,
    };
    // Read each live thread's own CPU clock. Sampling the PROCESS clock across
    // very short-lived threads can expose delayed accounting on Linux.
    let clock = if cfg!(target_os = "linux") { 3 } else { 16 };
    // SAFETY: clock_gettime writes the initialized ABI-sized stack structure.
    assert_eq!(unsafe { clock_gettime(clock, &mut value) }, 0);
    value.seconds as f64 + value.nanos as f64 * 1e-9
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
fn thread_cpu_seconds() -> f64 {
    0.0
}

struct Sample {
    elapsed: Duration,
    cpu_seconds: f64,
    checksum: u64,
    service_threads: usize,
}

fn sample(mode: Mode, workers: usize, shared: bool, iterations: u64) -> Sample {
    let resource_count = if shared { 1 } else { workers };
    let resources: Vec<_> = (0..resource_count)
        .map(|_| Arc::new(Resource::new()))
        .collect();
    let service_threads = match mode {
        Mode::SharedMutex | Mode::SharedAtomic | Mode::WorkerQueue | Mode::WorkerMailbox => 0,
        Mode::CoordinatorRpc => 1,
    };
    // ALL message processing runs on the same N callers. The parent services
    // requests only in the original coordinator case; no resource actor exists.
    let barrier = Arc::new(Barrier::new(workers + 1));
    let start = Arc::new(AtomicBool::new(false));
    let mut pool = Pool::with_profiling(workers, false);
    let mut memories = Vec::new();
    let mut views = Vec::new();
    for _ in 0..workers {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        views.push(memory.parallel_view(&mut Default::default()).unwrap());
        memories.push(memory);
    }
    let mut queues = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..if matches!(mode, Mode::WorkerQueue) {
        workers
    } else {
        0
    } {
        let (send, receive) = mpsc::channel::<BusMessage>();
        queues.push(send);
        receivers.push(Some(receive));
    }
    let queues = Arc::new(queues);
    let finished = Arc::new(AtomicUsize::new(0));
    let mailboxes: Arc<Vec<_>> = Arc::new((0..workers).map(|_| Mailbox::new()).collect());
    let (elapsed, cpu_seconds, checksum) = thread::scope(|scope| {
        let mut callers = Vec::new();
        for (caller, view) in views.into_iter().enumerate() {
            let resource = if shared { 0 } else { caller };
            let object = resources[resource].clone();
            let bus_receive = receivers.get_mut(caller).and_then(Option::take);
            let queues = queues.clone();
            let finished = finished.clone();
            let resources = &resources;
            let send = pool.send.clone();
            let barrier = barrier.clone();
            let start = start.clone();
            let mailboxes = mailboxes.clone();
            callers.push(scope.spawn(move || {
                // The actual production reply channel is reused per worker,
                // and its sole sender travels in the request and reply.
                let (reply, receive) = mpsc::channel();
                let mut reply = Some(reply);
                let mut view = Some(view);
                let owned: Vec<_> = (0..workers)
                    .filter(|&i| owner(i, workers, shared) == caller)
                    .collect();
                let mut seen = vec![0; workers];
                barrier.wait();
                while !start.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let cpu_before = thread_cpu_seconds();
                let mut checksum = 0u64;
                for i in 0..iterations {
                    let value = match mode {
                        Mode::SharedMutex => object.increment(black_box(1)),
                        Mode::SharedAtomic => object.atomic_increment(black_box(1)),
                        Mode::WorkerQueue => {
                            queues[owner(caller, workers, shared)]
                                .send(BusMessage::Request {
                                    caller,
                                    resource,
                                    delta: 1,
                                })
                                .unwrap();
                            // A worker waiting for its own result still handles
                            // peer requests. Blocking only on a reply would
                            // deadlock the independent-resource ring.
                            loop {
                                let message = bus_receive.as_ref().unwrap().recv().unwrap();
                                if let Some(value) = serve_queue(message, resources, &queues) {
                                    break value;
                                }
                            }
                        }
                        Mode::WorkerMailbox => {
                            let mailbox = &mailboxes[caller];
                            let sequence = i + 1;
                            mailbox.delta.store(1, Ordering::Relaxed);
                            mailbox.request.store(sequence, Ordering::Release);
                            while mailbox.complete.load(Ordering::Acquire) != sequence {
                                serve_mailboxes(&owned, &mut seen, &mailboxes, resources, shared);
                                std::hint::spin_loop();
                            }
                            mailbox.value.load(Ordering::Relaxed)
                        }
                        Mode::CoordinatorRpc => {
                            // Same envelope and boxing as workers.rs. This is
                            // a synthetic operation, NOT an implemented syscall.
                            send.send(Event::Service(Box::new(Request {
                                pid: caller as u32 + 1,
                                pc: 0x4004,
                                number: u32::MAX,
                                args: [1, resource as u64, 0, 0, 0, 0],
                                target: ReturnTo::Thread {
                                    memory: view.take().unwrap(),
                                    reply: reply.take().unwrap(),
                                },
                            })))
                            .unwrap();
                            let answer = receive.recv().unwrap();
                            view = Some(answer.memory);
                            reply = Some(answer.reply);
                            answer.value.unwrap()
                        }
                    };
                    checksum = checksum.wrapping_add(black_box(value));
                }
                // A worker that finishes its own calls must keep serving peers
                // until ALL calls have replies. No dedicated service thread or
                // parent-thread dispatch participates in either peer path.
                match mode {
                    Mode::WorkerQueue => {
                        if finished.fetch_add(1, Ordering::AcqRel) + 1 == workers {
                            for peer in queues.iter() {
                                peer.send(BusMessage::Shutdown).unwrap();
                            }
                        }
                        loop {
                            let message = bus_receive.as_ref().unwrap().recv().unwrap();
                            if matches!(message, BusMessage::Shutdown) {
                                break;
                            }
                            assert!(serve_queue(message, resources, &queues).is_none());
                        }
                    }
                    Mode::WorkerMailbox => {
                        finished.fetch_add(1, Ordering::AcqRel);
                        while finished.load(Ordering::Acquire) != workers {
                            serve_mailboxes(&owned, &mut seen, &mailboxes, resources, shared);
                            std::hint::spin_loop();
                        }
                    }
                    _ => {}
                }
                (checksum, (thread_cpu_seconds() - cpu_before).max(0.0))
            }));
        }
        barrier.wait();
        let cpu_before = thread_cpu_seconds();
        let began = Instant::now();
        start.store(true, Ordering::Release);
        if matches!(mode, Mode::CoordinatorRpc) {
            for _ in 0..iterations * workers as u64 {
                let Some(Event::Service(request)) =
                    pool.event_timeout(Duration::from_secs(30)).unwrap()
                else {
                    panic!("coordinator did not receive request");
                };
                let value = resources[request.args[1] as usize].increment(request.args[0]);
                request.respond(Some(value));
            }
        }
        let (checksum, worker_cpu) = callers
            .into_iter()
            .map(|t| t.join().unwrap())
            .fold((0u64, 0.0), |(sum, cpu), (value, elapsed)| {
                (sum + value, cpu + elapsed)
            });
        let elapsed = began.elapsed();
        let cpu_seconds = (thread_cpu_seconds() - cpu_before).max(0.0) + worker_cpu;
        (elapsed, cpu_seconds, checksum)
    });
    let expected = if shared {
        let total = iterations * workers as u64;
        total * (total + 1) / 2
    } else {
        workers as u64 * iterations * (iterations + 1) / 2
    };
    assert_eq!(checksum, expected, "lost, duplicated or incorrect response");
    for resource in &resources {
        let value = if matches!(mode, Mode::SharedAtomic) {
            resource.atomic.load(Ordering::Relaxed)
        } else {
            *resource.locked.lock().unwrap()
        };
        assert_eq!(value, iterations * if shared { workers as u64 } else { 1 });
    }
    // Dropped caller Views precede destruction of their coordinator Memory.
    drop(memories);
    Sample {
        elapsed,
        cpu_seconds,
        checksum,
        service_threads,
    }
}

#[test]
fn transport_experiment_preserves_results_under_contention() {
    for mode in [
        Mode::SharedMutex,
        Mode::SharedAtomic,
        Mode::WorkerQueue,
        Mode::WorkerMailbox,
        Mode::CoordinatorRpc,
    ] {
        for shared in [false, true] {
            sample(mode, 4, shared, 128);
        }
    }
}

#[test]
#[ignore = "manual fixed-work transport profile; no automatic benchmark runs"]
fn coordination_transport_profile() {
    let iterations = std::env::var("TRAMES_COORD_ITERATIONS")
        .ok()
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(20_000);
    let samples = std::env::var("TRAMES_COORD_SAMPLES")
        .ok()
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(3);
    assert!((1..=1_000_000).contains(&iterations) && (1..=20).contains(&samples));
    let modes = [
        Mode::SharedMutex,
        Mode::SharedAtomic,
        Mode::WorkerQueue,
        Mode::WorkerMailbox,
        Mode::CoordinatorRpc,
    ];
    println!("COORDINATOR_COST_HEADER {{\"schema\":1,\"host\":\"{}\",\"iterations_per_worker\":{iterations},\"samples\":{samples},\"request_bytes\":{},\"reply_bytes\":{},\"view_bytes\":{},\"scope\":\"fixed u64 counter; production RPC transport only; no Linux/VFS/interpreter/checkpoint cost\"}}", std::env::consts::ARCH, size_of::<Request>(), size_of::<Reply>(), size_of::<View>());
    for workers in [1, 2, 4] {
        for shared in [false, true] {
            // Warm every path. Alternate order rather than measuring one mode
            // for a whole batch while host load or temperature drifts.
            for mode in modes {
                sample(mode, workers, shared, 256);
            }
            for round in 0..samples {
                let order: Vec<_> = if round % 2 == 0 {
                    modes.into_iter().collect()
                } else {
                    modes.into_iter().rev().collect()
                };
                for mode in order {
                    let result = sample(mode, workers, shared, iterations);
                    let operations = iterations * workers as u64;
                    println!("COORDINATOR_COST {{\"mode\":\"{}\",\"workers\":{workers},\"shared_resource\":{shared},\"sample\":{round},\"operations\":{operations},\"seconds\":{:.9},\"cpu_seconds\":{:.9},\"ns_per_operation\":{:.3},\"checksum\":{},\"service_threads\":{}}}", mode.name(), result.elapsed.as_secs_f64(), result.cpu_seconds, result.elapsed.as_secs_f64() * 1e9 / operations as f64, result.checksum, result.service_threads);
                }
            }
        }
    }
}
