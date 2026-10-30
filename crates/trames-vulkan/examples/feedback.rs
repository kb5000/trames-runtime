// SPDX-License-Identifier: GPL-3.0-or-later
//! Real native GPU query/feedback oracle. Apple must also pass the unavailable
//! capability gate; a missing native extension is never reported as capture.
use std::{
    thread,
    time::{Duration, Instant},
};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vulkan::{Backend, Invocation};
const OUT: u64 = 0x2000;
struct Lab {
    b: Backend,
    m: Memory,
    dev: u64,
    queue: u64,
    pool: u64,
    cmd: u64,
    fence: u64,
}
impl Lab {
    fn request(&mut self, op: u64, a: &[u64]) -> u64 {
        self.words(0x1000, &{
            let mut v = vec![0; 16];
            v[..a.len()].copy_from_slice(a);
            v
        });
        match self.b.invoke(&mut self.m, op, 0x1000, 128).unwrap() {
            Invocation::Checkpoint => panic!("joined example requested a mapping checkpoint"),
            Invocation::Complete(n) => n,
            Invocation::Pending(job) => {
                let began = Instant::now();
                loop {
                    if let Some(n) = self.b.poll(&mut self.m, job).unwrap() {
                        break n;
                    }
                    assert!(began.elapsed() < Duration::from_secs(30));
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
    fn call(&mut self, op: u64, a: &[u64]) {
        assert_eq!(self.request(op, a), 0, "op={op} args={a:x?}");
    }
    fn make(&mut self, op: u64, a: &[u64]) -> u64 {
        self.call(op, a);
        self.word(OUT)
    }
    fn word(&self, at: u64) -> u64 {
        let mut b = [0; 8];
        self.m.read(at, &mut b).unwrap();
        u64::from_le_bytes(b)
    }
    fn words(&mut self, at: u64, v: &[u64]) {
        self.m
            .write(
                at,
                &v.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>(),
            )
            .unwrap();
    }
    fn poll(&mut self, op: u64, a: &[u64], pending: u64) {
        let began = Instant::now();
        loop {
            let n = self.request(op, a);
            if n == 0 {
                break;
            }
            assert_eq!(n, pending);
            assert!(began.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn buffer(&mut self, usage: u64, guest: u64) -> (u64, u64) {
        let buffer = self.make(11, &[self.dev, 1024, usage, OUT]);
        self.call(13, &[self.dev, buffer, 0x2100]);
        let size = self.word(0x2100);
        let bits = self.word(0x2110) as u32;
        let mut bytes = [0; 4];
        self.m.read(0x2500, &mut bytes).unwrap();
        let count = u32::from_le_bytes(bytes);
        let ty = (0..count)
            .find(|&i| {
                self.m.read(0x2504 + i as u64 * 8, &mut bytes).unwrap();
                bits & (1 << i) != 0 && u32::from_le_bytes(bytes) & 6 == 6
            })
            .unwrap();
        let mem = self.make(14, &[self.dev, size, ty as u64, OUT]);
        self.call(16, &[self.dev, buffer, mem, 0]);
        self.call(17, &[self.dev, mem, 0, 1024, guest]);
        self.m.write(guest, &[0xa5; 1024]).unwrap();
        (buffer, mem)
    }
    fn begin(&mut self) {
        self.call(38, &[self.dev, self.cmd, 0]);
    }
    fn barrier(&mut self, src: u64, dst: u64, read: u64, write: u64) {
        self.call(44, &[self.dev, self.cmd, src, dst, read, write]);
    }
    fn submit(&mut self) {
        self.call(39, &[self.dev, self.cmd]);
        self.words(0x3000, &[self.cmd]);
        self.call(50, &[self.dev, self.fence]);
        self.call(52, &[self.dev, self.queue, 0x3000, 1, self.fence]);
        self.poll(51, &[self.dev, self.fence], 1);
    }
    fn reset(&mut self) {
        self.call(53, &[self.dev, self.pool, 0]);
    }
    fn pass(&mut self, pass: u64, fb: u64, pipeline: u64) {
        self.call(71, &[self.dev, self.cmd, pass, fb, 0, 0, 8, 8, 0, 0]);
        self.call(41, &[self.dev, self.cmd, pipeline, 0]);
    }
}
fn main() {
    let mut m = Memory::new(256 << 10);
    m.map(0x1000, 31 * PAGE_SIZE, Permissions::RW).unwrap();
    let mut l = Lab {
        b: Backend::new(),
        m,
        dev: 0,
        queue: 0,
        pool: 0,
        cmd: 0,
        fence: 0,
    };
    let instance = l.make(1, &[OUT]);
    l.m.write(0x2080, &1u32.to_le_bytes()).unwrap();
    let physical = l.make(3, &[instance, 0x2080, OUT]);
    l.call(115, &[physical, OUT]);
    let feedback = l.word(OUT) & 1024 != 0;
    l.call(137, &[physical, 0x2700]);
    assert_eq!(l.word(0x2700) != 0, feedback);
    assert_eq!(l.word(0x2708), 0);
    l.dev = l.make(8, &[physical, 0, OUT]);
    assert_ne!(l.request(11, &[l.dev, 64, 0x800, OUT]), 0);
    assert_ne!(l.request(138, &[l.dev, 1000028004, 1, OUT]), 0);
    l.call(9, &[l.dev]);
    if !feedback {
        assert_eq!(
            l.request(8, &[physical, 0, OUT, 0, 0, 24576]),
            (-8i64) as u64
        );
        for i in 0..12 {
            assert_eq!(l.word(0x2700 + i * 8), 0);
        }
        println!("native-feedback-unavailable-ok: no extension/feature/limit claim and disabled calls rejected");
    }
    l.dev = l.make(
        8,
        &[physical, 0, OUT, 0, 0, if feedback { 24576 } else { 0 }],
    );
    l.queue = l.make(10, &[l.dev, 0, 0, OUT]);
    l.pool = l.make(34, &[l.dev, 0, 2, OUT]);
    l.cmd = l.make(36, &[l.dev, l.pool, OUT]);
    l.fence = l.make(48, &[l.dev, 0, OUT]);
    l.call(5, &[physical, 0x2500]);
    let (control, control_mem) = l.buffer(if feedback { 0x1103 } else { 3 }, 0xa000);
    l.m.write(0x2080, &1u32.to_le_bytes()).unwrap();
    l.call(6, &[physical, 0x2080, 0x2800]);
    let timestamps = l.word(0x2808) as u32 != 0;
    if timestamps {
        let timestamp = l.make(138, &[l.dev, 2, 3, OUT]);
        assert_ne!(l.request(138, &[l.dev, 2, 0, OUT]), 0);
        l.begin();
        l.call(140, &[l.dev, l.cmd, timestamp, 0, 3]);
        assert_ne!(l.request(140, &[l.dev, l.cmd, timestamp, 2, 2]), 0);
        assert_ne!(l.request(144, &[l.dev, l.cmd, timestamp, 0]), 0);
        assert_ne!(l.request(143, &[l.dev, l.cmd, timestamp, 0, 3]), 0);
        l.call(143, &[l.dev, l.cmd, timestamp, 0, 1]);
        l.call(46, &[l.dev, l.cmd, control, 0, 128, 0x12345678]);
        l.call(143, &[l.dev, l.cmd, timestamp, 1, 0x2000]);
        l.call(142, &[l.dev, l.cmd, timestamp, 0, 2, control, 128, 24, 7]);
        l.barrier(0x1000, 0x4000, 0x1000, 0x2000);
        l.submit();
        l.m.write(0x4000, &[0xa5; 80]).unwrap();
        let began = Instant::now();
        assert_eq!(
            l.request(141, &[l.dev, timestamp, 2, 1, 16, 0x4040, 16, 7]),
            1
        );
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(l.word(0x4040), 0xa5a5a5a5a5a5a5a5);
        assert_eq!(l.word(0x4048), 0);
        assert_ne!(
            l.request(141, &[l.dev, timestamp, 0, 2, 16, 0x4000, 24, 5]),
            0
        );
        l.call(141, &[l.dev, timestamp, 0, 2, 48, 0x4000, 24, 5]);
        assert!(l.word(0x4018) >= l.word(0x4000));
        assert_ne!(l.word(0x4008), 0);
        assert_ne!(l.word(0x4020), 0);
        assert_eq!(l.word(0x4010), 0xa5a5a5a5a5a5a5a5);
        assert_eq!(l.word(0x4028), 0xa5a5a5a5a5a5a5a5);
        assert_eq!(l.word(0xa080), l.word(0x4000));
        assert_eq!(l.word(0xa098), l.word(0x4018));
        l.reset();
        l.begin();
        l.call(140, &[l.dev, l.cmd, timestamp, 0, 1]);
        l.call(143, &[l.dev, l.cmd, timestamp, 0, 1]);
        l.call(142, &[l.dev, l.cmd, timestamp, 0, 1, control, 192, 8, 6]);
        l.barrier(0x1000, 0x4000, 0x1000, 0x2000);
        l.call(139, &[l.dev, timestamp]);
        l.submit();
        assert_ne!(l.word(0xa0c0) >> 32, 0);
        println!("native-query-ok: GPU timestamps, 32/64-bit results, availability, NOT_READY polling, stride/tail preservation, GPU copies and deferred pool destruction");
    } else {
        assert_eq!(l.request(138, &[l.dev, 2, 1, OUT]), (-8i64) as u64);
        println!("native-timestamp-unavailable-ok: queue reports zero valid bits; timestamp query creation rejected");
    }
    let mut allocations = vec![(control, control_mem)];
    if feedback {
        l.reset();
        let a = l.buffer(0x803, 0x8000);
        let b = l.buffer(0x803, 0x9000);
        let index = l.buffer(0x42, 0xb000);
        l.m.write(
            0xb000,
            &[4u32, 1, 3]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        allocations.extend([a, b, index]);
        let source = std::fs::read(
            std::env::args()
                .nth(1)
                .expect("feedback vertex SPIR-V path"),
        )
        .unwrap();
        l.m.write(0x5000, &source).unwrap();
        let shader = l.make(21, &[l.dev, 0x5000, source.len() as u64, OUT]);
        let layout = l.make(25, &[l.dev, 0, 0, 0, 0, OUT]);
        let pass = l.make(66, &[l.dev, 0, 0, 0, 0, 0, 0, 0, OUT, 0, 0x6000, 0]);
        let fb = l.make(68, &[l.dev, pass, 0, 8, 8, OUT, 0, 0x6000, 0]);
        l.m.write(0x2800, b"main\0").unwrap();
        l.words(0x6000, &[pass, 0, 0, 0, 0]);
        // Static viewport/scissor, no fragment shader, rasterizer discard.
        l.words(
            0x6100,
            &[
                512,
                0,
                0,
                8f32.to_bits() as u64,
                8f32.to_bits() as u64,
                0,
                1f32.to_bits() as u64,
                0,
                0,
                8,
                8,
            ],
        );
        let pipeline = l.make(
            70,
            &[
                l.dev, layout, shader, 0, 0x2800, 0, 0x6000, OUT, 0, 0, 0, 0, 0, 0, 65536, 0x6100,
            ],
        );
        let query = l.make(138, &[l.dev, 1000028004, 2, OUT]);
        l.begin();
        l.call(140, &[l.dev, l.cmd, query, 0, 2]);
        l.pass(pass, fb, pipeline);
        l.words(0x6200, &[a.0, b.0]);
        l.words(0x6220, &[16, 16]);
        l.words(0x6240, &[144, 48]);
        l.call(146, &[l.dev, l.cmd, 0, 2, 0x6200, 0x6220, 0x6240]);
        l.words(0x6260, &[control, control]);
        l.words(0x6280, &[256, 264]);
        l.call(144, &[l.dev, l.cmd, query, 0, 0, 0, 1]);
        l.call(147, &[l.dev, l.cmd, 0, 0]);
        assert_ne!(
            l.request(146, &[l.dev, l.cmd, 0, 2, 0x6200, 0x6220, 0x6240]),
            0
        );
        l.call(73, &[l.dev, l.cmd, 3, 1, 2, 4]);
        l.call(148, &[l.dev, l.cmd, 0, 2, 0x6260, 0x6280]);
        l.call(145, &[l.dev, l.cmd, query, 0, 0, 0, 1]);
        l.call(72, &[l.dev, l.cmd]);
        l.barrier(0x1000000, 0x1000000, 0x8000000, 0x4000000);
        l.pass(pass, fb, pipeline);
        l.call(144, &[l.dev, l.cmd, query, 1, 0, 0, 1]);
        l.call(147, &[l.dev, l.cmd, 0, 2, 0x6260, 0x6280]);
        l.call(96, &[l.dev, l.cmd, index.0, 0, 1]);
        l.call(97, &[l.dev, l.cmd, 3, 1, 0, 1, 5]);
        l.call(148, &[l.dev, l.cmd, 0, 2, 0x6260, 0x6280]);
        l.call(145, &[l.dev, l.cmd, query, 1, 0, 0, 1]);
        l.call(72, &[l.dev, l.cmd]);
        l.call(142, &[l.dev, l.cmd, query, 0, 2, control, 512, 32, 7]);
        l.barrier(0x1001000, 0x4000, 0xa001000, 0x2000);
        l.submit();
        for (i, (v, instance)) in [(2, 4), (3, 4), (4, 4), (5, 5), (2, 5), (4, 5)]
            .into_iter()
            .enumerate()
        {
            let mut raw = [0; 4];
            for (j, x) in [v as f32, instance as f32, (v * 3 + 1) as f32, 17.]
                .into_iter()
                .enumerate()
            {
                l.m.read(0x8000 + 16 + i as u64 * 24 + 4 + j as u64 * 4, &mut raw)
                    .unwrap();
                assert_eq!(f32::from_le_bytes(raw), x);
            }
            l.m.read(0x9000 + 16 + i as u64 * 8, &mut raw).unwrap();
            assert_eq!(f32::from_le_bytes(raw), (v + 100) as f32);
            l.m.read(0x8000 + 16 + i as u64 * 24, &mut raw).unwrap();
            assert_eq!(raw, [0xa5; 4]);
        }
        assert_eq!(l.word(0xa100) as u32, 144);
        assert_eq!(l.word(0xa108) as u32, 48);
        for offset in [512, 520, 544, 552] {
            assert_eq!(l.word(0xa000 + offset), 3);
        }
        println!("native-feedback-ok: two GPU buffers, interleaved padding, pause/resume counters, indexed vertices, base vertex/instance and query results");
        l.reset();
        l.m.write(0x8000, &[0xa5; 1024]).unwrap();
        l.m.write(0x9000, &[0xa5; 1024]).unwrap();
        l.begin();
        l.call(140, &[l.dev, l.cmd, query, 0, 1]);
        l.pass(pass, fb, pipeline);
        l.words(0x6240, &[48, 16]);
        l.call(146, &[l.dev, l.cmd, 0, 2, 0x6200, 0x6220, 0x6240]);
        l.call(144, &[l.dev, l.cmd, query, 0, 0, 0, 1]);
        l.call(147, &[l.dev, l.cmd, 0, 0]);
        l.call(149, &[l.dev, l.cmd, 1, 7, control, 256, 0, 24]);
        l.call(148, &[l.dev, l.cmd, 0, 2, 0x6260, 0x6280]);
        l.call(145, &[l.dev, l.cmd, query, 0, 0, 0, 1]);
        l.call(72, &[l.dev, l.cmd]);
        l.call(142, &[l.dev, l.cmd, query, 0, 1, control, 512, 24, 7]);
        l.barrier(0x1001000, 0x4000, 0xa001000, 0x2000);
        // No native object may be destroyed while a recorded or queued command uses it.
        for (op, id) in [
            (139, query),
            (28, pipeline),
            (26, layout),
            (22, shader),
            (69, fb),
            (67, pass),
        ] {
            l.call(op, &[l.dev, id]);
        }
        l.submit();
        assert_eq!(l.word(0xa200), 2);
        assert_eq!(l.word(0xa208), 6);
        assert_eq!(l.word(0xa100) as u32, 48);
        assert_eq!(l.word(0xa108) as u32, 16);
        assert_eq!(l.word(0x8040), 0xa5a5a5a5a5a5a5a5);
        assert_eq!(l.word(0x9020), 0xa5a5a5a5a5a5a5a5);
        let mut raw = [0; 4];
        l.m.read(0x8018, &mut raw).unwrap();
        assert_eq!(f32::from_le_bytes(raw), 7.);
        println!("native-feedback-overflow-ok: GPU byte-count indirect draw, bounded output, written/needed primitive counts and deferred dependencies");
    }
    l.reset();
    for (buffer, mem) in allocations {
        l.call(18, &[l.dev, mem]);
        l.call(12, &[l.dev, buffer]);
        l.call(15, &[l.dev, mem]);
    }
    l.call(49, &[l.dev, l.fence]);
    l.call(35, &[l.dev, l.pool]);
    l.call(9, &[l.dev]);
    l.call(2, &[instance]);
}
