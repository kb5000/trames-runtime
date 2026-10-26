// SPDX-License-Identifier: GPL-3.0-or-later
//! Original native driver regression for the new wire operations (also Metal).
use std::{
    thread,
    time::{Duration, Instant},
};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vulkan::{Backend, Budget, Invocation};
const PACKET: u64 = 0x1000;
const OUT: u64 = 0x2000;
fn request(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) -> u64 {
    let mut bytes = [0; 128];
    for (i, v) in args.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    m.write(PACKET, &bytes).unwrap();
    match b.invoke(m, op, PACKET, 128).unwrap() {
        Invocation::Complete(value) => value,
        other => panic!("unexpected {other:?}"),
    }
}
fn call(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64]) {
    assert_eq!(request(b, m, op, args), 0, "op {op}");
}
fn word(m: &Memory, at: u64) -> u64 {
    let mut bytes = [0; 8];
    m.read(at, &mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}
fn words(m: &mut Memory, at: u64, values: &[u64]) {
    m.write(
        at,
        &values
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>(),
    )
    .unwrap();
}
fn poll(b: &mut Backend, m: &mut Memory, op: u64, args: &[u64], pending: u64) {
    let began = Instant::now();
    loop {
        let r = request(b, m, op, args);
        if r == 0 {
            break;
        }
        assert_eq!(r, pending);
        assert!(began.elapsed() < Duration::from_secs(10));
        thread::sleep(Duration::from_micros(100));
    }
}

fn buffer(
    b: &mut Backend,
    m: &mut Memory,
    dev: u64,
    physical: u64,
    size: u64,
    usage: u64,
    mapped: u64,
) -> (u64, u64) {
    call(b, m, 11, &[dev, size, usage, OUT]);
    let object = word(m, OUT);
    call(b, m, 13, &[dev, object, 0x2100]);
    let allocation = word(m, 0x2100);
    let bits = word(m, 0x2110) as u32;
    call(b, m, 5, &[physical, 0x2500]);
    let count = word(m, 0x2500) as u32;
    let mut bytes = [0; 4];
    let ty = (0..count)
        .find(|&i| {
            m.read(0x2504 + i as u64 * 8, &mut bytes).unwrap();
            bits & (1 << i) != 0 && u32::from_le_bytes(bytes) & 6 == 6
        })
        .unwrap();
    call(b, m, 14, &[dev, allocation, ty as u64, OUT]);
    let memory = word(m, OUT);
    call(b, m, 16, &[dev, object, memory, 0]);
    call(b, m, 17, &[dev, memory, 0, size, mapped]);
    (object, memory)
}
fn compile(b: &mut Backend, m: &mut Memory, args: &[u64]) -> u64 {
    let mut packet = [0; 128];
    for (i, v) in args.iter().enumerate() {
        packet[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    m.write(PACKET, &packet).unwrap();
    let Invocation::Pending(job) = b.invoke(m, 27, PACKET, 128).unwrap() else {
        panic!("expected compiler job")
    };
    let began = Instant::now();
    loop {
        if let Some(result) = b.poll(m, job).unwrap() {
            assert_eq!(result, 0);
            break;
        }
        assert!(began.elapsed() < Duration::from_secs(30));
        thread::sleep(Duration::from_millis(1));
    }
    word(m, OUT)
}
fn main() {
    let code = std::fs::read(
        std::env::args()
            .nth(1)
            .expect("provide vulkan-resources.spv"),
    )
    .unwrap();
    assert!(code.len() < 8192);
    let mut m = Memory::new(2 << 20);
    m.map(0x1000, 256 * PAGE_SIZE, Permissions::RW).unwrap();
    let budget = Budget::default();
    let mut b = Backend::with_budget(budget.clone());
    call(&mut b, &mut m, 1, &[OUT]);
    let instance = word(&m, OUT);
    m.write(0x2080, &1u32.to_le_bytes()).unwrap();
    call(&mut b, &mut m, 3, &[instance, 0x2080, OUT]);
    let physical = word(&m, OUT);
    call(&mut b, &mut m, 115, &[physical, OUT]);
    assert_ne!(word(&m, OUT) & 256, 0);
    call(&mut b, &mut m, 4, &[physical, 0x5000]);
    println!(
        "resource driver: {}",
        String::from_utf8_lossy(&m.read_c_string(0x5014, 256).unwrap())
    );
    assert_eq!(
        request(&mut b, &mut m, 8, &[physical, 0, OUT, 0, 0, 2048]),
        (-8i64) as u64
    );
    call(&mut b, &mut m, 8, &[physical, 0, OUT, 0, 0, 3152]);
    let dev = word(&m, OUT);
    call(&mut b, &mut m, 10, &[dev, 0, 0, OUT]);
    let queue = word(&m, OUT);
    // All supported native drivers in this harness permit 256-byte dynamic UBO offsets.
    let (src, _) = buffer(&mut b, &mut m, dev, physical, 256, 4, 0x8000);
    let (dst, _) = buffer(&mut b, &mut m, dev, physical, 256, 8, 0x9000);
    let (uniform, _) = buffer(&mut b, &mut m, dev, physical, 272, 16, 0xa000);
    let (packed, _) = buffer(&mut b, &mut m, dev, physical, 20, 32, 0xc000);
    let (readback, _) = buffer(&mut b, &mut m, dev, physical, 256, 2, 0xd000);
    for i in 0..64 {
        m.write(0x8000 + i * 4, &((i * 7) as u32).to_le_bytes())
            .unwrap();
    }
    m.write(0xa000, &7u32.to_le_bytes()).unwrap();
    for i in 0..4 {
        m.write(0xc000 + i * 4, &((i + 1) as f32).to_bits().to_le_bytes())
            .unwrap();
    }
    m.write(0xc010, &5u32.to_le_bytes()).unwrap();
    assert_eq!(
        request(&mut b, &mut m, 127, &[dev, src, 98, 1, 256, OUT]),
        (-13i64) as u64
    );
    call(&mut b, &mut m, 127, &[dev, src, 98, 0, 256, OUT]);
    let source_view = word(&m, OUT);
    call(&mut b, &mut m, 127, &[dev, dst, 98, 0, 256, OUT]);
    let output_view = word(&m, OUT);
    m.write(0x3a40, &37u32.to_le_bytes()).unwrap();
    m.write(0x3a44, &43u32.to_le_bytes()).unwrap();
    call(
        &mut b,
        &mut m,
        60,
        &[dev, 37, 8, 8, 9, OUT, 0, 0x3a40, 2, 0x108],
    );
    let image = word(&m, OUT);
    call(&mut b, &mut m, 62, &[dev, image, 0x2100]);
    let size = word(&m, 0x2100);
    let bits = word(&m, 0x2110) as u32;
    call(
        &mut b,
        &mut m,
        14,
        &[dev, size, bits.trailing_zeros() as u64, OUT],
    );
    let image_memory = word(&m, OUT);
    call(&mut b, &mut m, 63, &[dev, image, image_memory, 0]);
    call(&mut b, &mut m, 64, &[dev, image, 37, OUT, 8, 1, 0x6543]);
    let image_view = word(&m, OUT);
    let types = [4u64, 5, 8, 3, 7];
    let bindings: Vec<_> = types
        .iter()
        .enumerate()
        .flat_map(|(i, t)| [i as u64, *t, 1, 0x3f])
        .collect();
    words(&mut m, 0x3000, &bindings);
    call(&mut b, &mut m, 23, &[dev, 0x3000, 5, OUT]);
    let set_layout = word(&m, OUT);
    words(&mut m, 0x3100, &[set_layout]);
    words(&mut m, 0x3110, &[0x1f, 0, 16]);
    call(&mut b, &mut m, 25, &[dev, 0x3100, 1, 0x3110, 1, OUT]);
    let layout = word(&m, OUT);
    m.write(0x6000, &code).unwrap();
    call(&mut b, &mut m, 21, &[dev, 0x6000, code.len() as u64, OUT]);
    let shader = word(&m, OUT);
    m.write(0x3900, b"main\0").unwrap();
    call(&mut b, &mut m, 112, &[dev, OUT]);
    let cache = word(&m, OUT);
    let pipeline = compile(
        &mut b,
        &mut m,
        &[dev, layout, shader, 0x3900, OUT, 0, 0, 0, 0, cache],
    );
    call(&mut b, &mut m, 130, &[dev, cache, 0x2100, 0]);
    let size = word(&m, 0x2100);
    assert!(size > 1 && size < 512 * 1024);
    m.write(0x2100, &1u64.to_le_bytes()).unwrap();
    m.write(0x2400, &[0xa5, 0xa5]).unwrap();
    assert_eq!(
        request(&mut b, &mut m, 130, &[dev, cache, 0x2100, 0x2400]),
        5
    );
    assert!(word(&m, 0x2100) <= 1);
    let mut canary = [0; 1];
    m.read(0x2401, &mut canary).unwrap();
    assert_eq!(canary, [0xa5]);
    m.write(0x2100, &size.to_le_bytes()).unwrap();
    call(&mut b, &mut m, 130, &[dev, cache, 0x2100, 0x20000]);
    let cache_bytes = word(&m, 0x2100);
    call(&mut b, &mut m, 112, &[dev, OUT, 0x20000, cache_bytes]);
    let restored = word(&m, OUT);
    words(&mut m, 0x3120, &[cache]);
    call(&mut b, &mut m, 131, &[dev, restored, 1, 0x3120]);
    call(&mut b, &mut m, 113, &[dev, restored]);
    let pool_sizes: Vec<_> = types.iter().flat_map(|t| [*t, 1]).collect();
    words(&mut m, 0x3500, &pool_sizes);
    call(&mut b, &mut m, 29, &[dev, 0x3500, 5, 500, 1, OUT]);
    let pool = word(&m, OUT);
    call(&mut b, &mut m, 34, &[dev, 0, 2, OUT]);
    let commands = word(&m, OUT);
    call(&mut b, &mut m, 36, &[dev, commands, OUT]);
    let cmd = word(&m, OUT);
    call(&mut b, &mut m, 48, &[dev, 0, OUT]);
    let fence = word(&m, OUT);
    for round in 0..2u32 {
        m.write(0xa100, &((round + 1) * 100).to_le_bytes()).unwrap();
        call(&mut b, &mut m, 31, &[dev, pool, 0x3100, 1, OUT]);
        let set = word(&m, OUT);
        let records = [
            [source_view, 0, 0],
            [output_view, 0, 0],
            [uniform, 0, 16],
            [0, image_view, 1],
            [packed, 0, 20],
        ];
        for (i, (ty, record)) in types.iter().zip(records).enumerate() {
            words(&mut m, 0x3700, &record);
            call(&mut b, &mut m, 33, &[dev, set, i as u64, 0, 1, *ty, 0x3700]);
        }
        call(&mut b, &mut m, 38, &[dev, cmd, 0]);
        words(&mut m, 0x3800, &[image, 0, 64, 0, 1, 1]);
        call(
            &mut b,
            &mut m,
            44,
            &[dev, cmd, 1, 2048, 0, 0, 0x3800, 1, 6, 1],
        );
        call(&mut b, &mut m, 41, &[dev, cmd, pipeline, 1]);
        words(&mut m, 0x3200, &[set]);
        m.write(0x3300, &512u32.to_le_bytes()).unwrap();
        assert_eq!(
            request(
                &mut b,
                &mut m,
                42,
                &[dev, cmd, layout, 0, 0x3200, 1, 0, 0x3300, 1]
            ),
            (-13i64) as u64
        );
        m.write(0x3300, &256u32.to_le_bytes()).unwrap();
        call(
            &mut b,
            &mut m,
            42,
            &[dev, cmd, layout, 0, 0x3200, 1, 0, 0x3300, 1],
        );
        call(&mut b, &mut m, 43, &[dev, cmd, 64, 1, 1]);
        words(&mut m, 0x3800, &[image, 64, 2048, 1, 6, 1]);
        call(
            &mut b,
            &mut m,
            44,
            &[dev, cmd, 2048, 4096, 0, 0, 0x3800, 1, 6],
        );
        words(&mut m, 0x3b00, &[0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 8, 8, 1]);
        call(
            &mut b,
            &mut m,
            74,
            &[dev, cmd, image, 6, readback, 0x3b00, 1],
        );
        call(
            &mut b,
            &mut m,
            44,
            &[dev, cmd, 6144, 16384, 4160, 8192, 0, 0, 6],
        );
        call(&mut b, &mut m, 39, &[dev, cmd]);
        words(&mut m, 0x3c00, &[cmd]);
        words(&mut m, 0x3d00, &[0, 0, 0, 0x3c00, 1, 0, 0]);
        call(&mut b, &mut m, 56, &[dev, queue, 0x3d00, 1, fence]);
        poll(&mut b, &mut m, 51, &[dev, fence], 1);
        let mut ints = [0; 256];
        let mut rgba = [0; 256];
        m.read(0x9000, &mut ints).unwrap();
        m.read(0xd000, &mut rgba).unwrap();
        for i in 0..64 {
            let expected = i as u32 * 7 + (round + 1) * 100 + 15;
            assert_eq!(
                u32::from_le_bytes(ints[i * 4..i * 4 + 4].try_into().unwrap()),
                expected
            );
            let p = &rgba[i * 4..i * 4 + 4];
            assert_eq!(p[0], (expected & 255) as u8);
            assert!(p[1].abs_diff(64) <= 1 && p[2].abs_diff(191) <= 1 && p[3] == 255);
        }
        call(&mut b, &mut m, 129, &[dev, pool, 0]);
        assert_eq!(
            request(&mut b, &mut m, 33, &[dev, set, 0, 0, 1, 4, 0x3700]),
            (-13i64) as u64
        );
        call(&mut b, &mut m, 53, &[dev, commands, 0]);
        call(&mut b, &mut m, 50, &[dev, fence]);
    }
    call(&mut b, &mut m, 9, &[dev]);
    assert_eq!(budget.used(), 0);
    call(&mut b, &mut m, 2, &[instance]);
    println!("native-resources-ok: dynamic offsets, texel read/write, scalar vec3 at offset4, storage image, pipeline cache roundtrip, descriptor pool reset/reuse and 256 GPU results correct; budget released");
}
