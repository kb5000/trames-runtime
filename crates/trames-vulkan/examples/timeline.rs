// SPDX-License-Identifier: GPL-3.0-or-later
//! Original native driver regression for the new wire operations (also Metal).
use std::{
    thread,
    time::{Duration, Instant},
};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vulkan::{Backend, Invocation};
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
fn main() {
    let mut m = Memory::new(128 << 10);
    m.map(0x1000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
    let mut b = Backend::new();
    call(&mut b, &mut m, 1, &[OUT]);
    let instance = word(&m, OUT);
    m.write(0x2080, &1u32.to_le_bytes()).unwrap();
    call(&mut b, &mut m, 3, &[instance, 0x2080, OUT]);
    let physical = word(&m, OUT);
    call(&mut b, &mut m, 115, &[physical, OUT]);
    assert_eq!(word(&m, OUT) & 7, 7);
    assert!(word(&m, OUT + 8) > 0);
    call(&mut b, &mut m, 121, &[physical, 0x2400]);
    println!(
        "native driver properties: {}",
        String::from_utf8_lossy(&m.read_c_string(0x2404, 256).unwrap())
    );
    call(&mut b, &mut m, 8, &[physical, 0, OUT, 0, 0, 15]);
    let device = word(&m, OUT);
    call(&mut b, &mut m, 10, &[device, 0, 0, OUT]);
    let queue = word(&m, OUT);
    let seed = 1u64 << 40;
    call(&mut b, &mut m, 54, &[device, OUT, 1, seed]);
    let gate = word(&m, OUT);
    call(&mut b, &mut m, 54, &[device, OUT, 1, seed]);
    let finished = word(&m, OUT);
    call(&mut b, &mut m, 117, &[device, gate, OUT]);
    assert_eq!(word(&m, OUT), seed);
    words(&mut m, 0x3300, &[gate]);
    words(&mut m, 0x3310, &[seed + 1]);
    assert_eq!(
        request(&mut b, &mut m, 119, &[device, 0x3300, 0x3310, 1, 0]),
        2
    );
    call(&mut b, &mut m, 11, &[device, 256, 2, OUT]);
    let buffer = word(&m, OUT);
    call(&mut b, &mut m, 13, &[device, buffer, 0x2100]);
    let size = word(&m, 0x2100);
    let bits = word(&m, 0x2110) as u32;
    call(&mut b, &mut m, 5, &[physical, 0x2500]);
    let mut bytes = [0; 4];
    m.read(0x2500, &mut bytes).unwrap();
    let count = u32::from_le_bytes(bytes);
    let memory_type = (0..count)
        .find(|&i| {
            m.read(0x2504 + i as u64 * 8, &mut bytes).unwrap();
            bits & (1 << i) != 0 && u32::from_le_bytes(bytes) & 6 == 6
        })
        .unwrap();
    call(&mut b, &mut m, 14, &[device, size, memory_type as u64, OUT]);
    let memory = word(&m, OUT);
    call(&mut b, &mut m, 16, &[device, buffer, memory, 0]);
    call(&mut b, &mut m, 17, &[device, memory, 0, 256, 0x4000]);
    call(&mut b, &mut m, 34, &[device, 0, 2, OUT]);
    let pool = word(&m, OUT);
    call(&mut b, &mut m, 36, &[device, pool, OUT]);
    let command = word(&m, OUT);
    call(&mut b, &mut m, 38, &[device, command, 0]);
    call(
        &mut b,
        &mut m,
        46,
        &[device, command, buffer, 0, 256, 0xabcdef01],
    );
    call(
        &mut b,
        &mut m,
        44,
        &[device, command, 0x1000, 0x4000, 0x1000, 0x2000, 0, 0, 6],
    );
    call(&mut b, &mut m, 39, &[device, command]);
    call(&mut b, &mut m, 116, &[device, pool, 0]);
    words(&mut m, 0x3320, &[finished]);
    words(&mut m, 0x3330, &[seed + 2]);
    words(&mut m, 0x3340, &[command]);
    m.write(0x3350, &0x1000u32.to_le_bytes()).unwrap();
    words(
        &mut m,
        0x3000,
        &[0x3300, 1, 0x3350, 0x3340, 1, 0x3320, 1, 0x3310, 0x3330],
    );
    let began = Instant::now();
    assert_eq!(
        request(&mut b, &mut m, 120, &[device, queue, 0x3000, 1, 0]),
        1
    );
    assert!(
        began.elapsed() < Duration::from_secs(1),
        "future wait blocked the native worker"
    );
    call(&mut b, &mut m, 118, &[device, gate, seed + 1]);
    call(&mut b, &mut m, 120, &[device, queue, 0x3000, 1, 0]);
    poll(&mut b, &mut m, 119, &[device, 0x3320, 0x3330, 1, 0], 2);
    for i in 0..64 {
        m.read(0x4000 + i * 4, &mut bytes).unwrap();
        assert_eq!(u32::from_le_bytes(bytes), 0xabcdef01);
    }
    call(&mut b, &mut m, 53, &[device, pool, 0]);
    call(&mut b, &mut m, 116, &[device, pool, 0]);
    call(&mut b, &mut m, 48, &[device, 0, OUT]);
    let fence = word(&m, OUT);
    call(&mut b, &mut m, 56, &[device, queue, 0, 0, fence]);
    poll(&mut b, &mut m, 51, &[device, fence], 1);
    call(&mut b, &mut m, 49, &[device, fence]);
    call(&mut b, &mut m, 35, &[device, pool]);
    call(&mut b, &mut m, 55, &[device, gate]);
    call(&mut b, &mut m, 55, &[device, finished]);
    call(&mut b, &mut m, 18, &[device, memory]);
    call(&mut b, &mut m, 12, &[device, buffer]);
    call(&mut b, &mut m, 15, &[device, memory]);
    call(&mut b, &mut m, 9, &[device]);
    call(&mut b, &mut m, 2, &[instance]);
    println!("native-timeline-ok: 64-bit driver counters, nonblocking future wait, real GPU coherent output, reset/trim and retained submission lifetimes");
}
