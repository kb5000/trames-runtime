// SPDX-License-Identifier: GPL-3.0-or-later
//! Original native driver regression for the new wire operations (also Metal).
use std::{
    cell::RefCell,
    rc::Rc,
    thread,
    time::{Duration, Instant},
};
use trames_memory::{Memory, MemoryError, PageBacking, Permissions, PAGE_SIZE};
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
struct FailedOutput(RefCell<[u8; PAGE_SIZE as usize]>);
impl PageBacking for FailedOutput {
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, at: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        out.copy_from_slice(&self.0.borrow()[at..at + out.len()]);
        Ok(())
    }
    fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::BackingIo(5))
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
// Late-bound images are never framebuffer dependencies. Commands must retain
// them themselves, including the submission snapshot after a pool reset.
fn image(b: &mut Backend, m: &mut Memory, dev: u64, format: u64, usage: u64) -> (u64, u64, u64) {
    m.write(0x3500, &(format as u32).to_le_bytes()).unwrap();
    call(b, m, 60, &[dev, format, 16, 16, usage, OUT, 0, 0x3500, 1]);
    let image = word(m, OUT);
    call(b, m, 62, &[dev, image, 0x2100]);
    let size = word(m, 0x2100);
    let bits = word(m, 0x2110) as u32;
    call(b, m, 14, &[dev, size, bits.trailing_zeros() as u64, OUT]);
    let memory = word(m, OUT);
    call(b, m, 63, &[dev, image, memory, 0]);
    call(b, m, 64, &[dev, image, format, OUT]);
    (image, word(m, OUT), memory)
}
// Exercise the complete attachment array, including a ninth depth attachment,
// both renderpass APIs, late binding, clear indexing and per-view ownership.
fn mrt(b: &mut Backend, m: &mut Memory, resources: [u64; 7]) {
    let [dev, physical, queue, buffer, pool, cmd, fence] = resources;
    call(b, m, 4, &[physical, 0x7000]);
    let offset = std::mem::offset_of!(ash::vk::PhysicalDeviceProperties, limits)
        + std::mem::offset_of!(ash::vk::PhysicalDeviceLimits, max_color_attachments);
    let mut bytes = [0; 4];
    m.read(0x7000 + offset as u64, &mut bytes).unwrap();
    let count = u32::from_le_bytes(bytes).min(8) as usize;
    assert!(count >= 4);
    for rp2 in [false, true] {
        for imageless in [false, true] {
            let mut images: Vec<_> = (0..count).map(|_| image(b, m, dev, 37, 17)).collect();
            images.push(image(b, m, dev, 126, 33));
            let colors: Vec<_> = (0..count).flat_map(|_| [37, 1, 0, 0, 2]).collect();
            words(m, 0x6000, &colors);
            words(m, 0x6200, &[126, 1, 0, 0, 3]);
            let create = [dev, 37, 1, 0, 0, 2, 0, 0, OUT, 0x6200, 0x6000, count as u64];
            let mut bad = create;
            bad[11] = 9;
            assert_eq!(
                request(b, m, if rp2 { 122 } else { 66 }, &bad),
                (-8i64) as u64
            );
            call(b, m, if rp2 { 122 } else { 66 }, &create);
            let pass = word(m, OUT);
            let views: Vec<_> = images.iter().map(|x| x.1).collect();
            words(m, 0x6300, &views);
            if imageless {
                m.write(0x6700, &37u32.to_le_bytes()).unwrap();
                m.write(0x6704, &126u32.to_le_bytes()).unwrap();
                let specs: Vec<_> = (0..=count)
                    .flat_map(|i| {
                        [
                            0,
                            if i == count { 33 } else { 17 },
                            16,
                            16,
                            1,
                            if i == count { 0x6704 } else { 0x6700 },
                            1,
                        ]
                    })
                    .collect();
                words(m, 0x6400, &specs);
                call(
                    b,
                    m,
                    125,
                    &[dev, pass, 16, 16, count as u64 + 1, 0x6400, OUT],
                );
            } else {
                let mut bad = [dev, pass, 0, 16, 16, OUT, 0, 0x6300, count as u64];
                assert_eq!(request(b, m, 68, &bad), (-13i64) as u64);
                bad[8] += 1;
                call(b, m, 68, &bad);
            }
            let fb = word(m, OUT);
            for i in 0..=count {
                let color = if i == count {
                    [0.5f32, 0., 0., 0.]
                } else {
                    [
                        (i & 1) as f32,
                        ((i >> 1) & 1) as f32,
                        ((i >> 2) & 1) as f32,
                        1.,
                    ]
                };
                for (channel, value) in color.into_iter().enumerate() {
                    m.write(
                        0x6800 + i as u64 * 16 + channel as u64 * 4,
                        &value.to_bits().to_le_bytes(),
                    )
                    .unwrap();
                }
            }
            for (i, &(img, view, backing)) in images.iter().enumerate() {
                call(b, m, 38, &[dev, cmd, 0]);
                if i == 0 {
                    let begin = [
                        dev,
                        cmd,
                        pass,
                        fb,
                        0,
                        0,
                        16,
                        16,
                        0x6800,
                        count as u64 + 1,
                        if imageless { 0x6300 } else { 0 },
                        if imageless { count as u64 + 1 } else { 0 },
                    ];
                    let mut bad = begin;
                    bad[9] = count as u64;
                    assert_eq!(
                        request(b, m, if rp2 { 123 } else { 71 }, &bad),
                        (-13i64) as u64
                    );
                    call(b, m, if rp2 { 123 } else { 71 }, &begin);
                    call(b, m, if rp2 { 124 } else { 72 }, &[dev, cmd]);
                }
                let depth = i == count;
                words(
                    m,
                    0x6900,
                    &[
                        img,
                        if depth { 1024 } else { 256 },
                        2048,
                        if depth { 3 } else { 2 },
                        6,
                        if depth { 2 } else { 1 },
                    ],
                );
                call(b, m, 44, &[dev, cmd, 1792, 4096, 0, 0, 0x6900, 1, 6]);
                words(
                    m,
                    0x6a00,
                    &[
                        0,
                        0,
                        0,
                        if depth { 2 } else { 1 },
                        0,
                        0,
                        1,
                        0,
                        0,
                        0,
                        16,
                        16,
                        1,
                    ],
                );
                call(b, m, 74, &[dev, cmd, img, 6, buffer, 0x6a00, 1]);
                call(b, m, 44, &[dev, cmd, 4096, 16384, 4096, 8192, 0, 0, 6]);
                call(b, m, 39, &[dev, cmd]);
                words(m, 0x6b00, &[cmd]);
                words(m, 0x6c00, &[0, 0, 0, 0x6b00, 1, 0, 0]);
                call(b, m, 56, &[dev, queue, 0x6c00, 1, fence]);
                // Both bound and imageless command lifetimes retain these views.
                call(b, m, 65, &[dev, view]);
                call(b, m, 61, &[dev, img]);
                call(b, m, 15, &[dev, backing]);
                poll(b, m, 51, &[dev, fence], 1);
                let mut pixels = [0; 1024];
                m.read(0x4000, &mut pixels).unwrap();
                let expected = if depth {
                    0.5f32.to_le_bytes()
                } else {
                    [
                        if i & 1 != 0 { 255 } else { 0 },
                        if i & 2 != 0 { 255 } else { 0 },
                        if i & 4 != 0 { 255 } else { 0 },
                        255,
                    ]
                };
                assert!(
                    pixels.chunks_exact(4).all(|p| p == expected),
                    "MRT attachment {i}, pass2={rp2}, imageless={imageless}"
                );
                call(b, m, 53, &[dev, pool, 0]);
                call(b, m, 50, &[dev, fence]);
            }
            call(b, m, 69, &[dev, fb]);
            call(b, m, 67, &[dev, pass]);
        }
    }
    println!("native-mrt-ok: {count} colors + depth, legacy/renderpass2, bound/imageless, every GPU pixel and deferred cleanup correct");
}
// Round-trip native texels through a GPU image. Clearing the staging buffer
// between directions prevents a skipped copy from accidentally passing.
fn format_transfers(b: &mut Backend, m: &mut Memory, resources: [u64; 7]) {
    let [dev, physical, queue, buffer, pool, cmd, fence] = resources;
    let mut verified = 0;
    for (format, texel) in [
        (9, 1),
        (16, 2),
        (37, 4),
        (76, 2),
        (83, 4),
        (97, 8),
        (100, 4),
        (103, 8),
        (109, 16),
        (124, 2),
        (126, 4),
    ] {
        call(b, m, 58, &[physical, format, 0x7000]);
        let mut flags = [0; 4];
        m.read(0x7004, &mut flags).unwrap();
        if u32::from_le_bytes(flags) & 0xc000 != 0xc000 {
            continue;
        }
        call(b, m, 60, &[dev, format, 4, 4, 3, OUT]);
        let img = word(m, OUT);
        call(b, m, 62, &[dev, img, 0x7100]);
        let size = word(m, 0x7100);
        let bits = word(m, 0x7110) as u32;
        call(b, m, 14, &[dev, size, bits.trailing_zeros() as u64, OUT]);
        let backing = word(m, OUT);
        call(b, m, 63, &[dev, img, backing, 0]);
        let aspect = if matches!(format, 124 | 126) { 2 } else { 1 };
        call(b, m, 38, &[dev, cmd, 0]);
        call(b, m, 46, &[dev, cmd, buffer, 0, 1024, 0x40404040]);
        words(m, 0x6900, &[img, 0, 4096, 0, 7, aspect]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 4096, 2048, 0x6900, 1, 6]);
        words(m, 0x6a00, &[0, 0, 0, aspect, 0, 0, 1, 0, 0, 0, 4, 4, 1]);
        call(b, m, 94, &[dev, cmd, img, 7, buffer, 0x6a00, 1]);
        words(m, 0x6900, &[img, 4096, 2048, 7, 6, aspect]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 6144, 6144, 0x6900, 1, 6]);
        call(b, m, 46, &[dev, cmd, buffer, 0, 1024, 0]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 4096, 4096, 0, 0, 6]);
        call(b, m, 74, &[dev, cmd, img, 6, buffer, 0x6a00, 1]);
        call(b, m, 44, &[dev, cmd, 4096, 16384, 4096, 8192, 0, 0, 6]);
        call(b, m, 39, &[dev, cmd]);
        words(m, 0x6b00, &[cmd]);
        words(m, 0x6c00, &[0, 0, 0, 0x6b00, 1, 0, 0]);
        call(b, m, 56, &[dev, queue, 0x6c00, 1, fence]);
        call(b, m, 61, &[dev, img]);
        call(b, m, 15, &[dev, backing]);
        poll(b, m, 51, &[dev, fence], 1);
        let mut pixels = [0; 1024];
        m.read(0x4000, &mut pixels).unwrap();
        assert!(
            pixels[..16 * texel].iter().all(|&p| p == 0x40),
            "format {format}"
        );
        assert!(
            pixels[16 * texel..].iter().all(|&p| p == 0),
            "format {format} copy tail"
        );
        call(b, m, 53, &[dev, pool, 0]);
        call(b, m, 50, &[dev, fence]);
        verified += 1;
    }
    assert!(
        verified >= 8,
        "basic native uncompressed color/float/depth transfer coverage"
    );
    println!("native-format-copy-ok: {verified} supported normalized/float/depth formats, exact texels, untouched tails and deferred cleanup correct");
}
// Exercise actual native images, views and subresource transfers with no shader
// or CPU image fallback. The guest can drop every image handle while work runs.
fn subresource_transfers(b: &mut Backend, m: &mut Memory, resources: [u64; 7]) {
    let [dev, physical, queue, buffer, pool, cmd, fence] = resources;
    for (ty, height, depth, layers, flags, view_type) in
        [(0, 1, 1, 3, 0, 4), (1, 4, 1, 12, 16, 5), (2, 4, 4, 1, 0, 2)]
    {
        let usage = if ty == 1 { 23 } else { 7 };
        call(b, m, 59, &[physical, 37, ty, 0, usage, flags, 0x7000]);
        let mut p = [0u8; 32];
        m.read(0x7000, &mut p).unwrap();
        let props: Vec<_> = p[..24]
            .chunks_exact(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .collect();
        assert!(props[3] >= 3 && props[4] >= layers as u32);
        call(
            b,
            m,
            60,
            &[
                dev, 37, 4, height, usage, OUT, 0, 0, 0, flags, ty, depth, 3, layers,
            ],
        );
        let img = word(m, OUT);
        call(b, m, 62, &[dev, img, 0x7100]);
        call(
            b,
            m,
            14,
            &[
                dev,
                word(m, 0x7100),
                (word(m, 0x7110) as u32).trailing_zeros() as u64,
                OUT,
            ],
        );
        let backing = word(m, OUT);
        call(b, m, 63, &[dev, img, backing, 0]);
        words(m, 0x7200, &[1, 1, u32::MAX as u64, 0, u32::MAX as u64]);
        call(b, m, 64, &[dev, img, 37, OUT, 0, view_type, 0, 0x7200]);
        let view = word(m, OUT);
        call(b, m, 65, &[dev, view]);
        if flags == 16 {
            words(m, 0x7200, &[1, 0, 3, 6, 6]);
            call(b, m, 64, &[dev, img, 37, OUT, 0, 3, 0, 0x7200]);
            call(b, m, 65, &[dev, word(m, OUT)]);
            call(b, m, 7, &[physical, 0x7000]);
            let cube_offset =
                std::mem::offset_of!(ash::vk::PhysicalDeviceFeatures, image_cube_array) as u64;
            if word(m, 0x7000 + cube_offset) as u32 != 0 {
                words(m, 0x7200, &[1, 0, 3, 0, 12]);
                call(b, m, 64, &[dev, img, 37, OUT, 0, 6, 0, 0x7200]);
                call(b, m, 65, &[dev, word(m, OUT)]);
            }
            // A normal 2D attachment view can select a single nonzero mip/layer.
            words(m, 0x7200, &[1, 1, 1, 5, 1]);
            call(b, m, 64, &[dev, img, 37, OUT, 0, 1, 0, 0x7200]);
            let view = word(m, OUT);
            call(b, m, 66, &[dev, 37, 1, 0, 0, 2, 0, 0, OUT]);
            let pass = word(m, OUT);
            assert_ne!(request(b, m, 68, &[dev, pass, view, 4, 4, OUT]), 0);
            call(b, m, 68, &[dev, pass, view, 2, 2, OUT]);
            let fb = word(m, OUT);
            call(b, m, 69, &[dev, fb]);
            call(b, m, 67, &[dev, pass]);
            call(b, m, 65, &[dev, view]);
        }
        call(b, m, 38, &[dev, cmd, 0]);
        let slice = 4 * height * 4;
        for i in 0..layers * depth {
            call(
                b,
                m,
                46,
                &[dev, cmd, buffer, i * slice, slice, 0xff112200 + i * 0x101],
            );
        }
        words(m, 0x6900, &[img, 0, 6144, 0, 1, 1, 0, 3, 0, layers]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 4096, 2048, 0x6900, 1, 10]);
        words(
            m,
            0x6a00,
            &[0, 0, 0, 1, 0, 0, layers, 0, 0, 0, 4, height, depth],
        );
        call(b, m, 94, &[dev, cmd, img, 1, buffer, 0x6a00, 1]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 4096, 6144, 0, 0, 10]);
        let layer = if ty == 2 { 0 } else { layers - 1 };
        let z = if ty == 2 { depth - 1 } else { 0 };
        words(
            m,
            0x7300,
            &[1, 0, 0, 1, 0, 0, 0, 1, 0, layer, 1, 0, 0, z, 4, height, 1],
        );
        // Nonoverlapping layers/slices of the same image are legal copies.
        call(b, m, 134, &[dev, cmd, img, 1, img, 1, 0x7300, 1]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 4096, 6144, 0, 0, 10]);
        let half_h = (height / 2).max(1);
        let half_d = (depth / 2).max(1);
        words(
            m,
            0x7400,
            &[
                1, 0, 0, layers, 0, 0, 0, 4, height, depth, 1, 1, 0, layers, 0, 0, 0, 2, half_h,
                half_d,
            ],
        );
        call(b, m, 135, &[dev, cmd, img, 1, img, 1, 0x7400, 1, 0]);
        m.write(
            0x7500,
            &[0f32, 1., 0., 1.]
                .into_iter()
                .flat_map(f32::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        words(m, 0x7600, &[1, 2, u32::MAX as u64, layer, 1]);
        call(b, m, 114, &[dev, cmd, img, 1, 0x7500, 0x7600, 1]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 6144, 6144, 0, 0, 10]);
        call(b, m, 46, &[dev, cmd, buffer, 0, 1024, 0xdddddddd]);
        call(b, m, 44, &[dev, cmd, 4096, 4096, 4096, 4096, 0, 0, 10]);
        call(b, m, 74, &[dev, cmd, img, 1, buffer, 0x6a00, 1]);
        words(
            m,
            0x6a00,
            &[768, 0, 0, 1, 1, 0, layers, 0, 0, 0, 2, half_h, half_d],
        );
        call(b, m, 74, &[dev, cmd, img, 1, buffer, 0x6a00, 1]);
        words(m, 0x6a00, &[1008, 0, 0, 1, 2, layer, 1, 0, 0, 0, 1, 1, 1]);
        call(b, m, 74, &[dev, cmd, img, 1, buffer, 0x6a00, 1]);
        call(b, m, 44, &[dev, cmd, 4096, 16384, 4096, 8192, 0, 0, 10]);
        call(b, m, 39, &[dev, cmd]);
        words(m, 0x6b00, &[cmd]);
        words(m, 0x6c00, &[0, 0, 0, 0x6b00, 1, 0, 0]);
        call(b, m, 56, &[dev, queue, 0x6c00, 1, fence]);
        call(b, m, 61, &[dev, img]);
        call(b, m, 15, &[dev, backing]);
        poll(b, m, 51, &[dev, fence], 1);
        let mut got = [0u8; 1024];
        m.read(0x4000, &mut got).unwrap();
        let mut expected = [0xdd; 1024];
        for i in 0..layers * depth {
            let source = if i == layers * depth - 1 { 0 } else { i };
            let color = (0xff112200u32 + source as u32 * 0x101).to_le_bytes();
            for pixel in
                expected[(i * slice) as usize..((i + 1) * slice) as usize].chunks_exact_mut(4)
            {
                pixel.copy_from_slice(&color);
            }
        }
        let half_slice = 2 * half_h * 4;
        for i in 0..layers * half_d {
            let mut source = if ty == 2 { i * 2 + 1 } else { i };
            if source == layers * depth - 1 {
                source = 0;
            }
            let color = (0xff112200u32 + source as u32 * 0x101).to_le_bytes();
            for pixel in expected
                [768 + (i * half_slice) as usize..768 + ((i + 1) * half_slice) as usize]
                .chunks_exact_mut(4)
            {
                pixel.copy_from_slice(&color);
            }
        }
        expected[1008..1012].copy_from_slice(&[0, 255, 0, 255]);
        assert_eq!(
            got, expected,
            "image type {ty}: base, mip blit, per-layer clear and untouched padding"
        );
        call(b, m, 53, &[dev, pool, 0]);
        call(b, m, 50, &[dev, fence]);
    }
    // Comparison samplers preserve the caller's actual compare operation.
    m.write(
        0x7500,
        &[0f32, 0., 2.]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    call(b, m, 115, &[physical, OUT]);
    let mut comparison = true;
    if word(m, OUT) & 512 != 0 {
        call(b, m, 133, &[physical, 0x7700]);
        comparison = word(m, 0x7718) as u32 != 0;
    }
    if comparison {
        for op in 0..8 {
            call(
                b,
                m,
                92,
                &[dev, 0, 0, 0, 2, 2, 2, 0, 0x7500, OUT, 0, 0, 1, op],
            );
            call(b, m, 93, &[dev, word(m, OUT)]);
        }
    }
    // Depth clearing is native and uses only the specified mip/layer.
    call(b, m, 60, &[dev, 126, 4, 4, 3, OUT, 0, 0, 0, 0, 1, 1, 3, 2]);
    let img = word(m, OUT);
    call(b, m, 62, &[dev, img, 0x7100]);
    call(
        b,
        m,
        14,
        &[
            dev,
            word(m, 0x7100),
            (word(m, 0x7110) as u32).trailing_zeros() as u64,
            OUT,
        ],
    );
    let backing = word(m, OUT);
    call(b, m, 63, &[dev, img, backing, 0]);
    call(b, m, 38, &[dev, cmd, 0]);
    words(m, 0x6900, &[img, 0, 4096, 0, 7, 2, 0, 3, 0, 2]);
    call(b, m, 44, &[dev, cmd, 4096, 4096, 0, 4096, 0x6900, 1, 10]);
    m.write(
        0x7500,
        &[0.25f32.to_bits().to_le_bytes(), 0u32.to_le_bytes()].concat(),
    )
    .unwrap();
    words(m, 0x7600, &[2, 1, 1, 1, 1]);
    call(b, m, 136, &[dev, cmd, img, 7, 0x7500, 0x7600, 1]);
    words(m, 0x6900, &[img, 4096, 2048, 7, 6, 2, 1, 1, 1, 1]);
    call(b, m, 44, &[dev, cmd, 4096, 4096, 0, 0, 0x6900, 1, 10]);
    words(m, 0x6a00, &[0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 2, 2, 1]);
    call(b, m, 74, &[dev, cmd, img, 6, buffer, 0x6a00, 1]);
    call(b, m, 44, &[dev, cmd, 4096, 16384, 4096, 8192, 0, 0, 10]);
    call(b, m, 39, &[dev, cmd]);
    call(b, m, 56, &[dev, queue, 0x6c00, 1, fence]);
    call(b, m, 61, &[dev, img]);
    call(b, m, 15, &[dev, backing]);
    poll(b, m, 51, &[dev, fence], 1);
    let mut got = [0; 16];
    m.read(0x4000, &mut got).unwrap();
    assert!(got.chunks_exact(4).all(|p| p == 0.25f32.to_le_bytes()));
    call(b, m, 53, &[dev, pool, 0]);
    call(b, m, 50, &[dev, fence]);
    println!("native-subresources-ok: 1D/2D arrays, cube views, 3D, mip blits, layer/slice self-copy, partial color/depth clears and exact readback with deferred cleanup");
}
fn volume_slice_attachment(b: &mut Backend, m: &mut Memory, resources: [u64; 7]) {
    let [dev, physical, queue, buffer, pool, cmd, fence] = resources;
    call(b, m, 115, &[physical, OUT]);
    if word(m, OUT) & 512 != 0 {
        call(b, m, 133, &[physical, 0x7700]);
        if word(m, 0x7710) as u32 == 0 {
            println!("native-volume-slice: native portability device does not expose 2D views of 3D images");
            return;
        }
    }
    if request(b, m, 59, &[physical, 37, 2, 0, 19, 32, 0x7000]) != 0 {
        println!("native-volume-slice: native device does not support the selected 3D attachment profile");
        return;
    }
    call(b, m, 60, &[dev, 37, 4, 4, 19, OUT, 0, 0, 0, 32, 2, 4, 3, 1]);
    let img = word(m, OUT);
    call(b, m, 62, &[dev, img, 0x7100]);
    call(
        b,
        m,
        14,
        &[
            dev,
            word(m, 0x7100),
            (word(m, 0x7110) as u32).trailing_zeros() as u64,
            OUT,
        ],
    );
    let backing = word(m, OUT);
    call(b, m, 63, &[dev, img, backing, 0]);
    // Mip 1 is a 2x2x2 volume; render only into slice 1.
    words(m, 0x7200, &[1, 1, 1, 1, 1]);
    call(b, m, 64, &[dev, img, 37, OUT, 0, 1, 0, 0x7200]);
    let view = word(m, OUT);
    words(m, 0x7200, &[1, 1, 1, 0, 2]);
    call(b, m, 64, &[dev, img, 37, OUT, 0, 5, 0, 0x7200]);
    let array_view = word(m, OUT);
    call(b, m, 66, &[dev, 37, 1, 0, 0, 1, 0, 0, OUT]);
    let pass = word(m, OUT);
    call(b, m, 68, &[dev, pass, view, 2, 2, OUT]);
    let fb = word(m, OUT);
    call(b, m, 38, &[dev, cmd, 0]);
    m.write(
        0x7500,
        &[0f32, 0., 1., 1.]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    call(b, m, 71, &[dev, cmd, pass, fb, 0, 0, 2, 2, 0x7500, 1]);
    call(b, m, 72, &[dev, cmd]);
    words(m, 0x6900, &[img, 256, 2048, 1, 6, 1, 1, 1, 0, 1]);
    call(b, m, 44, &[dev, cmd, 1024, 4096, 0, 0, 0x6900, 1, 10]);
    words(m, 0x6a00, &[0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 2, 2, 1]);
    call(b, m, 74, &[dev, cmd, img, 6, buffer, 0x6a00, 1]);
    call(b, m, 44, &[dev, cmd, 4096, 16384, 4096, 8192, 0, 0, 10]);
    call(b, m, 39, &[dev, cmd]);
    words(m, 0x6b00, &[cmd]);
    words(m, 0x6c00, &[0, 0, 0, 0x6b00, 1, 0, 0]);
    call(b, m, 56, &[dev, queue, 0x6c00, 1, fence]);
    for (op, id) in [
        (69, fb),
        (67, pass),
        (65, view),
        (65, array_view),
        (61, img),
        (15, backing),
    ] {
        call(b, m, op, &[dev, id]);
    }
    poll(b, m, 51, &[dev, fence], 1);
    let mut got = [0; 16];
    m.read(0x4000, &mut got).unwrap();
    assert!(got.chunks_exact(4).all(|p| p == [0, 0, 255, 255]));
    call(b, m, 53, &[dev, pool, 0]);
    call(b, m, 50, &[dev, fence]);
    println!("native-volume-slice-ok: 2D/array views of a nonzero 3D mip, attachment rendering and exact selected-slice readback");
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
    assert_eq!(word(&m, OUT) & 248, 248);
    // All dependency extensions but no imageless feature: native guard must
    // reject the operation before touching invalid guest attachment handles.
    call(&mut b, &mut m, 8, &[physical, 0, OUT, 0, 0, 496]);
    let disabled = word(&m, OUT);
    assert_eq!(request(&mut b, &mut m, 125, &[disabled]), (-8i64) as u64);
    call(&mut b, &mut m, 9, &[disabled]);
    call(&mut b, &mut m, 7, &[physical, 0x7000]);
    let cube_offset =
        std::mem::offset_of!(ash::vk::PhysicalDeviceFeatures, image_cube_array) as u64;
    let cube_feature = if word(&m, 0x7000 + cube_offset) as u32 != 0 {
        32
    } else {
        0
    };
    call(
        &mut b,
        &mut m,
        8,
        &[physical, 0, OUT, 0, cube_feature, 1009],
    );
    let dev = word(&m, OUT);
    call(&mut b, &mut m, 10, &[dev, 0, 0, OUT]);
    let queue = word(&m, OUT);
    call(&mut b, &mut m, 11, &[dev, 1024, 3, OUT]);
    let buffer = word(&m, OUT);
    call(&mut b, &mut m, 13, &[dev, buffer, 0x2100]);
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
    call(&mut b, &mut m, 14, &[dev, size, memory_type as u64, OUT]);
    let memory = word(&m, OUT);
    call(&mut b, &mut m, 16, &[dev, buffer, memory, 0]);
    call(&mut b, &mut m, 17, &[dev, memory, 0, 1024, 0x4000]);
    call(&mut b, &mut m, 34, &[dev, 0, 2, OUT]);
    let pool = word(&m, OUT);
    call(&mut b, &mut m, 36, &[dev, pool, OUT]);
    let cmd = word(&m, OUT);
    call(&mut b, &mut m, 48, &[dev, 0, OUT]);
    let fence = word(&m, OUT);
    for depth in [false, true] {
        for rp2 in [false, true] {
            words(&mut m, 0x3400, &[126, 1, 1, 0, 3]);
            call(
                &mut b,
                &mut m,
                if rp2 { 122 } else { 66 },
                &[
                    dev,
                    37,
                    1,
                    0,
                    0,
                    2,
                    0,
                    0,
                    OUT,
                    if depth { 0x3400 } else { 0 },
                ],
            );
            let pass = word(&m, OUT);
            m.write(0x3500, &37u32.to_le_bytes()).unwrap();
            m.write(0x3504, &126u32.to_le_bytes()).unwrap();
            words(
                &mut m,
                0x3300,
                &[0, 17, 16, 16, 1, 0x3500, 1, 0, 32, 16, 16, 1, 0x3504, 1],
            );
            call(
                &mut b,
                &mut m,
                125,
                &[dev, pass, 16, 16, if depth { 2 } else { 1 }, 0x3300, OUT],
            );
            let fb = word(&m, OUT);
            // Exceed the table capacity with post-preflight write failures.
            // Unpublished framebuffer/renderpass objects must be rolled back.
            if depth && rp2 {
                m.map_backed(
                    0xa000,
                    vec![Rc::new(FailedOutput(RefCell::new([0; PAGE_SIZE as usize])))],
                    true,
                    Permissions::RW,
                    false,
                )
                .unwrap();
                for _ in 0..260 {
                    for (op, args) in [
                        (125, vec![dev, pass, 16, 16, 2, 0x3300, 0xa000]),
                        (122, vec![dev, 37, 1, 0, 0, 2, 0, 0, 0xa000]),
                    ] {
                        let mut bytes = [0; 128];
                        for (i, v) in args.iter().enumerate() {
                            bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
                        }
                        m.write(PACKET, &bytes).unwrap();
                        assert_eq!(
                            b.invoke(&mut m, op, PACKET, 128),
                            Err(MemoryError::BackingIo(5))
                        );
                        assert_eq!(word(&m, 0xa000), 0);
                    }
                }
                m.unmap(0xa000, PAGE_SIZE).unwrap();
            }
            for color in [[1f32, 0., 0., 1.], [0., 1., 0., 1.]] {
                let (img, view, backing) = image(&mut b, &mut m, dev, 37, 17);
                let z = depth.then(|| image(&mut b, &mut m, dev, 126, 32));
                call(&mut b, &mut m, 38, &[dev, cmd, 0]);
                words(&mut m, 0x3600, &[view, z.map_or(0, |x| x.1)]);
                for (i, value) in color.iter().chain([0.5f32, 0., 0., 0.].iter()).enumerate() {
                    m.write(0x3700 + i as u64 * 4, &value.to_bits().to_le_bytes())
                        .unwrap();
                }
                // Missing late bindings and overflowing render areas are rejected
                // without changing command state, then the same buffer records.
                let begin = [
                    dev,
                    cmd,
                    pass,
                    fb,
                    0,
                    0,
                    16,
                    16,
                    0x3700,
                    if depth { 2 } else { 1 },
                    0x3600,
                    if depth { 2 } else { 1 },
                ];
                let mut bad = begin;
                bad[11] = 0;
                assert_eq!(
                    request(&mut b, &mut m, if rp2 { 123 } else { 71 }, &bad),
                    (-13i64) as u64
                );
                bad = begin;
                bad[6] = 17;
                assert_eq!(
                    request(&mut b, &mut m, if rp2 { 123 } else { 71 }, &bad),
                    (-13i64) as u64
                );
                call(&mut b, &mut m, if rp2 { 123 } else { 71 }, &begin);
                call(&mut b, &mut m, if rp2 { 124 } else { 72 }, &[dev, cmd]);
                words(&mut m, 0x3800, &[img, 256, 2048, 2, 6, 1]);
                call(
                    &mut b,
                    &mut m,
                    44,
                    &[dev, cmd, 1024, 4096, 0, 0, 0x3800, 1, 6],
                );
                words(&mut m, 0x3900, &[0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 16, 16, 1]);
                call(&mut b, &mut m, 74, &[dev, cmd, img, 6, buffer, 0x3900, 1]);
                call(
                    &mut b,
                    &mut m,
                    44,
                    &[dev, cmd, 4096, 16384, 4096, 8192, 0, 0, 6],
                );
                call(&mut b, &mut m, 39, &[dev, cmd]);
                words(&mut m, 0x3a00, &[cmd]);
                words(&mut m, 0x3b00, &[0, 0, 0, 0x3a00, 1, 0, 0]);
                call(&mut b, &mut m, 56, &[dev, queue, 0x3b00, 1, fence]);
                // Exercise the bridge's deferred cleanup: guest handle removal
                // cannot destroy attachments still owned by native commands.
                call(&mut b, &mut m, 65, &[dev, view]);
                call(&mut b, &mut m, 61, &[dev, img]);
                call(&mut b, &mut m, 15, &[dev, backing]);
                if let Some((img, view, backing)) = z {
                    call(&mut b, &mut m, 65, &[dev, view]);
                    call(&mut b, &mut m, 61, &[dev, img]);
                    call(&mut b, &mut m, 15, &[dev, backing]);
                }
                poll(&mut b, &mut m, 51, &[dev, fence], 1);
                let mut rgba = [0; 1024];
                m.read(0x4000, &mut rgba).unwrap();
                let expected: Vec<_> = color.iter().map(|c| (c * 255.) as u8).collect();
                assert!(rgba.chunks_exact(4).all(|p| p == expected));
                call(&mut b, &mut m, 53, &[dev, pool, 0]);
                call(&mut b, &mut m, 50, &[dev, fence]);
            }
            call(&mut b, &mut m, 69, &[dev, fb]);
            call(&mut b, &mut m, 67, &[dev, pass]);
        }
    }
    mrt(
        &mut b,
        &mut m,
        [dev, physical, queue, buffer, pool, cmd, fence],
    );
    format_transfers(
        &mut b,
        &mut m,
        [dev, physical, queue, buffer, pool, cmd, fence],
    );
    subresource_transfers(
        &mut b,
        &mut m,
        [dev, physical, queue, buffer, pool, cmd, fence],
    );
    volume_slice_attachment(
        &mut b,
        &mut m,
        [dev, physical, queue, buffer, pool, cmd, fence],
    );
    call(&mut b, &mut m, 49, &[dev, fence]);
    call(&mut b, &mut m, 35, &[dev, pool]);
    call(&mut b, &mut m, 18, &[dev, memory]);
    call(&mut b, &mut m, 12, &[dev, buffer]);
    call(&mut b, &mut m, 15, &[dev, memory]);
    call(&mut b, &mut m, 9, &[dev]);
    call(&mut b, &mut m, 2, &[instance]);
    println!("native-renderpass-ok: legacy/renderpass2, imageless rebinding, color/depth, feature/geometry guards, GPU readback and deferred attachment cleanup");
}
