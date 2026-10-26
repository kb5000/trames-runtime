// SPDX-License-Identifier: GPL-3.0-or-later
//! Signed-in pure host routines. No guest addresses, runtime code or host state.
pub mod allocator;
pub mod parse;
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/memcpy.s")),
    options(raw)
);
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/memset.s")),
    options(raw)
);
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn trames_native_memcpy(dst: *mut u8, src: *const u8, len: usize) -> *mut u8;
    fn trames_native_memset(dst: *mut u8, value: i32, len: usize) -> *mut u8;
}
pub fn copy(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Rust slices validate both complete allocations and enforce no alias.
    // The original Arm memcpy touches only this range and preserves the C ABI.
    unsafe {
        trames_native_memcpy(dst.as_mut_ptr(), src.as_ptr(), dst.len());
    }
    #[cfg(not(target_arch = "aarch64"))]
    dst.copy_from_slice(src);
}
pub fn fill(dst: &mut [u8], value: u8) {
    #[cfg(target_arch = "aarch64")]
    // SAFETY: The complete exclusive slice is valid. Upstream checks DCZID before
    // its bounded zeroing path; writes remain within the supplied allocation.
    unsafe {
        trames_native_memset(dst.as_mut_ptr(), value.into(), dst.len());
    }
    #[cfg(not(target_arch = "aarch64"))]
    dst.fill(value);
}
/// musl memchr's HASZERO scan, on a checked slice rather than a guest pointer.
pub fn first_byte(bytes: &[u8], byte: u8) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        let mut offset = 0;
        while offset + 16 <= bytes.len() {
            // SAFETY: AArch64 baseline NEON; the unaligned load stays entirely
            // inside this checked slice. No pointer or vector escapes the call.
            let found = unsafe {
                use core::arch::aarch64::*;
                vmaxvq_u8(vceqq_u8(
                    vld1q_u8(bytes.as_ptr().add(offset)),
                    vdupq_n_u8(byte),
                )) != 0
            };
            if found {
                return bytes[offset..offset + 16]
                    .iter()
                    .position(|&b| b == byte)
                    .map(|i| offset + i);
            }
            offset += 16;
        }
        bytes[offset..]
            .iter()
            .position(|&b| b == byte)
            .map(|i| offset + i)
    }
    #[cfg(not(target_arch = "aarch64"))]
    let repeated = u64::from_ne_bytes([byte; 8]);
    #[cfg(not(target_arch = "aarch64"))]
    {
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            let value = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ repeated;
            if value.wrapping_sub(0x0101_0101_0101_0101) & !value & 0x8080_8080_8080_8080 != 0 {
                return chunk.iter().position(|&b| b == byte).map(|n| i * 8 + n);
            }
        }
        let offset = bytes.len() / 8 * 8;
        bytes[offset..]
            .iter()
            .position(|&b| b == byte)
            .map(|n| offset + n)
    }
}

/// Reverse bounded search, with word skips and exact unsigned-byte matching.
pub fn last_byte(bytes: &[u8], byte: u8) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        let mut end = bytes.len();
        while end >= 16 {
            // SAFETY: Baseline NEON and a complete checked 16-byte slice.
            let found = unsafe {
                use core::arch::aarch64::*;
                vmaxvq_u8(vceqq_u8(
                    vld1q_u8(bytes.as_ptr().add(end - 16)),
                    vdupq_n_u8(byte),
                )) != 0
            };
            if found {
                return bytes[end - 16..end]
                    .iter()
                    .rposition(|&b| b == byte)
                    .map(|i| end - 16 + i);
            }
            end -= 16;
        }
        bytes[..end].iter().rposition(|&b| b == byte)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let repeated = u64::from_ne_bytes([byte; 8]);
        let mut end = bytes.len();
        while end >= 8 {
            let chunk = &bytes[end - 8..end];
            let value = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ repeated;
            if value.wrapping_sub(0x0101_0101_0101_0101) & !value & 0x8080_8080_8080_8080 != 0 {
                return chunk.iter().rposition(|&b| b == byte).map(|n| end - 8 + n);
            }
            end -= 8;
        }
        bytes[..end].iter().rposition(|&b| b == byte)
    }
}

/// Compare string fragments, returning None when both need another page.
pub fn compare_strings(left: &[u8], right: &[u8]) -> Option<i32> {
    assert_eq!(left.len(), right.len());
    let mut offset = 0;
    #[cfg(target_arch = "aarch64")]
    while offset + 16 <= left.len() {
        // SAFETY: Both equal-length slices contain the full unaligned vector;
        // equality and zero reductions return only values, retaining no pointer.
        let stop = unsafe {
            use core::arch::aarch64::*;
            let a = vld1q_u8(left.as_ptr().add(offset));
            let b = vld1q_u8(right.as_ptr().add(offset));
            vminvq_u8(vceqq_u8(a, b)) != 255 || vminvq_u8(a) == 0
        };
        if stop {
            break;
        }
        offset += 16;
    }
    #[cfg(not(target_arch = "aarch64"))]
    while offset + 8 <= left.len() {
        let a = u64::from_ne_bytes(left[offset..offset + 8].try_into().unwrap());
        let b = u64::from_ne_bytes(right[offset..offset + 8].try_into().unwrap());
        if a != b || a.wrapping_sub(0x0101_0101_0101_0101) & !a & 0x8080_8080_8080_8080 != 0 {
            break;
        }
        offset += 8;
    }
    for (&a, &b) in left[offset..].iter().zip(&right[offset..]) {
        if a != b || a == 0 {
            return Some(i32::from(a) - i32::from(b));
        }
    }
    None
}

/// Safe translation of pinned musl memcmp.c; unsigned-byte result, no host errno.
pub fn compare(left: &[u8], right: &[u8]) -> i32 {
    assert_eq!(left.len(), right.len());
    let mut offset = 0;
    #[cfg(target_arch = "aarch64")]
    while offset + 16 <= left.len() {
        // SAFETY: Complete checked vectors on baseline AArch64 NEON.
        let equal = unsafe {
            use core::arch::aarch64::*;
            vminvq_u8(vceqq_u8(
                vld1q_u8(left.as_ptr().add(offset)),
                vld1q_u8(right.as_ptr().add(offset)),
            )) == 255
        };
        if !equal {
            break;
        }
        offset += 16;
    }
    #[cfg(not(target_arch = "aarch64"))]
    while offset + 8 <= left.len() && left[offset..offset + 8] == right[offset..offset + 8] {
        offset += 8;
    }
    for (&a, &b) in left[offset..].iter().zip(&right[offset..]) {
        if a != b {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
/// Pinned musl strlen.c's HASZERO word algorithm on a validated bounded slice.
pub fn first_zero(bytes: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    {
        first_byte(bytes, 0)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        const ONES: u64 = u64::MAX / 255;
        const HIGHS: u64 = ONES * 128;
        let mut words = bytes.chunks_exact(8);
        for (index, word) in words.by_ref().enumerate() {
            let value = u64::from_ne_bytes(word.try_into().unwrap());
            if value.wrapping_sub(ONES) & !value & HIGHS != 0 {
                return word.iter().position(|&b| b == 0).map(|i| index * 8 + i);
            }
        }
        words
            .remainder()
            .iter()
            .position(|&b| b == 0)
            .map(|i| bytes.len() / 8 * 8 + i)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn word_search_and_string_compare_match_unsigned_byte_references() {
        for byte in 0..=255 {
            for len in 0usize..=80 {
                let mut bytes: Vec<_> = (0..len).map(|i| (i * 13 + 1) as u8).collect();
                for position in [0, len / 2, len.saturating_sub(1)] {
                    if len != 0 {
                        bytes[position] = byte;
                    }
                    assert_eq!(
                        first_byte(&bytes, byte),
                        bytes.iter().position(|&b| b == byte)
                    );
                    assert_eq!(
                        last_byte(&bytes, byte),
                        bytes.iter().rposition(|&b| b == byte)
                    );
                }
            }
        }
        for position in 0..80 {
            let mut a = [0xff; 80];
            let mut b = a;
            b[position] = 1;
            assert_eq!(compare_strings(&a, &b), Some(254));
            assert_eq!(compare_strings(&b, &a), Some(-254));
            a[position] = 0;
            b[position] = 0;
            if position + 1 < 80 {
                b[position + 1] = 17;
            }
            assert_eq!(compare_strings(&a, &b), Some(0));
        }
        assert_eq!(compare_strings(&[1; 64], &[1; 64]), None);
    }
    #[test]
    fn original_arm_routines_preserve_canaries_for_every_length_and_alignment() {
        for len in (0usize..260).chain([511, 512, 4095, 4096, 65536]) {
            for align in 0..16 {
                let src: Vec<_> = (0..len + 32)
                    .map(|i| (i.wrapping_mul(73) % 255 + 1) as u8)
                    .collect();
                let mut dst = vec![0xac; len + 32];
                copy(
                    &mut dst[align..align + len],
                    &src[15 - align..15 - align + len],
                );
                assert_eq!(&dst[align..align + len], &src[15 - align..15 - align + len]);
                assert!(dst[..align]
                    .iter()
                    .chain(&dst[align + len..])
                    .all(|&b| b == 0xac));
                for value in [0, 0x80, 255] {
                    dst.fill(0xac);
                    fill(&mut dst[align..align + len], value);
                    assert!(dst[align..align + len].iter().all(|&b| b == value));
                    assert!(dst[..align]
                        .iter()
                        .chain(&dst[align + len..])
                        .all(|&b| b == 0xac));
                }
                assert_eq!(first_zero(&src), None);
                assert_eq!(compare(&src, &src), 0);
            }
        }
        for index in 0..64 {
            let mut bytes = [0x80; 64];
            bytes[index] = 0;
            assert_eq!(first_zero(&bytes), Some(index));
        }
        assert_eq!(compare(&[255], &[1]), 254);
    }
}
