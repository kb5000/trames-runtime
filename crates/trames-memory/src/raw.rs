// SPDX-License-Identifier: GPL-3.0-or-later
//! Concurrent guest bytes, never LLVM/Rust references. These copies use ordinary
//! host instructions; no fence, atomics, speculative overread or stronger order.
//! The caller retains both allocations and excludes overlapping Rust borrows.

/// Copy exactly `len` nonoverlapping bytes. Either endpoint may be guest RAM.
///
/// # Safety
/// Both complete ranges are live and initialized; destination is writable. No
/// Rust reference to concurrently modified guest bytes may exist. Host buffers
/// retain their usual Rust ownership. On other architectures the caller must
/// exclude concurrent byte actors (the page guard keeps its hardware gate).
#[inline]
pub(crate) unsafe fn copy(mut source: *const u8, mut destination: *mut u8, len: usize) {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    {
        use core::arch::asm;
        #[cfg(target_arch = "aarch64")]
        let remaining = {
            let blocks = len / 64;
            if blocks != 0 {
                // SAFETY: each iteration touches exactly 64 live bytes. SIMD
                // operands stay inside asm, without references/LLVM race UB.
                // Bulk copies have no atomicity promise; scalar CPU accesses
                // below 64 bytes retain their existing instruction widths.
                unsafe {
                    asm!("2:",
                        "ldp q0, q1, [{source}], #32", "ldp q2, q3, [{source}], #32",
                        "stp q0, q1, [{destination}], #32", "stp q2, q3, [{destination}], #32",
                        "subs {blocks}, {blocks}, #1", "b.ne 2b",
                        source=inout(reg) source, destination=inout(reg) destination,
                        blocks=inout(reg) blocks => _,
                        out("v0") _, out("v1") _, out("v2") _, out("v3") _, options(nostack));
                }
            }
            len % 64
        };
        #[cfg(not(target_arch = "aarch64"))]
        let remaining = len;
        let words = remaining / 8;
        if words != 0 {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                asm!("2:", "ldr {value:x}, [{source}], #8",
                    "str {value:x}, [{destination}], #8", "subs {words}, {words}, #1", "b.ne 2b",
                    source=inout(reg) source, destination=inout(reg) destination,
                    words=inout(reg) words => _, value=out(reg) _, options(nostack));
            }
            #[cfg(target_arch = "x86_64")]
            unsafe {
                asm!("2:", "mov {value}, qword ptr [{source}]", "mov qword ptr [{destination}], {value}",
                    "add {source}, 8", "add {destination}, 8", "dec {words}", "jnz 2b",
                    source=inout(reg) source, destination=inout(reg) destination,
                    words=inout(reg) words => _, value=out(reg) _, options(nostack));
            }
        }
        macro_rules! tail {
            ($width:literal, $arm_load:literal, $arm_store:literal, $x86_load:literal, $x86_store:literal) => {
                if len & $width != 0 {
                    // SAFETY: tails fit exactly; asm has memory effects, no
                    // guest reference, and no assumption about racy values.
                    #[cfg(target_arch = "aarch64")]
                    unsafe { asm!($arm_load, $arm_store,
                        source=in(reg) source, destination=in(reg) destination,
                        value=out(reg) _, options(nostack)); }
                    #[cfg(target_arch = "x86_64")]
                    unsafe { asm!($x86_load, $x86_store,
                        source=in(reg) source, destination=in(reg) destination,
                        value=out(reg) _, options(nostack)); }
                    source=source.wrapping_add($width);
                    destination=destination.wrapping_add($width);
                }
            };
        }
        tail!(
            4,
            "ldr {value:w}, [{source}]",
            "str {value:w}, [{destination}]",
            "mov {value:e}, dword ptr [{source}]",
            "mov dword ptr [{destination}], {value:e}"
        );
        tail!(
            2,
            "ldrh {value:w}, [{source}]",
            "strh {value:w}, [{destination}]",
            "movzx {value:e}, word ptr [{source}]",
            "mov word ptr [{destination}], {value:x}"
        );
        tail!(
            1,
            "ldrb {value:w}, [{source}]",
            "strb {value:w}, [{destination}]",
            "movzx {value:e}, byte ptr [{source}]",
            "mov byte ptr [{destination}], {value:l}"
        );
        let _ = (source, destination);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    unsafe {
        std::ptr::copy_nonoverlapping(source, destination, len);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_copies_preserve_unaligned_ranges_and_neighbors() {
        let source: Vec<u8> = (0..4352).map(|i| (i * 37) as u8).collect();
        for start in 0..16 {
            for out in 0..16 {
                for len in (0..40).chain([63, 64, 65, 127, 255, 256, 257, 4095, 4096]) {
                    let mut destination = vec![0x93; len + 32];
                    unsafe {
                        super::copy(
                            source.as_ptr().add(start),
                            destination.as_mut_ptr().add(out),
                            len,
                        );
                    }
                    assert_eq!(&destination[out..out + len], &source[start..start + len]);
                    assert!(destination[..out]
                        .iter()
                        .chain(&destination[out + len..])
                        .all(|&v| v == 0x93));
                }
            }
        }
    }
}
