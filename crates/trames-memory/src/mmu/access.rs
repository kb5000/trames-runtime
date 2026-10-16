// SPDX-License-Identifier: GPL-3.0-or-later
//! Inlined native operands and a signed-in linker fixup table. Faults resume
//! inside the SAME asm block; no Rust stack frame, guard or destructor is skipped.
use core::arch::asm;

#[cfg(target_vendor = "apple")]
macro_rules! table { () => { ".pushsection __DATA,__trames_mmu,regular,no_dead_strip\n.p2align 3\n.quad 2b, 3b\n.popsection" }; }
#[cfg(not(target_vendor = "apple"))]
macro_rules! table {
    () => {
        ".pushsection trames_mmu_fixups,\"awR\"\n.p2align 3\n.quad 2b, 3b\n.popsection"
    };
}
#[used]
#[cfg_attr(target_vendor = "apple", unsafe(link_section = "__DATA,__trames_mmu"))]
#[cfg_attr(
    not(target_vendor = "apple"),
    unsafe(link_section = "trames_mmu_fixups")
)]
static SENTINEL: [usize; 2] = [0; 2];
unsafe extern "C" {
    #[cfg_attr(
        target_vendor = "apple",
        link_name = "\u{1}section$start$__DATA$__trames_mmu"
    )]
    #[cfg_attr(not(target_vendor = "apple"), link_name = "__start_trames_mmu_fixups")]
    static START: u8;
    #[cfg_attr(
        target_vendor = "apple",
        link_name = "\u{1}section$end$__DATA$__trames_mmu"
    )]
    #[cfg_attr(not(target_vendor = "apple"), link_name = "__stop_trames_mmu_fixups")]
    static END: u8;
}
pub(super) fn recovery(pc: usize) -> Option<usize> {
    let begin = (&raw const START) as usize;
    let end = (&raw const END) as usize;
    if end < begin || !(end - begin).is_multiple_of(16) {
        return None;
    }
    // SAFETY: linker-defined, aligned pairs of native addresses, immutable after
    // loader relocation. The sentinel ensures the section always exists.
    let entries =
        unsafe { std::slice::from_raw_parts(begin as *const [usize; 2], (end - begin) / 16) };
    entries
        .iter()
        .find_map(|entry| (entry[0] == pc && pc != 0).then_some(entry[1]))
}

#[cfg(target_arch = "aarch64")]
macro_rules! read_scalar { ($instruction:literal,$target:ident) => {{
    let value:u64; let ok:u32;
    // SAFETY: caller validates the complete, registered hardware-page-contained
    // operand. The failure label initializes ALL output registers.
    unsafe { asm!(concat!("2: ", $instruction, "\nmov {ok:w}, #1\nb 4f\n3: mov {value:x}, #0\nmov {ok:w}, #0\n4:\n",table!()),
        pointer=in(reg) $target, value=lateout(reg) value, ok=lateout(reg) ok, options(nostack,readonly)); }
    (ok!=0,value)
}}; }
#[cfg(target_arch = "x86_64")]
macro_rules! read_scalar { ($instruction:literal,$target:ident) => {{
    let value:u64; let ok:u32;
    // SAFETY: same bounded operand and local fixup invariant as AArch64.
    unsafe { asm!(concat!("2: ",$instruction,"\nmov {ok:e}, 1\njmp 4f\n3: xor {value:e}, {value:e}\nxor {ok:e}, {ok:e}\n4:\n",table!()),
        pointer=in(reg) $target, value=lateout(reg) value, ok=lateout(reg) ok, options(nostack,readonly)); }
    (ok!=0,value)
}}; }
#[cfg(target_arch = "aarch64")]
macro_rules! write_scalar { ($instruction:literal,$target:ident,$value:ident) => {{
    let ok:u32;
    // SAFETY: caller owns a complete, host-page-contained store; only this
    // instruction can fault. No Rust reference is manufactured at the target.
    unsafe { asm!(concat!("2: ",$instruction,"\nmov {ok:w}, #1\nb 4f\n3: mov {ok:w}, #0\n4:\n",table!()),
        pointer=in(reg) $target,value=in(reg) $value,ok=lateout(reg) ok,options(nostack)); }
    ok!=0
}}; }
#[cfg(target_arch = "x86_64")]
macro_rules! write_scalar { ($instruction:literal,$target:ident,$value:ident) => {{
    let ok:u32;
    // SAFETY: same contained store and fixed recovery site as AArch64.
    unsafe { asm!(concat!("2: ",$instruction,"\nmov {ok:e}, 1\njmp 4f\n3: xor {ok:e}, {ok:e}\n4:\n",table!()),
        pointer=in(reg) $target,value=in(reg) $value,ok=lateout(reg) ok,options(nostack)); }
    ok!=0
}}; }
#[inline(always)]
pub(crate) unsafe fn access<const N: usize>(write: bool, target: *mut u8, bytes: *mut u8) -> bool {
    if N == 16 {
        // SAFETY: caller provides a complete 16-byte host buffer and a target
        // wholly within one registered hardware page, with its lifetime guard.
        return unsafe { vector(write, target, bytes) };
    }
    if !matches!(N, 1 | 2 | 4 | 8) {
        return false;
    }
    if write {
        let mut input = [0; 8];
        // SAFETY: the input buffer contains N bytes and input has room for N.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes, input.as_mut_ptr(), N);
        }
        let value = u64::from_le_bytes(input);
        #[cfg(target_arch = "aarch64")]
        return match N {
            1 => write_scalar!("strb {value:w}, [{pointer}]", target, value),
            2 => write_scalar!("strh {value:w}, [{pointer}]", target, value),
            4 => write_scalar!("str {value:w}, [{pointer}]", target, value),
            _ => write_scalar!("str {value:x}, [{pointer}]", target, value),
        };
        #[cfg(target_arch = "x86_64")]
        return match N {
            1 => write_scalar!("mov byte ptr [{pointer}], {value:l}", target, value),
            2 => write_scalar!("mov word ptr [{pointer}], {value:x}", target, value),
            4 => write_scalar!("mov dword ptr [{pointer}], {value:e}", target, value),
            _ => write_scalar!("mov qword ptr [{pointer}], {value:r}", target, value),
        };
    }
    #[cfg(target_arch = "aarch64")]
    let (ok, value) = match N {
        1 => read_scalar!("ldrb {value:w}, [{pointer}]", target),
        2 => read_scalar!("ldrh {value:w}, [{pointer}]", target),
        4 => read_scalar!("ldr {value:w}, [{pointer}]", target),
        _ => read_scalar!("ldr {value:x}, [{pointer}]", target),
    };
    #[cfg(target_arch = "x86_64")]
    let (ok, value) = match N {
        1 => read_scalar!("movzx {value:e}, byte ptr [{pointer}]", target),
        2 => read_scalar!("movzx {value:e}, word ptr [{pointer}]", target),
        4 => read_scalar!("mov {value:e}, dword ptr [{pointer}]", target),
        _ => read_scalar!("mov {value:r}, qword ptr [{pointer}]", target),
    };
    if ok {
        // SAFETY: output is written only after a successful complete load.
        unsafe {
            std::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), bytes, N);
        }
    }
    ok
}
#[inline(always)]
unsafe fn vector(write: bool, target: *mut u8, bytes: *mut u8) -> bool {
    let ok: u32;
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::uint8x16_t;
        if write {
            // SAFETY: the trusted Rust buffer has a complete unaligned vector.
            let value = unsafe { std::ptr::read_unaligned(bytes.cast::<uint8x16_t>()) };
            unsafe {
                asm!(concat!("2: str {value:q}, [{pointer}]\nmov {ok:w}, #1\nb 4f\n3: mov {ok:w}, #0\n4:\n",table!()),
                pointer=in(reg) target,value=in(vreg) value,ok=lateout(reg) ok,options(nostack));
            }
        } else {
            let value: uint8x16_t;
            unsafe {
                asm!(concat!("2: ldr {value:q}, [{pointer}]\nmov {ok:w}, #1\nb 4f\n3: movi {value:v}.16b, #0\nmov {ok:w}, #0\n4:\n",table!()),
                pointer=in(reg) target,value=lateout(vreg) value,ok=lateout(reg) ok,options(nostack,readonly));
            }
            if ok != 0 {
                unsafe {
                    std::ptr::write_unaligned(bytes.cast::<uint8x16_t>(), value);
                }
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__m128i;
        if write {
            let value = unsafe { std::ptr::read_unaligned(bytes.cast::<__m128i>()) };
            unsafe {
                asm!(concat!("2: movdqu xmmword ptr [{pointer}], {value}\nmov {ok:e}, 1\njmp 4f\n3: xor {ok:e}, {ok:e}\n4:\n",table!()),
                pointer=in(reg) target,value=in(xmm_reg) value,ok=lateout(reg) ok,options(nostack));
            }
        } else {
            let value: __m128i;
            unsafe {
                asm!(concat!("2: movdqu {value}, xmmword ptr [{pointer}]\nmov {ok:e}, 1\njmp 4f\n3: pxor {value}, {value}\nxor {ok:e}, {ok:e}\n4:\n",table!()),
                pointer=in(reg) target,value=lateout(xmm_reg) value,ok=lateout(reg) ok,options(nostack,readonly));
            }
            if ok != 0 {
                unsafe {
                    std::ptr::write_unaligned(bytes.cast::<__m128i>(), value);
                }
            }
        }
    }
    ok != 0
}
