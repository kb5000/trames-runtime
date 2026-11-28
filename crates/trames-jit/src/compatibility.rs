// SPDX-License-Identifier: GPL-3.0-or-later
//! Lower the existing disabled-authentication/zero-allocation-tag profile.
//! This does not borrow host PAC keys, advertise MTE or introduce tag state.
use super::{sp_register, Assembler};

/// Cold lowering only. A true result terminates at the masked register target
/// in x17; a false result is an ordinary instruction with unchanged control flow.
pub(super) fn register(code: &mut Assembler, word: u32, pc: u64) -> Option<bool> {
    let rd = word & 31;
    let rn = (word >> 5) & 31;
    let rm = (word >> 16) & 31;
    if word & 0xffffe000 == 0xdac10000 || word & 0xffffe3e0 == 0xdac123e0 {
        // Authentication is disabled in the shared CPU profile, including the
        // non-hint register forms. Never sign/poison values with host keys.
    } else if matches!(word & 0xffffffe0, 0xdac143e0 | 0xdac147e0) {
        if rd == 31 {
            return Some(false);
        }
        let source = code.read(rd, 0);
        let dest = code.output(rd, 1 << source);
        code.words.push(0xd340bc00 | (source << 5) | dest); // ubfx #0,#48
    } else if word & 0xffe0fc00 == 0x9ac03000 {
        code.constant(rd, 0); // no generic authentication code in this profile
    } else if matches!(
        word & 0xfffffc00,
        0xd71f0800 | 0xd71f0c00 | 0xd73f0800 | 0xd73f0c00
    ) || matches!(
        word & 0xfffffc1f,
        0xd61f081f | 0xd61f0c1f | 0xd63f081f | 0xd63f0c1f
    ) || matches!(word, 0xd65f0bff | 0xd65f0fff)
    {
        let source = code.read(
            if word & 0xfffffbff == 0xd65f0bff {
                30
            } else {
                rn
            },
            0,
        );
        // Capture before a linked branch overwrites x30, including rn == 30.
        code.words.push(0xd340bc00 | (source << 5) | 17);
        if word & (1 << 21) != 0 {
            code.constant(30, pc.wrapping_add(4));
        }
        code.context = true;
        return Some(true);
    } else if matches!(
        word & 0xffe0fc00,
        0x9ac01000 | 0x9ac01400 | 0x9ac00000 | 0xbac00000
    ) {
        let key = word & 0xffe0fc00;
        if rd == 31 && matches!(key, 0x9ac01400 | 0x9ac00000) {
            return Some(false); // discarded value, no flags or memory effect
        }
        let lhs = code.read(sp_register(rn), 0);
        if key == 0x9ac01000 {
            let dest = code.output(sp_register(rd), 1 << lhs);
            code.words.push(0xd340bc00 | (lhs << 5) | dest);
        } else {
            let rhs = code.read(
                if key == 0x9ac01400 {
                    rm
                } else {
                    sp_register(rm)
                },
                1 << lhs,
            );
            if key == 0x9ac01400 {
                // Scratch allocation evicts only this block's binding. No new
                // architectural bank or per-instruction helper is needed.
                let temp = code.scratch((1 << lhs) | (1 << rhs));
                code.words.push(0xd378ec00 | (lhs << 5) | 17); // ubfx #56,#4
                code.words.push(0xd2800020 | temp); // mov #1
                code.words.push(0x9ad12000 | (temp << 5) | temp); // lslv temp,temp,x17
                let dest = code.output(rd, (1 << rhs) | (1 << temp));
                code.words
                    .push(0xaa000000 | (temp << 16) | (rhs << 5) | dest);
            } else {
                code.words.push(0x9340dc00 | (rhs << 5) | 17);
                let temp = if rd == 31 {
                    code.scratch((1 << lhs) | (1 << rhs))
                } else {
                    code.output(rd, (1 << lhs) | (1 << rhs))
                };
                code.words.push(0x9340dc00 | (lhs << 5) | temp); // sxt #56
                let dest = if rd == 31 { 31 } else { temp };
                code.words.push(
                    (if key == 0xbac00000 {
                        0xeb110000
                    } else {
                        0xcb110000
                    }) | (temp << 5)
                        | dest,
                );
                if key == 0xbac00000 {
                    code.flags_written();
                }
            }
        }
    } else if matches!(word & 0xffc0c000, 0x91800000 | 0xd1800000) {
        let source = code.read(sp_register(rn), 0);
        let dest = code.output(sp_register(rd), 1 << source);
        code.words.push(0xd340bc00 | (source << 5) | dest);
        let offset = ((word >> 16) & 63) * 16;
        if offset != 0 {
            code.words.push(
                (if word & (1 << 30) != 0 {
                    0xd1000000
                } else {
                    0x91000000
                }) | (offset << 10)
                    | (dest << 5)
                    | dest,
            );
        }
    } else {
        return None;
    }
    Some(false)
}
