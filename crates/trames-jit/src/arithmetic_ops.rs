// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold stateless arithmetic forms. Immediate/lane bits survive register remap;
//! execution uses the original host instruction and the existing CPU FP banks.
use super::{Form, Operation};
use Form::*;
fn baseline(form: Form) -> Option<Operation> {
    Some(Operation::new(form, 1))
}
fn binary(accumulate: bool) -> Form {
    Binary { accumulate }
}
fn indexed(low: bool, accumulate: bool) -> Form {
    Indexed { low, accumulate }
}

pub(super) fn decode(word: u32) -> Option<Operation> {
    if word & 0xfffffc00 == 0x1e7e0000 {
        return Some(Operation::new(ToGprFlags, 13));
    }
    if word & 0xff207c00 == 0x1e204000
        && matches!((word >> 22) & 3, 0 | 1)
        && matches!((word >> 15) & 63, 16..=19)
    {
        return Some(Operation::second(Unary, 8));
    }
    if let Some(op) = extensions(word) {
        return Some(op);
    }
    let scalar = matches!(word & 0xdf000000, 0x5e000000 | 0x5f000000);
    let vector = matches!(word & 0x9f000000, 0x0e000000 | 0x0f000000);
    if !scalar && !vector {
        return None;
    }
    let normal = if scalar { word & !(1 << 28) } else { word };
    if let Some(op) = half(word, normal, scalar) {
        return Some(op);
    }
    if let Some(op) = floating(word, normal, scalar) {
        return Some(op);
    }
    integer(word, normal, scalar)
}
fn extensions(word: u32) -> Option<Operation> {
    let scalar = matches!(word & 0xdf000000, 0x5e000000 | 0x5f000000);
    let normal = if scalar { word & !(1 << 28) } else { word };
    let q = word & (1 << 30) != 0;
    let size = (word >> 22) & 3;
    let unary = word & 0xbffffc00;
    let b = word & 0xbfe0fc00;
    let i = word & 0xbfc0f400;
    if word & 0xfffffc00 == 0x1e634000 {
        return Some(Operation::second(Unary, 14));
    }
    if unary == 0x0ea16800 {
        return Some(Operation::second(if q { MergeUnary } else { Unary }, 14));
    }
    if matches!(b, 0x2e40fc00 | 0x2e40ec00 | 0x2ec0fc00) {
        if b == 0x2e40ec00 && !q {
            return None;
        }
        return Some(Operation::second(binary(true), 14));
    }
    if matches!(i, 0x0f40f000 | 0x0fc0f000) {
        return Some(Operation::second(indexed(i == 0x0fc0f000, true), 14));
    }
    if matches!(b, 0x0e20ec00 | 0x0ea0ec00 | 0x2e20cc00 | 0x2ea0cc00) {
        return Some(Operation::new(binary(true), 23));
    }
    if matches!(i, 0x0f800000 | 0x0f804000 | 0x2f808000 | 0x2f80c000) {
        return Some(Operation::new(indexed(true, true), 23));
    }
    let complex = word & 0xbf20e400 == 0x2e00c400;
    let add = word & 0xbf20ec00 == 0x2e00e400;
    let lane = word & 0xbf009400 == 0x2f001000;
    if complex || add || lane {
        if size == 0
            || size == 3 && (!q || lane)
            || lane && size == 2 && (!q || word & (1 << 21) != 0)
            || lane && size == 1 && !q && word & (1 << 11) != 0
        {
            return None;
        }
        let mut op = Operation::new(
            if lane {
                indexed(false, true)
            } else {
                binary(!add)
            },
            14,
        );
        if size == 1 {
            op.required.hwcap |= 1 << 10;
        }
        return Some(op);
    }
    if !matches!(normal & 0x9f000000, 0x0e000000 | 0x0f000000) {
        return None;
    }
    let b = normal & 0xbf20fc00;
    let i = normal & 0xbf00f400;
    if !scalar
        && matches!(
            b,
            0x0e009400 | 0x2e009400 | 0x0e009c00 | 0x0e00a400 | 0x2e00a400 | 0x0e00ac00
        )
    {
        if size != 2 || matches!(b, 0x0e00a400 | 0x2e00a400 | 0x0e00ac00) && !q {
            return None;
        }
        return Some(if matches!(b, 0x0e009400 | 0x2e009400) {
            Operation::new(binary(true), 20)
        } else {
            Operation::second(binary(true), 13)
        });
    }
    if !scalar && matches!(i, 0x0f00e000 | 0x2f00e000 | 0x0f00f000) {
        if (i == 0x0f00f000 && size & 1 != 0) || (i != 0x0f00f000 && size != 2) {
            return None;
        }
        return Some(if i == 0x0f00f000 {
            Operation::second(indexed(false, true), 13)
        } else {
            Operation::new(indexed(false, true), 20)
        });
    }
    if matches!(b, 0x2e008400 | 0x2e008c00) || matches!(i, 0x2f00d000 | 0x2f00f000) {
        if !matches!(size, 1 | 2) {
            return None;
        }
        return Some(Operation::new(
            if matches!(i, 0x2f00d000 | 0x2f00f000) {
                indexed(size == 1, true)
            } else {
                binary(true)
            },
            12,
        ));
    }
    None
}
fn half(word: u32, normal: u32, scalar: bool) -> Option<Operation> {
    let op = |form| Some(Operation::new(form, if scalar { 9 } else { 10 }));
    let u = normal & 0xbffffc00;
    let b = normal & 0xbfe0fc00;
    let i = normal & 0xbfc0f400;
    if matches!(i, 0x0f009000 | 0x2f009000 | 0x0f001000 | 0x0f005000) {
        return op(indexed(true, matches!(i, 0x0f001000 | 0x0f005000)));
    }
    if matches!(b, 0x0f00e400 | 0x2f00e400 | 0x0f00fc00 | 0x2f00fc00)
        && (16..32).contains(&((word >> 16) & 127))
    {
        return op(Unary);
    }
    if matches!(
        u,
        0x0e30c800 | 0x0eb0c800 | 0x0e30f800 | 0x0eb0f800 | 0x0e30d800
    ) {
        if u == 0x0e30d800 && !scalar {
            return None;
        }
        return op(Unary);
    }
    if matches!(
        u,
        0x0ef8f800
            | 0x2ef8f800
            | 0x2ef9f800
            | 0x0e798800
            | 0x0ef98800
            | 0x0e799800
            | 0x0ef99800
            | 0x2e798800
            | 0x2e799800
            | 0x2ef99800
            | 0x0e79d800
            | 0x2e79d800
            | 0x0ef9b800
            | 0x2ef9b800
            | 0x0e79a800
            | 0x2e79a800
            | 0x0ef9a800
            | 0x2ef9a800
            | 0x0e79b800
            | 0x2e79b800
            | 0x0e79c800
            | 0x2e79c800
            | 0x0ef9d800
            | 0x2ef9d800
            | 0x0ef9f800
            | 0x0ef8c800
            | 0x2ef8c800
            | 0x0ef8d800
            | 0x2ef8d800
            | 0x0ef8e800
    ) {
        if scalar
            && matches!(
                u,
                0x0ef8f800
                    | 0x2ef8f800
                    | 0x2ef9f800
                    | 0x0e798800
                    | 0x0ef98800
                    | 0x0e799800
                    | 0x0ef99800
                    | 0x2e798800
                    | 0x2e799800
                    | 0x2ef99800
            )
            || !scalar && u == 0x0ef9f800
        {
            return None;
        }
        return op(Unary);
    }
    if matches!(
        b,
        0x0e401400
            | 0x0ec01400
            | 0x2e401c00
            | 0x2e403c00
            | 0x0e400c00
            | 0x0ec00c00
            | 0x0e403400
            | 0x0ec03400
            | 0x0e400400
            | 0x0ec00400
            | 0x0e402400
            | 0x2e402400
            | 0x2ec02400
            | 0x2e402c00
            | 0x2ec02c00
            | 0x2e401400
            | 0x0e401c00
            | 0x2ec01400
            | 0x2e403400
            | 0x2ec03400
            | 0x2e400400
            | 0x2ec00400
            | 0x0e403c00
            | 0x0ec03c00
    ) {
        if scalar
            && !matches!(
                b,
                0x0e401c00
                    | 0x2ec01400
                    | 0x0e403c00
                    | 0x0ec03c00
                    | 0x0e402400
                    | 0x2e402400
                    | 0x2ec02400
                    | 0x2e402c00
                    | 0x2ec02c00
            )
        {
            return None;
        }
        return op(binary(matches!(b, 0x0e400c00 | 0x0ec00c00)));
    }
    None
}
fn floating(word: u32, normal: u32, scalar: bool) -> Option<Operation> {
    let q = word & (1 << 30) != 0;
    let double = word & (1 << 22) != 0;
    let u = normal & 0xbfbffc00;
    let b = normal & 0xbfa0fc00;
    let exact = normal & 0xbffffc00;
    if matches!(
        u,
        0x0ea1d800
            | 0x2ea1d800
            | 0x0e21d800
            | 0x2e21d800
            | 0x0ea1b800
            | 0x2ea1b800
            | 0x0e21a800
            | 0x2e21a800
            | 0x0ea1a800
            | 0x2ea1a800
            | 0x0e21b800
            | 0x2e21b800
            | 0x0e21c800
            | 0x2e21c800
            | 0x0ea0c800
            | 0x2ea0c800
            | 0x0ea0d800
            | 0x2ea0d800
            | 0x0ea0e800
    ) || scalar && u == 0x0ea1f800
    {
        if double && !q && !scalar {
            return None;
        }
        return baseline(Unary);
    }
    if !scalar && matches!(exact, 0x0ea1c800 | 0x2ea1c800) {
        return baseline(Unary);
    }
    if !scalar && matches!(u, 0x0e21e800 | 0x2e21e800 | 0x0e21f800 | 0x2e21f800) {
        if double && !q {
            return None;
        }
        return Some(Operation::second(Unary, 8));
    }
    if matches!(
        exact,
        0x0e617800 | 0x0e616800 | 0x2e616800 | 0x0e217800 | 0x0e216800
    ) && (!scalar || exact == 0x2e616800)
    {
        let narrow = !matches!(exact, 0x0e617800 | 0x0e217800);
        return baseline(if narrow && q && !scalar {
            MergeUnary
        } else {
            Unary
        });
    }
    let imm = (word >> 16) & 127;
    if matches!(normal & 0x9f80fc00, 0x0f00e400 | 0x0f00fc00) && imm >= 32 {
        if imm >= 64 && !q && !scalar {
            return None;
        }
        return baseline(Unary);
    }
    if matches!(
        normal & 0xbf00f400,
        0x0f009000 | 0x0f001000 | 0x0f005000 | 0x2f009000
    ) {
        let size = (word >> 22) & 3;
        if !matches!(size, 2 | 3) || size == 3 && ((!q && !scalar) || word & (1 << 21) != 0) {
            return None;
        }
        return baseline(indexed(
            false,
            matches!(normal & 0xbf00f400, 0x0f001000 | 0x0f005000),
        ));
    }
    if matches!(b, 0x0e20fc00 | 0x0ea0fc00 | 0x0e20dc00 | 0x2ea0d400)
        || scalar
            && matches!(
                b,
                0x0e20e400 | 0x2e20e400 | 0x2ea0e400 | 0x2e20ec00 | 0x2ea0ec00
            )
        || !scalar && matches!(b, 0x2e20f400 | 0x2ea0f400 | 0x2e20c400 | 0x2ea0c400)
    {
        if double && !q && !scalar {
            return None;
        }
        return baseline(binary(false));
    }
    if scalar
        && matches!(
            u,
            0x2e30d800 | 0x2e30f800 | 0x2eb0f800 | 0x2e30c800 | 0x2eb0c800
        )
    {
        return baseline(Unary);
    }
    if !scalar && matches!(u, 0x2e30f800 | 0x2eb0f800 | 0x2e30c800 | 0x2eb0c800) && q && !double {
        return baseline(Unary);
    }
    None
}
fn integer(word: u32, normal: u32, scalar: bool) -> Option<Operation> {
    let q = word & (1 << 30) != 0;
    let size = (word >> 22) & 3;
    let unsigned = word & (1 << 29) != 0;
    let u = normal & 0xbf3ffc00;
    let b = normal & 0xbf20fc00;
    let i = normal & 0xbf00f400;
    if scalar
        && matches!(
            word & 0xffe0fc00,
            0x5ee08400
                | 0x7ee08400
                | 0x7ee08c00
                | 0x5ee03400
                | 0x5ee03c00
                | 0x7ee03400
                | 0x7ee03c00
                | 0x5ee08c00
        )
    {
        return baseline(binary(false));
    }
    if scalar && matches!(word & 0xfffffc00, 0x5ee0b800 | 0x7ee0b800 | 0x5ef1b800) {
        return baseline(Unary);
    }
    if matches!(
        u,
        0x0e208800
            | 0x2e208800
            | 0x0e209800
            | 0x2e209800
            | 0x0e20a800
            | 0x0e203800
            | 0x2e203800
            | 0x0e207800
            | 0x2e207800
    ) {
        if size == 3 && !q && !scalar
            || scalar
                && size != 3
                && matches!(
                    u,
                    0x0e208800 | 0x2e208800 | 0x0e209800 | 0x2e209800 | 0x0e20a800
                )
        {
            return None;
        }
        return baseline(if matches!(u, 0x0e203800 | 0x2e203800) {
            MergeUnary
        } else {
            Unary
        });
    }
    if !scalar && u == 0x2e213800 && size < 3 {
        return baseline(Unary);
    }
    if matches!(
        i,
        0x0f008000
            | 0x2f000000
            | 0x2f004000
            | 0x0f00a000
            | 0x2f00a000
            | 0x0f002000
            | 0x2f002000
            | 0x0f006000
            | 0x2f006000
            | 0x0f00b000
            | 0x0f003000
            | 0x0f007000
            | 0x0f00c000
            | 0x0f00d000
    ) {
        if !matches!(size, 1 | 2)
            || scalar
                && !matches!(
                    i,
                    0x0f00b000 | 0x0f003000 | 0x0f007000 | 0x0f00c000 | 0x0f00d000
                )
        {
            return None;
        }
        return baseline(indexed(
            size == 1,
            matches!(
                i,
                0x2f000000
                    | 0x2f004000
                    | 0x0f002000
                    | 0x2f002000
                    | 0x0f006000
                    | 0x2f006000
                    | 0x0f003000
                    | 0x0f007000
            ),
        ));
    }
    if !scalar
        && matches!(
            u,
            0x0e31b800
                | 0x0e303800
                | 0x2e303800
                | 0x0e30a800
                | 0x0e31a800
                | 0x2e30a800
                | 0x2e31a800
        )
        && size < 3
        && (size != 2 || q)
    {
        return baseline(Unary);
    }
    if !scalar && matches!(u, 0x0e202800 | 0x2e202800 | 0x0e206800 | 0x2e206800) && size < 3 {
        return baseline(if word & 0x4000 != 0 {
            MergeUnary
        } else {
            Unary
        });
    }
    if matches!(u, 0x0e214800 | 0x2e214800 | 0x2e212800) && size < 3
        || !scalar && u == 0x0e212800 && size < 3
    {
        return baseline(if !scalar && q { MergeUnary } else { Unary });
    }
    if normal & 0x9f200c00 == 0x0e200000 {
        let op = (word >> 12) & 15;
        if op == 15
            || size == 3 && op != 14
            || op == 14 && (unsigned || size != 0 && size != 3)
            || matches!(op, 9 | 11 | 13) && (unsigned || size == 0)
            || scalar && !matches!(op, 9 | 11 | 13)
        {
            return None;
        }
        if matches!(op, 4 | 6) && !scalar && q {
            return baseline(binary(true));
        }
        return baseline(binary(matches!(op, 5 | 8 | 10 | 9 | 11)));
    }
    if matches!(
        normal & 0x9f20fc00,
        0x0e200400
            | 0x0e202400
            | 0x0e201400
            | 0x0e200c00
            | 0x0e202c00
            | 0x0e206400
            | 0x0e206c00
            | 0x0e207400
            | 0x0e207c00
            | 0x0e209c00
            | 0x0e209400
            | 0x0e20b400
            | 0x0e205400
            | 0x0e204c00
            | 0x0e205c00
            | 0x0e204400
    ) {
        let key = normal & 0x9f20fc00;
        if size == 3
            && (!scalar
                && (!q
                    || !matches!(
                        key,
                        0x0e200c00 | 0x0e202c00 | 0x0e205400 | 0x0e204c00 | 0x0e205c00 | 0x0e204400
                    )))
            || scalar
                && !matches!(
                    key,
                    0x0e200c00
                        | 0x0e202c00
                        | 0x0e20b400
                        | 0x0e205400
                        | 0x0e204c00
                        | 0x0e205c00
                        | 0x0e204400
                )
            || scalar && size != 3 && matches!(key, 0x0e205400 | 0x0e204400)
            || key == 0x0e20b400 && !matches!(size, 1 | 2)
            || key == 0x0e209c00 && unsigned && size != 0
        {
            return None;
        }
        return baseline(binary(matches!(key, 0x0e207c00 | 0x0e209400)));
    }
    if !scalar && matches!(b, 0x0e20a400 | 0x0e20ac00 | 0x2e20a400 | 0x2e20ac00) && size < 3 {
        return baseline(binary(false));
    }
    if normal & 0x9f800400 == 0x0f000400 {
        let imm = (word >> 16) & 127;
        if imm < 8 {
            return None;
        }
        let bits = 1 << (31 - imm.leading_zeros());
        let op = (word >> 11) & 31;
        if !matches!(op, 0 | 2 | 4 | 6 | 8 | 10 | 12 | 14 | 16..=20) {
            return None;
        }
        let narrow = (16..=19).contains(&op);
        if bits == 64 && (narrow || !scalar && !q)
            || scalar && !narrow && !matches!(op, 12 | 14) && bits != 64
            || matches!(op, 8 | 12) && !unsigned
            || scalar && matches!(op, 16 | 17) && !unsigned
            || op == 20 && (scalar || bits == 64)
        {
            return None;
        }
        return baseline(
            if (narrow && q && !scalar) || matches!(op, 2 | 6 | 8) || (op == 10 && unsigned) {
                MergeUnary
            } else {
                Unary
            },
        );
    }
    None
}
