// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold A64 FP/AdvSIMD operand classification. Execution uses original opcodes.
#[derive(Clone, Copy)]
pub(super) enum Form {
    Unary,
    Binary { accumulate: bool },
    Ternary,
    Immediate,
    Compare { zero: bool, conditional: bool },
    Select,
    ToGpr,
    FromGpr { merge: bool },
}
#[derive(Clone, Copy)]
pub(super) struct Operation {
    pub form: Form,
    pub capability: u8,
}
pub(super) fn decode(word: u32) -> Option<Operation> {
    use Form::*;
    let scalar = |form, half| {
        Some(Operation {
            form,
            capability: if half { 9 } else { 0 },
        })
    };
    if word & 0xfffffc00 == 0x9eae0000 {
        return scalar(ToGpr, false);
    }
    if word & 0xfffffc00 == 0x9eaf0000 {
        return scalar(FromGpr { merge: true }, false);
    }
    let kind = (word >> 22) & 3;
    if kind != 2 {
        let half = kind == 3;
        if word & 0xff201fe0 == 0x1e201000 {
            return scalar(Immediate, half);
        }
        if word & 0xff207c00 == 0x1e204000 {
            let op = (word >> 15) & 63;
            // Precision conversion, including H<->S/D, is baseline FEAT_FP;
            // half arithmetic/moves require the separate FP16 capability.
            if matches!(op, 4 | 5 | 7) && op != [4, 5, 0, 7][kind as usize] {
                return scalar(Unary, false);
            }
            if matches!(op,0..=3|8..=12|14..=15) {
                return scalar(Unary, half);
            }
        }
        if word & 0xff200c00 == 0x1e200800 && (word >> 12) & 15 <= 8 {
            return scalar(Binary { accumulate: false }, half);
        }
        if word & 0xff000000 == 0x1f000000 {
            return scalar(Ternary, half);
        }
        if word & 0xff20fc07 == 0x1e202000 && (word & 8 == 0 || (word >> 16) & 31 == 0) {
            return scalar(
                Compare {
                    zero: word & 8 != 0,
                    conditional: false,
                },
                half,
            );
        }
        if word & 0xff200c00 == 0x1e200400 {
            return scalar(
                Compare {
                    zero: false,
                    conditional: true,
                },
                half,
            );
        }
        if word & 0xff200c00 == 0x1e200c00 {
            return scalar(Select, half);
        }
        if word & 0x7f200000 == 0x1e200000 && word & 0xfc00 == 0 {
            let op = (word >> 16) & 31;
            if matches!(op, 0 | 1 | 4 | 5 | 8 | 9 | 16 | 17 | 24 | 25) {
                return scalar(ToGpr, half);
            }
            if matches!(op, 2 | 3) {
                return scalar(FromGpr { merge: false }, half);
            }
            if matches!(op, 6 | 7) && (kind == 1) == (word >> 31 != 0) {
                return scalar(
                    if op == 6 {
                        ToGpr
                    } else {
                        FromGpr { merge: false }
                    },
                    half,
                );
            }
        }
        if word & 0x7f200000 == 0x1e000000
            && 64 - ((word >> 10) & 63) <= if word >> 31 != 0 { 64 } else { 32 }
        {
            match (word >> 16) & 31 {
                2 | 3 => return scalar(FromGpr { merge: false }, half),
                24 | 25 => return scalar(ToGpr, half),
                _ => {}
            }
        }
    }
    let vector = |form| {
        Some(Operation {
            form,
            capability: 1,
        })
    };
    let q = word & (1 << 30) != 0;
    let size = (word >> 22) & 3;
    let logical = word & 0xbfe0fc00;
    if matches!(
        logical,
        0x0e201c00
            | 0x0ea01c00
            | 0x2e201c00
            | 0x0e601c00
            | 0x0ee01c00
            | 0x2e601c00
            | 0x2ea01c00
            | 0x2ee01c00
    ) {
        return vector(Binary {
            accumulate: matches!(logical, 0x2e601c00 | 0x2ea01c00 | 0x2ee01c00),
        });
    }
    let binary = word & 0xbfa0fc00;
    if matches!(
        binary,
        0x0e20d400
            | 0x0ea0d400
            | 0x2e20d400
            | 0x2e20dc00
            | 0x2e20fc00
            | 0x0e20cc00
            | 0x0ea0cc00
            | 0x0e20f400
            | 0x0ea0f400
            | 0x0e20c400
            | 0x0ea0c400
            | 0x0e20e400
            | 0x2e20e400
            | 0x2ea0e400
            | 0x2e20ec00
            | 0x2ea0ec00
    ) && (word & (1 << 22) == 0 || q)
    {
        return vector(Binary {
            accumulate: matches!(binary, 0x0e20cc00 | 0x0ea0cc00),
        });
    }
    let unary = word & 0xbfbffc00;
    if matches!(
        unary,
        0x0ea0f800
            | 0x2ea0f800
            | 0x2ea1f800
            | 0x0e218800
            | 0x0ea18800
            | 0x0e219800
            | 0x0ea19800
            | 0x2e218800
            | 0x2e219800
            | 0x2ea19800
            | 0x0e21d800
            | 0x2e21d800
            | 0x0ea1b800
            | 0x2ea1b800
    ) && (word & (1 << 22) == 0 || q)
    {
        return vector(Unary);
    }
    let integer = word & 0xbf20fc00;
    let wide = matches!(
        integer,
        0x0e208400
            | 0x2e208400
            | 0x0e20bc00
            | 0x0e208c00
            | 0x2e208c00
            | 0x0e203400
            | 0x2e203400
            | 0x0e203c00
            | 0x2e203c00
            | 0x0e200c00
            | 0x2e200c00
            | 0x0e202c00
            | 0x2e202c00
            | 0x0e204400
            | 0x2e204400
            | 0x0e204c00
            | 0x2e204c00
            | 0x0e205400
            | 0x2e205400
            | 0x0e205c00
            | 0x2e205c00
    );
    if (wide
        || matches!(
            integer,
            0x0e209c00
                | 0x0e209400
                | 0x2e209400
                | 0x0e206400
                | 0x2e206400
                | 0x0e206c00
                | 0x2e206c00
        ))
        && (size != 3 || wide && q)
    {
        return vector(Binary {
            accumulate: matches!(integer, 0x0e209400 | 0x2e209400),
        });
    }
    let unary = word & 0xbf3ffc00;
    if (unary == 0x0e205800 && size == 0)
        || (unary == 0x2e205800 && size <= 1)
        || (matches!(unary, 0x0e204800 | 0x2e204800) && size < 3)
        || (matches!(unary, 0x0e20b800 | 0x2e20b800 | 0x0e207800 | 0x2e207800) && (size < 3 || q))
    {
        return vector(Unary);
    }
    None
}
