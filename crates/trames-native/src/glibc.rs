// SPDX-License-Identifier: GPL-3.0-or-later
//! Debian 13 narrow C-locale conversion semantics, independent of host libc.
//! Integer grammar follows glibc 2.41 strtol_l.c (classic and C23 entry points).
//! Finite nearest FP conversion shares correctly-rounded gdtoa; glibc's NaN
//! payload grammar is applied separately. Guest wrappers retain other locales
//! and FP controls in the original library.
use crate::parse::{glibc_floating, ParsedFloat};
fn digit(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => (c - b'0') as u32,
        b'a'..=b'z' => (c - b'a') as u32 + 10,
        b'A'..=b'Z' => (c - b'A') as u32 + 10,
        _ => 255,
    }
}
pub fn integer(bytes: &[u8], mut base: u32, unsigned: bool, binary: bool) -> ParsedFloat {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t'..=b'\r') {
        i += 1;
    }
    let negative = bytes.get(i) == Some(&b'-');
    if matches!(bytes.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    if bytes.get(i) == Some(&b'0') {
        if bytes.get(i + 1).is_none()
            || ((base == 0 || base == 16)
                && matches!(bytes.get(i + 1), Some(b'x' | b'X'))
                && bytes.get(i + 2).is_none())
            || (binary
                && (base == 0 || base == 2)
                && matches!(bytes.get(i + 1), Some(b'b' | b'B'))
                && bytes.get(i + 2).is_none())
        {
            return ParsedFloat {
                bits: 0,
                consumed: 0,
                errno: 0,
                needs_more: true,
                fpsr: 0,
            };
        }
        if (base == 0 || base == 16)
            && matches!(bytes.get(i + 1), Some(b'x' | b'X'))
            && bytes.get(i + 2).is_some_and(|&c| digit(c) < 16)
        {
            base = 16;
            i += 2;
        } else if binary
            && (base == 0 || base == 2)
            && matches!(bytes.get(i + 1), Some(b'b' | b'B'))
            && bytes.get(i + 2).is_some_and(|&c| digit(c) < 2)
        {
            base = 2;
            i += 2;
        } else if base == 0 {
            base = 8;
        }
    } else if base == 0 {
        base = 10;
    }
    let start = i;
    let limit = if unsigned {
        u64::MAX
    } else if negative {
        1u64 << 63
    } else {
        i64::MAX as u64
    };
    let (cutoff, cutlim) = (limit / base as u64, limit % base as u64);
    let (mut value, mut overflow) = (0u64, false);
    while let Some(&c) = bytes.get(i) {
        let d = digit(c);
        if d >= base {
            break;
        }
        if value > cutoff || (value == cutoff && d as u64 > cutlim) {
            overflow = true;
        } else {
            value = value * base as u64 + d as u64;
        }
        i += 1;
    }
    let more = i == bytes.len();
    let any = i != start;
    let bits = if overflow {
        if unsigned {
            u64::MAX
        } else if negative {
            1u64 << 63
        } else {
            i64::MAX as u64
        }
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    };
    ParsedFloat {
        bits,
        consumed: if any { i } else { 0 },
        errno: if overflow { 34 } else { 0 },
        needs_more: more,
        fpsr: 0,
    }
}
pub fn floating(bytes: &[u8], single: bool) -> ParsedFloat {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t'..=b'\r') {
        i += 1;
    }
    let negative = bytes.get(i) == Some(&b'-');
    if matches!(bytes.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    if bytes
        .get(i..i + 3)
        .is_some_and(|s| s.eq_ignore_ascii_case(b"nan"))
    {
        let mut end = i + 3;
        let mut payload = 0;
        if bytes.get(end) == Some(&b'(') {
            let start = end + 1;
            let mut at = start;
            while bytes
                .get(at)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                at += 1;
            }
            if bytes.get(at) == Some(&b')') {
                end = at + 1;
                let parsed = integer(&bytes[start..end], 0, true, false);
                if parsed.consumed == at - start {
                    payload = parsed.bits;
                }
            }
        }
        let bits = if single {
            0x7fc0_0000 | (payload & 0x003f_ffff) | (u64::from(negative) << 31)
        } else {
            0x7ff8_0000_0000_0000 | (payload & 0x0007_ffff_ffff_ffff) | (u64::from(negative) << 63)
        };
        return ParsedFloat {
            bits,
            consumed: end,
            errno: 0,
            needs_more: false,
            fpsr: 0,
        };
    }
    glibc_floating(bytes, single)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classic_c23_overflow_and_nan_payloads_are_distinct() {
        assert_eq!(integer(b"0b101!", 0, false, false).consumed, 1);
        assert!(!integer(b"0b", 0, false, false).needs_more);
        assert!(!integer(b"0x", 10, false, false).needs_more);
        assert!(integer(b"0b", 0, false, true).needs_more);
        assert_eq!(integer(b"-0b101!", 0, false, true).bits, (-5i64) as u64);
        assert_eq!(integer(b"+!", 10, false, false).errno, 0);
        assert_eq!(
            integer(b"18446744073709551616!", 10, true, false).bits,
            u64::MAX
        );
        assert_eq!(integer(b"9223372036854775808!", 10, false, false).errno, 34);
        assert_eq!(floating(b"nan(123)!", false).bits, 0x7ff8_0000_0000_007b);
        assert_eq!(floating(b"-nan(0x123)!", true).bits, 0xffc0_0123);
        assert_eq!(floating(b"nan(foo)!", false).consumed, 8);
        assert_eq!(floating(b"nan(bad%)!", false).consumed, 3);
    }
}
