// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent test oracle driven by assembly semantic cases, never binary decode.
use trames_execution::Aarch64State;

fn condition(c: u32, flags: u32) -> bool {
    let n = flags & 8 != 0;
    let z = flags & 4 != 0;
    let carry = flags & 2 != 0;
    let v = flags & 1 != 0;
    match c {
        0 => z,
        1 => !z,
        2 => carry,
        3 => !carry,
        4 => n,
        5 => !n,
        6 => v,
        7 => !v,
        8 => carry && !z,
        9 => !carry || z,
        10 => n == v,
        11 => n != v,
        12 => !z && n == v,
        13 => z || n != v,
        _ => true,
    }
}
fn sx(value: u64, bits: u32) -> i64 {
    ((value << (64 - bits)) as i64) >> (64 - bits)
}
pub fn expected(row: &str, state: &Aarch64State) -> Aarch64State {
    let fields: Vec<_> = row.split_whitespace().collect();
    let kind = fields[0];
    let numbers: Vec<i64> = fields[1..].iter().map(|x| x.parse().unwrap()).collect();
    let (cond, bits, left, right, immediate, offset) = (
        numbers[0] as u32,
        numbers[1] as u32,
        numbers[2] as usize,
        numbers[3] as usize,
        numbers[4] != 0,
        numbers[5] as u64,
    );
    let read = |r: usize| if r == 31 { 0 } else { state.registers[r] };
    let take = match kind {
        "cond" | "hbc" => condition(cond, state.nzcv >> 28),
        "zero" => {
            ((read(left)
                & if bits == 32 {
                    u32::MAX as u64
                } else {
                    u64::MAX
                })
                != 0)
                == (cond != 0)
        }
        "bit" => (read(left) & (1 << bits) != 0) == (cond != 0),
        "cmp" => {
            let mask = if bits == 64 {
                u64::MAX
            } else {
                (1 << bits) - 1
            };
            let a = read(left) & mask;
            let b = if immediate {
                right as u64
            } else {
                read(right) & mask
            };
            match cond {
                0 => a == b,
                1 => a != b,
                2 => sx(a, bits) > sx(b, bits),
                3 => sx(a, bits) >= sx(b, bits),
                4 => sx(a, bits) < sx(b, bits),
                5 => sx(a, bits) <= sx(b, bits),
                6 => a > b,
                7 => a >= b,
                8 => a < b,
                9 => a <= b,
                _ => unreachable!(),
            }
        }
        _ => true,
    };
    let mut result = state.clone();
    result.pc = if matches!(kind, "br" | "blr" | "ret") {
        read(left)
    } else if take {
        state.pc.wrapping_add(offset)
    } else {
        state.pc.wrapping_add(4)
    };
    if kind == "bl" || kind == "blr" {
        result.registers[30] = state.pc.wrapping_add(4);
    }
    result
}
