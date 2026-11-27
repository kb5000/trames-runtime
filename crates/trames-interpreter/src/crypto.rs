// SPDX-License-Identifier: GPL-3.0-or-later
//! ARM AES/SHA1/SHA256 rounds. Only virtual registers are read or written.
use super::Cpu;

const fn gf(mut a: u8, mut b: u8) -> u8 {
    let mut value = 0;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            value ^= a;
        }
        a = (a << 1) ^ if a & 128 != 0 { 0x1b } else { 0 };
        b >>= 1;
        i += 1;
    }
    value
}
const fn tables() -> ([u8; 256], [u8; 256]) {
    let mut forward = [0u8; 256];
    let mut inverse = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let mut power = 254;
        let mut base = i as u8;
        let mut x = 1u8;
        while power != 0 {
            if power & 1 != 0 {
                x = gf(x, base);
            }
            base = gf(base, base);
            power >>= 1;
        }
        if i == 0 {
            x = 0;
        }
        let y =
            x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4) ^ 0x63;
        forward[i] = y;
        inverse[y as usize] = i as u8;
        i += 1;
    }
    (forward, inverse)
}
const SBOX: ([u8; 256], [u8; 256]) = tables();
pub(super) fn words(value: u128) -> [u32; 4] {
    std::array::from_fn(|i| (value >> (i * 32)) as u32)
}
pub(super) fn packed(value: [u32; 4]) -> u128 {
    value
        .iter()
        .enumerate()
        .fold(0, |result, (i, x)| result | ((*x as u128) << (i * 32)))
}
fn small0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn small1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

impl Cpu {
    pub(super) fn execute_crypto(&mut self, ins: u32) -> bool {
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let old = self.vectors[rd];
        let a = self.vectors[rn];
        let b = self.vectors[rm];
        let two = ins & 0xfffffc00;
        let three = ins & 0xffe0fc00;
        use trames_compute::CryptoOp as C;
        let native = match (two, three) {
            (0x4e284800, _) => Some(C::AesEncrypt),
            (0x4e285800, _) => Some(C::AesDecrypt),
            (0x4e286800, _) => Some(C::AesMix),
            (0x4e287800, _) => Some(C::AesInverseMix),
            (0x5e280800, _) => Some(C::Sha1Hash),
            (0x5e281800, _) => Some(C::Sha1Schedule1),
            (0x5e282800, _) => Some(C::Sha256Schedule0),
            (_, 0x5e000000) => Some(C::Sha1Choose),
            (_, 0x5e001000) => Some(C::Sha1Parity),
            (_, 0x5e002000) => Some(C::Sha1Majority),
            (_, 0x5e003000) => Some(C::Sha1Schedule0),
            (_, 0x5e004000) => Some(C::Sha256Hash),
            (_, 0x5e005000) => Some(C::Sha256Hash2),
            (_, 0x5e006000) => Some(C::Sha256Schedule1),
            _ => None,
        };
        if let Some(op) = native {
            if let Some(value) = trames_compute::crypto(op, old, a, b) {
                self.vectors[rd] = value;
                return true;
            }
        }
        let result;
        if matches!(two, 0x4e284800 | 0x4e285800 | 0x4e286800 | 0x4e287800) {
            let mut output = [0u8; 16];
            if matches!(two, 0x4e284800 | 0x4e285800) {
                let input = (old ^ a).to_le_bytes();
                let inverse = two == 0x4e285800;
                for column in 0..4 {
                    for row in 0..4 {
                        let source = 4 * if inverse {
                            (column + 4 - row) % 4
                        } else {
                            (column + row) % 4
                        } + row;
                        output[4 * column + row] = if inverse {
                            SBOX.1[input[source] as usize]
                        } else {
                            SBOX.0[input[source] as usize]
                        };
                    }
                }
            } else {
                let input = a.to_le_bytes();
                let coefficients = if two == 0x4e286800 {
                    [2, 3, 1, 1]
                } else {
                    [14, 11, 13, 9]
                };
                for column in 0..4 {
                    for row in 0..4 {
                        for k in 0..4 {
                            output[column * 4 + row] ^=
                                gf(input[column * 4 + (row + k) % 4], coefficients[k]);
                        }
                    }
                }
            }
            result = u128::from_le_bytes(output);
        } else if two == 0x5e280800 {
            result = (a as u32).rotate_right(2) as u128;
        } else if two == 0x5e281800 {
            let d = words(old);
            let n = words(a);
            let mut out = [0u32; 4];
            for i in 0..3 {
                out[i] = (d[i] ^ n[i + 1]).rotate_left(1);
            }
            out[3] = (d[3] ^ out[0]).rotate_left(1);
            result = packed(out);
        } else if two == 0x5e282800 {
            let d = words(old);
            let n = words(a);
            result = packed([
                d[0].wrapping_add(small0(d[1])),
                d[1].wrapping_add(small0(d[2])),
                d[2].wrapping_add(small0(d[3])),
                d[3].wrapping_add(small0(n[0])),
            ]);
        } else if matches!(three, 0x5e000000 | 0x5e001000 | 0x5e002000) {
            let [mut av, mut bv, mut cv, mut dv] = words(old);
            let mut ev = a as u32;
            for message in words(b) {
                let f = match three {
                    0x5e000000 => (bv & cv) ^ (!bv & dv),
                    0x5e001000 => bv ^ cv ^ dv,
                    _ => (bv & cv) ^ (bv & dv) ^ (cv & dv),
                };
                let temporary = av
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(ev)
                    .wrapping_add(message);
                ev = dv;
                dv = cv;
                cv = bv.rotate_right(2);
                bv = av;
                av = temporary;
            }
            result = packed([av, bv, cv, dv]);
        } else if three == 0x5e003000 {
            let d = words(old);
            let n = words(a);
            let m = words(b);
            result = packed([
                d[0] ^ d[2] ^ m[0],
                d[1] ^ d[3] ^ m[1],
                d[2] ^ n[0] ^ m[2],
                d[3] ^ n[1] ^ m[3],
            ]);
        } else if matches!(three, 0x5e004000 | 0x5e005000) {
            let (first, second) = if three == 0x5e004000 {
                (old, a)
            } else {
                (a, old)
            };
            let [mut av, mut bv, mut cv, mut dv] = words(first);
            let [mut ev, mut fv, mut gv, mut hv] = words(second);
            for message in words(b) {
                let sum1 = ev.rotate_right(6) ^ ev.rotate_right(11) ^ ev.rotate_right(25);
                let choose = (ev & fv) ^ (!ev & gv);
                let t1 = hv
                    .wrapping_add(sum1)
                    .wrapping_add(choose)
                    .wrapping_add(message);
                let sum0 = av.rotate_right(2) ^ av.rotate_right(13) ^ av.rotate_right(22);
                let majority = (av & bv) ^ (av & cv) ^ (bv & cv);
                let t2 = sum0.wrapping_add(majority);
                hv = gv;
                gv = fv;
                fv = ev;
                ev = dv.wrapping_add(t1);
                dv = cv;
                cv = bv;
                bv = av;
                av = t1.wrapping_add(t2);
            }
            result = packed(if three == 0x5e004000 {
                [av, bv, cv, dv]
            } else {
                [ev, fv, gv, hv]
            });
        } else if three == 0x5e006000 {
            let mut d = words(old);
            let n = words(a);
            let m = words(b);
            d[0] = d[0].wrapping_add(n[1]).wrapping_add(small1(m[2]));
            d[1] = d[1].wrapping_add(n[2]).wrapping_add(small1(m[3]));
            d[2] = d[2].wrapping_add(n[3]).wrapping_add(small1(d[0]));
            d[3] = d[3].wrapping_add(m[0]).wrapping_add(small1(d[1]));
            result = packed(d);
        } else {
            return false;
        }
        self.vectors[rd] = result;
        true
    }
}
