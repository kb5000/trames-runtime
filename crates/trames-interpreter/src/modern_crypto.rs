// SPDX-License-Identifier: GPL-3.0-or-later
//! SHA-512, Keccak and SM3/SM4 round/schedule operations on virtual registers.
use super::Cpu;
use crate::crypto::{packed, words};
use trames_compute::ExtendedCryptoOp as C;
fn pair(value: u128) -> [u64; 2] {
    [value as u64, (value >> 64) as u64]
}
fn pack(value: [u64; 2]) -> u128 {
    value[0] as u128 | (value[1] as u128) << 64
}
fn sha_small0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
fn sha_small1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
fn sha_big0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
fn sha_big1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
fn choose(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}
fn majority(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}
fn sm3_p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}
fn sm3_p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}
const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];
fn sm4_sub(x: u32) -> u32 {
    u32::from_le_bytes(x.to_le_bytes().map(|b| SM4_SBOX[b as usize]))
}
impl Cpu {
    pub(super) fn execute_modern_crypto(&mut self, ins: u32) -> bool {
        if ins >> 24 != 0xce {
            return false;
        }
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let ra = ((ins >> 10) & 31) as usize;
        let (d, n, m, a) = (
            self.vectors[rd],
            self.vectors[rn],
            self.vectors[rm],
            self.vectors[ra],
        );
        let two = ins & 0xfffffc00;
        let three = ins & 0xffe0fc00;
        let op = match two {
            0xcec08000 => Some(C::Sha512Schedule0),
            0xcec08400 => Some(C::Sm4Encrypt),
            _ => None,
        }
        .or(match three {
            0xce608000 => Some(C::Sha512Hash),
            0xce608400 => Some(C::Sha512Hash2),
            0xce608800 => Some(C::Sha512Schedule1),
            0xce608c00 => Some(C::Rax1),
            0xce60c000 => Some(C::Sm3Schedule1),
            0xce60c400 => Some(C::Sm3Schedule2),
            0xce60c800 => Some(C::Sm4Schedule),
            _ => None,
        })
        .or(match ins & 0xffe08000 {
            0xce000000 => Some(C::Eor3),
            0xce200000 => Some(C::Bcax),
            0xce400000 => Some(C::Sm3Ss1),
            _ => None,
        })
        .or(match ins & 0xffe0cc00 {
            0xce408000 => Some(C::Sm3Tt1A),
            0xce408400 => Some(C::Sm3Tt1B),
            0xce408800 => Some(C::Sm3Tt2A),
            0xce408c00 => Some(C::Sm3Tt2B),
            _ => None,
        })
        .or_else(|| (ins & 0xffe00000 == 0xce800000).then_some(C::Xar));
        let Some(op) = op else { return false };
        let immediate = if matches!(op, C::Xar) {
            (ins >> 10) & 63
        } else {
            (ins >> 12) & 3
        };
        if let Some(result) = trames_compute::crypto_extended(op, d, n, m, a, immediate) {
            self.vectors[rd] = result;
            return true;
        }
        let result = match op {
            C::Eor3 => n ^ m ^ a,
            C::Bcax => n ^ (m & !a),
            C::Xar => pack(pair(n ^ m).map(|v| v.rotate_right(immediate))),
            C::Rax1 => {
                let n = pair(n);
                let m = pair(m);
                pack([n[0] ^ m[0].rotate_left(1), n[1] ^ m[1].rotate_left(1)])
            }
            C::Sha512Hash | C::Sha512Hash2 | C::Sha512Schedule0 | C::Sha512Schedule1 => {
                let mut d = pair(d);
                let n = pair(n);
                let m = pair(m);
                match op {
                    C::Sha512Hash => {
                        d[1] = d[1]
                            .wrapping_add(sha_big1(m[1]))
                            .wrapping_add(choose(m[1], n[0], n[1]));
                        let v = d[1].wrapping_add(m[0]);
                        d[0] = d[0]
                            .wrapping_add(sha_big1(v))
                            .wrapping_add(choose(v, m[1], n[0]));
                    }
                    C::Sha512Hash2 => {
                        d[1] = d[1]
                            .wrapping_add(sha_big0(m[0]))
                            .wrapping_add(majority(n[0], m[1], m[0]));
                        d[0] = d[0]
                            .wrapping_add(sha_big0(d[1]))
                            .wrapping_add(majority(d[1], m[0], m[1]));
                    }
                    C::Sha512Schedule0 => {
                        d[0] = d[0].wrapping_add(sha_small0(d[1]));
                        d[1] = d[1].wrapping_add(sha_small0(n[0]));
                    }
                    _ => {
                        for i in 0..2 {
                            d[i] = d[i].wrapping_add(sha_small1(n[i])).wrapping_add(m[i]);
                        }
                    }
                }
                pack(d)
            }
            C::Sm3Ss1 => {
                let n = words(n);
                let m = words(m);
                let a = words(a);
                (n[3]
                    .rotate_left(12)
                    .wrapping_add(m[3])
                    .wrapping_add(a[3])
                    .rotate_left(7) as u128)
                    << 96
            }
            C::Sm3Tt1A | C::Sm3Tt1B | C::Sm3Tt2A | C::Sm3Tt2B => {
                let d = words(d);
                let n = words(n);
                let m = words(m);
                let f = match op {
                    C::Sm3Tt1B => (d[3] & d[2]) ^ (d[3] & d[1]) ^ (d[2] & d[1]),
                    C::Sm3Tt2B => (d[3] & d[2]) ^ (!d[3] & d[1]),
                    _ => d[3] ^ d[2] ^ d[1],
                };
                let t = f.wrapping_add(d[0]).wrapping_add(m[immediate as usize]);
                let first = matches!(op, C::Sm3Tt1A | C::Sm3Tt1B);
                let value = if first {
                    t.wrapping_add(n[3] ^ d[3].rotate_left(12))
                } else {
                    sm3_p0(t.wrapping_add(n[3]))
                };
                packed([
                    d[1],
                    d[2].rotate_left(if first { 9 } else { 19 }),
                    d[3],
                    value,
                ])
            }
            C::Sm3Schedule1 | C::Sm3Schedule2 => {
                let mut d = words(d);
                let n = words(n);
                let m = words(m);
                if matches!(op, C::Sm3Schedule1) {
                    for i in 0..4 {
                        let t = d[i]
                            ^ n[i]
                            ^ if i == 3 {
                                d[0].rotate_left(15)
                            } else {
                                m[i + 1].rotate_left(15)
                            };
                        d[i] = sm3_p1(t);
                    }
                } else {
                    let t = n[0] ^ m[0].rotate_left(7);
                    for i in 0..4 {
                        d[i] ^= n[i] ^ m[i].rotate_left(7);
                    }
                    d[3] ^= t.rotate_left(15) ^ t.rotate_left(30) ^ t.rotate_left(6);
                }
                packed(d)
            }
            C::Sm4Encrypt | C::Sm4Schedule => {
                let mut state = words(if matches!(op, C::Sm4Encrypt) { d } else { n });
                let keys = words(if matches!(op, C::Sm4Encrypt) { n } else { m });
                for i in 0..4 {
                    let t = sm4_sub(
                        state[(i + 1) % 4] ^ state[(i + 2) % 4] ^ state[(i + 3) % 4] ^ keys[i],
                    );
                    let t = if matches!(op, C::Sm4Encrypt) {
                        t ^ t.rotate_left(2)
                            ^ t.rotate_left(10)
                            ^ t.rotate_left(18)
                            ^ t.rotate_left(24)
                    } else {
                        t ^ t.rotate_left(13) ^ t.rotate_left(23)
                    };
                    state[i] ^= t;
                }
                packed(state)
            }
        };
        self.vectors[rd] = result;
        true
    }
}
