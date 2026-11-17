// SPDX-License-Identifier: GPL-3.0-or-later
//! Verified classic socket BPF. Guest pointers are imported by the Linux ABI.
use crate::{NetError, Result};
#[derive(Clone, Copy)]
struct Instruction {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
pub(crate) struct Program(Vec<Instruction>);
impl Program {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() % 8 != 0 || bytes.len() > 4096 * 8 {
            return Err(NetError(22));
        }
        let code: Vec<_> = bytes
            .chunks_exact(8)
            .map(|b| Instruction {
                code: u16::from_le_bytes([b[0], b[1]]),
                jt: b[2],
                jf: b[3],
                k: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            })
            .collect();
        for (pc, i) in code.iter().enumerate() {
            let valid = match i.code {
                0x00 | 0x01 | 0x80 | 0x81 | 0x20 | 0x28 | 0x30 | 0x40 | 0x48 | 0x50 | 0xb1
                | 0x06 | 0x16 | 0x07 | 0x87 => true,
                0x60 | 0x61 | 0x02 | 0x03 => i.k < 16,
                0x05 => (i.k as usize) < code.len() - pc - 1,
                0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                    usize::from(i.jt.max(i.jf)) < code.len() - pc - 1
                }
                0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x3c | 0x44 | 0x4c | 0x54 | 0x5c
                | 0x6c | 0x7c | 0x84 | 0x9c | 0xa4 | 0xac => true,
                0x64 | 0x74 => i.k < 32,
                0x34 | 0x94 => i.k != 0,
                _ => false,
            };
            // Ancillary negative offsets require per-protocol metadata and are
            // explicitly unsupported; never reinterpret them as host pointers.
            if !valid || matches!(i.code, 0x20 | 0x28 | 0x30 | 0xb1) && i.k >= 0xfffff000 {
                return Err(NetError(22));
            }
        }
        if !matches!(code.last().unwrap().code, 0x06 | 0x16) {
            return Err(NetError(22));
        }
        // Definite scratch initialization on every predecessor (forward-only CFG).
        let mut initialized = vec![None; code.len()];
        initialized[0] = Some(0u16);
        for (pc, i) in code.iter().enumerate() {
            let Some(mut mask) = initialized[pc] else {
                continue;
            };
            if matches!(i.code, 0x60 | 0x61) && mask & (1 << i.k) == 0 {
                return Err(NetError(22));
            }
            if matches!(i.code, 0x02 | 0x03) {
                mask |= 1 << i.k;
            }
            let mut edge = |at: usize| {
                if at < code.len() {
                    initialized[at] = Some(initialized[at].map_or(mask, |m| m & mask));
                }
            };
            match i.code & 7 {
                6 => (),
                5 if i.code == 5 => edge(pc + 1 + i.k as usize),
                5 => {
                    edge(pc + 1 + i.jt as usize);
                    edge(pc + 1 + i.jf as usize);
                }
                _ => edge(pc + 1),
            }
        }
        Ok(Self(code))
    }
    pub fn run(&self, packet: &[u8]) -> usize {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let mut m = [0u32; 16];
        while let Some(i) = self.0.get(pc) {
            pc += 1;
            let v = if i.code & 8 != 0 { x } else { i.k };
            match i.code {
                0x00 => a = i.k,
                0x01 => x = i.k,
                0x80 => a = packet.len() as u32,
                0x81 => x = packet.len() as u32,
                0x60 => a = m[i.k as usize],
                0x61 => x = m[i.k as usize],
                0x02 => m[i.k as usize] = a,
                0x03 => m[i.k as usize] = x,
                0x20 | 0x28 | 0x30 | 0x40 | 0x48 | 0x50 | 0xb1 => {
                    let off = u64::from(i.k)
                        + if i.code & 0xe0 == 0x40 {
                            u64::from(x)
                        } else {
                            0
                        };
                    let size = match i.code & 0x18 {
                        0 => 4,
                        8 => 2,
                        _ => 1,
                    };
                    let Some(bytes) = usize::try_from(off)
                        .ok()
                        .and_then(|off| packet.get(off..off.checked_add(size)?))
                    else {
                        return 0;
                    };
                    let value = bytes.iter().fold(0, |n, b| (n << 8) | u32::from(*b));
                    if i.code == 0xb1 {
                        x = (value & 15) << 2;
                    } else {
                        a = value;
                    }
                }
                0x04 | 0x0c => a = a.wrapping_add(v),
                0x14 | 0x1c => a = a.wrapping_sub(v),
                0x24 | 0x2c => a = a.wrapping_mul(v),
                0x34 | 0x3c => {
                    if v == 0 {
                        return 0;
                    }
                    a /= v;
                }
                0x94 | 0x9c => {
                    if v == 0 {
                        return 0;
                    }
                    a %= v;
                }
                0x44 | 0x4c => a |= v,
                0x54 | 0x5c => a &= v,
                0xa4 | 0xac => a ^= v,
                0x64 | 0x6c => a = a.wrapping_shl(v),
                0x74 | 0x7c => a = a.wrapping_shr(v),
                0x84 => a = a.wrapping_neg(),
                0x07 => x = a,
                0x87 => a = x,
                0x05 => pc += i.k as usize,
                0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                    let yes = match i.code & 0xf0 {
                        0x10 => a == v,
                        0x20 => a > v,
                        0x30 => a >= v,
                        _ => a & v != 0,
                    };
                    pc += usize::from(if yes { i.jt } else { i.jf });
                }
                0x06 => return i.k as usize,
                0x16 => return a as usize,
                _ => unreachable!("verified classic BPF"),
            }
        }
        0
    }
}
