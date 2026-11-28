// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold compare-branch decoding over the existing GPR bank; no extension state.
#[derive(Clone, Copy, Debug)]
pub struct CompareBranch {
    pub register: u8,
    /// Bit 7 selects an unsigned six-bit immediate; otherwise a GPR index.
    pub operand: u8,
    pub bits: u8,
    pub condition: u8,
    pub offset: i16,
}
impl CompareBranch {
    pub fn decode(word: u32) -> Option<Self> {
        if word & 0x7e000000 != 0x74000000 {
            return None;
        }
        let immediate = word & (1 << 24) != 0;
        let condition = ((word >> 21) & 7) as u8;
        if condition == 4 || condition == 5 {
            return None;
        }
        let bits = if immediate {
            if word & (1 << 14) != 0 {
                return None;
            }
            if word >> 31 != 0 {
                64
            } else {
                32
            }
        } else {
            match (word >> 14) & 3 {
                0 => {
                    if word >> 31 != 0 {
                        64
                    } else {
                        32
                    }
                }
                2 if word >> 31 == 0 => 8,
                3 if word >> 31 == 0 => 16,
                _ => return None,
            }
        };
        Some(Self {
            register: (word & 31) as u8,
            operand: if immediate {
                0x80 | ((word >> 15) & 63) as u8
            } else {
                ((word >> 16) & 31) as u8
            },
            bits,
            condition,
            offset: super::sign_extend(((word >> 5) & 511) as u64, 9).wrapping_mul(4) as i16,
        })
    }
    pub fn immediate(self) -> bool {
        self.operand & 0x80 != 0
    }
    pub fn taken(self, left: u64, right: u64) -> bool {
        let mask = super::width_mask(self.bits == 64) >> 32_u8.saturating_sub(self.bits);
        let left = left & mask;
        let right = if self.immediate() {
            (self.operand & 63) as u64
        } else {
            right & mask
        };
        let signed_left = super::sign_extend(left, self.bits as u32) as i64;
        let signed_right = super::sign_extend(right, self.bits as u32) as i64;
        match self.condition {
            0 => signed_left > signed_right,
            1 => {
                if self.immediate() {
                    signed_left < signed_right
                } else {
                    signed_left >= signed_right
                }
            }
            2 => left > right,
            3 => {
                if self.immediate() {
                    left < right
                } else {
                    left >= right
                }
            }
            6 => left == right,
            7 => left != right,
            _ => unreachable!("validated compare-branch condition"),
        }
    }
}
/// Owned control/exception spaces; unknown stateful/system instructions are not
/// thereby advertised. JIT uses original page/identity authority for fault nodes.
pub fn owns_encoding(word: u32) -> bool {
    word & 0xff000000 == 0x54000000
        || word & 0x7e000000 == 0x74000000
        || word & 0xfe000000 == 0xd6000000
        || word & 0xff000000 == 0xd4000000
}
