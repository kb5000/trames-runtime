// SPDX-License-Identifier: GPL-3.0-or-later
//! One Linux ABI classification for original task/mm execution. Admission,
//! source custody, image replacement and bounded batching share these variants.
//! Guest registers are preserved; only ABI-defined integer selectors truncate.
use trames_engine::Cpu;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    Memory(Memory),
    Clone,
    Exec { at: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Memory {
    Break,
    Unmap,
    Remap,
    Map,
    Protect,
    Residency,
    Advice { discard: bool },
    Register { operation: u32 },
}
impl Call {
    pub fn decode(number: u32, args: [u64; 6]) -> Option<Self> {
        Some(match number {
            214 => Self::Memory(Memory::Break),
            215 => Self::Memory(Memory::Unmap),
            216 => Self::Memory(Memory::Remap),
            222 => Self::Memory(Memory::Map),
            226 => Self::Memory(Memory::Protect),
            232 => Self::Memory(Memory::Residency),
            233 => Self::Memory(Memory::Advice {
                discard: args[2] as u32 == 4,
            }),
            427 => Self::Memory(Memory::Register {
                operation: args[1] as u32,
            }),
            220 => Self::Clone,
            221 => Self::Exec { at: false },
            281 => Self::Exec { at: true },
            _ => return None,
        })
    }
    pub fn from_cpu<C: Cpu>(cpu: &C) -> Option<Self> {
        Self::decode(cpu.x(8) as u32, std::array::from_fn(|i| cpu.x(i)))
    }
    pub fn memory(self) -> Option<Memory> {
        match self {
            Self::Memory(memory) => Some(memory),
            _ => None,
        }
    }
    pub fn task(self) -> bool {
        !matches!(self, Self::Memory(_))
    }
    pub fn exec(self) -> bool {
        matches!(self, Self::Exec { .. })
    }
    pub fn number(self) -> u32 {
        match self {
            Self::Memory(memory) => memory.number(),
            Self::Clone => 220,
            Self::Exec { at: false } => 221,
            Self::Exec { at: true } => 281,
        }
    }
    /// Pinning requires original Memory before effects. Other registration
    /// commands keep their normal direct path; a genuine admission miss can
    /// still use this same original-resource structural route afterwards.
    pub fn preflight(self) -> bool {
        !matches!(self,Self::Memory(Memory::Register{operation}) if !matches!(operation,0|22))
    }
}
impl Memory {
    pub fn number(self) -> u32 {
        match self {
            Self::Break => 214,
            Self::Unmap => 215,
            Self::Remap => 216,
            Self::Map => 222,
            Self::Protect => 226,
            Self::Residency => 232,
            Self::Advice { .. } => 233,
            Self::Register { .. } => 427,
        }
    }
    pub fn index(self) -> usize {
        match self {
            Self::Break => 0,
            Self::Unmap => 1,
            Self::Remap => 2,
            Self::Map => 3,
            Self::Protect => 4,
            Self::Residency => 5,
            Self::Advice { discard: true } => 6,
            Self::Advice { discard: false } => 7,
            Self::Register { .. } => 8,
        }
    }
    pub fn mapping(self) -> bool {
        matches!(self, Self::Map)
    }
}
