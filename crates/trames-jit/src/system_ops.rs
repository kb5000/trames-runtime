// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold system-instruction classification. No host TLS or privileged register
//! access is forwarded from a guest instruction.
use trames_interpreter::NativeSystemRegister as R;

#[derive(Clone, Copy)]
pub(super) enum Register {
    Read(R),
    Write(R),
    Constant(u64),
    Counter { synchronized: bool },
    Random,
    ClearExclusive,
}
pub(super) fn register(word: u32) -> Option<Register> {
    if word & 0xfffff0ff == 0xd503305f {
        return Some(Register::ClearExclusive);
    }
    Some(match word & !31 {
        0xd53bd040 => Register::Read(R::Tls),
        0xd51bd040 => Register::Write(R::Tls),
        0xd53bd0a0 => Register::Read(R::Tls2),
        0xd51bd0a0 => Register::Write(R::Tls2),
        0xd53bd060 => Register::Constant(0),
        0xd53b0020 => Register::Constant(0xb4448004),
        0xd53b00e0 => Register::Constant(4),
        0xd53be000 => Register::Constant(trames_interpreter::counter::frequency()),
        0xd53be020 | 0xd53be040 => Register::Counter {
            synchronized: false,
        },
        0xd53be0a0 | 0xd53be0c0 => Register::Counter { synchronized: true },
        0xd53b4400 => Register::Read(R::Fpcr),
        0xd53b4420 => Register::Read(R::Fpsr),
        0xd51b4400 => Register::Write(R::Fpcr),
        0xd51b4420 => Register::Write(R::Fpsr),
        0xd53b2400 | 0xd53b2420 => Register::Random,
        _ => return None,
    })
}
pub(super) fn floating(op: Register) -> bool {
    matches!(
        op,
        Register::Read(R::Fpcr | R::Fpsr) | Register::Write(R::Fpcr | R::Fpsr)
    )
}
pub(super) fn barrier(word: u32) -> bool {
    matches!(word & 0xfffff0ff, 0xd503309f | 0xd50330bf | 0xd50330df) || word == 0xd50330ff
}
pub(super) fn hint(word: u32) -> bool {
    matches!(
        word,
        0xd503201f
            | 0xd503203f
            | 0xd503205f
            | 0xd503207f
            | 0xd503209f
            | 0xd50320bf
            | 0xd50320df
            | 0xd50320ff
            | 0xd503221f
            | 0xd503229f
            | 0xd503211f
            | 0xd503215f
            | 0xd503219f
            | 0xd50321df
            | 0xd503231f
            | 0xd503235f
            | 0xd503239f
            | 0xd50323df
            | 0xd503241f
            | 0xd503245f
            | 0xd503249f
            | 0xd50324df
            | 0xd503251f
            | 0xd503233f
            | 0xd503237f
            | 0xd50323bf
            | 0xd50323ff
            | 0xd50322df
            | 0xd503225f
            | 0xd503227f
    ) || matches!(word & !31, 0xd5031000 | 0xd5031020)
}

#[derive(Clone, Copy)]
pub(super) struct Boundary {
    pub word: u32,
}
impl Boundary {
    pub fn decode(word: u32) -> Option<Self> {
        matches!(word & 0xffe0001f, 0xd4200000 | 0xd4400000).then_some(Self { word })
    }
    pub fn native_call(self, cpu: &trames_interpreter::Cpu) -> bool {
        self.word == 0xd44a8a40 && cpu.native_call_target().is_some()
    }
    pub fn fault(self, pc: u64) -> trames_engine::CpuFault {
        trames_engine::CpuFault::Trap {
            pc,
            instruction: self.word,
            signal: if self.word & 0xffe0001f == 0xd4200000 {
                5
            } else {
                4
            },
            code: 1,
        }
    }
}
