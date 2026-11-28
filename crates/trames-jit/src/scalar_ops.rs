// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure cold scalar decoding and native lowering; no guest execution/state model.
use super::{logical_mask, signed, sp_register, Assembler};

pub(super) fn owns(word: u32) -> bool {
    matches!((word >> 25) & 15, 5 | 8 | 9 | 13)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Crc,
    Move,
    AddImmediate,
    AddShift,
    AddExtended,
    LogicalShift,
    LogicalImmediate,
    Bitfield,
    Extract,
    Select,
    Compare,
    Carry,
    Multiply,
    MinMax,
    Binary,
    Unary,
    Flags,
    FlagValue,
    ReadNzcv,
    WriteNzcv,
    Address,
}
pub(super) fn decode(word: u32) -> Option<Operation> {
    let sf = word >> 31;
    let flags = word & (1 << 29) != 0;
    let rm = (word >> 16) & 31;
    if word & 0x7fe0e000 == 0x1ac04000 {
        if (sf != 0) != (1 << ((word >> 10) & 3) == 8) {
            return None;
        }
        Some(Operation::Crc)
    } else if word & 0x1f800000 == 0x12800000 {
        if (word >> 29) & 3 == 1 || (sf == 0 && (word >> 21) & 3 >= 2) {
            return None;
        }
        Some(Operation::Move)
    } else if word & 0x1f800000 == 0x11000000 {
        Some(Operation::AddImmediate)
    } else if word & 0x1f200000 == 0x0b000000 {
        if (word >> 22) & 3 == 3 || (sf == 0 && (word >> 10) & 63 >= 32) {
            return None;
        }
        Some(Operation::AddShift)
    } else if word & 0x1f200000 == 0x0b200000 {
        if (word >> 10) & 7 > 4 || word & (3 << 22) != 0 {
            return None;
        }
        Some(Operation::AddExtended)
    } else if word & 0x1f000000 == 0x0a000000 {
        if sf == 0 && (word >> 10) & 63 >= 32 {
            return None;
        }
        Some(Operation::LogicalShift)
    } else if word & 0x1f800000 == 0x12000000 {
        if !logical_mask(
            (word >> 22) & 1,
            (word >> 10) & 63,
            (word >> 16) & 63,
            sf != 0,
        ) {
            return None;
        }
        Some(Operation::LogicalImmediate)
    } else if word & 0x1f800000 == 0x13000000 {
        if (word >> 29) & 3 == 3
            || (word >> 22) & 1 != sf
            || (word >> 16) & 63 >= if sf == 0 { 32 } else { 64 }
            || (word >> 10) & 63 >= if sf == 0 { 32 } else { 64 }
        {
            return None;
        }
        Some(Operation::Bitfield)
    } else if word & 0x1f800000 == 0x13800000 {
        if word & 0x60200000 != 0 || (word >> 22) & 1 != sf || (sf == 0 && (word >> 10) & 63 >= 32)
        {
            return None;
        }
        Some(Operation::Extract)
    } else if word & 0x1fe00800 == 0x1a800000 {
        if flags {
            return None;
        }
        Some(Operation::Select)
    } else if word & 0x1fe00410 == 0x1a400000 {
        if !flags {
            return None;
        }
        Some(Operation::Compare)
    } else if word & 0x1fe0fc00 == 0x1a000000 {
        Some(Operation::Carry)
    } else if word & 0x1f000000 == 0x1b000000 {
        if word & 0x60000000 != 0
            || !((word >> 21) & 7 == 0
                || (sf != 0 && matches!((word >> 21) & 7, 1 | 5))
                || (sf != 0 && word & (1 << 15) == 0 && matches!((word >> 21) & 7, 2 | 6)))
        {
            return None;
        }
        Some(Operation::Multiply)
    } else if word & 0x7fe0f000 == 0x1ac06000 || word & 0x7ff00000 == 0x11c00000 {
        Some(Operation::MinMax)
    } else if word & 0x5fe00000 == 0x1ac00000 {
        if flags || !matches!((word >> 10) & 63, 2 | 3 | 8..=11) {
            return None;
        }
        Some(Operation::Binary)
    } else if word & 0x7fe00000 == 0x5ac00000 {
        if rm != 0 || (word >> 10) & 63 > 8 || (sf == 0 && (word >> 10) & 63 == 3) {
            return None;
        }
        Some(Operation::Unary)
    } else if matches!(word, 0xd500401f | 0xd500403f | 0xd500405f) {
        Some(Operation::Flags)
    } else if word & 0xffe07c10 == 0xba000400 || word & 0xffffbc1f == 0x3a00080d {
        Some(Operation::FlagValue)
    } else if word & 0xffffffe0 == 0xd53b4200 {
        Some(Operation::ReadNzcv)
    } else if word & 0xffffffe0 == 0xd51b4200 {
        Some(Operation::WriteNzcv)
    } else if word & 0x1f000000 == 0x10000000 {
        Some(Operation::Address)
    } else {
        None
    }
}
pub(super) fn emit(code: &mut Assembler, word: u32, pc: u64) -> bool {
    let Some(operation) = decode(word) else {
        return false;
    };
    let rd = word & 31;
    let rn = (word >> 5) & 31;
    let rm = (word >> 16) & 31;
    let sf = word >> 31;
    let flags = word & (1 << 29) != 0;
    match operation {
        Operation::Crc => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        }
        Operation::Move => {
            let opc = (word >> 29) & 3;
            if opc == 3 {
                code.read(rd, 0);
            }
            let dest = code.output(rd, 0);
            code.words.push((word & !31) | dest);
        }
        Operation::AddImmediate => {
            let lhs = code.read(sp_register(rn), 0);
            let dest = code.output(if flags { rd } else { sp_register(rd) }, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        }
        Operation::AddShift => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        }
        Operation::AddExtended => {
            let lhs = code.read(sp_register(rn), 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(
                if flags { rd } else { sp_register(rd) },
                (1 << lhs) | (1 << rhs),
            );
            // The reference accepts UXTX/SXTX in a W operation. Its low 32
            // bits are identical to UXTW/SXTW; use the valid host W encoding.
            let word = if sf == 0 && (word >> 13) & 3 == 3 {
                word & !(1 << 13)
            } else {
                word
            };
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        }
        Operation::LogicalShift => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if (word >> 29) & 3 == 3 {
                code.flags_written();
            }
        }
        Operation::LogicalImmediate => {
            let lhs = code.read(rn, 0);
            let writes_flags = (word >> 29) & 3 == 3;
            let dest = code.output(if writes_flags { rd } else { sp_register(rd) }, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
            if writes_flags {
                code.flags_written();
            }
        }
        Operation::Bitfield => {
            let opc = (word >> 29) & 3;
            let lhs = code.read(rn, 0);
            if opc == 1 {
                code.read(rd, 1 << lhs);
            }
            let dest = code.output(rd, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
        }
        Operation::Extract => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        }
        Operation::Select => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.flags_read();
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        }
        Operation::Compare => {
            let lhs = code.read(rn, 0);
            let rhs = if word & (1 << 11) == 0 {
                code.read(rm, 1 << lhs)
            } else {
                rm
            };
            code.flags_read();
            code.words
                .push((word & !0x1f03e0) | (rhs << 16) | (lhs << 5));
            code.flags_written();
        }
        Operation::Carry => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.flags_read();
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        }
        Operation::Multiply => {
            // SMULH/UMULH ignore Ra in hardware. Select canonical ZR during
            // translation; never bind or load the guest's unused field.
            let ra = if matches!((word >> 21) & 7, 2 | 6) {
                31
            } else {
                (word >> 10) & 31
            };
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let addend = code.read(ra, (1 << lhs) | (1 << rhs));
            let dest = code.output(rd, (1 << lhs) | (1 << rhs) | (1 << addend));
            code.words
                .push((word & !0x1f7fff) | (rhs << 16) | (addend << 10) | (lhs << 5) | dest);
        }
        Operation::MinMax => {
            let immediate = word & 0x7ff00000 == 0x11c00000;
            let lhs = code.read(rn, 0);
            let rhs = if immediate {
                0
            } else {
                code.read(rm, 1 << lhs)
            };
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            let mask = if immediate { 0x3ff } else { 0x1f03ff };
            code.words
                .push((word & !mask) | (if immediate { 0 } else { rhs << 16 }) | (lhs << 5) | dest);
        }
        Operation::Binary => {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        }
        Operation::Unary => {
            let lhs = code.read(rn, 0);
            let dest = code.output(rd, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
        }
        Operation::Flags => {
            code.flags_read();
            code.words.push(word);
            code.flags_written();
        }
        Operation::FlagValue => {
            let source = code.read(rn, 0);
            code.flags_read();
            code.words.push((word & !0x3e0) | (source << 5));
            code.flags_written();
        }
        Operation::ReadNzcv => {
            let dest = code.output(rd, 0);
            code.flags_read();
            code.words.push(0xd53b4200 | dest);
        }
        Operation::WriteNzcv => {
            let value = code.read(rd, 0);
            code.words.push(0xd51b4200 | value);
            code.flags_written();
        }
        Operation::Address => {
            let imm = signed(
                (((word >> 5) & 0x7ffff) as u64) << 2 | ((word >> 29) & 3) as u64,
                21,
            );
            let value = if sf == 1 {
                (pc & !0xfff).wrapping_add(imm << 12)
            } else {
                pc.wrapping_add(imm)
            };
            code.constant(rd, value);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn ignored_high_multiply_fields_never_bind_the_unused_register() {
        for base in [0x9b400020, 0x9bc00020] {
            let mut reference = Assembler::new();
            assert!(emit(&mut reference, base | (31 << 10), 0x1000));
            for ignored in 0..32 {
                let mut actual = Assembler::new();
                assert!(emit(&mut actual, base | (ignored << 10), 0x1000));
                assert_eq!(actual.words, reference.words);
                assert_eq!(
                    actual.traffic.register_loads,
                    reference.traffic.register_loads
                );
                assert!(actual
                    .words
                    .iter()
                    .any(|&w| w & 0xffe08000 == base & 0xffe08000));
            }
        }
    }
    #[test]
    fn cold_scalar_encoding_admission() {
        let mut output = std::env::var_os("TRAMES_JIT_SCALAR_ADMISSION")
            .map(|path| std::io::BufWriter::new(std::fs::File::create(path).unwrap()));
        let mut counts = [0u64; 21];
        let mut candidates = 0;
        for high in 0..512u32 {
            if !owns(high << 23) {
                continue;
            }
            for middle in 0..8192 {
                let word = (high << 23) | (middle << 10) | (1 << 5);
                candidates += 1;
                if let Some(op) = decode(word) {
                    counts[op as usize] += 1;
                    if let Some(output) = &mut output {
                        writeln!(output, "{word:08x} {op:?}").unwrap();
                    }
                }
            }
        }
        for word in [
            0xd500401f, 0xd500403f, 0xd500405f, 0x3a00082d, 0x3a00482d, 0xd53b4200, 0xd51b4200,
        ] {
            let op = decode(word).unwrap();
            counts[op as usize] += 1;
            if let Some(output) = &mut output {
                writeln!(output, "{word:08x} {op:?}").unwrap();
            }
        }
        assert_eq!(candidates, 1_048_576);
        assert!(counts.iter().all(|&count| count > 0), "{counts:?}");
        eprintln!("cold scalar selectors: {candidates}; forms {counts:?}");
    }
    struct Word(u32);
    impl trames_memory::CpuMemory for Word {
        fn mapped_at_or_after(&self, _a: u64) -> bool {
            false
        }
        fn read(&self, _a: u64, _out: &mut [u8]) -> Result<(), trames_memory::MemoryError> {
            panic!("scalar data read")
        }
        fn write(&mut self, _a: u64, _bytes: &[u8]) -> Result<(), trames_memory::MemoryError> {
            panic!("scalar data write")
        }
        fn check(
            &self,
            _a: u64,
            _len: usize,
            _access: trames_memory::Access,
        ) -> Result<(), trames_memory::MemoryError> {
            panic!("scalar data permission query")
        }
        fn check_translation(&self, _a: u64) -> Result<(), trames_memory::MemoryError> {
            panic!("scalar data translation")
        }
        fn fetch_u32(&self, _a: u64) -> Result<u32, trames_memory::MemoryError> {
            Ok(self.0)
        }
        fn instruction_identity(&self) -> (u64, u64, u64) {
            (0, 0, self.0 as u64)
        }
        fn instruction_page_identity(
            &self,
            _a: u64,
        ) -> Result<(u64, u64, u64), trames_memory::MemoryError> {
            Ok((0, 0, self.0 as u64))
        }
        fn atomic_update<T>(
            &mut self,
            _a: u64,
            _len: usize,
            _f: impl FnOnce(&mut [u8]) -> (T, bool),
        ) -> Result<T, trames_memory::MemoryError> {
            panic!("scalar transaction")
        }
        fn exclusive_read(
            &mut self,
            _a: u64,
            _out: &mut [u8],
        ) -> Result<u128, trames_memory::MemoryError> {
            panic!("scalar exclusive read")
        }
        fn exclusive_write(
            &mut self,
            _a: u64,
            _bytes: &[u8],
            _token: Option<u128>,
        ) -> Result<bool, trames_memory::MemoryError> {
            panic!("scalar exclusive write")
        }
    }
    #[test]
    fn every_untranslated_scalar_selector_is_an_original_reference_instruction_fault() {
        let mut output = std::env::var_os("TRAMES_JIT_SCALAR_REJECTED")
            .map(|p| std::io::BufWriter::new(std::fs::File::create(p).unwrap()));
        let mut cpu = trames_interpreter::Cpu::new(0x1000, 0x2000);
        let original = cpu.architectural_state();
        let mut mismatches = Vec::new();
        let mut checked = 0;
        for high in 0..512u32 {
            if !owns(high << 23) {
                continue;
            }
            for middle in 0..8192 {
                let word = (high << 23) | (middle << 10) | (1 << 5);
                if decode(word).is_some() {
                    continue;
                }
                let mut code = Assembler::new();
                if super::super::compatibility::register(&mut code, word, 0x1000).is_some() {
                    continue;
                }
                cpu.restore_architectural_state(&original);
                let result = cpu.step(&mut Word(word));
                if !matches!(result,Err(trames_engine::CpuFault::Instruction{pc:0x1000,instruction}) if instruction==word)
                    && mismatches.len() < 64
                {
                    mismatches.push((word, format!("{result:?}")));
                }
                if checked % 64 == 0 {
                    if let Some(output) = &mut output {
                        writeln!(output, "{word:08x}").unwrap();
                    }
                }
                checked += 1;
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:x?}");
        eprintln!("Original interpreter fault closure: {checked} rejected scalar selectors");
    }
}
