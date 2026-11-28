// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::io::Write;
use trames_engine::CpuFault;

struct Word(u32);
impl CpuMemory for Word {
    fn mapped_at_or_after(&self, _: u64) -> bool {
        false
    }
    fn read(&self, _: u64, _: &mut [u8]) -> Result<(), trames_memory::MemoryError> {
        panic!("control data read")
    }
    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), trames_memory::MemoryError> {
        panic!("control data write")
    }
    fn check(
        &self,
        _: u64,
        _: usize,
        _: trames_memory::Access,
    ) -> Result<(), trames_memory::MemoryError> {
        panic!("control data check")
    }
    fn check_translation(&self, _: u64) -> Result<(), trames_memory::MemoryError> {
        panic!("control data translation")
    }
    fn fetch_u32(&self, _: u64) -> Result<u32, trames_memory::MemoryError> {
        Ok(self.0)
    }
    fn instruction_identity(&self) -> Identity {
        (0, 0, self.0 as u64)
    }
    fn instruction_page_identity(&self, _: u64) -> Result<Identity, trames_memory::MemoryError> {
        Ok(self.instruction_identity())
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, trames_memory::MemoryError> {
        panic!("control transaction")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, trames_memory::MemoryError> {
        panic!("control reservation")
    }
    fn exclusive_write(
        &mut self,
        _: u64,
        _: &[u8],
        _: Option<u128>,
    ) -> Result<bool, trames_memory::MemoryError> {
        panic!("control reservation")
    }
}

#[test]
fn every_cmpbr_selector_matches_llvm_admission_and_retains_real_opcode() {
    let mut valid = 0;
    for line in
        include_str!("../../../docs/validation/jit-control-20261128/compare-selectors.words")
            .lines()
    {
        let (raw, accepted) = line.split_once(' ').unwrap();
        let word = u32::from_str_radix(raw, 16).unwrap();
        let compiled = compile_with_features(
            &Word(word),
            0x1000,
            1,
            0,
            0,
            trames_execution::Features {
                hwcap: u64::MAX,
                hwcap2: u64::MAX,
            },
        )
        .unwrap();
        assert_eq!(compiled.is_some(), accepted == "1", "{word:x}");
        if let Some(compiled) = compiled {
            let opcodes: Vec<_> = compiled
                .block
                .code
                .published_words()
                .iter()
                .copied()
                .filter(|w| w & 0x7e000000 == 0x74000000)
                .collect();
            assert!(!opcodes.is_empty(), "{word:x}");
            // Only register allocation and local branch displacement change.
            let variable = 0x3fff | if word & (1 << 24) == 0 { 31 << 16 } else { 0 };
            assert!(
                opcodes.iter().all(|op| op & !variable == word & !variable),
                "{word:x}"
            );
            assert!(
                !compiled
                    .block
                    .code
                    .published_words()
                    .iter()
                    .any(|w| matches!(w & 0xffffffe0, 0xd53b4200 | 0xd51b4200)),
                "CMPBR must not read/write NZCV"
            );
            valid += 1;
        }
    }
    assert_eq!(valid, 1536);
    for condition in 0..16 {
        let word = 0x54000010 | condition;
        let compiled = compile_with_features(
            &Word(word),
            0x1000,
            1,
            0,
            0,
            trames_execution::Features {
                hwcap: 3,
                hwcap2: 1 << 44,
            },
        )
        .unwrap()
        .unwrap();
        assert!(compiled
            .block
            .code
            .published_words()
            .iter()
            .any(|w| w & 0xff00001f == word));
    }
}

fn handled(word: u32) -> bool {
    word & 0xff000000 == 0x54000000
        || trames_interpreter::control::CompareBranch::decode(word).is_some()
        || matches!(word & 0xfffffc1f, 0xd61f0000 | 0xd63f0000 | 0xd65f0000)
        || compatibility::register(&mut Assembler::new(), word, 0x1000).is_some()
        || crate::system_ops::Boundary::decode(word).is_some()
        || word & 0xffe0001f == 0xd4000001
}
#[test]
fn untranslated_owned_control_selectors_are_original_reference_faults() {
    let mut output = std::env::var_os("TRAMES_JIT_CONTROL_REJECTED")
        .map(|p| std::io::BufWriter::new(std::fs::File::create(p).unwrap()));
    let mut cpu = trames_interpreter::Cpu::new(0x1000, 0x2000);
    let original = cpu.architectural_state();
    let mut count = 0;
    let mut check = |word| {
        assert!(trames_interpreter::control::owns_encoding(word));
        if handled(word) {
            return;
        }
        cpu.restore_architectural_state(&original);
        let result = cpu.step(&mut Word(word));
        assert!(
            matches!(result, Err(CpuFault::Instruction { pc: 0x1000, instruction }) if instruction == word),
            "{word:x}/{result:?}"
        );
        if count % 64 == 0 {
            if let Some(output) = &mut output {
                writeln!(output, "{word:08x}").unwrap();
            }
        }
        count += 1;
    };
    // Complete high opcode selectors; independently exercise low modifier and
    // source aliases. Literal/register values do not stand in for new opcodes.
    for high in 0..2 {
        for middle in 0..16384 {
            for source in [0, 1, 18, 30, 31] {
                for low in [0, 1, 17, 30, 31] {
                    check(0xd6000000 | (high << 24) | (middle << 10) | (source << 5) | low);
                }
            }
        }
    }
    for selector in 0..8 {
        for immediate in [0, 1, 0x7fff, 0xffff] {
            for low in 0..32 {
                check(0xd4000000 | (selector << 21) | (immediate << 5) | low);
            }
        }
    }
    for line in
        include_str!("../../../docs/validation/jit-control-20261128/compare-selectors.words")
            .lines()
    {
        check(u32::from_str_radix(line.split_once(' ').unwrap().0, 16).unwrap());
    }
    eprintln!("Original control fault closure: {count} selectors");
}

#[test]
fn control_generated_code_receipt() {
    let Some(path) = std::env::var_os("TRAMES_JIT_CONTROL_CODEGEN") else {
        return;
    };
    let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    writeln!(
        output,
        "LAYOUT {} {} {} {}",
        std::mem::size_of::<crate::memory_ops::Operation>(),
        std::mem::size_of::<Block>(),
        std::mem::size_of::<Node>(),
        std::mem::size_of::<Frame>()
    )
    .unwrap();
    let words = include_str!("../../../docs/validation/jit-control-20261128/category.words");
    let rows = include_str!("../../../docs/validation/jit-control-20261128/category.cases");
    for (raw, row) in words.lines().zip(rows.lines()) {
        if row.starts_with("hbc ") || row.starts_with("cmp ") {
            continue;
        }
        let word = u32::from_str_radix(raw, 16).unwrap();
        let compiled = compile_with_features(
            &Word(word),
            0x1000,
            1,
            0,
            0,
            trames_execution::Features {
                hwcap: u64::MAX,
                hwcap2: u64::MAX,
            },
        )
        .unwrap()
        .unwrap();
        write!(output, "{word:08x}").unwrap();
        for word in compiled.block.code.published_words() {
            write!(output, " {word:08x}").unwrap();
        }
        writeln!(output).unwrap();
    }
}
