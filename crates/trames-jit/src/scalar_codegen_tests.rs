// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{collections::BTreeSet, io::Write};
use trames_memory::{Memory, Permissions};

#[test]
fn scalar_generated_code_receipt() {
    let Some(path) = std::env::var_os("TRAMES_JIT_SCALAR_CODEGEN") else {
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
    let mut seen = BTreeSet::new();
    let mut cases = 0;
    for (i, line) in include_str!("../../../docs/validation/jit-scalars-20261128/execution.words")
        .lines()
        .enumerate()
    {
        let (raw, form) = line.split_once(' ').unwrap();
        let first = seen.insert(form);
        if i % 257 != 0 && !first {
            continue;
        }
        let mut word = u32::from_str_radix(raw, 16).unwrap();
        // Compare existing canonical code on both versions. Noncanonical high
        // multiply acceptance has separate real-hardware/whole-state tests.
        if word & 0x1f000000 == 0x1b000000 && matches!((word >> 21) & 7, 2 | 6) {
            word |= 31 << 10;
        }
        for pressure in [false, true] {
            let mut words = if pressure {
                (0..31)
                    .map(|r| 0x91000400 | (r << 5) | r)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            words.extend_from_slice(&[word, 0xd4000001]);
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            for (i, word) in words.iter().enumerate() {
                memory
                    .write_array(0x1000 + 4 * i as u64, word.to_le_bytes())
                    .unwrap();
            }
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let compiled = compile_with_features(
                &memory,
                0x1000,
                64,
                0,
                8,
                trames_execution::Features {
                    hwcap: u64::MAX,
                    hwcap2: u64::MAX,
                },
            )
            .unwrap()
            .unwrap();
            write!(output, "{word:08x} {pressure}").unwrap();
            for word in compiled.block.code.published_words() {
                write!(output, " {word:08x}").unwrap();
            }
            writeln!(output).unwrap();
            cases += 1;
        }
    }
    eprintln!(
        "Scalar native-code receipt: {cases} compiled programs across {} forms",
        seen.len()
    );
}
