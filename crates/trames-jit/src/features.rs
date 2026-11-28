// SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable process-host capabilities. No per-task extension model or hot probes.
use std::sync::OnceLock;
use trames_execution::Features;

pub(crate) struct Profile {
    pub raw: Features,
    pub allowed: Features,
    pub names: String,
    pub lor: bool,
}
static PROFILE: OnceLock<Profile> = OnceLock::new();
const NAMES: &[(usize, u8, &str)] = &[
    (0, 0, "fp"),
    (0, 1, "asimd"),
    (0, 3, "aes"),
    (0, 4, "pmull"),
    (0, 5, "sha1"),
    (0, 6, "sha2"),
    (0, 7, "crc32"),
    (0, 8, "atomics"),
    (0, 9, "fphp"),
    (0, 10, "asimdhp"),
    (0, 12, "asimdrdm"),
    (0, 13, "jscvt"),
    (0, 14, "fcma"),
    (0, 15, "lrcpc"),
    (0, 17, "sha3"),
    (0, 18, "sm3"),
    (0, 19, "sm4"),
    (0, 20, "asimddp"),
    (0, 21, "sha512"),
    (0, 23, "asimdfhm"),
    (0, 26, "ilrcpc"),
    (0, 27, "flagm"),
    (0, 29, "sb"),
    (1, 7, "flagm2"),
    (1, 8, "frint"),
    (1, 13, "i8mm"),
    (1, 14, "bf16"),
    (1, 15, "dgh"),
    (1, 16, "rng"),
    (1, 34, "cssc"),
    (1, 43, "mops"),
    (1, 47, "lse128"),
];
pub(crate) fn profile() -> &'static Profile {
    PROFILE.get_or_init(|| {
        // The OS-provided process capabilities already account for heterogeneous
        // CPUs and enabled user ABI. Read once, never per guest instruction.
        let raw = Features {
            hwcap: unsafe { libc::getauxval(libc::AT_HWCAP) } as u64,
            hwcap2: unsafe { libc::getauxval(libc::AT_HWCAP2) } as u64,
        };
        // Transitional ABI coverage: never add a software-only capability to
        // the host. Stateful extensions wait for their real context-save path.
        let allowed = Features {
            hwcap: raw.hwcap & trames_interpreter::HWCAP,
            hwcap2: raw.hwcap2 & (trames_interpreter::HWCAP2 | (1 << 47)),
        };
        let words = [allowed.hwcap, allowed.hwcap2];
        let names = NAMES
            .iter()
            .filter(|&&(word, bit, _)| words[word] & (1 << bit) != 0)
            .map(|&(_, _, name)| name)
            .collect::<Vec<_>>()
            .join(" ");
        // Linux's HWCAP_CPUID ABI returns a system-wide safe, sanitized ID
        // register. Hidden LOR fields remain zero; never probe a physical core.
        let lor = if raw.hwcap & (1 << 11) != 0 {
            let id: u64;
            unsafe { std::arch::asm!("mrs {}, id_aa64mmfr1_el1", out(reg) id, options(nomem, nostack, preserves_flags)); }
            (id >> 16) & 15 == 1
        } else { false };
        Profile { raw, allowed, names, lor }
    })
}
/// Cold translation gate. A missing extension faults when reached, rather than
/// acquiring the reference interpreter's software implementation.
pub(crate) fn permits(host: Features, word: u32) -> bool {
    if matches!(
        word & 0xffe0fc00,
        0xf8209000 | 0xf820a000 | 0xf820b000 | 0xf820d000
    ) {
        // LS64 needs the HWCAP3/device-memory contract, which this CPU profile
        // does not expose. Do not reinterpret it as LSE or software-emulate it.
        return false;
    }
    if matches!(word & 0x3ffffc00, 0x08df7c00 | 0x089f7c00) {
        return profile().lor;
    }
    // MOPS SETG also requires real allocation-tag ownership. The current JIT
    // CPU does not advertise MTE, so no compatibility fill can implement it.
    if word & 0xffe00c00 == 0x1dc00400 {
        return false;
    }
    if let Some(op) = crate::vector_ops::decode(word) {
        return host.hwcap & op.required.hwcap == op.required.hwcap
            && host.hwcap2 & op.required.hwcap2 == op.required.hwcap2;
    }
    let required = if matches!(word & 0xbf000000, 0x0c000000 | 0x0d000000) {
        Some((0, 1)) // AdvSIMD multiple/single structures and replicate loads
    } else if word & 0x3ffffc00 == 0x38bfc000 {
        Some((0, 15)) // LRCPC: LDAPR/B/H
    } else if word & 0x3f200c00 == 0x19000000 {
        Some((0, 26)) // ILRCPC: LDAPUR/STLUR and sign-extending forms
    } else if word & 0xbfa07c00 == 0x08207c00
        || word & 0x3fa07c00 == 0x08a07c00
        || word & 0x3f200c00 == 0x38200000
    {
        Some((0, 8)) // LSE, including discard-result store aliases
    } else if word & 0x7fe0e000 == 0x1ac04000 {
        Some((0, 7))
    } else if matches!(word & 0x7ffffc00, 0x5ac01800 | 0x5ac01c00 | 0x5ac02000)
        || word & 0x7fe0f000 == 0x1ac06000
        || word & 0x7ff00000 == 0x11c00000
    {
        Some((1, 34))
    } else if word == 0xd500401f
        || word & 0xffe07c10 == 0xba000400
        || word & 0xffffbc1f == 0x3a00080d
    {
        Some((0, 27))
    } else if matches!(word, 0xd500403f | 0xd500405f) {
        Some((1, 7))
    } else if word == 0xd50330ff {
        Some((0, 29)) // SB is an instruction, unlike backward-compatible hints.
    } else if matches!(word & 0xffffffe0, 0xd53b2400 | 0xd53b2420) {
        Some((1, 16))
    } else if matches!(word & 0xff200c00, 0x19000400 | 0x1d000400) {
        Some((1, 43))
    } else if matches!(word & 0xff20fc00, 0x19208000 | 0x19201000 | 0x19203000) {
        Some((1, 47))
    } else {
        None
    };
    if let Some((index, bit)) = required {
        [host.hwcap, host.hwcap2][index] & (1 << bit) != 0
    } else {
        fallback_permits(host, word)
    }
}

/// Close ISA gates for untranslated forms as well as native ones. This runs
/// only while compiling a block/negative cache entry, before interpreter entry.
fn fallback_permits(host: Features, word: u32) -> bool {
    let scalar = matches!(word & 0xdf000000, 0x5e000000 | 0x5f000000);
    let normal = if scalar { word & !(1 << 28) } else { word };
    let unary = normal & 0xbffffc00;
    let binary = normal & 0xbfe0fc00;
    let indexed = normal & 0xbfc0f400;
    let mut need = Features {
        hwcap: 0,
        hwcap2: 0,
    };
    if word & 0xfffffc00 == 0x1e7e0000 {
        need.hwcap = 1 << 13; // JSCVT
    } else if word & 0xfffffc00 == 0x1e634000
        || unary == 0x0ea16800
        || matches!(binary, 0x2e40fc00 | 0x2e40ec00 | 0x2ec0fc00)
        || matches!(indexed, 0x0f40f000 | 0x0fc0f000)
    {
        need.hwcap2 = 1 << 14; // BF16, including scalar/vector conversion
    } else if matches!(binary, 0x0e20ec00 | 0x0ea0ec00 | 0x2e20cc00 | 0x2ea0cc00)
        || matches!(indexed, 0x0f800000 | 0x0f804000 | 0x2f808000 | 0x2f80c000)
    {
        need.hwcap = 1 << 23; // FHM
    } else if word & 0xbf20e400 == 0x2e00c400
        || word & 0xbf20ec00 == 0x2e00e400
        || word & 0xbf009400 == 0x2f001000
    {
        need.hwcap = (1 << 14) | if (word >> 22) & 3 == 1 { 1 << 10 } else { 0 };
    // FCMA + FP16
    } else if matches!(
        normal & 0xbf20fc00,
        0x0e009c00 | 0x0e00a400 | 0x2e00a400 | 0x0e00ac00
    ) || normal & 0xbf00f400 == 0x0f00f000
    {
        need.hwcap2 = 1 << 13; // I8MM, mixed signed dot and matrix forms
    } else if matches!(normal & 0xbf20fc00, 0x0e009400 | 0x2e009400)
        || matches!(normal & 0xbf00f400, 0x0f00e000 | 0x2f00e000)
    {
        need.hwcap = 1 << 20; // DotProd
    } else if matches!(normal & 0xbf20fc00, 0x2e008400 | 0x2e008c00)
        || matches!(normal & 0xbf00f400, 0x2f00d000 | 0x2f00f000)
    {
        need.hwcap = 1 << 12; // RDM
    } else if half_instruction(normal, unary, binary, indexed) {
        need.hwcap = 1 << if scalar { 9 } else { 10 };
    } else if word & 0xff207c00 == 0x1e204000 && matches!((word >> 15) & 63, 16..=19) {
        need.hwcap2 = 1 << 8; // FRINT32/64
    } else if word & 0x5f000000 == 0x1e000000 || word & 0x5f000000 == 0x1f000000 {
        need.hwcap = 1 << if (word >> 22) & 3 == 3 { 9 } else { 0 };
    } else if word & 0x0e000000 == 0x0e000000 {
        need.hwcap = 1 << 1;
    }
    host.hwcap & need.hwcap == need.hwcap && host.hwcap2 & need.hwcap2 == need.hwcap2
}

fn half_instruction(normal: u32, unary: u32, binary: u32, indexed: u32) -> bool {
    matches!(indexed, 0x0f009000 | 0x2f009000 | 0x0f001000 | 0x0f005000)
        || matches!(binary, 0x0f00e400 | 0x2f00e400 | 0x0f00fc00 | 0x2f00fc00)
            && (16..32).contains(&((normal >> 16) & 127))
        || matches!(
            unary,
            0x0e30c800
                | 0x0eb0c800
                | 0x0e30f800
                | 0x0eb0f800
                | 0x0e30d800
                | 0x0ef8f800
                | 0x2ef8f800
                | 0x2ef9f800
                | 0x0e798800
                | 0x0ef98800
                | 0x0e799800
                | 0x0ef99800
                | 0x2e798800
                | 0x2e799800
                | 0x2ef99800
                | 0x0e79d800
                | 0x2e79d800
                | 0x0ef9b800
                | 0x2ef9b800
                | 0x0e79a800
                | 0x2e79a800
                | 0x0ef9a800
                | 0x2ef9a800
                | 0x0e79b800
                | 0x2e79b800
                | 0x0e79c800
                | 0x2e79c800
                | 0x0ef9d800
                | 0x2ef9d800
                | 0x0ef9f800
                | 0x0ef8c800
                | 0x2ef8c800
                | 0x0ef8d800
                | 0x2ef8d800
                | 0x0ef8e800
        )
        || matches!(
            binary,
            0x0e401400
                | 0x0ec01400
                | 0x2e401c00
                | 0x2e403c00
                | 0x0e400c00
                | 0x0ec00c00
                | 0x0e403400
                | 0x0ec03400
                | 0x0e400400
                | 0x0ec00400
                | 0x0e402400
                | 0x2e402400
                | 0x2ec02400
                | 0x2e402c00
                | 0x2ec02c00
                | 0x2e401400
                | 0x0e401c00
                | 0x2ec01400
                | 0x2e403400
                | 0x2ec03400
                | 0x2e400400
                | 0x2ec00400
                | 0x0e403c00
                | 0x0ec03c00
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_profile_never_advertises_software_only_or_unowned_state() {
        let p = profile();
        assert_eq!(p.allowed.hwcap & !p.raw.hwcap, 0);
        assert_eq!(p.allowed.hwcap2 & !p.raw.hwcap2, 0);
        assert_eq!(p.allowed.hwcap & ((1 << 22) | (1 << 30) | (1 << 31)), 0); // SVE / PAC
        assert_eq!(p.allowed.hwcap2 & ((1 << 17) | (1 << 18) | (1 << 23)), 0); // BTI/MTE/SME state
        for &(index, bit, name) in NAMES {
            assert_eq!(
                p.names.split_whitespace().any(|n| n == name),
                [p.allowed.hwcap, p.allowed.hwcap2][index] & (1 << bit) != 0
            );
        }
    }
    #[test]
    fn untranslated_extensions_cannot_escape_host_isa_gates() {
        let base = Features {
            hwcap: 3,
            hwcap2: 0,
        };
        for (word, index, bit) in [
            (0x1e7e0020, 0, 13),
            (0x1e634020, 1, 14),
            (0x0ea16820, 1, 14),
            (0x6e40fc20, 1, 14),
            (0x4e20ec20, 0, 23),
            (0x6e80e420, 0, 14),
            (0x4e829420, 0, 20),
            (0x4e829c20, 1, 13),
            (0x4e82a420, 1, 13),
            (0x6e428420, 0, 12),
            (0x4e421420, 0, 10),
            (0x5e421420, 0, 9),
            (0x4ef9d820, 0, 10),
            (0x1e284020, 1, 8),
            (0xd50330ff, 0, 29),
        ] {
            assert!(!permits(base, word), "{word:08x}");
            let mut enabled = base;
            if index == 0 {
                enabled.hwcap |= 1 << bit;
            } else {
                enabled.hwcap2 |= 1 << bit;
            }
            assert!(permits(enabled, word), "{word:08x}");
        }
        for word in [0xf83fd020, 0xf83f9020, 0xf822a020, 0xf822b020] {
            assert!(!permits(
                Features {
                    hwcap: u64::MAX,
                    hwcap2: u64::MAX
                },
                word
            ));
        }
    }

    #[test]
    fn limited_ordering_uses_an_explicit_safe_host_gate_and_ls64_owns_no_device_contract() {
        use trames_engine::{Cpu as Backend, SliceOutcome};
        use trames_execution::Registers;
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let fixture =
            include_str!("../../../docs/validation/jit-special-memory-20261128/category.words");
        let words: Vec<_> = fixture
            .lines()
            .map(|line| u32::from_str_radix(line, 16).unwrap())
            .collect();
        let all = Features {
            hwcap: u64::MAX,
            hwcap2: u64::MAX,
        };
        for &word in &words[504..536] {
            assert_eq!(permits(all, word), profile().lor);
            if profile().lor {
                continue;
            }
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.write_array(0x1000, word.to_le_bytes()).unwrap();
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let mut cpu = crate::Cpu::new(0x1000, 0x2800);
            let mut engine = crate::Engine::default();
            assert!(matches!(
                cpu.run(&mut engine, &mut memory, 64),
                SliceOutcome::Fault(_)
            ));
            assert_eq!(
                (
                    cpu.pc(),
                    cpu.fault_retired(),
                    engine.stats.fallback_instructions
                ),
                (0x1000, 0, 0)
            );
        }
        for &word in &words[536..] {
            assert!(!permits(all, word));
        }
    }

    #[test]
    fn extension_gates_are_cold_and_do_not_gain_emulated_support() {
        let base = Features {
            hwcap: 3,
            hwcap2: 0,
        };
        for word in [
            0x1ac24020, 0x5ac01820, 0x1ac26020, 0xd500401f, 0xd500403f, 0xd53b2400, 0x19000400,
            0x19208000, 0xf8220020, 0xc8a07c22, 0x48207c22, 0xf8bfc020, 0xd9400020, 0x1ee22820,
        ] {
            assert!(!permits(base, word), "{word:08x}");
            assert!(permits(
                Features {
                    hwcap: u64::MAX,
                    hwcap2: u64::MAX
                },
                word
            ));
        }
        for word in [0x4c40203f, 0x4d40c03f, 0x4d00203f] {
            assert!(permits(base, word));
            assert!(!permits(
                Features {
                    hwcap: 1,
                    hwcap2: 0
                },
                word
            ));
        }
        for (word, bit) in [
            (0x4e284820, 3),
            (0x0ee2e020, 4),
            (0x5e020020, 5),
            (0x5e024020, 6),
            (0xce020c20, 17),
            (0xce42ac20, 18),
            (0xcec08420, 19),
            (0xce628020, 21),
        ] {
            assert!(!permits(base, word), "{word:08x}");
            assert!(permits(
                Features {
                    hwcap: 3 | (1 << bit),
                    hwcap2: 0
                },
                word
            ));
        }
        assert!(permits(base, 0x91000400));
        for word in [
            0x1e23c020, 0x1e63c020, 0x1ee24020, 0x1ee2c020, 0x1e22c020, 0x1e624020,
        ] {
            assert!(
                permits(base, word),
                "baseline precision conversion {word:08x}"
            );
        }
    }
}
