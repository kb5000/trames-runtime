// SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable process-host capabilities. No per-task extension model or hot probes.
use std::sync::OnceLock;
use trames_execution::Features;

pub(crate) struct Profile {
    pub raw: Features,
    pub allowed: Features,
    pub names: String,
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
            hwcap2: raw.hwcap2 & trames_interpreter::HWCAP2,
        };
        let words = [allowed.hwcap, allowed.hwcap2];
        let names = NAMES
            .iter()
            .filter(|&&(word, bit, _)| words[word] & (1 << bit) != 0)
            .map(|&(_, _, name)| name)
            .collect::<Vec<_>>()
            .join(" ");
        Profile {
            raw,
            allowed,
            names,
        }
    })
}
/// Cold translation gate. A missing extension faults when reached, rather than
/// acquiring the reference interpreter's software implementation.
pub(crate) fn permits(host: Features, word: u32) -> bool {
    let required = if let Some(op) = crate::vector_ops::decode(word) {
        Some((0, op.capability))
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
    } else if matches!(word & 0xffffffe0, 0xd53b2400 | 0xd53b2420) {
        Some((1, 16))
    } else if matches!(word & 0xff200c00, 0x19000400 | 0x1d000400) {
        Some((1, 43))
    } else if matches!(word & 0xff20fc00, 0x19208000 | 0x19201000 | 0x19203000) {
        Some((1, 47))
    } else {
        None
    };
    required.is_none_or(|(index, bit)| [host.hwcap, host.hwcap2][index] & (1 << bit) != 0)
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
