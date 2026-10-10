// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict little-endian ELF64/AArch64 ET_EXEC loading for M0.
use std::fmt;
use trames_memory::{Memory, MemoryError, Permissions, ADDRESS_LIMIT, PAGE_SIZE};

const EH_SIZE: usize = 64;
const PH_SIZE: usize = 56;
pub const MAX_ELF_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum ElfError {
    Invalid(&'static str),
    Unsupported(&'static str),
    Memory(MemoryError),
}
impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid ELF: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported ELF: {s}"),
            Self::Memory(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for ElfError {}
impl From<MemoryError> for ElfError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

pub struct LoadedElf {
    pub memory: Memory,
    pub entry: u64,
    pub phdr: Option<u64>,
    pub phnum: u16,
}

#[derive(Debug)]
struct Segment {
    offset: usize,
    address: u64,
    filesz: usize,
    memsz: u64,
    permissions: Permissions,
    base: u64,
    size: u64,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated header"),
    )
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated header"),
    )
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated header"),
    )
}

pub fn load(bytes: &[u8], memory_limit: usize) -> Result<LoadedElf, ElfError> {
    use ElfError::{Invalid, Unsupported};
    if bytes.len() < EH_SIZE || bytes.len() > MAX_ELF_SIZE {
        return Err(Invalid("file size"));
    }
    if &bytes[..4] != b"\x7fELF" {
        return Err(Invalid("magic"));
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(Unsupported("requires ELF64 little-endian version 1"));
    }
    if u16_at(bytes, 16) != 2 {
        return Err(Unsupported("only static ET_EXEC is supported in M0"));
    }
    if u16_at(bytes, 18) != 183 {
        return Err(Unsupported("machine must be AArch64"));
    }
    if u32_at(bytes, 20) != 1 || u16_at(bytes, 52) != EH_SIZE as u16 {
        return Err(Invalid("header version or size"));
    }
    if u32_at(bytes, 48) != 0 {
        return Err(Invalid("AArch64 e_flags must be zero"));
    }
    let entry = u64_at(bytes, 24);
    let phoff = usize::try_from(u64_at(bytes, 32)).map_err(|_| Invalid("program header offset"))?;
    let phnum = u16_at(bytes, 56);
    if u16_at(bytes, 54) != PH_SIZE as u16 || phnum == 0 || phnum > 1024 || phoff < EH_SIZE {
        return Err(Invalid("program header table"));
    }
    let phend = phoff
        .checked_add(phnum as usize * PH_SIZE)
        .filter(|&end| end <= bytes.len())
        .ok_or(Invalid("truncated program headers"))?;
    let mut segments: Vec<Segment> = Vec::new();
    for pos in (phoff..phend).step_by(PH_SIZE) {
        match u32_at(bytes, pos) {
            2 => return Err(Unsupported("PT_DYNAMIC")),
            3 => return Err(Unsupported("PT_INTERP")),
            1 => {}
            _ => continue,
        }
        let flags = u32_at(bytes, pos + 4);
        if flags & !7 != 0 {
            return Err(Invalid("PT_LOAD flags"));
        }
        let offset =
            usize::try_from(u64_at(bytes, pos + 8)).map_err(|_| Invalid("segment offset"))?;
        let address = u64_at(bytes, pos + 16);
        let filesz =
            usize::try_from(u64_at(bytes, pos + 32)).map_err(|_| Invalid("segment size"))?;
        let memsz = u64_at(bytes, pos + 40);
        let align = u64_at(bytes, pos + 48);
        if filesz as u64 > memsz {
            return Err(Invalid("p_filesz exceeds p_memsz"));
        }
        if filesz != 0
            && offset
                .checked_add(filesz)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(Invalid("segment outside file"));
        }
        if align > 1 && (!align.is_power_of_two() || address % align != offset as u64 % align) {
            return Err(Invalid("segment alignment"));
        }
        let end = address
            .checked_add(memsz)
            .filter(|&end| address < ADDRESS_LIMIT && end <= ADDRESS_LIMIT)
            .ok_or(Invalid("segment address range"))?;
        if memsz == 0 {
            continue;
        }
        let base = address & !(PAGE_SIZE - 1);
        let page_end = end
            .checked_add(PAGE_SIZE - 1)
            .ok_or(Invalid("page range"))?
            & !(PAGE_SIZE - 1);
        let permissions = Permissions {
            read: flags & 4 != 0,
            write: flags & 2 != 0,
            execute: flags & 1 != 0,
        };
        if segments
            .iter()
            .any(|s| base < s.base + s.size && s.base < page_end)
        {
            return Err(Unsupported("overlapping PT_LOAD pages"));
        }
        segments.push(Segment {
            offset,
            address,
            filesz,
            memsz,
            permissions,
            base,
            size: page_end - base,
        });
    }
    if entry % 4 != 0
        || !segments
            .iter()
            .any(|s| s.permissions.execute && entry >= s.address && entry < s.address + s.memsz)
    {
        return Err(Invalid("entry is not aligned inside an executable segment"));
    }
    let phdr = segments.iter().find_map(|s| {
        if phoff >= s.offset && phend <= s.offset + s.filesz {
            Some(s.address + (phoff - s.offset) as u64)
        } else {
            None
        }
    });
    let mut memory = Memory::new(memory_limit);
    for s in segments {
        memory.map(s.base, s.size, Permissions::RW)?;
        if s.filesz != 0 {
            memory.write(s.address, &bytes[s.offset..s.offset + s.filesz])?;
        }
        memory.protect(s.base, s.size, s.permissions)?;
    }
    Ok(LoadedElf {
        memory,
        entry,
        phdr,
        phnum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0; 124];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes());
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x1078u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&1u32.to_le_bytes());
        b[68..72].copy_from_slice(&5u32.to_le_bytes());
        b[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
        b[96..104].copy_from_slice(&124u64.to_le_bytes());
        b[104..112].copy_from_slice(&256u64.to_le_bytes());
        b[112..120].copy_from_slice(&4096u64.to_le_bytes());
        b
    }
    #[test]
    fn loads_permissions_zero_fill_and_phdr() {
        let e = load(&image(), 4096).unwrap();
        assert_eq!(e.entry, 0x1078);
        assert_eq!(e.phdr, Some(0x1040));
        assert_eq!(e.memory.read_u64(0x1080).unwrap(), 0);
        assert_eq!(e.memory.fetch_u32(e.entry).unwrap(), 0);
    }
    #[test]
    fn rejects_truncation_and_malformed_segments() {
        for end in 0..124 {
            assert!(load(&image()[..end], 4096).is_err(), "prefix {end}");
        }
        let mut b = image();
        b[96..104].copy_from_slice(&257u64.to_le_bytes());
        assert!(load(&b, 4096).is_err());
        b = image();
        b[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(load(&b, 4096).is_err());
        b = image();
        b[112..120].copy_from_slice(&3u64.to_le_bytes());
        assert!(load(&b, 4096).is_err());
        b = image();
        b[24..32].copy_from_slice(&0x1001u64.to_le_bytes());
        assert!(load(&b, 4096).is_err());
        b = image();
        b[68..72].copy_from_slice(&4u32.to_le_bytes());
        assert!(load(&b, 4096).is_err());
    }
    #[test]
    fn rejects_dynamic_elf_and_memory_exhaustion() {
        let mut b = image();
        b[16..18].copy_from_slice(&3u16.to_le_bytes());
        assert!(load(&b, 4096).is_err());
        b = image();
        b[64..68].copy_from_slice(&3u32.to_le_bytes());
        assert!(load(&b, 4096).is_err());
        assert!(matches!(
            load(&image(), 0),
            Err(ElfError::Memory(MemoryError::Limit))
        ));
    }

    #[test]
    fn bss_segment_may_have_file_offset_beyond_eof() {
        let mut b = image();
        b[72..80].copy_from_slice(&0x10000u64.to_le_bytes());
        b[96..104].copy_from_slice(&0u64.to_le_bytes());
        let e = load(&b, 4096).unwrap();
        assert_eq!(e.memory.read_u64(0x1000).unwrap(), 0);
        assert_eq!(e.phdr, None);
    }

    #[test]
    fn mutated_headers_never_panic() {
        // Exercise every bit in a valid seed with a small allocation ceiling.
        let seed = image();
        for byte in 0..seed.len() {
            for bit in 0..8 {
                let mut mutated = seed.clone();
                mutated[byte] ^= 1 << bit;
                let _ = load(&mutated, 8192);
            }
        }
    }
}
