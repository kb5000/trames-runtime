// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked ELF64/AArch64 loading; the guest interpreter performs dynamic relocation.
use std::fmt;

// Keep the low 4 GiB available for runtimes with compressed heap/image pointers
// (notably ART). This is a guest virtual address, not reserved resident memory.
pub const INTERPRETER_BASE: u64 = 0x7000_0000_0000;
use trames_memory::{MappingFileInfo, Memory, MemoryError, Permissions, ADDRESS_LIMIT, PAGE_SIZE};

const EH_SIZE: usize = 64;
const PH_SIZE: usize = 56;
/// Bounded input for large unmodified Go executables, including dockerd.
pub const MAX_ELF_SIZE: usize = 256 * 1024 * 1024;

#[derive(Debug)]
pub enum ElfError {
    Invalid(&'static str),
    Unsupported(&'static str),
    SegmentMapping(&'static str),
    Interpreter(u32),
    Memory(MemoryError),
}
impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid ELF: {s}"),
            Self::SegmentMapping(s) => write!(f, "cannot map ELF image: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported ELF: {s}"),
            Self::Interpreter(n) => write!(f, "guest ELF interpreter: Linux errno {n}"),
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
    pub start_entry: u64,
    pub interpreter_base: u64,
    pub code: (u64, u64),
    pub data: (u64, u64),
    pub brk_base: u64,
}

#[derive(Debug)]
struct Segment {
    offset: usize,
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
    load_with_interpreter(bytes, memory_limit, |_| {
        Err(ElfError::Unsupported(
            "interpreter requires a guest filesystem",
        ))
    })
}

pub fn load_with_interpreter(
    bytes: &[u8],
    memory_limit: usize,
    mut resolve: impl FnMut(&[u8]) -> Result<Vec<u8>, ElfError>,
) -> Result<LoadedElf, ElfError> {
    load_with_files(bytes, memory_limit, None, |path| {
        resolve(path).map(|b| (b, None))
    })
}

pub fn load_with_files(
    bytes: &[u8],
    memory_limit: usize,
    main_file: Option<&MappingFileInfo>,
    mut resolve: impl FnMut(&[u8]) -> Result<(Vec<u8>, Option<MappingFileInfo>), ElfError>,
) -> Result<LoadedElf, ElfError> {
    let mut memory = Memory::new(memory_limit);
    let header = Header::parse(bytes, 0x4000_0000)?;
    // Linux opens and validates PT_INTERP before begin_new_exec. A missing
    // loader must still return ENOENT even if a later PT_LOAD cannot map.
    let interpreter = header.interpreter.map(&mut resolve).transpose()?;
    let loader_header = interpreter
        .as_ref()
        .map(|(bytes, _)| {
            let header = Header::parse(bytes, INTERPRETER_BASE).map_err(|err| match err {
                ElfError::Invalid(_) | ElfError::Unsupported(_) => ElfError::Interpreter(80),
                other => other,
            })?;
            if header.interpreter.is_some() {
                return Err(ElfError::Invalid("nested PT_INTERP"));
            }
            Ok(header)
        })
        .transpose()?;
    let main = map_image(bytes, &mut memory, header, main_file)?;
    let (start_entry, interpreter_base) =
        if let Some(((bytes, file), header)) = interpreter.as_ref().zip(loader_header) {
            let loader = map_image(bytes, &mut memory, header, file.as_ref())?;
            (loader.entry, loader.bias)
        } else {
            (main.entry, 0)
        };
    Ok(LoadedElf {
        memory,
        entry: main.entry,
        phdr: main.phdr,
        phnum: main.phnum,
        start_entry,
        interpreter_base,
        code: main.executable.code,
        data: main.executable.data,
        brk_base: main.executable.start_brk,
    })
}
struct Image {
    entry: u64,
    phdr: Option<u64>,
    phnum: u16,
    bias: u64,
    executable: trames_memory::ExecutableRanges,
}
struct Header<'a> {
    bias: u64,
    phoff: usize,
    phend: usize,
    phnum: u16,
    interpreter: Option<&'a [u8]>,
}
impl<'a> Header<'a> {
    fn parse(bytes: &'a [u8], dynamic_bias: u64) -> Result<Self, ElfError> {
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
        let bias = match u16_at(bytes, 16) {
            2 => 0,
            3 => dynamic_bias,
            _ => return Err(Unsupported("requires ET_EXEC or ET_DYN")),
        };
        if u16_at(bytes, 18) != 183 {
            return Err(Unsupported("machine must be AArch64"));
        }
        if u32_at(bytes, 20) != 1 {
            return Err(Invalid("header version"));
        }
        if u32_at(bytes, 48) != 0 {
            return Err(Invalid("AArch64 e_flags must be zero"));
        }
        let phoff =
            usize::try_from(u64_at(bytes, 32)).map_err(|_| Invalid("program header offset"))?;
        let phnum = u16_at(bytes, 56);
        if u16_at(bytes, 54) != PH_SIZE as u16 || phnum == 0 || phnum > 1024 || phoff < EH_SIZE {
            return Err(Invalid("program header table"));
        }
        let phend = phoff
            .checked_add(phnum as usize * PH_SIZE)
            .filter(|&end| end <= bytes.len())
            .ok_or(Invalid("truncated program headers"))?;
        let mut interpreter = None;
        for pos in (phoff..phend).step_by(PH_SIZE) {
            if u32_at(bytes, pos) != 3 {
                continue;
            }
            if interpreter.is_some() {
                return Err(Invalid("duplicate PT_INTERP"));
            }
            let offset = usize::try_from(u64_at(bytes, pos + 8))
                .map_err(|_| Invalid("interpreter offset"))?;
            let size = usize::try_from(u64_at(bytes, pos + 32))
                .map_err(|_| Invalid("interpreter size"))?;
            let end = offset
                .checked_add(size)
                .filter(|&e| e <= bytes.len())
                .ok_or(Invalid("interpreter range"))?;
            if !(2..=4096).contains(&size) {
                return Err(Invalid("interpreter size"));
            }
            let path = &bytes[offset..end];
            if path[size - 1] != 0 {
                return Err(Invalid("interpreter path"));
            }
            let name = path.split(|&c| c == 0).next().unwrap();
            if name.is_empty() {
                return Err(ElfError::Interpreter(13));
            }
            interpreter = Some(name);
        }
        Ok(Self {
            bias,
            phoff,
            phend,
            phnum,
            interpreter,
        })
    }
}
fn map_image(
    bytes: &[u8],
    memory: &mut Memory,
    header: Header<'_>,
    file: Option<&MappingFileInfo>,
) -> Result<Image, ElfError> {
    use ElfError::{Invalid, SegmentMapping};
    let Header {
        bias,
        phoff,
        phend,
        phnum,
        interpreter,
    } = header;
    let entry = u64_at(bytes, 24)
        .checked_add(bias)
        .ok_or(SegmentMapping("entry overflow"))?;
    let mut segments = Vec::new();
    let mut code = (u64::MAX, 0u64);
    let mut data = (0u64, 0u64);
    for pos in (phoff..phend).step_by(PH_SIZE) {
        if u32_at(bytes, pos) != 1 {
            continue;
        }
        let flags = u32_at(bytes, pos + 4);
        if flags & !7 != 0 {
            return Err(Invalid("PT_LOAD flags"));
        }
        let offset =
            usize::try_from(u64_at(bytes, pos + 8)).map_err(|_| Invalid("segment offset"))?;
        let address = u64_at(bytes, pos + 16)
            .checked_add(bias)
            .ok_or(SegmentMapping("segment bias overflow"))?;
        let filesz =
            usize::try_from(u64_at(bytes, pos + 32)).map_err(|_| Invalid("segment size"))?;
        let memsz = u64_at(bytes, pos + 40);
        let align = u64_at(bytes, pos + 48);
        if filesz as u64 > memsz {
            return Err(SegmentMapping("p_filesz exceeds p_memsz"));
        }
        if filesz != 0
            && offset
                .checked_add(filesz)
                .is_none_or(|end| end > bytes.len().next_multiple_of(PAGE_SIZE as usize))
        {
            return Err(Invalid("segment outside file"));
        }
        if filesz != 0 && address % PAGE_SIZE != offset as u64 % PAGE_SIZE {
            return Err(SegmentMapping("segment page offset"));
        }
        if align > 1 && (!align.is_power_of_two() || address % align != offset as u64 % align) {
            return Err(Invalid("segment alignment"));
        }
        let end = address
            .checked_add(memsz)
            .filter(|&end| address < ADDRESS_LIMIT && end <= ADDRESS_LIMIT)
            .ok_or(SegmentMapping("segment address range"))?;
        // Linux binfmt_elf records file-backed ends, excluding the BSS tail.
        let file_end = address + filesz as u64;
        code.0 = code.0.min(address);
        if flags & 1 != 0 {
            code.1 = code.1.max(file_end);
        }
        data.0 = data.0.max(address);
        data.1 = data.1.max(file_end);
        if memsz == 0 {
            continue;
        }
        let base = address & !(PAGE_SIZE - 1);
        let page_end = end
            .checked_add(PAGE_SIZE - 1)
            .ok_or(SegmentMapping("page range"))?
            & !(PAGE_SIZE - 1);
        let permissions = Permissions {
            read: flags & 4 != 0,
            write: flags & 2 != 0,
            execute: flags & 1 != 0,
        };
        segments.push(Segment {
            offset,
            filesz,
            memsz,
            permissions,
            base,
            size: page_end - base,
        });
    }
    // PT_INTERP supplies the first instruction. The main entry is AT_ENTRY
    // data for that loader, including executables with no main entry point.
    if interpreter.is_none()
        && (!entry.is_multiple_of(4)
            || !segments
                .iter()
                .any(|s| s.permissions.execute && (s.base..s.base + s.size).contains(&entry)))
    {
        return Err(Invalid("entry is not aligned inside an executable mapping"));
    }
    let mut phdr = None;
    let end = segments
        .iter()
        .map(|s| s.base + s.size)
        .max()
        .ok_or(Invalid("no load segments"))?;
    // A fixed segment in a single image may replace an earlier segment.
    // A separately placed PIE interpreter must not replace the main image.
    if bias != 0 && segments.iter().any(|s| !memory.is_free(s.base, s.size)) {
        return Err(SegmentMapping("dynamic image address collision"));
    }
    for s in segments {
        match memory.map(s.base, s.size, Permissions::RW) {
            Err(MemoryError::Overlap(_)) => memory.map_fixed(s.base, s.size, Permissions::RW)?,
            other => other?,
        }
        if phdr.is_some_and(|p| (s.base..s.base + s.size).contains(&p)) {
            phdr = None;
        }
        let mut file_pages = 0;
        if s.filesz != 0 {
            // mmap exposes the prefix of the first file page and the last
            // page up to EOF. BSS starts exactly at p_filesz when present.
            let start = s.offset & !(PAGE_SIZE as usize - 1);
            let file_end = s.offset + s.filesz;
            let end = if s.memsz == s.filesz as u64 {
                file_end.next_multiple_of(PAGE_SIZE as usize)
            } else {
                file_end
            }
            .min(bytes.len());
            file_pages = (file_end.next_multiple_of(PAGE_SIZE as usize) - start) as u64;
            if let Some(file) = file {
                memory.record_image_file(s.base, file_pages, start as u64, file.clone());
            }
            if start < end {
                memory.write(s.base, &bytes[start..end])?;
                if start <= phoff && phend <= end {
                    phdr = Some(s.base + (phoff - start) as u64);
                }
            }
        }
        // Linux allocates complete anonymous BSS pages with brk semantics.
        // The partial BSS tail inside a file page keeps the segment protection.
        let anonymous = Permissions {
            execute: s.permissions.execute,
            ..Permissions::RW
        };
        if file_pages == s.size || anonymous == s.permissions {
            memory.protect(s.base, s.size, s.permissions)?;
        } else {
            if file_pages != 0 {
                memory.protect(s.base, file_pages, s.permissions)?;
            }
            memory.protect(s.base + file_pages, s.size - file_pages, anonymous)?;
        }
    }
    Ok(Image {
        entry,
        phdr,
        phnum,
        bias,
        executable: trames_memory::ExecutableRanges {
            code,
            data,
            start_brk: end,
        },
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
    fn page_aligned_file_prefix_and_bss_have_distinct_provenance() {
        let mut b = image();
        b[52..54].fill(0);
        b[72..80].copy_from_slice(&120u64.to_le_bytes());
        b[80..88].copy_from_slice(&0x1078u64.to_le_bytes());
        b[96..104].copy_from_slice(&4u64.to_le_bytes());
        b[104..112].copy_from_slice(&(2 * PAGE_SIZE).to_le_bytes());
        let file = MappingFileInfo {
            device: 1,
            inode: 7,
            path: b"/image".as_slice().into(),
            path_mount: None,
        };
        let e =
            load_with_files(&b, 4 * PAGE_SIZE as usize, Some(&file), |_| unreachable!()).unwrap();
        assert_eq!(e.memory.read_array::<4>(0x1000).unwrap(), *b"\x7fELF");
        assert_eq!(e.phdr, Some(0x1040));
        let report = e.memory.memory_report().maps();
        let maps = std::str::from_utf8(&report).unwrap();
        let line = maps.lines().find(|l| l.ends_with("/image")).unwrap();
        let (start, end) = line
            .split_whitespace()
            .next()
            .unwrap()
            .split_once('-')
            .unwrap();
        assert_eq!(u64::from_str_radix(start, 16), Ok(0x1000));
        assert_eq!(u64::from_str_radix(end, 16), Ok(0x2000));
        assert_eq!(maps.matches("/image").count(), 1);
    }

    #[test]
    fn executable_page_prefix_is_an_entry_and_retains_file_bytes() {
        let mut b = image();
        b[72..80].copy_from_slice(&120u64.to_le_bytes());
        b[80..88].copy_from_slice(&0x1078u64.to_le_bytes());
        b[96..104].copy_from_slice(&4u64.to_le_bytes());
        b[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        let loaded = load(&b, 4096).unwrap();
        assert_eq!(loaded.start_entry, 0x1000);
        assert_eq!(loaded.memory.read_array::<4>(0x1000).unwrap(), *b"\x7fELF");
    }
    #[test]
    fn rejects_truncation_and_malformed_segments() {
        for end in 0..EH_SIZE + PH_SIZE {
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
        b[16..18].copy_from_slice(&1u16.to_le_bytes());
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

    #[test]
    fn pie_load_bias_and_interpreter_metadata_are_distinct() {
        let mut main = image();
        main.resize(210, 0);
        main[16..18].copy_from_slice(&3u16.to_le_bytes());
        main[56..58].copy_from_slice(&2u16.to_le_bytes());
        main[96..104].copy_from_slice(&210u64.to_le_bytes());
        main[24..32].copy_from_slice(&0x10b0u64.to_le_bytes());
        main[120..124].copy_from_slice(&3u32.to_le_bytes());
        main[128..136].copy_from_slice(&192u64.to_le_bytes());
        let path = b"/lib/ld-test.so\0";
        main[152..160].copy_from_slice(&(path.len() as u64).to_le_bytes());
        main[192..192 + path.len()].copy_from_slice(path);
        let mut loader = image();
        loader[16..18].copy_from_slice(&3u16.to_le_bytes());
        let mut e = load_with_interpreter(&main, 12288, |p| {
            assert_eq!(p, &path[..path.len() - 1]);
            Ok(loader.clone())
        })
        .unwrap();
        assert_eq!(e.entry, 0x400010b0);
        assert_eq!(e.start_entry, INTERPRETER_BASE + 0x1078);
        assert_eq!(e.interpreter_base, INTERPRETER_BASE);
        assert_eq!(e.phdr, Some(0x40001040));
        assert_eq!(e.brk_base, 0x40002000);
        assert_eq!(e.code, (0x40001000, 0x40001000 + 210));
        assert_eq!(e.data, e.code);
        // ART boot images and compressed-reference heaps may occupy this range.
        e.memory
            .map(0x7000_1000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        e.memory.write(0x7000_1078, &42u64.to_le_bytes()).unwrap();
        assert_eq!(e.memory.read_u64(0x7000_1078).unwrap(), 42);
        // The interpreter starts even when AT_ENTRY falls outside the main image.
        main[24..32].copy_from_slice(&0u64.to_le_bytes());
        let interpreted = load_with_interpreter(&main, 8192, |_| Ok(loader.clone())).unwrap();
        assert_eq!(interpreted.entry, 0x4000_0000);
        assert_eq!(interpreted.start_entry, INTERPRETER_BASE + 0x1078);

        main[192] = b'x';
        load_with_interpreter(&main, 8192, |name| {
            assert_eq!(name, b"xlib/ld-test.so");
            Ok(loader.clone())
        })
        .unwrap();

        // An invalid segment in main cannot hide an earlier interpreter error.
        main[72..80].copy_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            load_with_interpreter(&main, 8192, |_| Err(ElfError::Interpreter(2))),
            Err(ElfError::Interpreter(2))
        ));
        assert!(matches!(
            load_with_interpreter(&main, 8192, |_| Ok(vec![0; 64])),
            Err(ElfError::Interpreter(80))
        ));
        assert!(matches!(
            load_with_interpreter(&main, 8192, |_| Ok(loader.clone())),
            Err(ElfError::SegmentMapping(_))
        ));
        main[72..80].copy_from_slice(&0u64.to_le_bytes());
        loader[72..80].copy_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            load_with_interpreter(&main, 8192, |_| Ok(loader.clone())),
            Err(ElfError::SegmentMapping(_))
        ));
    }
}
