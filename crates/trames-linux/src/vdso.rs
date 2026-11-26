// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional AArch64 Linux clock vDSO, independent of the execution backend.
//! Immutable guest RX code and R calibration data use ordinary guest memory.
use trames_memory::{Memory, MemoryError, Permissions, PAGE_SIZE};
#[path = "vdso/code.rs"]
mod code;
pub const AUXV: u64 = 33; // AT_SYSINFO_EHDR
pub const DATA: u64 = PAGE_SIZE;
const MAGIC: [u8; 8] = *b"TRMCLK01";
const DYNAMIC: usize = 0x180;
const SYMTAB: usize = 0x280;
const STRTAB: usize = 0x340;
const HASH: usize = 0x480;
const VERSYM: usize = 0x4e0;
const VERDEF: usize = 0x500;
#[derive(Clone, Copy)]
pub struct TimeBase {
    pub counter: u64,
    pub frequency: u64,
    pub seconds: u64,
    pub nanos: u64,
}
fn word(b: &mut [u8], at: usize, v: u64, n: usize) {
    b[at..at + n].copy_from_slice(&v.to_le_bytes()[..n]);
}
fn hash(name: &str) -> u32 {
    let mut h = 0u32;
    for c in name.bytes() {
        h = (h << 4).wrapping_add(c as u32);
        let high = h & 0xf0000000;
        h ^= high >> 24;
        h &= !high;
    }
    h
}
fn string(bytes: &mut Vec<u8>, value: &str) -> u64 {
    let at = bytes.len();
    bytes.extend(value.bytes());
    bytes.push(0);
    at as u64
}
pub fn image() -> Vec<u8> {
    assert!(0x600 + code::CODE.len() * 4 <= PAGE_SIZE as usize);
    let mut bytes = vec![0; 2 * PAGE_SIZE as usize];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    word(&mut bytes, 16, 3, 2);
    word(&mut bytes, 18, 183, 2);
    word(&mut bytes, 20, 1, 4);
    word(&mut bytes, 32, 64, 8);
    word(&mut bytes, 52, 64, 2);
    word(&mut bytes, 54, 56, 2);
    word(&mut bytes, 56, 2, 2);
    // One RX ELF load segment; the adjacent R calibration mapping is not an
    // ELF load segment. Older glibc uses a zero load address as an unset sentinel
    // and miscomputes the bias when a second PT_LOAD follows the zero-based one.
    for (i, (kind, flags, offset, len, align)) in [
        (1, 5, 0, PAGE_SIZE, PAGE_SIZE),
        (2, 4, DYNAMIC as u64, 160, 8),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        word(&mut bytes, at, kind, 4);
        word(&mut bytes, at + 4, flags, 4);
        word(&mut bytes, at + 8, offset, 8);
        word(&mut bytes, at + 16, offset, 8);
        word(&mut bytes, at + 32, len, 8);
        word(&mut bytes, at + 40, len, 8);
        word(&mut bytes, at + 48, align, 8);
    }
    let mut strings = vec![0];
    let soname = string(&mut strings, "linux-vdso.so.1");
    let version = string(&mut strings, "LINUX_2.6.39");
    let mut buckets = [0u32; 3];
    let mut chains = vec![0u32; code::SYMBOLS.len() + 1];
    for (i, &(name, value, size)) in code::SYMBOLS.iter().enumerate() {
        let index = i + 1;
        let at = SYMTAB + index * 24;
        let name_at = string(&mut strings, name);
        word(&mut bytes, at, name_at, 4);
        bytes[at + 4] = 0x12;
        word(&mut bytes, at + 6, 1, 2);
        word(&mut bytes, at + 8, value, 8);
        word(&mut bytes, at + 16, size, 8);
        word(&mut bytes, VERSYM + index * 2, 2, 2);
        let bucket = hash(name) as usize % buckets.len();
        let mut tail = buckets[bucket];
        if tail == 0 {
            buckets[bucket] = index as u32;
        } else {
            while chains[tail as usize] != 0 {
                tail = chains[tail as usize];
            }
            chains[tail as usize] = index as u32;
        }
    }
    assert!(STRTAB + strings.len() <= HASH);
    bytes[STRTAB..STRTAB + strings.len()].copy_from_slice(&strings);
    for (i, v) in [buckets.len() as u32, chains.len() as u32]
        .into_iter()
        .chain(buckets)
        .chain(chains)
        .enumerate()
    {
        word(&mut bytes, HASH + i * 4, v as u64, 4);
    }
    for (i, (tag, value)) in [
        (4, HASH as u64),
        (5, STRTAB as u64),
        (6, SYMTAB as u64),
        (10, strings.len() as u64),
        (11, 24),
        (14, soname),
        (0x6ffffff0, VERSYM as u64),
        (0x6ffffffc, VERDEF as u64),
        (0x6ffffffd, 1),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        word(&mut bytes, DYNAMIC + i * 16, tag, 8);
        word(&mut bytes, DYNAMIC + i * 16 + 8, value, 8);
    }
    for (at, v, n) in [
        (0, 1, 2),
        (4, 2, 2),
        (6, 1, 2),
        (8, hash("LINUX_2.6.39") as u64, 4),
        (12, 20, 4),
        (20, version, 4),
    ] {
        word(&mut bytes, VERDEF + at, v, n);
    }
    for (i, &op) in code::CODE.iter().enumerate() {
        word(&mut bytes, 0x600 + i * 4, op as u64, 4);
    }
    bytes[PAGE_SIZE as usize + 32..PAGE_SIZE as usize + 40].copy_from_slice(&MAGIC);
    bytes
}
pub fn install(memory: &mut Memory) -> Result<u64, MemoryError> {
    let mut install = Install::new(memory)?;
    let mut wait = None;
    loop {
        match install.run(memory) {
            Err(MemoryError::Pending(fault)) => {
                let wait = match &mut wait {
                    Some(wait) => wait,
                    slot @ None => slot.insert(
                        trames_shared::HostWait::new().map_err(|_| MemoryError::BackingIo(5))?,
                    ),
                };
                wait.begin();
                wait.retain(fault.wait.subscribe(wait.signal()));
                if let Some(deadline) = fault.wait.deadline() {
                    wait.until(deadline);
                }
                if !fault.wait.ready() {
                    wait.wait().map_err(|_| MemoryError::BackingIo(5))?;
                }
            }
            result => return result,
        }
    }
}
pub struct Install {
    base: u64,
    mapped: bool,
    written: usize,
    protected: u8,
    resources: trames_memory::CgroupMemoryContext,
}
impl Install {
    pub fn new(memory: &Memory) -> Result<Self, MemoryError> {
        // Keep the stack/signal trampoline independent and randomize the free slot.
        let mut entropy = [0; 2];
        crate::fill_entropy(&mut entropy).map_err(|e| MemoryError::BackingIo(e.0))?;
        let start = 0x0000_7fff_fe00_0000 + ((u16::from_le_bytes(entropy) as u64 & 255) * 0x10000);
        let base = memory
            .find_free(start, 2 * PAGE_SIZE)
            .ok_or(MemoryError::Limit)?;
        Ok(Self {
            base,
            mapped: false,
            written: 0,
            protected: 0,
            resources: trames_memory::CgroupMemoryContext::capture(),
        })
    }
    pub fn run(&mut self, memory: &mut Memory) -> Result<u64, MemoryError> {
        let _resources = self.resources.enter();
        let base = self.base;
        if !self.mapped {
            memory.map(base, 2 * PAGE_SIZE, Permissions::RW)?;
            self.mapped = true;
        }
        static IMAGE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let bytes = IMAGE.get_or_init(image);
        while self.written < bytes.len() {
            let count = (bytes.len() - self.written).min(PAGE_SIZE as usize);
            memory.write(
                base + self.written as u64,
                &bytes[self.written..self.written + count],
            )?;
            self.written += count;
        }
        if self.protected == 0 {
            memory.protect(base, PAGE_SIZE, Permissions::RX)?;
            self.protected = 1;
        }
        if self.protected == 1 {
            memory.protect(base + DATA, PAGE_SIZE, Permissions::R)?;
            self.protected = 2;
        }
        memory.identify_vdso(base);
        Ok(base)
    }
}
pub fn initialize(memory: &mut Memory, base: u64, time: TimeBase) -> Result<(), MemoryError> {
    let address = base.checked_add(DATA).ok_or(MemoryError::InvalidRange)?;
    // A guest may have removed/replaced its optional mapping before resuming.
    if memory.read_array::<8>(address + 32).ok() != Some(MAGIC) {
        return Ok(());
    }
    if time.frequency > u64::MAX / 1_000_000_000 || time.nanos >= 1_000_000_000 {
        return Err(MemoryError::InvalidRange);
    }
    let mut bytes = [0; 32];
    for (i, v) in [time.counter, time.frequency, time.seconds, time.nanos]
        .into_iter()
        .enumerate()
    {
        word(&mut bytes, i * 8, v, 8);
    }
    memory.update_vvar(address, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::Access;
    #[test]
    fn partial_install_keeps_its_original_address_owner_and_written_prefix() {
        use std::sync::Arc;
        use trames_memory::{
            CgroupMemoryKind, CgroupMemoryTarget, CgroupPageCharge, CgroupReclaim, MemoryCgroup,
            PageWait,
        };
        struct Held(Arc<PageWait>);
        impl CgroupReclaim for Held {
            fn reclaim(&self, _: &MemoryCgroup, _: usize) -> usize {
                0
            }
            fn writeback(&self, _: &Arc<MemoryCgroup>, _: usize) -> Option<Arc<PageWait>> {
                (!self.0.ready()).then(|| self.0.clone())
            }
        }
        let group = MemoryCgroup::new(None);
        group.set_limit(2 * PAGE_SIZE as usize);
        let other = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        let ballast = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
        let held = Arc::new(Held(Arc::default()));
        ballast.register_reclaimer(&(held.clone() as Arc<dyn CgroupReclaim>));
        let mut memory = Memory::default();
        let mut work = Install::new(&memory).unwrap();
        let base = work.base;
        assert!(matches!(
            work.run(&mut memory),
            Err(MemoryError::Pending(_))
        ));
        assert_eq!(work.written, PAGE_SIZE as usize);
        memory.write(base + 300, &[99]).unwrap();
        target.set(Some(other.clone()));
        drop(ballast);
        held.0.finish();
        assert_eq!(work.run(&mut memory).unwrap(), base);
        assert_eq!(memory.read_array::<1>(base + 300).unwrap(), [99]);
        assert!(memory.check(base, 1, Access::Write).is_err());
        assert_eq!(group.current(), 2 * PAGE_SIZE as usize);
        assert_eq!(other.current(), 0);
        drop(memory);
        assert_eq!(group.current(), 0);
    }
    fn time() -> TimeBase {
        TimeBase {
            counter: 71,
            frequency: 24_000_000,
            seconds: 123,
            nanos: 999_999_999,
        }
    }
    #[test]
    fn elf_and_versioned_exports_have_separate_rx_code_and_readonly_data() {
        let mut m = Memory::default();
        let base = install(&mut m).unwrap();
        assert_eq!(m.read_array::<4>(base).unwrap(), *b"\x7fELF");
        assert!(m.check(base, PAGE_SIZE as usize, Access::Execute).is_ok());
        assert!(m.check(base, 1, Access::Write).is_err());
        assert!(m.check(base + DATA, 1, Access::Execute).is_err());
        assert!(m.check(base + DATA, 1, Access::Write).is_err());
        initialize(&mut m, base, time()).unwrap();
        assert_eq!(m.read_array::<8>(base + DATA).unwrap(), 71u64.to_le_bytes());
        assert!(m.check(base + DATA, 1, Access::Write).is_err());
        assert_eq!(
            m.read_array::<8>(base + DATA + 24).unwrap(),
            999_999_999u64.to_le_bytes()
        );
    }
    #[test]
    fn recalibration_preserves_guest_permissions_and_can_disable_the_fast_clock() {
        let mut m = Memory::default();
        let base = install(&mut m).unwrap();
        assert!(matches!(
            m.protect(base + DATA, PAGE_SIZE, Permissions::RW),
            Err(MemoryError::Permission {
                access: Access::Write,
                ..
            })
        ));
        initialize(&mut m, base, time()).unwrap();
        assert!(m.check(base + DATA, 1, Access::Write).is_err());
        initialize(
            &mut m,
            base,
            TimeBase {
                frequency: 0,
                ..time()
            },
        )
        .unwrap();
        assert_eq!(m.read_array::<8>(base + DATA + 8).unwrap(), [0; 8]);
        assert!(initialize(
            &mut m,
            base,
            TimeBase {
                frequency: u64::MAX,
                ..time()
            }
        )
        .is_err());
    }
    #[test]
    fn a_removed_or_replaced_optional_mapping_is_not_overwritten_on_resume() {
        let mut m = Memory::default();
        let base = install(&mut m).unwrap();
        m.unmap(base, 2 * PAGE_SIZE).unwrap();
        initialize(&mut m, base, time()).unwrap();
        m.map(base, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        m.write(base + DATA, &[0xa7; 40]).unwrap();
        initialize(&mut m, base, time()).unwrap();
        assert_eq!(m.read_array::<40>(base + DATA).unwrap(), [0xa7; 40]);
    }
}
