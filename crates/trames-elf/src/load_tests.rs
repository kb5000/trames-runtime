// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Arc;
use trames_memory::{
    CgroupMemoryKind, CgroupMemoryTarget, CgroupPageCharge, CgroupReclaim, MemoryCgroup, PageWait,
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
fn image(pages: usize, dynamic: bool, interpreter: bool) -> Vec<u8> {
    let mut bytes = vec![41; pages * PAGE_SIZE as usize];
    bytes[..176].fill(0);
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&(if dynamic { 3u16 } else { 2u16 }).to_le_bytes());
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x1078u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(if interpreter { 2u16 } else { 1u16 }).to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&(pages as u64 * PAGE_SIZE).to_le_bytes());
    bytes[104..112].copy_from_slice(&(pages as u64 * PAGE_SIZE).to_le_bytes());
    bytes[112..120].copy_from_slice(&PAGE_SIZE.to_le_bytes());
    if interpreter {
        bytes[120..124].copy_from_slice(&3u32.to_le_bytes());
        bytes[128..136].copy_from_slice(&256u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&7u64.to_le_bytes());
        bytes[256..263].copy_from_slice(b"/ld.so\0");
    }
    bytes
}
#[test]
fn main_and_interpreter_mapping_resume_original_pages_and_owner_after_migration() {
    for interpreted in [false, true] {
        let group = MemoryCgroup::new(None);
        group.set_limit((2 + usize::from(interpreted)) * PAGE_SIZE as usize);
        let other = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        let ballast = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
        let held = Arc::new(Held(Arc::default()));
        ballast.register_reclaimer(&(held.clone() as Arc<dyn CgroupReclaim>));
        let mut loader = Loader::new(
            image(if interpreted { 1 } else { 2 }, false, interpreted),
            16 * PAGE_SIZE as usize,
            None,
            interpreted.then(|| (image(2, true, false), None)),
        )
        .unwrap();
        assert!(loader.run().unwrap().is_none());
        assert!(target.take_oom().is_none());
        assert_eq!(group.current(), group.limit());
        target.set(Some(other.clone()));
        drop(ballast);
        held.0.finish();
        let loaded = loader.run().unwrap().unwrap();
        assert_eq!(loaded.memory.read_array::<1>(0x1000 + 300).unwrap(), [41]);
        let last = if interpreted {
            INTERPRETER_BASE + 0x2000
        } else {
            0x2000
        };
        assert_eq!(loaded.memory.read_array::<1>(last + 300).unwrap(), [41]);
        assert_eq!(other.current(), 0);
        assert_eq!(group.current(), group.limit());
        drop(loaded);
        assert_eq!(group.current(), 0);
    }
}
#[test]
fn cancelling_partial_elf_mapping_retires_only_its_original_physical_pages() {
    let group = MemoryCgroup::new(None);
    group.set_limit(2 * PAGE_SIZE as usize);
    let target = Arc::new(CgroupMemoryTarget::default());
    target.set(Some(group.clone()));
    let _scope = target.scope();
    let ballast = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
    let held = Arc::new(Held(Arc::default()));
    ballast.register_reclaimer(&(held.clone() as Arc<dyn CgroupReclaim>));
    let mut loader =
        Loader::new(image(2, false, false), 8 * PAGE_SIZE as usize, None, None).unwrap();
    assert!(loader.run().unwrap().is_none());
    drop(loader);
    assert_eq!(group.current(), PAGE_SIZE as usize);
    assert!(target.take_oom().is_none());
    drop(ballast);
    assert_eq!(group.current(), 0);
}
