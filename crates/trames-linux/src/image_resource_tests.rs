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
#[test]
fn stack_entropy_pointers_and_completed_page_writes_survive_allocation_pressure() {
    let group = MemoryCgroup::new(None);
    group.set_limit(2 * PAGE_SIZE as usize);
    let target = Arc::new(CgroupMemoryTarget::default());
    target.set(Some(group.clone()));
    let _scope = target.scope();
    let ballast = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
    let held = Arc::new(Held(Arc::default()));
    ballast.register_reclaimer(&(held.clone() as Arc<dyn CgroupReclaim>));
    let mut elf = LoadedElf {
        memory: Memory::new(2 * STACK_SIZE as usize),
        entry: 0x1000,
        phdr: None,
        phnum: 0,
        start_entry: 0x1000,
        interpreter_base: 0,
        code: (0x1000, 0x2000),
        data: (0, 0),
        brk_base: 0x2000,
    };
    let mut stack = InitialStack::new(
        &elf,
        &[vec![b'a'; PAGE_SIZE as usize + 30]],
        &[],
        &Default::default(),
        Features {
            hwcap: 0,
            hwcap2: 0,
        },
        &[],
        None,
    )
    .unwrap();
    let writes = stack.writes.clone();
    let Err(ImageError::Memory(MemoryError::Pending(fault))) = stack.run(&mut elf.memory) else {
        panic!("original stack pressure")
    };
    assert!(stack.written != 0);
    assert!(target.take_oom().is_none());
    target.set(Some(MemoryCgroup::new(None)));
    group.set_limit(8 * PAGE_SIZE as usize);
    assert!(
        fault.wait.ready(),
        "new max credits wake the retained allocation"
    );
    let sp = stack.run(&mut elf.memory).unwrap();
    assert_eq!(sp, stack.sp);
    for (address, bytes) in writes {
        let mut actual = vec![0; bytes.len()];
        elf.memory.read(address, &mut actual).unwrap();
        assert_eq!(actual, bytes);
    }
    assert_eq!(elf.memory.read_u64(sp).unwrap(), 1);
    drop(elf);
    assert_eq!(group.current(), PAGE_SIZE as usize);
    drop(ballast);
}
