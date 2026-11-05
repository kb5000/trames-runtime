// SPDX-License-Identifier: GPL-3.0-or-later
//! Retired address spaces may still have external guarded byte borrowers.
use super::*;
use std::sync::mpsc;

struct Backing {
    identity: u64,
    bytes: RefCell<[u8; PAGE_SIZE as usize]>,
    gate: RefCell<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}
impl PageBacking for Backing {
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.identity, 0))
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        out.copy_from_slice(&self.bytes.borrow()[offset..offset + out.len()]);
        Ok(())
    }
    fn write(&self, offset: usize, input: &[u8]) -> Result<(), MemoryError> {
        // Emulate a provider blocked on I/O. It never re-enters Memory; an
        // independent guarded borrower writes a different physical frame.
        if let Some((start, wrote)) = self.gate.borrow_mut().take() {
            start.send(()).unwrap();
            wrote
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        self.bytes.borrow_mut()[offset..offset + input.len()].copy_from_slice(input);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}

#[test]
fn retired_publication_keeps_new_dirty_bits_until_the_last_borrow_returns() {
    let (start, ready) = mpsc::channel();
    let (wrote, written) = mpsc::channel();
    let (finish, finished) = mpsc::channel();
    let first = Rc::new(Backing {
        identity: new_backing_identity(),
        bytes: RefCell::new([0; PAGE_SIZE as usize]),
        gate: RefCell::new(Some((start, written))),
    });
    let second = Rc::new(Backing {
        identity: new_backing_identity(),
        bytes: RefCell::new([0; PAGE_SIZE as usize]),
        gate: RefCell::new(None),
    });
    let mut memory = Memory::default();
    memory
        .map_backed(
            0x1000,
            vec![first.clone(), second.clone()],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    let mut view = memory.parallel_view(&mut Registry::default()).unwrap();
    view.write_array(0x1000, [7]).unwrap();
    let borrower = std::thread::spawn(move || {
        ready
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        view.write_array(0x2000, [9]).unwrap();
        wrote.send(()).unwrap();
        finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        drop(view);
    });
    memory.commit_retired_parallel().unwrap();
    assert_eq!(first.bytes.borrow()[0], 7);
    assert_eq!(second.bytes.borrow()[0], 0);
    assert!(!memory.parallel_views_quiescent());
    finish.send(()).unwrap();
    borrower.join().unwrap();
    assert!(memory.parallel_views_quiescent());
    memory.commit_parallel().unwrap();
    assert_eq!(second.bytes.borrow()[0], 9);
}

#[test]
fn fork_with_a_retained_borrow_keeps_late_parent_backing_writes() {
    let backing = Rc::new(Backing {
        identity: new_backing_identity(),
        bytes: RefCell::new([0; PAGE_SIZE as usize]),
        gate: RefCell::new(None),
    });
    let mut memory = Memory::default();
    memory
        .map_backed(0x1000, vec![backing.clone()], true, Permissions::RW, false)
        .unwrap();
    let mut registry = Registry::default();
    let mut borrowed = memory.parallel_view(&mut registry).unwrap();
    borrowed.write_array(0x1000, [7]).unwrap();
    memory.commit_retired_parallel().unwrap();
    assert_eq!(backing.bytes.borrow()[0], 7);
    let _child = memory.clone();
    let resumed = memory.parallel_view(&mut registry).unwrap();
    borrowed.write_array(0x1000, [9]).unwrap();
    assert_eq!(resumed.read_array::<1>(0x1000).unwrap(), [9]);
    drop((borrowed, resumed));
    memory.commit_parallel().unwrap();
    assert_eq!(backing.bytes.borrow()[0], 9);
}

#[test]
fn retained_private_parent_and_child_diverge_after_fork() {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
    let mut registry = Registry::default();
    let mut borrowed = memory.parallel_view(&mut registry).unwrap();
    borrowed.write_array(0x1000, 7u64.to_le_bytes()).unwrap();
    memory.commit_retired_parallel().unwrap();
    let mut child = memory.clone();
    let mut resumed = memory.parallel_view(&mut registry).unwrap();
    borrowed.write_array(0x1000, 9u64.to_le_bytes()).unwrap();
    resumed.write_array(0x2000, 11u64.to_le_bytes()).unwrap();
    assert_eq!(child.read_u64(0x1000).unwrap(), 7);
    assert_eq!(child.read_u64(0x2000).unwrap(), 0);
    child.write_array(0x1000, 13u64.to_le_bytes()).unwrap();
    assert_eq!(borrowed.read_u64(0x1000).unwrap(), 9);
    drop((borrowed, resumed));
    memory.commit_parallel().unwrap();
    assert_eq!(memory.read_u64(0x1000).unwrap(), 9);
    assert_eq!(memory.read_u64(0x2000).unwrap(), 11);
}
