// SPDX-License-Identifier: GPL-3.0-or-later
//! Cross-thread original mm custody and independent fork byte ownership.
use super::*;
use std::sync::Barrier;

const BASE: u64 = 0x40000;

#[test]
fn structural_admission_keeps_actual_root_counts_and_never_locks_view_bytes() {
    let mut memory = source(2);
    let peer = memory.share();
    let owners = memory.coordinator_ownership();
    let view = memory
        .parallel_view(&mut parallel::Registry::default())
        .unwrap();
    let permit = memory.try_admit().unwrap();
    assert_eq!(
        memory.coordinator_ownership(),
        owners,
        "a permit is not a guest root"
    );
    let (sent, received) = std::sync::mpsc::channel();
    let join = std::thread::spawn(move || {
        assert!(peer.try_admit().is_none());
        assert_eq!(view.read_array::<64>(BASE).unwrap(), [37; 64]);
        sent.send(()).unwrap();
        peer
    });
    received
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let peer = join.join().unwrap();
    drop(permit);
    let permit = peer.try_admit().unwrap();
    assert_eq!(memory.coordinator_ownership(), owners);
    drop((memory, peer));
    // A retired root's structural state stays alive until its final permit
    // ends, without exposing a new Memory wrapper or a dangling mutex guard.
    drop(permit);
}

// Also exercise byte-owner handoff independently of a complete root's lifetime.
fn fork_bytes(parent: &Memory) -> Arc<PageBytes> {
    let mut child = parent.clone();
    child.materialize_descriptors(BASE, 1);
    let frame = child.frame(BASE).unwrap();
    child.frames[frame].take().unwrap().bytes
}

fn adopt_bytes(bytes: Arc<PageBytes>) -> Memory {
    let mut memory = Memory::default();
    let mut page = (*memory.anonymous_page(Permissions::RW)).clone();
    page.bytes = bytes;
    page.charge.ensure().unwrap();
    memory.insert_owned_page(BASE, page);
    memory
}

fn source(kind: u32) -> Memory {
    let mut memory = Memory::default();
    memory.map(BASE, 4 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(BASE, &[37; 64]).unwrap();
    if kind == 0 {
        // A software-only host group uses heap storage on the same COW path.
        let frame = memory.frame(BASE).unwrap();
        let bytes = memory.frames[frame].as_ref().unwrap().bytes.snapshot();
        memory.mmu.retire();
        memory.invalidate_translations();
        memory.frames[frame].as_mut().unwrap().bytes = Arc::new(PageBytes::new(bytes));
    } else if kind == 2 {
        let mut registry = parallel::Registry::default();
        let view = memory.parallel_view(&mut registry).unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        let frame = memory.frame(BASE).unwrap();
        assert!(memory.frames[frame]
            .as_ref()
            .unwrap()
            .bytes
            .shared()
            .is_some());
    } else {
        let frame = memory.frame(BASE).unwrap();
        assert!(memory.frames[frame]
            .as_ref()
            .unwrap()
            .bytes
            .physical()
            .is_some());
    }
    memory
}

#[test]
fn fork_byte_owners_detach_and_retire_on_independent_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PageBytes>();
    for kind in 0..3 {
        let mut parent = source(kind);
        let gate = Arc::new(Barrier::new(9));
        let children: Vec<_> = (0..8)
            .map(|id| {
                let bytes = fork_bytes(&parent);
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    if id % 2 == 0 {
                        // Last-owner transitions race with sibling detachment.
                        drop(bytes);
                        return;
                    }
                    let mut child = adopt_bytes(bytes);
                    assert_eq!(child.read_array::<64>(BASE).unwrap(), [37; 64]);
                    for round in 0..32 {
                        let old = child.read_array::<64>(BASE).unwrap();
                        let mut grandchild = child.clone();
                        let value = (id * 32 + round) as u8;
                        child.write(BASE, &[value; 64]).unwrap();
                        assert_eq!(grandchild.read_array::<64>(BASE).unwrap(), old);
                        grandchild.write(BASE, &[value ^ 255; 64]).unwrap();
                        assert_eq!(child.read_array::<64>(BASE).unwrap(), [value; 64]);
                    }
                })
            })
            .collect();
        gate.wait();
        parent.write(BASE, &[211; 64]).unwrap();
        for child in children {
            child.join().unwrap();
        }
        assert_eq!(parent.read_array::<64>(BASE).unwrap(), [211; 64]);
    }
}

#[test]
fn moved_fork_bytes_keep_physical_slots_alive_after_original_mm_exit() {
    let parent = source(1);
    let bytes = fork_bytes(&parent);
    let storage = Arc::downgrade(bytes.physical().unwrap().0);
    drop(parent);
    let child = std::thread::spawn(move || {
        let mut child = adopt_bytes(bytes);
        assert_eq!(child.read_array::<64>(BASE).unwrap(), [37; 64]);
        child.write(BASE, &[19; 64]).unwrap();
        assert_eq!(child.read_array::<64>(BASE).unwrap(), [19; 64]);
        child.unmap(BASE, PAGE_SIZE).unwrap();
    });
    child.join().unwrap();
    assert!(
        storage.upgrade().is_none(),
        "final byte owner releases host RAM"
    );
}

#[test]
fn execution_views_never_inflate_fork_byte_ownership() {
    let mut parent = source(2);
    let frame = parent.frame(BASE).unwrap();
    let mut registry = parallel::Registry::default();
    let mut view = parent.parallel_view(&mut registry).unwrap();
    let peers: Vec<_> = (0..8).map(|_| view.clone()).collect();
    assert_eq!(
        Arc::strong_count(&parent.frames[frame].as_ref().unwrap().bytes),
        1
    );
    view.write_array(BASE, [97; 64]).unwrap();
    for peer in peers {
        assert_eq!(peer.read_array::<64>(BASE).unwrap(), [97; 64]);
    }
    drop(view);
    parent.commit_parallel().unwrap();
    assert_eq!(parent.read_array::<64>(BASE).unwrap(), [97; 64]);
    assert_eq!(registry.metrics.cow_detach_bytes, 0);
}

#[test]
fn complete_forked_address_spaces_move_between_executors() {
    fn send<T: Send>() {}
    send::<Memory>();
    send::<SharedRoot>();
    let mut parent = source(1);
    let mut child = parent.try_fork().unwrap();
    let gate = Arc::new(Barrier::new(2));
    let peer_gate = gate.clone();
    let work = std::thread::spawn(move || {
        peer_gate.wait();
        for value in 0..128u8 {
            child.write_array(BASE, [value; 64]).unwrap();
            let mut fork = child.try_fork().unwrap();
            fork.write_array(BASE, [value ^ 255; 64]).unwrap();
            assert_eq!(child.read_array::<64>(BASE).unwrap(), [value; 64]);
        }
        child
    });
    gate.wait();
    for value in 0..128u8 {
        parent.write_array(BASE, [value ^ 255; 64]).unwrap();
    }
    let child = work.join().unwrap();
    assert_eq!(parent.read_array::<64>(BASE).unwrap(), [128; 64]);
    assert_eq!(child.read_array::<64>(BASE).unwrap(), [127; 64]);
}

#[test]
fn clone_vm_roots_share_structural_changes_after_executor_handoff() {
    let mut parent = source(2);
    let mut peer = parent.share();
    let custody = parent.shared_root().unwrap();
    let mut peer = std::thread::spawn(move || {
        let mut registry = parallel::Registry::default();
        let mut view = peer.parallel_view(&mut registry).unwrap();
        view.write_array(BASE, [91; 64]).unwrap();
        drop(view);
        custody.commit_parallel().unwrap();
        peer.map(BASE + 8 * PAGE_SIZE, PAGE_SIZE, Permissions::RW)
            .unwrap();
        peer.write_array(BASE + 8 * PAGE_SIZE, [113; 64]).unwrap();
        peer
    })
    .join()
    .unwrap();
    assert_eq!(parent.read_array::<64>(BASE).unwrap(), [91; 64]);
    assert_eq!(
        parent.read_array::<64>(BASE + 8 * PAGE_SIZE).unwrap(),
        [113; 64]
    );
    assert_eq!(parent.coordinator_ownership().1, 2);
    peer.unmap(BASE + 8 * PAGE_SIZE, PAGE_SIZE).unwrap();
    assert!(parent.read_array::<1>(BASE + 8 * PAGE_SIZE).is_err());
    drop(peer);
    assert_eq!(parent.coordinator_ownership().1, 1);
}
