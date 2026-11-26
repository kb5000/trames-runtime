// SPDX-License-Identifier: GPL-3.0-or-later
//! Deleted cgroups retain original resource incarnations and removed parents.
use super::*;

fn setup() -> Vfs {
    let mut v = Vfs::default();
    v.set_runtime_info(1, RuntimeInfo::default());
    v
}
fn write(v: &mut Vfs, path: &[u8], value: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, value).unwrap(), value.len());
    v.close(fd).unwrap();
}
fn stat(v: &mut Vfs, descendants: usize, dying: usize) {
    let fd = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.stat", 0, 0)
        .unwrap();
    assert_eq!(
        String::from_utf8(v.pread(fd, 4096, 0).unwrap()).unwrap(),
        format!("nr_descendants {descendants}\nnr_dying_descendants {dying}\n")
    );
    v.close(fd).unwrap();
}
fn create(v: &mut Vfs, name: &[u8]) {
    v.mkdir_at(AT_FDCWD, name, 0o755).unwrap();
}

#[test]
fn a_removed_child_keeps_its_removed_parent_until_the_last_control_reference() {
    let mut v = setup();
    create(&mut v, b"/sys/fs/cgroup/a");
    create(&mut v, b"/sys/fs/cgroup/a/b");
    let held = v
        .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/b/cgroup.procs", 0, 0)
        .unwrap();
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a/b", true).unwrap();
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a", true).unwrap();
    stat(&mut v, 0, 2);
    create(&mut v, b"/sys/fs/cgroup/a");
    stat(&mut v, 1, 2);
    assert_eq!(v.pread(held, 8, 0), Err(Errno(19)));
    v.close(held).unwrap();
    stat(&mut v, 1, 0);
    create(&mut v, b"/sys/fs/cgroup/next");
    assert!(v.cgroups.borrow().dying.is_empty());
}

#[test]
fn old_memory_charges_survive_controller_replacement_and_release_only_the_original_group() {
    use trames_memory::{CgroupMemoryKind, CgroupPageCharge, PAGE_SIZE};

    let mut v = setup();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+memory");
    create(&mut v, b"/sys/fs/cgroup/a");
    let task = v.cgroup_task(1).unwrap();
    let _resources = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let original = {
        let cg = v.cgroups.borrow();
        Arc::downgrade(cg.groups[&cg.member_group(1)].memory.as_ref().unwrap())
    };
    let page = CgroupPageCharge::new(CgroupMemoryKind::Shmem).unwrap();
    let alias = page.clone();
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"-memory");
    stat(&mut v, 1, 0);
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+memory");
    let replacement = {
        let cg = v.cgroups.borrow();
        cg.groups
            .values()
            .find(|group| group.parent.is_some())
            .unwrap()
            .memory
            .as_ref()
            .unwrap()
            .clone()
    };
    assert!(!Arc::ptr_eq(&original.upgrade().unwrap(), &replacement));
    assert_eq!(replacement.current(), 0);
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a", true).unwrap();
    stat(&mut v, 0, 1);
    assert_eq!(original.upgrade().unwrap().current(), PAGE_SIZE as usize);
    drop(replacement);
    drop(page);
    stat(&mut v, 0, 1);
    drop(alias);
    assert!(original.upgrade().is_none());
    stat(&mut v, 0, 0);
}

#[test]
fn an_accepted_memory_context_keeps_its_original_limit_after_controller_removal() {
    use trames_memory::{CgroupMemoryContext, CgroupMemoryKind, CgroupPageCharge, PAGE_SIZE};

    let mut v = setup();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+memory");
    create(&mut v, b"/sys/fs/cgroup/a");
    write(
        &mut v,
        b"/sys/fs/cgroup/a/memory.max",
        PAGE_SIZE.to_string().as_bytes(),
    );
    let task = v.cgroup_task(1).unwrap();
    let _resources = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let accepted = CgroupMemoryContext::capture();
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"-memory");
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a", true).unwrap();
    stat(&mut v, 0, 1);
    let page = {
        let _original = accepted.enter();
        let page = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
        assert!(CgroupPageCharge::new(CgroupMemoryKind::File).is_err());
        page
    };
    // OOM feedback retains its actual source until the original task consumes
    // it, independently of the target's current membership after migration.
    let (origin, failed) = task.member.memory.take_oom().unwrap();
    assert!(Arc::ptr_eq(&origin, &failed));
    assert_eq!(origin.current(), PAGE_SIZE as usize);
    drop((origin, failed));
    drop(accepted);
    stat(&mut v, 0, 1);
    drop(page);
    stat(&mut v, 0, 0);
}

#[test]
fn an_admitted_io_permit_pins_deleted_ancestry_after_all_group_handles_are_gone() {
    let mut v = setup();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    create(&mut v, b"/sys/fs/cgroup/a");
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.subtree_control", b"+io");
    create(&mut v, b"/sys/fs/cgroup/a/b");
    let task = v.cgroup_task(1).unwrap();
    let _resources = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/b/cgroup.procs", b"1");
    let permit = admit_io(4096, true).unwrap().unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a/b", true).unwrap();
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a", true).unwrap();
    stat(&mut v, 0, 2);
    create(&mut v, b"/sys/fs/cgroup/a");
    stat(&mut v, 1, 2);
    permit.complete(1024);
    stat(&mut v, 1, 0);
    let root = v.cgroups.borrow().io_at(ROOT);
    assert!(root.format_stat().contains("wbytes=1024 "));
    assert!(root.format_stat().contains("wios=1 "));
}

#[test]
fn disabled_io_incarnations_remain_tracked_until_their_last_accepted_request() {
    let mut v = setup();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    create(&mut v, b"/sys/fs/cgroup/a");
    let task = v.cgroup_task(1).unwrap();
    let _resources = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    let permit = admit_io(1, false).unwrap().unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.procs", b"1");
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"-io");
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a", true).unwrap();
    stat(&mut v, 0, 1);
    drop(permit);
    stat(&mut v, 0, 0);
    assert!(v.cgroups.borrow().io_at(ROOT).format_stat().is_empty());
}
