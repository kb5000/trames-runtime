// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn atomic_create_keeps_mode_descriptor_flags_and_the_granted_handle() {
    let (v, dev) = mounted();
    v.set_umask(0o027);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(
            AT_FDCWD,
            b"/mnt/new",
            O_CREAT | O_CLOEXEC | 0x80 | 2,
            0o666,
            0,
            &files
        )
        .is_none());
    let work = paths.take_open_work().unwrap();
    let lookup = receive(c, 1, 1);
    c.write(&reply(id(&lookup), -2, &[])).unwrap();
    let work = waiting(work);
    let create = receive(c, 35, 1);
    assert_eq!(
        &create[40..44],
        &(O_CREAT | 0x80 | 2 | O_LARGEFILE).to_le_bytes()
    );
    assert_eq!(&create[44..48], &0o100640u32.to_le_bytes());
    assert_eq!(&create[48..52], &0o027u32.to_le_bytes());
    assert_eq!(&create[56..], b"new\0");
    let mut out = entry(80, 180, 0o100640).to_vec();
    out.extend(9876u64.to_le_bytes());
    out.extend([0; 8]);
    answer(c, &create, &out);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let opened = v.shared_files().lookup(fd as u32).unwrap().unwrap();
    assert_eq!(opened.open.flags.get(), 2 | O_LARGEFILE);
    assert!(v.descriptor(fd as u32).unwrap().cloexec.get());
}

#[test]
fn atomic_create_masks_only_in_the_live_callback_and_resamples_on_fallback() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    v.set_umask(0o077);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/parent/new", O_CREAT | 2, 0o666, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    let parent = receive(c, 1, 1);
    v.set_umask(0o002);
    answer(c, &parent, &entry(70, 170, 0o40755));
    let work = waiting(work);
    let lookup = receive(c, 1, 70);
    v.set_umask(0o070);
    c.write(&reply(id(&lookup), -2, &[])).unwrap();
    let work = waiting(work);
    let create = receive(c, 35, 70);
    assert_eq!(&create[44..48], &0o100606u32.to_le_bytes());
    assert_eq!(&create[48..52], &0o070u32.to_le_bytes());
    v.set_umask(0o020);
    c.write(&reply(id(&create), -38, &[])).unwrap();
    let work = waiting(work);
    let mknod = receive(c, 8, 70);
    assert_eq!(&mknod[40..44], &0o100646u32.to_le_bytes());
    assert_eq!(&mknod[48..52], &0o020u32.to_le_bytes());
    answer(c, &mknod, &entry(80, 180, 0o100646));
    let work = waiting(work);
    // The original parent survives through both creation callbacks. The OPEN
    // request is queued before its parent lease is released.
    answer(c, &receive(c, 14, 80), &[0; 16]);
    receive(c, 2, 70);
    assert!(matches!(finish(work), Ok(FileValue::Count(_))));
}

#[test]
fn exclusive_create_existing_inode_precedes_link_and_readonly_errors() {
    for (kind, policy) in [(0o120777, 0), (0o120777, 4), (0o40755, 0), (0o100600, 0)] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        v.mount(None, b"/mnt", None, 32 | 4096 | 1, None).unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        assert!(paths
            .open_at_resolve(
                AT_FDCWD,
                b"/mnt/existing",
                O_CREAT | 0x80 | O_NOFOLLOW | 2,
                0o600,
                policy,
                &files
            )
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(80, 180, kind));
        assert!(matches!(finish(work), Err(Errno(17))));
        receive(c, 2, 80);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn unsupported_create_uses_mknod_open_and_remembers_the_connection_fallback() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    for i in 0..2 {
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/new", O_CREAT | 2, 0o600, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        let lookup = receive(c, 1, 1);
        c.write(&reply(id(&lookup), -2, &[])).unwrap();
        let mut work = waiting(work);
        if i == 0 {
            let create = receive(c, 35, 1);
            c.write(&reply(id(&create), -38, &[])).unwrap();
            work = waiting(work);
        }
        let mknod = receive(c, 8, 1);
        assert_eq!(&mknod[40..44], &0o100600u32.to_le_bytes());
        answer(c, &mknod, &entry(80 + i, 180 + i, 0o100600));
        let work = waiting(work);
        let open = receive(c, 14, 80 + i);
        answer(c, &open, &[0; 16]);
        assert!(matches!(finish(work), Ok(FileValue::Count(_))));
    }
}

#[test]
fn canceled_create_balances_both_resources_before_or_after_reply_arrives() {
    let (_dev, c) = start();
    for cancel_first in [true, false] {
        let request = c.request(35, 1, Caller::default(), &[0; 16]).unwrap();
        let create = receive(&c, 35, 1);
        let mut out = entry(80, 180, 0o100600).to_vec();
        out.extend(9876u64.to_le_bytes());
        out.extend([0; 8]);
        if cancel_first {
            drop(request);
            answer(&c, &create, &out);
        } else {
            answer(&c, &create, &out);
            drop(request);
        }
        let release = receive(&c, 18, 80);
        assert_eq!(&release[40..48], &9876u64.to_le_bytes());
        answer(&c, &release, &[]);
        receive(&c, 2, 80);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}
