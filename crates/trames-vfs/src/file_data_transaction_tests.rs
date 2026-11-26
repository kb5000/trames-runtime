// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn suspended_plain_file_transaction_declines_direct_writes_and_retains_its_actual_wait() {
    let file = PlainFile::new(Bytes::Memory(b"base".to_vec()));
    let lease = file.begin_transaction().unwrap().unwrap();
    let scope = crate::resource_io::Scope::enter();
    assert_eq!(file.write_at(0, b"late"), Err(Errno(11)));
    let pending = scope.finish().unwrap();
    assert_eq!(pending.progress, 0);
    assert!(!pending.wait.ready());
    let mut cache = DiskReadCache::default();
    assert!(file.write_local(0, b"late", false, &mut cache).is_none());
    assert_eq!(
        file.epoch_read_at(0, 4, &mut cache).unwrap().unwrap(),
        b"base"
    );
    let scope = crate::resource_io::Scope::enter();
    assert_eq!(file.truncate(0), Err(Errno(11)));
    assert!(scope.finish().is_some());
    {
        let _owner = lease.enter();
        assert_eq!(file.write_at(0, b"part"), Ok(4));
        assert_eq!(file.read_at(0, 4, None).unwrap(), b"part");
    }
    let other = PlainFile::new(Bytes::Memory(Vec::new()));
    assert_eq!(other.write_at(0, b"independent"), Ok(11));
    {
        let _writeback = trames_shared::FileTransactionScope::writeback();
        assert_eq!(file.write_at(0, b"page"), Ok(4));
    }
    assert!(!pending.wait.ready());
    drop(lease);
    assert!(pending.wait.ready());
    assert_eq!(file.read_at(0, 4, None).unwrap(), b"page");
}
