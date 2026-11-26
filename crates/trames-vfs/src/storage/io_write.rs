// SPDX-License-Identifier: GPL-3.0-or-later
//! One admitted native metadata write, including short writes and true errors.
use crate::cgroup::IoPermit;
use std::io::{self, Write};

/// The original full metadata record is one virtual-device request. Native
/// short writes continue within its admitted bytes, without another resource
/// wait after a prefix has reached the temporary file. Record that real prefix
/// even if a later native write fails; failures before this helper refund the
/// complete, still-unissued permit on drop.
pub(super) fn write_all(
    writer: &mut impl Write,
    bytes: &[u8],
    permit: Option<IoPermit>,
) -> io::Result<()> {
    let mut written = 0;
    let result = (|| {
        while written < bytes.len() {
            match writer.write(&bytes[written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    if let Some(permit) = permit {
        permit.complete(written as u64);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cgroup, Vfs};

    struct Writer {
        bytes: Vec<u8>,
        interrupt: bool,
        fail: Option<usize>,
    }
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.interrupt) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let available = self
                .fail
                .map_or(usize::MAX, |limit| limit - self.bytes.len());
            if available == 0 {
                return Err(io::ErrorKind::StorageFull.into());
            }
            let count = bytes.len().min(3).min(available);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn write(vfs: &mut Vfs, path: &[u8], bytes: &[u8]) {
        let fd = vfs.open_at(-100, path, 2, 0).unwrap();
        vfs.write(fd, bytes).unwrap();
        vfs.close(fd).unwrap();
    }
    #[test]
    fn a_native_metadata_record_reports_its_actual_prefix_on_short_writes_or_error() {
        for fail in [None, Some(5)] {
            let mut vfs = Vfs::default();
            vfs.set_runtime_info(1, Default::default());
            write(&mut vfs, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
            vfs.mkdir_at(-100, b"/sys/fs/cgroup/a", 0o755).unwrap();
            write(&mut vfs, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
            write(&mut vfs, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
            let task = vfs.cgroup_task(1).unwrap();
            let _scope = task.resource_scope();
            let permit = cgroup::admit_io(8, true).unwrap();
            let mut writer = Writer {
                bytes: Vec::new(),
                interrupt: true,
                fail,
            };
            let result = write_all(&mut writer, b"12345678", permit);
            assert_eq!(result.is_ok(), fail.is_none());
            assert_eq!(writer.bytes, b"12345678"[..fail.unwrap_or(8)]);
            let fd = vfs
                .open_at(-100, b"/sys/fs/cgroup/a/io.stat", 0, 0)
                .unwrap();
            let stat = String::from_utf8(vfs.pread(fd, 4096, 0).unwrap()).unwrap();
            assert!(stat.split_whitespace().any(|field| field == "wios=1"));
            assert!(stat
                .split_whitespace()
                .any(|field| field == format!("wbytes={}", writer.bytes.len())));
        }
    }
}
