// SPDX-License-Identifier: GPL-3.0-or-later
//! Native image FD ownership through the same files_struct used by SCM_RIGHTS.
use super::*;
use crate::fd_table::{Slot, SlotOpen};
use std::io;
use trames_graphics::{Image, ImageFds};
static NEXT_IMAGE_OFD: AtomicU64 = AtomicU64::new(1u64 << 60);
struct Images {
    files: SharedFiles,
    owner: (u32, u32),
}
impl Vfs {
    pub fn image_fds(&self) -> Arc<dyn ImageFds> {
        Arc::new(Images {
            files: self.shared_files(),
            owner: (self.credentials.uid, self.credentials.gid),
        })
    }
}
impl ImageFds for Images {
    fn lookup(&self, fd: u32) -> io::Result<Arc<dyn Image>> {
        self.files
            .lookup(fd)
            .unwrap_or(Err(Errno(9)))
            .and_then(|file| file.native_image().ok_or(Errno(22)))
            .map_err(|e| io::Error::from_raw_os_error(e.0 as i32))
    }
    fn insert(&self, image: Arc<dyn Image>) -> io::Result<u32> {
        // Construct the complete OFD before publishing one slot. The table
        // mutex covers membership only; no native operation runs under it.
        let open = Arc::new(SharedOpenDescription {
            native_image: Some(image),
            mount_resource: Default::default(),
            control: None,
            id: NEXT_IMAGE_OFD.fetch_add(1, Ordering::Relaxed),
            owner: self.owner,
            kind: FdKind::Anonymous,
            flags: (0).into(),
            file_position: Arc::default(),
            flock: Default::default(),
            node: None,
            read_node: None,
            pipe: None,
            bridge: None,
            kernel_log: None,
            notification: None,
        });
        let mut entries = self.files.0.entries.lock().unwrap();
        let fd = (0..MAX_FDS)
            .find(|fd| !entries.contains_key(fd))
            .ok_or_else(|| io::Error::from_raw_os_error(24))?;
        entries.insert(
            fd,
            Slot {
                open: SlotOpen::Shared(open),
                cloexec: true.into(),
            },
        );
        self.files.changed(&mut entries);
        Ok(fd)
    }
    fn close(&self, fd: u32) {
        let _ = self.files.close(fd, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestImage;
    // SAFETY: test metadata only; this implementation never returns a native pointer.
    unsafe impl Image for TestImage {
        fn info(&self) -> trames_graphics::ImageInfo {
            trames_graphics::ImageInfo {
                width: 8,
                height: 8,
                format: trames_graphics::Format::R8,
                pitch: 8,
                size: 64,
            }
        }
        unsafe fn metal_texture(&self, _: usize) -> io::Result<Arc<trames_graphics::Texture>> {
            Err(io::Error::from_raw_os_error(95))
        }
    }
    #[test]
    fn worker_image_fd_survives_dup_rights_transfer_and_import_lease() {
        let mut sender = Vfs::default();
        let files = sender.image_fds();
        let image = Arc::new(TestImage);
        let weak = Arc::downgrade(&image);
        let fd = std::thread::spawn(move || files.insert(image).unwrap())
            .join()
            .unwrap();
        assert_eq!(sender.seek(fd, 0, 2), Ok(64));
        let snapshot = sender.fd_snapshot();
        assert!(snapshot
            .iter()
            .any(|entry| entry.fd == fd && entry.target == b"anon_inode:[trames-image]"));
        let filesystem = sender.statfs_fd(fd).unwrap();
        assert_eq!(
            u64::from_le_bytes(filesystem[..8].try_into().unwrap()),
            0x444d4142
        );
        let stat = sender.stat_fd(fd).unwrap();
        assert_eq!(u64::from_le_bytes(stat[48..56].try_into().unwrap()), 64);
        let alias = sender.dup(fd, 0, true).unwrap();
        let rights = sender.send_rights(&[fd]).unwrap();
        sender.close(fd).unwrap();
        sender.close(alias).unwrap();
        assert!(weak.upgrade().is_some());
        let mut receiver = Vfs::default();
        let (fds, truncated) = receiver.receive_rights(rights, 1, true);
        assert!(!truncated);
        let lease = receiver.image_fds().lookup(fds[0]).unwrap();
        receiver.close(fds[0]).unwrap();
        assert!(weak.upgrade().is_some());
        drop(lease);
        assert!(weak.upgrade().is_none());
    }
}
