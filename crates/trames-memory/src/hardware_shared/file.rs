// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained sealed memfd allocations for CPU/device imports, with real host pages.
use super::SharedMapping;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    sync::Arc,
};
struct Allocation {
    pointer: usize,
    length: usize,
    _file: Arc<OwnedFd>,
}
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer as *mut libc::c_void, self.length);
        }
    }
}
impl SharedMapping {
    /// Allocate demand-zero shared bytes. CPU granules and device alignment are
    /// independent: larger device alignment adds only owned file/mapping padding.
    pub fn anonymous_file(length: usize, alignment: usize) -> io::Result<Self> {
        let page = crate::host_mapping_granule();
        if length == 0 || !alignment.is_power_of_two() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let alignment = alignment.max(page);
        let length = length
            .checked_next_multiple_of(page)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let total = length
            .checked_add(alignment - page)
            .filter(|&n| n <= i64::MAX as usize)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let fd = unsafe {
            libc::memfd_create(
                c"trames-shared".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        if unsafe { libc::ftruncate(file.as_raw_fd(), total as _) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = raw as usize;
        let aligned = base.next_multiple_of(alignment);
        let offset = aligned - base;
        let owner = Allocation {
            pointer: base,
            length: total,
            _file: file.clone(),
        };
        // SAFETY: both views retain this sealed initialized allocation. Padding
        // is original demand-zero storage; no persistent second byte store exists.
        unsafe {
            Self::from_allocation(aligned as *mut u8, length, owner)
                .with_file_descriptor(file, offset as u64)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_file_alias_retains_original_bytes_across_logical_truncate() {
        let file = trames_shared::SharedFile::anonymous().unwrap();
        file.set_len(8192).unwrap();
        let mapping = file.map(4096, 4096).unwrap();
        let mapping = SharedMapping::from_shared_file(mapping);
        assert!(mapping.file_geometry_owned());
        assert_eq!(
            mapping.file_offset().unwrap() + mapping.allocation_offset() as u64,
            4096
        );
        let page = mapping.shared_page();
        let exported = unsafe {
            page.export_hardware_with_mapping(
                |_| panic!("owned file bytes must not move"),
                |mapping| {
                    assert!(mapping.file_descriptor().is_some() && mapping.file_geometry_owned());
                    Err(crate::MemoryError::BackingIo(95))
                },
            )
        };
        assert!(exported.is_err());
        page.copy_write(19, &[0x29]);
        assert_eq!(file.read_at(4115, 1).unwrap(), [0x29]);
        file.set_len(4096).unwrap();
        let mut out = [0x77];
        page.copy_read(19, &mut out);
        assert_eq!(out, [0]);
    }
    #[test]
    fn fd_survives_page_capabilities_and_device_alignment_keeps_cpu_granules() {
        for alignment in [4096, 65536, 2 << 20] {
            let mapping = SharedMapping::anonymous_file(8192, alignment).unwrap();
            assert_eq!(mapping.allocation_pointer() as usize % alignment, 0);
            assert_eq!(
                mapping.allocation_len(),
                8192usize.next_multiple_of(crate::host_mapping_granule())
            );
            let mapping = mapping.with_offset(4096).unwrap();
            let expected = mapping.file_offset().unwrap() + 4096;
            let page = unsafe { crate::SharedPage::from_resource_mapping(mapping) };
            let exported = unsafe {
                page.export_hardware_with_mapping(
                    |_| panic!("original file bytes cannot be replaced"),
                    |mapping| {
                        assert_eq!(
                            mapping.file_offset().unwrap() + mapping.allocation_offset() as u64,
                            expected
                        );
                        assert!(mapping.file_descriptor().is_some());
                        Err(crate::MemoryError::BackingIo(95))
                    },
                )
            };
            assert!(exported.is_err());
            page.copy_write(0, &[13, 37, 91]);
            let mut out = [0; 3];
            page.copy_read(0, &mut out);
            assert_eq!(out, [13, 37, 91]);
        }
    }
}
