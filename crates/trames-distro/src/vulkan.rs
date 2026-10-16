// SPDX-License-Identifier: GPL-3.0-or-later
//! Refresh the app-owned guest ICD without recreating files on every launch.
use crate::{Error, Vfs, AT_FDCWD};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_STAGING: AtomicU64 = AtomicU64::new(1);
const LIMIT: usize = 4 * 1024 * 1024;
const LIBRARY: &[u8] = b"/usr/lib/libtrames_vulkan_icd.so";
const MANIFEST: &[u8] = b"/usr/share/vulkan/icd.d/trames.json";
const JSON: &[u8] = br#"{"file_format_version":"1.0.0","ICD":{"api_version":"1.0.0","library_path":"/usr/lib/libtrames_vulkan_icd.so"}}"#;

/// Validate before changing the namespace, keep identical inodes, and replace
/// updated files with a synced sibling + atomic rename before guest startup.
pub fn install_vulkan_icd(reader: &mut impl Read, vfs: &mut Vfs) -> Result<bool, Error> {
    let mut bytes = Vec::new();
    reader.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT
        || bytes.get(..6) != Some(b"\x7fELF\x02\x01")
        || bytes.get(18..20) != Some(&183u16.to_le_bytes())
    {
        return Err(Error::Invalid("invalid bundled AArch64 Vulkan ICD"));
    }
    let library = replace(vfs, LIBRARY, &bytes)?;
    let manifest = replace(vfs, MANIFEST, JSON)?;
    Ok(library || manifest)
}
fn replace(vfs: &mut Vfs, path: &[u8], bytes: &[u8]) -> Result<bool, Error> {
    if let Ok(fd) = vfs.open_at(AT_FDCWD, path, 0, 0) {
        let current = vfs.read(fd, bytes.len() + 1);
        vfs.close(fd)?;
        if current.is_ok_and(|current| current == bytes) {
            return Ok(false);
        }
    }
    let mut staging = None;
    for _ in 0..128 {
        let mut candidate = path.to_vec();
        candidate.extend_from_slice(
            format!(
                ".trames-icd-{}.new",
                NEXT_STAGING.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        match vfs.stat_at_flags(AT_FDCWD, &candidate, true) {
            Err(error) if error.0 == 2 => {
                staging = Some(candidate);
                break;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
    }
    let staging = staging.ok_or(Error::Invalid("Vulkan staging names exhausted"))?;
    let mut reader = bytes;
    vfs.import_reader(&staging, &mut reader, false)?;
    let result = vfs.rename_at(AT_FDCWD, &staging, AT_FDCWD, path, 0);
    if result.is_err() {
        let _ = vfs.unlink_at(AT_FDCWD, &staging, false);
    }
    result?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn library() -> Vec<u8> {
        // Installation checks the same signed-bundle header as the embedding;
        // this fixture is never executed or passed to a native driver.
        let mut bytes = vec![0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
        bytes
    }
    fn read(vfs: &mut Vfs, path: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        vfs.export_writer(path, &mut bytes).unwrap();
        bytes
    }
    #[test]
    fn repeated_install_keeps_inodes_updates_bundles_and_preserves_user_files() {
        let mut vfs = Vfs::default();
        vfs.import_file(b"/root/user-data", b"keep".to_vec())
            .unwrap();
        let mut bytes = library();
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        let before = vfs.stat_at(AT_FDCWD, LIBRARY).unwrap();
        let manifest = vfs.stat_at(AT_FDCWD, MANIFEST).unwrap();
        assert!(!install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(
            &before[8..16],
            &vfs.stat_at(AT_FDCWD, LIBRARY).unwrap()[8..16]
        );
        bytes.push(42);
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(read(&mut vfs, LIBRARY), bytes);
        assert_eq!(
            &manifest[8..16],
            &vfs.stat_at(AT_FDCWD, MANIFEST).unwrap()[8..16]
        );
        assert_eq!(read(&mut vfs, b"/root/user-data"), b"keep");
        vfs.unlink_at(AT_FDCWD, MANIFEST, false).unwrap();
        assert!(install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap());
        assert_eq!(read(&mut vfs, MANIFEST), JSON);
        vfs.unlink_at(AT_FDCWD, LIBRARY, false).unwrap();
        vfs.symlink_at(b"/root/user-data", AT_FDCWD, LIBRARY)
            .unwrap();
        install_vulkan_icd(&mut bytes.as_slice(), &mut vfs).unwrap();
        assert_eq!(read(&mut vfs, b"/root/user-data"), b"keep");
        assert_eq!(read(&mut vfs, LIBRARY), bytes);
        assert!(install_vulkan_icd(&mut b"bad".as_slice(), &mut vfs).is_err());
        assert_eq!(read(&mut vfs, LIBRARY), bytes);
    }
}
